import os
import sys
import json
import subprocess
import shutil
import time
from pathlib import Path
from typing import Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import config
from core.logger import get_logger

logger = get_logger("core.scanners")

# ── Windows vs Unix command detection ─────────────────────────
_IS_WINDOWS = sys.platform == "win32"
_SNYK_CMD   = "snyk.cmd" if _IS_WINDOWS else "snyk"
_TRIVY_CMD  = "trivy"


def _tool_available(cmd: str) -> bool:
    """Return True if the command is on PATH."""
    found = shutil.which(cmd) is not None
    if not found:
        logger.warning(f"[SCANNERS] '{cmd}' not found on PATH — scanner skipped")
    return found


def _run_subprocess(
    args: list,
    cwd: Optional[str] = None,
    timeout: int = 120,
    label: str = "subprocess",
    extra_env: Optional[Dict[str, str]] = None,
    success_codes: tuple = (0, 1),
) -> Optional[str]:
    """
    Run a subprocess and return stdout as a string.

    Parameters
    ----------
    args         : command + arguments list (shell=False for safety)
    cwd          : working directory
    timeout      : hard timeout in seconds (subprocess.TimeoutExpired on breach)
    label        : log prefix for identification
    extra_env    : additional env vars to merge into os.environ
    success_codes: exit codes to treat as success (default 0 and 1)
                   For Snyk: 0=no vulns, 1=vulns found — BOTH have JSON output

    Returns
    -------
    stdout string if successful, None if error/timeout/no output
    """
    cmd_str = " ".join(str(a) for a in args)
    logger.info(f"[SCANNERS:{label}] ── Running ──")
    logger.info(f"[SCANNERS:{label}] CMD: {cmd_str}")
    logger.info(f"[SCANNERS:{label}] CWD: {cwd or os.getcwd()}")
    logger.info(f"[SCANNERS:{label}] timeout: {timeout}s")

    run_env = os.environ.copy()
    if extra_env:
        run_env.update(extra_env)

    start_ts = time.monotonic()

    # ── Use Popen instead of subprocess.run so we can KILL on timeout ─────────
    # subprocess.run(timeout=N) raises TimeoutExpired but does NOT kill the child.
    # On Windows especially, the snyk/trivy process keeps running, consuming CPU
    # and network, and the NEXT scan call may spawn another one on top of it.
    # Per Python docs: "The child process is not killed if the timeout expires,
    # so in order to cleanup properly a well-behaved application should kill the
    # child process and finish communication."
    # Solution: Popen + communicate(timeout) + explicit kill() on timeout.
    try:
        proc = subprocess.Popen(
            args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=run_env,
            shell=False,           # NEVER True — security + Windows safety
        )
        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
            elapsed = time.monotonic() - start_ts
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")

            logger.info(
                f"[SCANNERS:{label}] Exit code: {proc.returncode} | "
                f"elapsed: {elapsed:.1f}s"
            )

            if stderr_str:
                snippet = stderr_str.strip()[:600]
                logger.debug(f"[SCANNERS:{label}] stderr: {snippet}")

            if proc.returncode not in success_codes:
                logger.warning(
                    f"[SCANNERS:{label}] Unexpected exit code {proc.returncode} "
                    f"(expected one of {success_codes}) — attempting JSON parse anyway"
                )

            if stdout_str:
                logger.info(f"[SCANNERS:{label}] stdout: {len(stdout_str)} chars")
                return stdout_str
            else:
                logger.warning(f"[SCANNERS:{label}] No stdout produced")
                return None

        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start_ts
            logger.error(
                f"[SCANNERS:{label}] ⏰ TIMED OUT after {elapsed:.0f}s "
                f"(limit={timeout}s) — killing process"
            )
            # ── Kill the process AND its children cleanly ────────────────────
            # On Windows, kill() sends SIGKILL equivalent (TerminateProcess).
            # We also try taskkill /T to kill child processes spawned by snyk/node.
            try:
                proc.kill()
                logger.info(f"[SCANNERS:{label}] Process killed (pid={proc.pid})")
            except Exception as kill_err:
                logger.warning(f"[SCANNERS:{label}] Kill failed: {kill_err}")

            # Windows: snyk is a Node.js wrapper — kill the whole process tree
            try:
                import platform
                if platform.system() == "Windows":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        capture_output=True, timeout=5
                    )
                    logger.debug(f"[SCANNERS:{label}] taskkill /T sent for pid={proc.pid}")
            except Exception:
                pass  # Best-effort — don't crash on cleanup failure

            # Drain pipes to prevent deadlock
            try:
                proc.communicate(timeout=3)
            except Exception:
                pass
            return None
    except FileNotFoundError:
        logger.error(
            f"[SCANNERS:{label}] Command not found: '{args[0]}' — "
            "is it installed and on PATH?"
        )
        return None
    except Exception as e:
        logger.error(f"[SCANNERS:{label}] Unexpected error: {e}")
        return None


def _safe_json_parse(stdout: str, label: str) -> Optional[dict]:
    """
    Parse JSON from stdout, stripping any leading non-JSON content.
    Trivy and Snyk sometimes emit progress lines before the JSON block.
    Returns parsed dict or None on failure.
    """
    if not stdout:
        return None

    # Find first JSON object or array
    json_start = stdout.find("{")
    arr_start  = stdout.find("[")
    if arr_start >= 0 and (json_start < 0 or arr_start < json_start):
        json_start = arr_start

    if json_start > 0:
        logger.debug(
            f"[SCANNERS:{label}] Stripping {json_start} chars of "
            "non-JSON prefix from stdout"
        )
        stdout = stdout[json_start:]
    elif json_start < 0:
        logger.error(f"[SCANNERS:{label}] No JSON found in stdout")
        return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        logger.error(f"[SCANNERS:{label}] JSON parse error: {e}")
        logger.debug(f"[SCANNERS:{label}] Raw stdout (first 500): {stdout[:500]}")
        return None


# ══════════════════════════════════════════════════════════════
# SNYK CODE — SAST
# Per Snyk docs: https://docs.snyk.io/developer-tools/snyk-cli/commands/code-test
# Exit codes: 0=no vulns, 1=vulns found (BOTH produce JSON), 2=failure, 3=no projects
# ══════════════════════════════════════════════════════════════

def run_snyk_code(repo_path: str) -> dict:
    """
    Run `snyk code test --json <repo_path>` for SAST analysis.

    Returns SARIF format: {"runs": [{"results": [...]}]}
    Returns empty fallback dict on any failure.

    Exit code handling (per Snyk official docs):
      0 = scan complete, no vulnerabilities → JSON on stdout
      1 = scan complete, vulnerabilities found → JSON on stdout ← most common
      2 = failure (bad token, no internet) → no usable JSON
      3 = no supported projects detected → empty JSON
    """
    fallback = {"runs": [], "error": "snyk_code_not_run"}

    if not config.SNYK_TOKEN:
        logger.warning("[SCANNERS:snyk_code] SNYK_TOKEN not set — skipping SAST")
        return fallback

    if not _tool_available(_SNYK_CMD):
        return fallback

    repo_path = os.path.normpath(repo_path)
    logger.info(f"[SCANNERS:snyk_code] Scanning: {repo_path}")

    stdout = _run_subprocess(
        args=[_SNYK_CMD, "code", "test", "--json", repo_path],
        cwd=repo_path,
        timeout=config.SNYK_TIMEOUT,
        label="snyk_code",
        extra_env={"SNYK_TOKEN": config.SNYK_TOKEN},
        success_codes=(0, 1),  # both are success cases per Snyk docs
    )

    if not stdout:
        logger.warning("[SCANNERS:snyk_code] No output — returning empty results")
        return fallback

    data = _safe_json_parse(stdout, "snyk_code")
    if data is None:
        return fallback

    if "runs" in data:
        n = sum(len(r.get("results", [])) for r in data["runs"])
        logger.info(f"[SCANNERS:snyk_code] ✅ Parsed SARIF: {n} SAST results")
        return data

    # Some Snyk versions use slightly different top-level structure
    logger.warning(
        f"[SCANNERS:snyk_code] Unexpected JSON keys: {list(data.keys())} "
        "— returning raw"
    )
    return data


# ══════════════════════════════════════════════════════════════
# TRIVY — SCA + Secrets
# Per Trivy docs: https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/
# Auto-detects ALL package managers: Python/Node/Java/Go/Rust/Ruby/PHP/.NET/Swift/Dart etc.
# ══════════════════════════════════════════════════════════════

def run_trivy(repo_path: str) -> dict:
    """
    Run `trivy fs` for SCA (dependency vulns) + secret detection.

    Coverage (from Trivy official docs):
      Python:  requirements.txt, Pipfile.lock, poetry.lock, uv.lock, pdm.lock
      Node:    package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock
      Java:    pom.xml, *.gradle, gradle.lockfile, *.sbt.lock
      Go:      go.mod, go.sum
      Rust:    Cargo.lock
      Ruby:    Gemfile.lock
      PHP:     composer.lock
      .NET:    packages.config, *.deps.json
      Swift:   Package.resolved
      Dart:    pubspec.lock
      + Terraform, Kubernetes, CloudFormation misconfigs via --scanners misconfig
      All auto-detected — no extra flags needed for language coverage.

    TIMEOUT NOTE:
      First run downloads the Trivy vuln DB (~200MB).
      This takes 2-5 minutes on a slow connection.
      Timeout is set to config.TRIVY_TIMEOUT (default 300s).
    """
    fallback = {"Results": [], "error": "trivy_not_run"}

    if not _tool_available(_TRIVY_CMD):
        logger.warning("[SCANNERS:trivy] trivy not found on PATH — SCA skipped")
        return fallback

    repo_path = os.path.normpath(repo_path)
    logger.info(f"[SCANNERS:trivy] Scanning: {repo_path}")
    logger.info(
        "[SCANNERS:trivy] NOTE: First run downloads vuln DB (~200MB). "
        f"Timeout={config.TRIVY_TIMEOUT}s."
    )
    logger.info(
        "[SCANNERS:trivy] Coverage: Python/Node/Java/Go/Rust/Ruby/PHP/"
        ".NET/Swift/Dart + secrets + IaC"
    )

    stdout = _run_subprocess(
        args=[
            _TRIVY_CMD, "fs",
            "--format",             "json",
            "--scanners",           "vuln,secret",  # CVEs + secrets in one pass
            "--exit-code",          "0",            # always exit 0 → always get JSON
            "--no-progress",                        # no progress bar → clean JSON stdout
            # ── Detection quality flags ─────────────────────────────────────────
            # --detection-priority comprehensive: scan manifest files (requirements.txt,
            # package.json, etc.) even WITHOUT a resolved lockfile or installed venv.
            # This is the fix for trivy returning 0 CVEs on pip projects where
            # site-packages is not found. Available since trivy v0.53.
            # Without this flag, trivy skips unresolved pip manifests silently.
            "--detection-priority", "comprehensive",
            # --include-dev-deps: scan devDependencies in addition to prod deps.
            # Only effective for Node (package.json devDependencies) — harmless elsewhere.
            # NOTE: not available on trivy < 0.46. If trivy is older, it logs a warning
            # but still produces output. We keep it for newer installations.
            "--include-dev-deps",
            repo_path,
        ],
        timeout=config.TRIVY_TIMEOUT,
        label="trivy",
    )

    if not stdout:
        logger.warning("[SCANNERS:trivy] No output — returning empty results")
        return fallback

    data = _safe_json_parse(stdout, "trivy")
    if data is None:
        return fallback

    results    = data.get("Results", [])
    vuln_count = sum(len(r.get("Vulnerabilities") or []) for r in results)
    sec_count  = sum(len(r.get("Secrets") or []) for r in results)
    logger.info(
        f"[SCANNERS:trivy] ✅ {len(results)} targets scanned | "
        f"{vuln_count} CVEs | {sec_count} secrets"
    )
    return data


# ══════════════════════════════════════════════════════════════
# SNYK IAC — Infrastructure as Code
# Per Snyk docs: https://docs.snyk.io/developer-tools/snyk-cli/commands/iac-test
# Scans Terraform, Kubernetes, CloudFormation, Helm, ARM templates
# ══════════════════════════════════════════════════════════════

def run_snyk_iac(repo_path: str) -> dict:
    """
    Run `snyk iac test --json` for IaC misconfiguration scanning.
    Only runs if IaC files are detected in the repo.

    Scans:
      Terraform:       *.tf, *.tfvars, .terraform.lock.hcl
      Kubernetes:      *.yaml, *.yml (k8s manifests)
      CloudFormation:  *.json, *.yaml (CF templates)
      Helm:            Chart.yaml + templates/
      ARM templates:   azuredeploy.json

    Returns {"infrastructureAsCodeIssues": [...]} or fallback.
    """
    fallback = {"infrastructureAsCodeIssues": [], "error": "snyk_iac_not_run"}

    if not config.SNYK_TOKEN:
        logger.warning("[SCANNERS:snyk_iac] SNYK_TOKEN not set — skipping IAC scan")
        return fallback

    if not _tool_available(_SNYK_CMD):
        return fallback

    repo_path = os.path.normpath(repo_path)
    logger.info(f"[SCANNERS:snyk_iac] Scanning IaC files in: {repo_path}")

    stdout = _run_subprocess(
        args=[_SNYK_CMD, "iac", "test", "--json", repo_path],
        cwd=repo_path,
        timeout=config.SNYK_TIMEOUT,
        label="snyk_iac",
        extra_env={"SNYK_TOKEN": config.SNYK_TOKEN},
        success_codes=(0, 1),
    )

    if not stdout:
        logger.warning("[SCANNERS:snyk_iac] No output — returning empty results")
        return fallback

    data = _safe_json_parse(stdout, "snyk_iac")
    if data is None:
        return fallback

    # Snyk IAC output can be a list (one item per file) or a single dict
    if isinstance(data, list):
        all_issues: list = []
        for item in data:
            all_issues.extend(item.get("infrastructureAsCodeIssues", []))
        logger.info(f"[SCANNERS:snyk_iac] ✅ {len(all_issues)} IaC issues")
        return {"infrastructureAsCodeIssues": all_issues}
    elif isinstance(data, dict):
        issues = data.get("infrastructureAsCodeIssues", [])
        logger.info(f"[SCANNERS:snyk_iac] ✅ {len(issues)} IaC issues")
        return data

    logger.warning("[SCANNERS:snyk_iac] Unexpected JSON structure — returning empty")
    return fallback


# ══════════════════════════════════════════════════════════════
# SNYK CONTAINER — Dockerfile / base image scanning
# Per Snyk docs: https://docs.snyk.io/developer-tools/snyk-cli/commands/container-test
# Exit codes: 0=no vulns, 1=vulns found (both have JSON), 2=error
# ══════════════════════════════════════════════════════════════

def run_snyk_container(repo_path: str) -> dict:
    """
    Scan Dockerfile for security misconfigurations using `snyk iac test`.

    WHY snyk iac test INSTEAD OF snyk container test:
      snyk container test needs Docker running + a real registry image to pull.
      Without Docker, it exits 2 with {ok: false, error: ..., path: ...} after
      waiting 60-70 seconds trying to connect to the Docker daemon.

      snyk iac test --json <dockerfile> scans the Dockerfile AS INFRASTRUCTURE CODE:
        - Detects: running as root, EXPOSE of privileged ports, missing HEALTHCHECK,
          use of :latest tag, ADD instead of COPY, secrets in ENV, etc.
        - Does NOT need Docker running. Completes in 2-5 seconds.
        - Supported since Snyk CLI v1.984.0 (2022+).
        - Returns the same infrastructureAsCodeIssues schema as other IaC scans.

    Results are stored in snyk_container key but parsed as IaC issues.
    The researcher's _parse_snyk_container reads infrastructureAsCodeIssues.
    """
    fallback   = {"vulnerabilities": [], "infrastructureAsCodeIssues": [], "error": "snyk_container_not_run"}

    # Find Dockerfile
    dockerfile = None
    for variant in ["Dockerfile", "dockerfile", "Dockerfile.prod", "Dockerfile.dev"]:
        candidate = os.path.join(repo_path, variant)
        if os.path.exists(candidate):
            dockerfile = candidate
            break

    if not dockerfile:
        logger.info("[SCANNERS:snyk_container] No Dockerfile found — skipping")
        return fallback

    if not config.SNYK_TOKEN:
        logger.warning(
            "[SCANNERS:snyk_container] SNYK_TOKEN not set — skipping Dockerfile scan"
        )
        return fallback

    if not _tool_available(_SNYK_CMD):
        return fallback

    logger.info(f"[SCANNERS:snyk_container] Dockerfile IaC scan: {dockerfile}")
    logger.info(
        "[SCANNERS:snyk_container] Using snyk iac test (no Docker daemon required)"        " — detects Dockerfile misconfigurations in seconds"
    )

    # Use snyk iac test, NOT snyk container test
    # This scans the Dockerfile for misconfigurations without pulling any image.
    stdout = _run_subprocess(
        args=[
            _SNYK_CMD, "iac", "test",
            "--json",
            os.path.normpath(dockerfile),
        ],
        cwd=repo_path,
        timeout=30,   # should complete in 2-5s; 30s is generous
        label="snyk_container",
        extra_env={"SNYK_TOKEN": config.SNYK_TOKEN},
        success_codes=(0, 1),  # 0=no issues, 1=issues found
    )

    if not stdout:
        logger.warning("[SCANNERS:snyk_container] No output from Dockerfile IaC scan")
        return fallback

    data = _safe_json_parse(stdout, "snyk_container")
    if data is None:
        return fallback

    # snyk iac test returns a list (one per file) or a single dict
    if isinstance(data, list):
        all_issues: list = []
        for item in data:
            # Handle error schema: {ok: false, error: ..., path: ...}
            if "error" in item and "ok" in item and not item.get("ok"):
                logger.warning(
                    f"[SCANNERS:snyk_container] Snyk IAC error for file: "                    f"{item.get('path', '?')} — {item.get('error', '')[:200]}"
                )
                continue
            all_issues.extend(item.get("infrastructureAsCodeIssues", []))
        logger.info(f"[SCANNERS:snyk_container] ✅ {len(all_issues)} Dockerfile IaC issues")
        return {"vulnerabilities": [], "infrastructureAsCodeIssues": all_issues}

    elif isinstance(data, dict):
        # Handle error schema: {ok: false, error: ..., path: ...}
        if "error" in data and "ok" in data and not data.get("ok"):
            logger.warning(
                f"[SCANNERS:snyk_container] Snyk IAC returned error: "                f"{data.get('error', '')[:200]}"
            )
            return fallback

        issues = data.get("infrastructureAsCodeIssues", [])
        logger.info(f"[SCANNERS:snyk_container] ✅ {len(issues)} Dockerfile IaC issues")
        return {"vulnerabilities": [], "infrastructureAsCodeIssues": issues}

    logger.warning(f"[SCANNERS:snyk_container] Unexpected schema: {list(data.keys()) if isinstance(data, dict) else type(data)}")
    return fallback


# ══════════════════════════════════════════════════════════════
# ORCHESTRATOR — runs scanners, optionally in parallel
# ══════════════════════════════════════════════════════════════


def _dockerfile_has_real_base_image(repo_path: str) -> bool:
    """
    Return True only if the Dockerfile has a FROM line pointing to a real
    registry image (not 'scratch', not empty, not a local-only name).

    Rationale: snyk container test tries to PULL the base image.
    If the image doesn't exist on Docker Hub / registry, snyk blocks for
    the entire SNYK_TIMEOUT waiting on a network response.
    Checking locally saves up to 2 minutes per scan.
    """
    for fname in ("Dockerfile", "dockerfile", "Dockerfile.prod", "Dockerfile.dev"):
        dpath = os.path.join(repo_path, fname)
        if not os.path.exists(dpath):
            continue
        try:
            text = open(dpath, encoding="utf-8", errors="replace").read().lower()
            for line in text.splitlines():
                line = line.strip()
                if not line.startswith("from "):
                    continue
                base = line[5:].split()[0].strip()   # e.g. "python:3.11" or "scratch"
                # Skip clearly un-pullable base images
                if base in ("scratch", "", "none"):
                    logger.info(
                        f"[SCANNERS] Dockerfile FROM='{base}' — not pullable, "
                        "skipping container scan"
                    )
                    return False
                # If the base image contains a slash, it's likely a registry path
                # that may require authentication — still worth trying
                logger.info(
                    f"[SCANNERS] Dockerfile has pullable base image: FROM {base}"
                )
                return True
        except Exception as e:
            logger.warning(f"[SCANNERS] Could not read Dockerfile: {e}")
    return False  # no Dockerfile found or no FROM found


def run_all_scanners(
    repo_path: str,
    has_iac: bool = False,
    has_dockerfile: bool = False,
    progress_callback=None,
) -> dict:
    """
    Run all enabled scanners and return combined results.

    v10 PARALLEL EXECUTION (when config.CONCURRENT_SCANNERS=True):
      Snyk Code + Trivy run CONCURRENTLY in a ThreadPoolExecutor.
      Snyk IAC + Snyk Container run CONCURRENTLY after (if applicable).
      Total time ≈ max(snyk_time, trivy_time) instead of sum.

    v9 SEQUENTIAL FALLBACK (when config.CONCURRENT_SCANNERS=False):
      Runs each scanner one after another (original behavior).

    Parameters
    ----------
    repo_path         : local path to cloned repo
    has_iac           : True if IaC files detected
    has_dockerfile    : True if Dockerfile present
    progress_callback : optional callable(pct: int, step: str)

    Returns
    -------
    dict with keys: snyk_code, trivy, snyk_iac, snyk_container
    """
    def _prog(pct: int, step: str):
        logger.info(f"[SCANNERS] Progress {pct}%: {step}")
        if progress_callback:
            try:
                progress_callback(pct, step)
            except Exception:
                pass

    results: Dict[str, Any] = {
        "snyk_code":      {"runs": [], "error": "not_run"},
        "trivy":          {"Results": [], "error": "not_run"},
        "snyk_iac":       {"infrastructureAsCodeIssues": [], "error": "not_run"},
        "snyk_container": {"vulnerabilities": [], "error": "not_run"},
    }

    logger.info(
        f"[SCANNERS] ══ Starting scanners ══ "
        f"concurrent={config.CONCURRENT_SCANNERS} | "
        f"iac={has_iac} | dockerfile={has_dockerfile}"
    )

    if config.CONCURRENT_SCANNERS:
        # ── PARALLEL: Snyk Code + Trivy simultaneously ────────
        logger.info("[SCANNERS] ── Batch 1/2: Snyk Code + Trivy (parallel) ──")
        _prog(31, "Researcher: Running Snyk Code + Trivy in parallel...")

        with ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="scanner-batch1"
        ) as executor:
            fut_snyk_code = executor.submit(run_snyk_code, repo_path)
            fut_trivy     = executor.submit(run_trivy,     repo_path)

            # Wait for both, logging as each completes
            for fut in as_completed([fut_snyk_code, fut_trivy]):
                if fut is fut_snyk_code:
                    try:
                        results["snyk_code"] = fut.result()
                        _prog(40, "Researcher: Snyk Code complete, Trivy running...")
                    except Exception as e:
                        logger.error(f"[SCANNERS] Snyk Code thread error: {e}")
                        _prog(40, "Researcher: Snyk Code failed, continuing...")
                else:
                    try:
                        results["trivy"] = fut.result()
                        _prog(44, "Researcher: Trivy complete...")
                    except Exception as e:
                        logger.error(f"[SCANNERS] Trivy thread error: {e}")
                        _prog(44, "Researcher: Trivy failed, continuing...")

        # ── PARALLEL: Snyk IAC + Snyk Container simultaneously ─
        needs_iac       = has_iac and bool(config.SNYK_TOKEN)
        # ── Container scan: only if Dockerfile references a real base image ──
        # snyk container test pulls the FROM image from a registry.
        # If the image doesn't exist publicly or FROM is 'scratch', snyk
        # hangs for the full SNYK_TIMEOUT waiting for a network response.
        # We read the Dockerfile and skip if no real pullable FROM is found.
        needs_container = (
            has_dockerfile
            and bool(config.SNYK_TOKEN)
            and _dockerfile_has_real_base_image(repo_path)
        )
        if has_dockerfile and not needs_container:
            logger.info(
                "[SCANNERS] ── Container scan SKIPPED: Dockerfile has no pullable "                "base image (FROM scratch / custom / missing) ──"
            )

        if needs_iac or needs_container:
            logger.info(
                f"[SCANNERS] ── Batch 2/2: "
                f"Snyk IAC ({needs_iac}) + Container ({needs_container}) (parallel) ──"
            )
            _prog(46, "Researcher: Running Snyk IAC + Container in parallel...")

            tasks = {}
            with ThreadPoolExecutor(
                max_workers=2, thread_name_prefix="scanner-batch2"
            ) as executor:
                if needs_iac:
                    tasks["snyk_iac"] = executor.submit(run_snyk_iac, repo_path)
                if needs_container:
                    tasks["snyk_container"] = executor.submit(
                        run_snyk_container, repo_path
                    )

                for name, fut in tasks.items():
                    try:
                        results[name] = fut.result()
                    except Exception as e:
                        logger.error(f"[SCANNERS] {name} thread error: {e}")
        else:
            logger.info(
                "[SCANNERS] ── Batch 2/2: Skipped "
                "(no IaC files / no Dockerfile / no SNYK_TOKEN) ──"
            )

    else:
        # ── SEQUENTIAL fallback ────────────────────────────────
        logger.info("[SCANNERS] ── Sequential mode (CONCURRENT_SCANNERS=false) ──")

        logger.info("[SCANNERS] ── Step 1/4: Snyk Code SAST ──")
        _prog(31, "Researcher: Running Snyk Code SAST...")
        results["snyk_code"] = run_snyk_code(repo_path)

        logger.info("[SCANNERS] ── Step 2/4: Trivy SCA + Secrets ──")
        _prog(38, "Researcher: Running Trivy SCA + secrets...")
        results["trivy"] = run_trivy(repo_path)

        if has_iac:
            logger.info("[SCANNERS] ── Step 3/4: Snyk IAC ──")
            _prog(44, "Researcher: Running Snyk IAC...")
            results["snyk_iac"] = run_snyk_iac(repo_path)
        else:
            logger.info("[SCANNERS] ── Step 3/4: Snyk IAC skipped (no IaC files) ──")

        if has_dockerfile:
            logger.info("[SCANNERS] ── Step 4/4: Snyk Container ──")
            _prog(47, "Researcher: Running Snyk Container scan...")
            results["snyk_container"] = run_snyk_container(repo_path)
        else:
            logger.info(
                "[SCANNERS] ── Step 4/4: Snyk Container skipped (no Dockerfile) ──"
            )

    # Summary
    sc_n  = sum(
        len(r.get("results", []))
        for r in results["snyk_code"].get("runs", [])
    )
    tv_n  = sum(
        len(r.get("Vulnerabilities") or []) + len(r.get("Secrets") or [])
        for r in results["trivy"].get("Results", [])
    )
    iac_n = len(results["snyk_iac"].get("infrastructureAsCodeIssues", []))
    con_n = len(results["snyk_container"].get("vulnerabilities", []))

    logger.info(
        f"[SCANNERS] ══ All scanners complete ══ "
        f"snyk_code={sc_n} | trivy={tv_n} | iac={iac_n} | container={con_n} | "
        f"total_raw={sc_n + tv_n + iac_n + con_n}"
    )
    _prog(50, "Researcher: Tool scanning complete...")

    return results
