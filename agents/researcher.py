import json
import os
import shutil
import hashlib
import tempfile
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import config
from core.logger import get_logger
from core.models import (
    FileInfo, VulnerabilityFinding, Severity, VulnCategory,
    DetectionSource,
)
from core.scanners import run_all_scanners
from tools.security_tools import RESEARCHER_TOOLS
from utils.chunker import chunk_file_content
from utils.llm_client import invoke_agent_with_fallback, call_llm_for_json
from utils.llm_providers import get_primary_llm, get_primary_name
from agents.history_guard import HistoryGuard

logger = get_logger("agents.researcher")


# ============================================================
# NORMALISATION HELPERS
# ============================================================

def _normalize_severity(raw: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high":     Severity.HIGH,
        "medium":   Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "low":      Severity.LOW,
        "warning":  Severity.MEDIUM,
        "error":    Severity.HIGH,
        "info":     Severity.INFO,
        "note":     Severity.INFO,
        "unknown":  Severity.MEDIUM,
    }
    return mapping.get(str(raw).lower().strip(), Severity.MEDIUM)


def _normalize_category(raw: str) -> VulnCategory:
    raw_lower = str(raw).lower()
    checks = [
        (["hardcoded", "secret", "credential", "token", "key", "password"],
         VulnCategory.HARDCODED_SECRET),
        (["sql", "injection", "sqli"],           VulnCategory.SQL_INJECTION),
        (["auth", "authentication", "login"],    VulnCategory.BROKEN_AUTH),
        (["xss", "cross-site", "cross_site"],    VulnCategory.XSS),
        (["csrf"],                               VulnCategory.CSRF),
        (["idor", "object reference"],           VulnCategory.IDOR),
        (["command", "cmd", "exec", "shell"],    VulnCategory.COMMAND_INJECTION),
        (["path", "traversal", "directory"],     VulnCategory.PATH_TRAVERSAL),
        (["ssrf", "request forgery"],            VulnCategory.SSRF),
        (["redirect", "open_redirect"],          VulnCategory.OPEN_REDIRECT),
        (["dependency", "cve", "vulnerable"],    VulnCategory.DEPENDENCY_VULN),
        (["config", "insecure", "misconfigur"],  VulnCategory.INSECURE_CONFIG),
        (["sensitive", "exposure", "leak"],      VulnCategory.SENSITIVE_DATA),
        (["deser", "pickle", "yaml.load"],       VulnCategory.INSECURE_DESERIALIZATION),
    ]
    for keywords, category in checks:
        if any(kw in raw_lower for kw in keywords):
            return category
    return VulnCategory.UNKNOWN


def _make_finding_id(source: str, file_path: str, line: Any) -> str:
    raw = f"{source}::{file_path}::{line}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12].upper()


def _is_dependency_file(file_path: str) -> bool:
    p              = Path(file_path)
    filename_lower = p.name.lower()
    ext_lower      = p.suffix.lower()
    if filename_lower in config.DEPENDENCY_FILENAMES:
        return True
    if ext_lower in config.DEP_EXTENSIONS:
        return True
    if ext_lower == ".csproj":
        return True
    if filename_lower.endswith(".deps.json"):
        return True
    return False


# ============================================================
# SCANNER OUTPUT PARSERS
# ============================================================

def _parse_snyk_code(data: dict, repo_path: str) -> List[VulnerabilityFinding]:
    """Parse Snyk Code SARIF output into VulnerabilityFinding objects."""
    findings = []
    if not data or "runs" not in data:
        return findings

    for run in data.get("runs", []):
        # Build rule → description mapping
        rules = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[rule["id"]] = rule.get("fullDescription", {}).get("text", "")

        for result in run.get("results", []):
            rule_id  = result.get("ruleId", "snyk_code")
            msg_text = result.get("message", {}).get("text", "")
            level    = result.get("level", "warning")
            sev      = _normalize_severity(level)

            # Extract file + line from locations
            locations = result.get("locations", [])
            file_path = ""
            line_num  = None
            snippet   = ""
            if locations:
                loc = locations[0]
                pl  = loc.get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                file_path = uri.replace("file:///", "").replace("/", os.sep)
                reg = pl.get("region", {})
                line_num = reg.get("startLine")
                snippet  = reg.get("snippet", {}).get("text", "")

            # Clean relative path
            if repo_path and file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip(os.sep)

            findings.append(VulnerabilityFinding(
                finding_id=_make_finding_id(rule_id, file_path, line_num),
                file_path=file_path,
                line_number=line_num,
                code_snippet=snippet[:500] if snippet else "",
                category=_normalize_category(rule_id),
                severity=sev,
                title=msg_text[:120] if msg_text else rule_id,
                description=rules.get(rule_id, msg_text)[:800],
                cwe_id=rule_id if rule_id.startswith("CWE") else None,
                detection_source=DetectionSource.SNYK_CODE,
            ))

    logger.info(f"[RESEARCHER] Parsed Snyk Code: {len(findings)} findings")
    return findings


def _parse_trivy(data: dict, repo_path: str) -> List[VulnerabilityFinding]:
    """
    Parse Trivy JSON output into VulnerabilityFinding objects.
    Handles both Vulnerabilities and Secrets from the same output.
    """
    findings = []
    if not data or "Results" not in data:
        return findings

    for result_item in data.get("Results", []):
        target = result_item.get("Target", "")

        # Parse CVE vulnerabilities
        for vuln in result_item.get("Vulnerabilities") or []:
            pkg_name = vuln.get("PkgName", "")
            version  = vuln.get("InstalledVersion", "")
            cve_id   = vuln.get("VulnerabilityID", "")
            sev      = _normalize_severity(vuln.get("Severity", "MEDIUM"))
            title    = vuln.get("Title", "") or f"{cve_id} in {pkg_name}"
            desc     = vuln.get("Description", "")[:800]
            fix_ver  = vuln.get("FixedVersion", "")
            patch    = f"Upgrade {pkg_name} from {version} to {fix_ver}" if fix_ver else ""

            findings.append(VulnerabilityFinding(
                finding_id=_make_finding_id(cve_id, target, pkg_name),
                file_path=target,
                category=VulnCategory.DEPENDENCY_VULN,
                severity=sev,
                title=title[:120],
                description=desc,
                cwe_id=cve_id,
                patch_explanation=patch,
                detection_source=DetectionSource.TRIVY,
            ))

        # Parse secrets
        for secret in result_item.get("Secrets") or []:
            rule_id   = secret.get("RuleID", "secret")
            cat       = secret.get("Category", "secret")
            title     = secret.get("Title", f"Secret: {rule_id}")
            sev       = _normalize_severity(secret.get("Severity", "HIGH"))
            line_num  = secret.get("StartLine")
            match_str = secret.get("Match", "")[:200]

            findings.append(VulnerabilityFinding(
                finding_id=_make_finding_id(rule_id, target, line_num),
                file_path=target,
                line_number=line_num,
                code_snippet=match_str,
                category=VulnCategory.HARDCODED_SECRET,
                severity=sev,
                title=title[:120],
                description=f"Secret detected: {cat} — {match_str}",
                detection_source=DetectionSource.TRIVY,
            ))

    logger.info(f"[RESEARCHER] Parsed Trivy: {len(findings)} findings")
    return findings


def _parse_snyk_iac(data: dict, repo_path: str) -> List[VulnerabilityFinding]:
    """Parse Snyk IAC JSON output into VulnerabilityFinding objects."""
    findings = []
    if not data:
        return findings

    for issue in data.get("infrastructureAsCodeIssues", []):
        sev   = _normalize_severity(issue.get("severity", "MEDIUM"))
        title = issue.get("title", "IaC Issue")
        desc  = issue.get("description", "") or issue.get("msg", "")
        path  = issue.get("path", [""])
        ref   = issue.get("references", "")
        line  = issue.get("lineNumber")

        findings.append(VulnerabilityFinding(
            finding_id=_make_finding_id(
                issue.get("id", title),
                str(path[0]) if path else "",
                line,
            ),
            file_path=str(path[0]) if path else "",
            line_number=line,
            category=_normalize_category(title),
            severity=sev,
            title=title[:120],
            description=str(desc)[:800],
            cwe_id=issue.get("id"),
            patch_explanation=str(ref)[:400],
            detection_source=DetectionSource.SNYK_IAC,
        ))

    logger.info(f"[RESEARCHER] Parsed Snyk IAC: {len(findings)} findings")
    return findings


def _parse_snyk_container(data: dict, repo_path: str) -> List[VulnerabilityFinding]:
    """
    Parse Snyk Container / Dockerfile IaC scan output.

    After v10 fix: the scanner now uses `snyk iac test` on the Dockerfile
    (instead of `snyk container test` which required Docker).
    Output format: {vulnerabilities: [], infrastructureAsCodeIssues: [...]}

    We parse BOTH schemas for compatibility:
      - infrastructureAsCodeIssues: from new snyk iac test approach
      - vulnerabilities: from old snyk container test (legacy, kept for safety)
    """
    findings = []
    if not data:
        return findings

    # ── Schema 1: IaC issues from `snyk iac test` (new approach) ─────────────
    # This is what we get now: Dockerfile misconfiguration issues.
    for issue in data.get("infrastructureAsCodeIssues", []):
        sev   = _normalize_severity(issue.get("severity", "MEDIUM"))
        title = issue.get("title", "Dockerfile misconfiguration")
        desc  = issue.get("description", "") or issue.get("msg", "")
        ref   = issue.get("references", "")
        rule  = issue.get("id", "") or issue.get("publicId", "")
        path  = issue.get("path", [])
        loc   = " → ".join(str(p) for p in path) if isinstance(path, list) else str(path)

        findings.append(VulnerabilityFinding(
            finding_id=_make_finding_id(rule, "Dockerfile", title[:40]),
            file_path="Dockerfile",
            category=VulnCategory.INSECURE_CONFIG,
            severity=sev,
            title=title[:120],
            description=f"{desc}\nLocation: {loc}" if loc else desc,
            cwe_id=rule,
            patch_explanation=ref[:300] if ref else "Review Dockerfile security best practices",
            detection_source=DetectionSource.SNYK_CONTAINER,
        ))

    # ── Schema 2: legacy vulnerabilities from old snyk container test ─────────
    for vuln in data.get("vulnerabilities", []):
        sev      = _normalize_severity(vuln.get("severity", "MEDIUM"))
        title    = vuln.get("title", "Container vulnerability")
        pkg_name = vuln.get("packageName", "")
        version  = vuln.get("version", "")
        desc     = vuln.get("description", "")[:800]
        cve_id   = vuln.get("id", "")
        fix      = vuln.get("fixedIn", [])
        patch    = (
            f"Upgrade base image or {pkg_name} to {fix[0]}" if fix else ""
        )
        findings.append(VulnerabilityFinding(
            finding_id=_make_finding_id(cve_id, "Dockerfile", pkg_name),
            file_path="Dockerfile",
            category=VulnCategory.DEPENDENCY_VULN,
            severity=sev,
            title=title[:120],
            description=desc,
            cwe_id=cve_id,
            patch_explanation=patch,
            detection_source=DetectionSource.SNYK_CONTAINER,
        ))

    logger.info(f"[RESEARCHER] Parsed Snyk Container/Dockerfile: {len(findings)} findings")
    return findings


# ============================================================
# REPO CLONE + IaC DETECTION
# ============================================================

def _clone_repo_to_temp(repo_url: str) -> Optional[str]:
    """Clone the repo with --depth=1 for tool scanning. Returns path or None."""
    from utils.github_fetcher import clone_repo_locally
    return clone_repo_locally(repo_url)


def _has_iac_files(files: List[FileInfo]) -> bool:
    """Return True if any navigator-selected file has IaC extensions."""    # NOTE: this is now only used as a fallback. Prefer _has_iac_files_on_disk().
    IAC_EXTS = {".tf", ".hcl", ".yaml", ".yml", ".json"}
    IAC_NAMES = {
        "main.tf", "variables.tf", "outputs.tf", "providers.tf",
        "terraform.tfvars", "kubernetes.yaml", "k8s.yaml",
        "deployment.yaml", "service.yaml", "Chart.yaml",
        "cloudformation.yaml", "template.yaml",
        "docker-compose.yml", "docker-compose.yaml",
    }
    for f in files:
        p = Path(f.path)
        if p.name.lower() in IAC_NAMES:
            return True
        if p.suffix.lower() in IAC_EXTS:
            return True
    return False


def _has_iac_files_on_disk(clone_dir: str) -> bool:
    """
    Walk the cloned repository and return True if any IaC file exists.

    Why this matters:
      Navigator scores files by security priority and drops anything scoring 0.
      docker-compose.yml scores 0 (no security keywords, not a source file) so
      it never appears in researcher's `files` list.
      But Snyk IAC DOES scan docker-compose, k8s manifests, Terraform, etc.
      We must check the full clone dir, independent of navigator's picks.

    IaC file types covered:
      Docker Compose:  docker-compose*.yml / *.yaml
      Terraform:       *.tf, *.tfvars, .terraform.lock.hcl
      Kubernetes:      *.yaml, *.yml (broad — Snyk IAC determines if k8s)
      Helm:            Chart.yaml + templates/
      CloudFormation:  *.json, *.yaml with CF structure
      ARM:             azuredeploy.json, azuredeploy.parameters.json
      Ansible:         playbook.yml, site.yml
    """
    IAC_EXTS = {".tf", ".hcl"}   # Definite IaC
    IAC_NAMES = {
        # Docker Compose
        "docker-compose.yml", "docker-compose.yaml",
        "docker-compose.prod.yml", "docker-compose.prod.yaml",
        "docker-compose.override.yml", "docker-compose.override.yaml",
        # Terraform
        "main.tf", "variables.tf", "outputs.tf", "providers.tf",
        "terraform.tfvars", ".terraform.lock.hcl",
        # Kubernetes / Helm
        "kubernetes.yaml", "k8s.yaml", "deployment.yaml",
        "service.yaml", "ingress.yaml", "Chart.yaml", "values.yaml",
        # CloudFormation
        "cloudformation.yaml", "cloudformation.json",
        "template.yaml", "template.json", "sam.yaml",
        # ARM
        "azuredeploy.json", "azuredeploy.parameters.json",
    }
    try:
        for root, dirs, filenames in os.walk(clone_dir):
            # Skip hidden dirs and node_modules (same as navigator)
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
            for fname in filenames:
                fl = fname.lower()
                if fl in IAC_NAMES:
                    logger.info(
                        f"[RESEARCHER] IaC file detected on disk: {fname}"                        f" (in {os.path.relpath(root, clone_dir)})"                    )
                    return True
                ext = Path(fname).suffix.lower()
                if ext in IAC_EXTS:
                    logger.info(
                        f"[RESEARCHER] IaC file detected on disk: {fname}"                        f" (in {os.path.relpath(root, clone_dir)})"                    )
                    return True
    except Exception as e:
        logger.warning(f"[RESEARCHER] IaC disk scan error (non-fatal): {e}")
    return False


# ============================================================
# RESEARCHER AGENT
# ============================================================

class ResearcherAgent:
    """
    v10 Researcher — LogicAuditor removed, parallel LLM scanning added.

    Pipeline:
      Phase 1  — Clone repo for tool scanners
      Phase 2  — Run tool scanners (parallel: Snyk Code + Trivy concurrently)
      Phase 3  — Parse scanner JSON into VulnerabilityFinding objects
      Phase 4  — HistoryGuard (git entropy scan for zombie secrets)
      Phase 5  — LLM parallel chunk scan (up to CONCURRENT_LLM_SCANS workers)
      Phase 6  — LLM patch enrichment for tool findings
      Phase 7  — Deduplicate findings
      Phase 8  — Cleanup temp clone

    Latency improvements vs v9:
      - No LogicAuditor (removed ~60-120s of AST + LLM per-function calls)
      - Parallel LLM chunk scan (~75% faster for multi-file repos)
      - Parallel scanners (Snyk + Trivy concurrently, not sequentially)
    """

    def __init__(self, progress_callback=None, finding_callback=None):
        self.llm             = get_primary_llm()
        self._primary_name   = get_primary_name()
        self._progress_cb    = progress_callback or (lambda p, s: None)
        self._finding_cb     = finding_callback  or (lambda f: None)
        logger.info(
            f"[RESEARCHER] v10 initialized | "
            f"LLM: {self._primary_name} | "
            f"LogicAuditor: DISABLED | "
            f"Parallel LLM workers: {config.CONCURRENT_LLM_SCANS} | "
            f"Parallel scanners: {config.CONCURRENT_SCANNERS} | "
            f"Finding callback: {'SET' if finding_callback else 'none'}"
        )

    def _progress(self, pct: int, step: str) -> None:
        logger.info(f"[RESEARCHER] Progress {pct}%: {step}")
        try:
            self._progress_cb(pct, step)
        except Exception:
            pass

    def run(
        self,
        files: List[FileInfo],
        repo_url: str = "",
    ) -> List[VulnerabilityFinding]:
        logger.info(
            f"[RESEARCHER] ══ Starting v10 analysis ══ "
            f"{len(files)} files | repo: {repo_url}"
        )
        start_time    = datetime.now()
        all_findings: List[VulnerabilityFinding] = []
        clone_dir:    Optional[str]              = None

        # ── Phase 1: Clone ───────────────────────────────────────
        logger.info("[RESEARCHER] ── Phase 1: Cloning repository ──")
        self._progress(28, "Researcher: Cloning repository...")

        if repo_url:
            clone_dir = _clone_repo_to_temp(repo_url)
            if clone_dir:
                logger.info(f"[RESEARCHER] ✅ Clone ready: {clone_dir}")
            else:
                logger.warning(
                    "[RESEARCHER] Clone failed — tool scanners + HistoryGuard "
                    "will be skipped. LLM analysis continues."
                )
        else:
            logger.warning(
                "[RESEARCHER] No repo_url provided — "
                "skipping clone-dependent phases"
            )

        try:
            # ── Phase 2: Tool scanners (parallel) ────────────────
            if clone_dir:
                has_dockerfile = os.path.exists(
                    os.path.join(clone_dir, "Dockerfile")
                )
                # Also check lowercase variant
                if not has_dockerfile:
                    has_dockerfile = os.path.exists(
                        os.path.join(clone_dir, "dockerfile")
                    )
                # ── Scan CLONE DIR for IaC, not just navigator-selected files ──────
                # Navigator filters files by security priority for LLM analysis.
                # docker-compose.yml scores 0 → dropped from navigator selection.
                # But Snyk IAC needs to know if IaC files exist anywhere in the repo.
                # We walk the clone directory directly — independent of navigator picks.
                has_iac = _has_iac_files_on_disk(clone_dir)
                logger.info(
                    f"[RESEARCHER] ── Phase 2: Tool scanners ── "
                    f"path={clone_dir} | dockerfile={has_dockerfile} | "
                    f"iac={has_iac} | parallel={config.CONCURRENT_SCANNERS}"
                )

                raw = run_all_scanners(
                    repo_path=clone_dir,
                    has_iac=has_iac,
                    has_dockerfile=has_dockerfile,
                    progress_callback=self._progress_cb,
                )

                # ── Phase 3: Parse scanner output ─────────────────
                logger.info("[RESEARCHER] ── Phase 3: Parsing scanner output ──")
                sc = _parse_snyk_code(raw.get("snyk_code", {}), clone_dir)
                tv = _parse_trivy(raw.get("trivy", {}), clone_dir)
                ia = _parse_snyk_iac(raw.get("snyk_iac", {}), clone_dir)
                cn = _parse_snyk_container(raw.get("snyk_container", {}), clone_dir)

                logger.info(
                    f"[RESEARCHER] Tool totals: "
                    f"snyk_code={len(sc)} | trivy={len(tv)} | "
                    f"iac={len(ia)} | container={len(cn)}"
                )
                new_tool = sc + tv + ia + cn
                for f in new_tool:
                    try: self._finding_cb(f)
                    except Exception: pass
                all_findings.extend(new_tool)
            else:
                logger.info(
                    "[RESEARCHER] ── Phases 2+3 skipped (no clone) ──"
                )

            # ── Phase 4: HistoryGuard ─────────────────────────────
            if clone_dir:
                logger.info(
                    "[RESEARCHER] ── Phase 4: HistoryGuard (git entropy scan) ──"
                )
                self._progress(52, "Researcher: Running HistoryGuard...")
                try:
                    hg = HistoryGuard(clone_dir).scan(scan_all=True)
                    logger.info(f"[RESEARCHER] HistoryGuard: {len(hg)} zombie secrets")
                    for f in hg:
                        try: self._finding_cb(f)
                        except Exception: pass
                    all_findings.extend(hg)
                except Exception as e:
                    logger.error(f"[RESEARCHER] HistoryGuard failed: {e}")
            else:
                logger.info(
                    "[RESEARCHER] ── Phase 4: HistoryGuard skipped (no clone) ──"
                )

            # ── Phase 5: Parallel LLM chunk scan ─────────────────
            src_files = [
                f for f in files
                if f.content and not _is_dependency_file(f.path)
            ]
            logger.info(
                f"[RESEARCHER] ── Phase 5: Parallel LLM chunk scan ── "
                f"{len(src_files)} source files | "
                f"{config.CONCURRENT_LLM_SCANS} workers"
            )
            self._progress(
                55,
                f"Researcher: LLM scanning {len(src_files)} files "
                f"({config.CONCURRENT_LLM_SCANS} parallel)..."
            )

            if src_files:
                llm_results = self._run_llm_parallel(src_files)
                total_llm   = sum(len(v) for v in llm_results.values())
                logger.info(
                    f"[RESEARCHER] ✅ Parallel LLM scan complete: "
                    f"{total_llm} findings across {len(src_files)} files"
                )
                for findings_list in llm_results.values():
                    for f in findings_list:
                        try: self._finding_cb(f)
                        except Exception: pass
                    all_findings.extend(findings_list)
            else:
                logger.info(
                    "[RESEARCHER] No source files to LLM-scan (all deps/no content)"
                )

            # ── Phase 6: Patch enrichment for tool findings ───────
            logger.info("[RESEARCHER] ── Phase 6: LLM patch enrichment ──")
            self._progress(72, "Researcher: Enriching findings with patch guidance...")

            llm_sources   = {DetectionSource.LLM_ONLY, DetectionSource.HISTORY_GUARD}
            tool_findings = [
                f for f in all_findings
                if f.detection_source not in llm_sources
            ]
            llm_only_findings = [
                f for f in all_findings
                if f.detection_source in llm_sources
            ]
            logger.info(
                f"[RESEARCHER] Enriching {len(tool_findings)} tool findings "
                f"| {len(llm_only_findings)} LLM findings pass-through"
            )
            enriched     = self._enrich_tool_findings(tool_findings, files)
            all_findings = enriched + llm_only_findings

        finally:
            # ── Phase 8: Cleanup ──────────────────────────────────
            if clone_dir:
                logger.info(
                    f"[RESEARCHER] ── Phase 8: Cleanup → {clone_dir} ──"
                )
                try:
                    shutil.rmtree(clone_dir, ignore_errors=True)
                    logger.info("[RESEARCHER] ✅ Temp clone removed")
                except Exception as e:
                    logger.warning(f"[RESEARCHER] Cleanup failed: {e}")

        # ── Phase 7: Deduplicate ──────────────────────────────────
        logger.info("[RESEARCHER] ── Phase 7: Deduplicating findings ──")
        deduped = self._deduplicate(all_findings)

        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"[RESEARCHER] ══ v10 analysis complete ══ "
            f"{elapsed:.2f}s | {len(deduped)} unique findings "
            f"(from {len(all_findings)} raw)"
        )
        return deduped

    # ----------------------------------------------------------------
    # PARALLEL LLM CHUNK SCAN
    # ----------------------------------------------------------------

    def _run_llm_parallel(
        self,
        src_files: List[FileInfo],
    ) -> dict:
        """
        Analyze multiple files in parallel using ThreadPoolExecutor.

        Thread safety:
          invoke_agent_with_fallback() creates its own HTTP session per call.
          No shared state between threads.
          ThreadPoolExecutor is stdlib — safe on Windows.

        Returns dict mapping file_path → List[VulnerabilityFinding]
        """
        results: dict = {}
        total   = len(src_files)
        workers = min(config.CONCURRENT_LLM_SCANS, total)

        logger.info(
            f"[RESEARCHER] Parallel LLM scan: {total} files | {workers} workers"
        )

        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="llm-worker",
        ) as executor:
            future_to_file = {
                executor.submit(
                    self._run_llm_analysis, file_info
                ): file_info
                for file_info in src_files
            }

            completed = 0
            for future in as_completed(future_to_file):
                file_info = future_to_file[future]
                completed += 1
                pct        = 55 + int((completed / max(total, 1)) * 15)
                self._progress(
                    pct,
                    f"Researcher: LLM scan {completed}/{total} files..."
                )
                try:
                    findings = future.result()
                    results[file_info.path] = findings
                    logger.info(
                        f"[RESEARCHER] [{completed}/{total}] "
                        f"{file_info.path}: {len(findings)} findings"
                    )
                except Exception as e:
                    logger.error(
                        f"[RESEARCHER] LLM scan failed for "
                        f"{file_info.path}: {e}"
                    )
                    results[file_info.path] = []

        return results

    def _run_llm_analysis(
        self, file_info: FileInfo
    ) -> List[VulnerabilityFinding]:
        """
        Run LLM security analysis on a single file's chunks.
        Called from threads — uses only local state (thread-safe).
        """
        chunks       = chunk_file_content(file_info.content, file_info.path)
        all_findings = []

        for chunk_text, chunk_idx, total_chunks in chunks:
            safe_chunk = self._sanitise_chunk(
                chunk_text, chunk_idx, total_chunks, file_info.path
            )
            initial_messages = [{
                "role": "user",
                "content": (
                    f"Use analyze_file_for_vulnerabilities to perform "
                    f"logic-level security analysis.\n"
                    f"File: {file_info.path} "
                    f"(chunk {chunk_idx + 1}/{total_chunks})\n\n"
                    f"Content:\n{safe_chunk}"
                ),
            }]

            try:
                result = invoke_agent_with_fallback(
                    tools=RESEARCHER_TOOLS,
                    initial_messages=initial_messages,
                    label=f"researcher_{file_info.path}_chunk{chunk_idx+1}",
                )
                tool_output = self._extract_tool_output(result)
                if not tool_output:
                    continue

                try:
                    parsed = json.loads(tool_output)
                except Exception:
                    continue

                for raw in parsed.get("findings", []):
                    if not raw.get("title"):
                        continue
                    finding = VulnerabilityFinding(
                        finding_id=_make_finding_id(
                            raw.get("title", ""),
                            file_info.path,
                            raw.get("line_number"),
                        ),
                        file_path=file_info.path,
                        line_number=raw.get("line_number"),
                        code_snippet=raw.get("code_snippet", ""),
                        category=_normalize_category(raw.get("category", "")),
                        severity=_normalize_severity(
                            raw.get("severity", "MEDIUM")
                        ),
                        title=raw.get("title", "Security Finding"),
                        description=raw.get("description", ""),
                        cwe_id=raw.get("cwe_id"),
                        owasp_category=raw.get("owasp_category"),
                        confidence=str(
                            raw.get("confidence", "MEDIUM")
                        ).upper(),
                        reasoning_trace=raw.get("reasoning_trace", ""),
                        patch_code=raw.get("patch_code", ""),
                        patch_explanation=raw.get("patch_explanation", ""),
                        detection_source=DetectionSource.LLM_ONLY,
                    )
                    all_findings.append(finding)

            except Exception as e:
                logger.error(
                    f"[RESEARCHER] LLM failed — "
                    f"{file_info.path} chunk {chunk_idx+1}/{total_chunks}: {e}"
                )

        return all_findings

    def _sanitise_chunk(
        self,
        chunk_text: str,
        chunk_idx: int,
        total_chunks: int,
        file_path: str,
    ) -> str:
        """Sanitize chunk content: remove non-printable chars, truncate long lines."""
        lines     = chunk_text.splitlines()
        sanitised = []
        for line in lines:
            clean = "".join(
                ch if (ch == "\t" or ch.isprintable()) else " "
                for ch in line
            )
            if len(clean) > 400:
                clean = clean[:400] + f"  # [TRUNCATED {len(line)} chars]"
            sanitised.append(clean)
        return "\n".join(sanitised)

    def _extract_tool_output(self, result: dict) -> Optional[str]:
        """Extract tool output from LangChain agent result messages."""
        if not result:
            return None
        messages = result.get("messages", [])
        for msg in reversed(messages):
            msg_type = getattr(msg, "__class__", type(msg)).__name__
            content  = getattr(msg, "content", "")
            if "ToolMessage" in msg_type and content:
                return content
        # Fallback: last AI message with substantial content
        for msg in reversed(messages):
            content = getattr(msg, "content", "")
            if content and len(content) > 50:
                return content
        return None

    # ----------------------------------------------------------------
    # PATCH ENRICHMENT
    # ----------------------------------------------------------------

    def _enrich_tool_findings(
        self,
        findings: List[VulnerabilityFinding],
        files: List[FileInfo],
    ) -> List[VulnerabilityFinding]:
        """
        Add patch guidance to tool findings via LLM.
        Skips findings that already have patch explanations.
        """
        if not findings:
            return findings

        file_map     = {f.path: f.content for f in files if f.content}
        needs_patch  = [f for f in findings if not f.patch_explanation]
        has_patch    = [f for f in findings if f.patch_explanation]

        if not needs_patch:
            logger.info(
                "[RESEARCHER] All tool findings already have patch guidance"
            )
            return findings

        logger.info(
            f"[RESEARCHER] Enriching {len(needs_patch)} findings "
            f"(skipping {len(has_patch)} already patched)"
        )

        for i, finding in enumerate(needs_patch):
            context  = file_map.get(finding.file_path, "")[:2000]
            prompt   = (
                f"File: {finding.file_path}\n"
                f"Vulnerability: {finding.title}\n"
                f"Severity: {finding.severity}\n"
                f"Description: {finding.description}\n"
                f"Code context:\n{context}\n\n"
                "Provide a SHORT, practical remediation:\n"
                "1. What to change (one sentence)\n"
                "2. Example fix (5-10 lines max)\n"
                "3. Why it fixes the issue (one sentence)"
            )
            try:
                patch = call_llm_for_json(
                    system_prompt="You are a security expert. Provide a short, practical remediation.",
                    user_prompt=prompt,
                    label=f"patch_enrich_{i+1}",
                )
                if patch:
                    # call_llm_for_json returns a dict; extract text if available
                    if isinstance(patch, dict):
                        finding.patch_explanation = str(patch.get("remediation") or patch.get("patch") or patch.get("fix") or list(patch.values())[0] if patch else "")[:800]
                    else:
                        finding.patch_explanation = str(patch)[:800]
            except Exception as e:
                logger.warning(
                    f"[RESEARCHER] Patch enrichment failed for "
                    f"{finding.title}: {e}"
                )

        return needs_patch + has_patch

    # ----------------------------------------------------------------
    # DEDUPLICATION
    # ----------------------------------------------------------------

    def _deduplicate(
        self, findings: List[VulnerabilityFinding]
    ) -> List[VulnerabilityFinding]:
        """
        Remove duplicate findings by finding_id, then by title+file similarity.
        Severity priority: CRITICAL > HIGH > MEDIUM > LOW > INFO.
        """
        SEV_ORDER = {
            Severity.CRITICAL: 0,
            Severity.HIGH:     1,
            Severity.MEDIUM:   2,
            Severity.LOW:      3,
            Severity.INFO:     4,
        }

        seen_ids:   dict = {}
        seen_title: dict = {}

        for f in findings:
            # Primary dedup: by finding_id
            if f.finding_id in seen_ids:
                existing = seen_ids[f.finding_id]
                if SEV_ORDER.get(f.severity, 5) < SEV_ORDER.get(existing.severity, 5):
                    seen_ids[f.finding_id] = f
                continue
            seen_ids[f.finding_id] = f

            # Secondary dedup: by (title[:40], file_path) to catch near-duplicates
            sig = (f.title[:40].lower(), f.file_path)
            if sig in seen_title:
                existing = seen_title[sig]
                if SEV_ORDER.get(f.severity, 5) < SEV_ORDER.get(existing.severity, 5):
                    seen_title[sig] = f
                    seen_ids[f.finding_id] = f
            else:
                seen_title[sig] = f

        deduped = list(seen_ids.values())
        logger.info(
            f"[RESEARCHER] Deduplication: {len(findings)} → {len(deduped)} findings"
        )
        return deduped
