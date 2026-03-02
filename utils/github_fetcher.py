import os
import socket
import time
import base64
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from binaryornot.helpers import is_binary_string

from core.config import config
from core.logger import get_logger
from core.models import RepoMetadata, FileInfo
from utils.chunker import detect_language

logger = get_logger("utils.github_fetcher")

# ── OS-level socket timeout — covers TCP connect + SSL handshake ──
# On Windows, requests timeout= does NOT cover the TCP connect phase.
# socket.setdefaulttimeout() is the only reliable way to prevent hangs.
# Per: https://docs.python.org/3/library/socket.html#socket.setdefaulttimeout
socket.setdefaulttimeout(20)

# ── Per-call (connect_seconds, read_seconds) tuples ──────────────
# Using tuples per requests docs: timeout=(connect, read)
# connect: TCP+SSL establishment; read: response body receipt
_T_METADATA = (8, 15)
_T_BRANCH   = (8, 12)
_T_TREE     = (8, 30)
_T_FILE     = (8, 15)
_T_RATE     = (5,  8)


def _parse_github_url(url: str) -> Tuple[str, str]:
    """Parse a GitHub URL into (owner, repo) tuple."""
    url = url.strip().rstrip("/")
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    parts  = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        raise ValueError(f"Cannot parse GitHub URL: {url!r}")
    owner = parts[0]
    repo  = parts[1].replace(".git", "")
    logger.info(f"[FETCHER] Parsed URL: owner='{owner}' repo='{repo}'")
    return owner, repo


def _build_session(token: Optional[str] = None) -> requests.Session:
    """
    Build a requests.Session with:
    - Fast-fail retry (1 retry, 0.5s backoff)
    - GitHub auth headers
    Each thread that fetches files creates its own session (thread-safe).
    Per requests docs: Sessions are not thread-safe for concurrent use,
    so each thread must have its own instance.
    """
    session = requests.Session()
    retry   = Retry(
        total=1,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        # ── CRITICAL: disable Retry-After header respect ──────────────────
        # urllib3 respects Retry-After BY DEFAULT. GitHub sends Retry-After: 60
        # (or longer) on secondary rate limits. With total=1 retry, this causes
        # the thread to SLEEP for up to 400 seconds silently.
        # We fast-fail instead and let the caller handle it.
        # Per urllib3 docs: respect_retry_after_header defaults to True.
        respect_retry_after_header=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))

    headers = {
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":           "SwiftAudit/10.0",
    }
    effective_token = token or config.GITHUB_TOKEN
    if effective_token:
        headers["Authorization"] = f"Bearer {effective_token}"
        logger.info("[FETCHER] GitHub: authenticated (5000 req/hr)")
    else:
        logger.warning("[FETCHER] No GitHub token — 60 req/hr unauthenticated limit")

    session.headers.update(headers)
    return session


def _check_rate_limit(session: requests.Session) -> None:
    """Check remaining GitHub API calls and wait if near zero."""
    try:
        logger.info("[FETCHER] Checking GitHub rate limit...")
        resp      = session.get("https://api.github.com/rate_limit", timeout=_T_RATE)
        data      = resp.json()
        remaining = data.get("rate", {}).get("remaining", 999)
        reset_at  = data.get("rate", {}).get("reset", 0)
        logger.info(f"[FETCHER] Rate limit: {remaining} requests remaining")
        if remaining < 10:
            wait = min(max(0, reset_at - int(time.time())) + 5, 30)
            logger.warning(f"[FETCHER] Rate limit near zero — sleeping {wait}s")
            time.sleep(wait)
    except Exception as e:
        logger.warning(f"[FETCHER] Rate limit check failed (non-fatal): {e}")


def fetch_repo_metadata(url: str, token: Optional[str] = None) -> RepoMetadata:
    """
    Fetch repository metadata from GitHub API.
    Raises ValueError with a clear message if anything goes wrong.
    """
    owner, repo = _parse_github_url(url)
    session     = _build_session(token)
    api_url     = f"https://api.github.com/repos/{owner}/{repo}"

    logger.info(
        f"[FETCHER] → GET metadata "
        f"(connect={_T_METADATA[0]}s read={_T_METADATA[1]}s): {api_url}"
    )

    try:
        response = session.get(api_url, timeout=_T_METADATA)
    except requests.exceptions.ConnectTimeout:
        raise ValueError(
            f"GitHub API connect timed out after {_T_METADATA[0]}s. "
            "Check network/firewall. Try: curl https://api.github.com from terminal."
        )
    except requests.exceptions.ReadTimeout:
        raise ValueError(
            f"GitHub API read timed out after {_T_METADATA[1]}s — server too slow."
        )
    except requests.exceptions.ConnectionError as e:
        raise ValueError(f"Cannot connect to GitHub API: {e}")

    if response.status_code == 404:
        raise ValueError(f"Repository not found: {url}")
    if response.status_code == 403:
        raise ValueError(
            "GitHub API access denied (403). Check token permissions or rate limit."
        )
    if response.status_code == 401:
        raise ValueError("GitHub token invalid (401). Run: gh auth login")
    if response.status_code != 200:
        raise ValueError(f"GitHub API returned HTTP {response.status_code}")

    data    = response.json()
    size_kb = data.get("size", 0)
    logger.info(
        f"[FETCHER] ✅ Metadata: {owner}/{repo} | "
        f"size={size_kb}KB | stars={data.get('stargazers_count', 0)} | "
        f"lang={data.get('language', '?')} | "
        f"branch={data.get('default_branch', 'main')}"
    )

    return RepoMetadata(
        url=url,
        owner=owner,
        repo_name=repo,
        default_branch=data.get("default_branch", "main"),
        language=data.get("language") or "Unknown",
        stars=data.get("stargazers_count", 0),
        size_kb=size_kb,
        is_private=data.get("private", False),
        description=data.get("description") or "",
    )


def fetch_repo_file_tree(
    owner: str,
    repo: str,
    branch: str = "main",
    token: Optional[str] = None,
) -> List[Dict]:
    """
    Fetch the full recursive file tree via GitHub API.
    Returns a list of file dicts with keys: path, type, size, sha, url.
    """
    session = _build_session(token)
    # NOTE: _check_rate_limit() removed from hot path — it adds a round trip
    # and can block if GitHub returns Retry-After. Call it manually if needed.

    # Step 1: resolve branch → commit SHA
    branch_url = f"https://api.github.com/repos/{owner}/{repo}/branches/{branch}"
    logger.info(
        f"[FETCHER] → GET branch SHA "
        f"(connect={_T_BRANCH[0]}s read={_T_BRANCH[1]}s)"
    )

    try:
        resp = session.get(branch_url, timeout=_T_BRANCH)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as e:
        raise ValueError(f"Branch fetch timed out: {e}")
    except requests.exceptions.ConnectionError as e:
        raise ValueError(f"Cannot connect to GitHub (branch fetch): {e}")

    if resp.status_code != 200:
        # Try 'master' as fallback
        logger.warning(
            f"[FETCHER] Branch '{branch}' not found ({resp.status_code}). "
            "Trying 'master'..."
        )
        try:
            resp = session.get(
                f"https://api.github.com/repos/{owner}/{repo}/branches/master",
                timeout=_T_BRANCH,
            )
        except Exception as e:
            raise ValueError(f"Both 'main' and 'master' branch fetch failed: {e}")
        if resp.status_code != 200:
            raise ValueError(
                f"Cannot find default branch (tried 'main' and 'master'). "
                f"Last status: {resp.status_code}"
            )

    sha = resp.json()["commit"]["sha"]
    logger.info(f"[FETCHER] ✅ Branch SHA: {sha[:12]}...")

    # Step 2: fetch full recursive tree
    tree_url = (
        f"https://api.github.com/repos/{owner}/{repo}"
        f"/git/trees/{sha}?recursive=1"
    )
    logger.info(
        f"[FETCHER] → GET file tree "
        f"(connect={_T_TREE[0]}s read={_T_TREE[1]}s)"
    )

    try:
        resp = session.get(tree_url, timeout=_T_TREE)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as e:
        raise ValueError(f"File tree fetch timed out: {e}")
    except requests.exceptions.ConnectionError as e:
        raise ValueError(f"Cannot connect to GitHub (tree fetch): {e}")

    if resp.status_code != 200:
        raise ValueError(f"File tree API returned HTTP {resp.status_code}")

    tree_data = resp.json()
    if tree_data.get("truncated"):
        logger.warning(
            "[FETCHER] ⚠️  GitHub truncated the tree (repo >100k files). "
            "Scanning partial tree only."
        )

    files = [item for item in tree_data.get("tree", []) if item.get("type") == "blob"]
    logger.info(f"[FETCHER] ✅ File tree: {len(files)} blobs")
    return files


def _fetch_single_file(
    owner: str,
    repo: str,
    file_info: FileInfo,
    branch: str,
    token: Optional[str],
    idx: int,
    total: int,
) -> FileInfo:
    """
    Fetch content for a single file.
    Each thread calls this — creates its own session (thread-safe).
    Returns the FileInfo with content filled in (or unchanged on failure).
    """
    # Each thread creates its own session — sessions are not thread-safe
    session      = _build_session(token)
    encoded_path = requests.utils.quote(file_info.path, safe="/")
    url          = (
        f"https://api.github.com/repos/{owner}/{repo}"
        f"/contents/{encoded_path}?ref={branch}"
    )

    logger.info(f"[FETCHER] [{idx}/{total}] Fetching: {file_info.path}")

    try:
        resp = session.get(url, timeout=_T_FILE)

        if resp.status_code == 404:
            logger.warning(f"[FETCHER] 404: {file_info.path}")
            return file_info
        if resp.status_code != 200:
            logger.error(
                f"[FETCHER] HTTP {resp.status_code}: {file_info.path}"
            )
            return file_info

        data = resp.json()

        if data.get("size", 0) > config.MAX_FILE_SIZE_BYTES:
            logger.warning(
                f"[FETCHER] Too large ({data.get('size')} bytes): "
                f"{file_info.path} — skipping"
            )
            return file_info

        encoding = data.get("encoding", "")
        if encoding == "base64":
            raw_bytes = base64.b64decode(data.get("content", ""))
            if is_binary_string(raw_bytes[:1024]):
                logger.debug(f"[FETCHER] Binary file skipped: {file_info.path}")
                return file_info
            try:
                content = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    import chardet
                    enc     = chardet.detect(raw_bytes).get("encoding") or "latin-1"
                    content = raw_bytes.decode(enc)
                except Exception:
                    logger.warning(
                        f"[FETCHER] Cannot decode: {file_info.path}"
                    )
                    return file_info

            file_info.content = content
            better_lang       = detect_language(file_info.path, content)
            if better_lang and better_lang != "Unknown":
                file_info.language = better_lang
            logger.info(
                f"[FETCHER] ✅ [{idx}/{total}] {file_info.path} "
                f"({len(content)} chars, lang={file_info.language})"
            )
        else:
            # Content returned as plain text (rare but possible)
            content = data.get("content", "")
            if content:
                file_info.content = content

    except requests.exceptions.ConnectTimeout:
        logger.error(
            f"[FETCHER] Connect timeout ({_T_FILE[0]}s): {file_info.path}"
        )
    except requests.exceptions.ReadTimeout:
        logger.error(
            f"[FETCHER] Read timeout ({_T_FILE[1]}s): {file_info.path}"
        )
    except requests.exceptions.ConnectionError as e:
        logger.error(f"[FETCHER] Connection error: {file_info.path}: {e}")
    except Exception as e:
        logger.error(f"[FETCHER] Unexpected error: {file_info.path}: {e}")

    return file_info


def fetch_file_contents_parallel(
    files: List[FileInfo],
    owner: str,
    repo: str,
    branch: str,
    token: Optional[str] = None,
) -> List[FileInfo]:
    """
    Fetch content for multiple files IN PARALLEL using ThreadPoolExecutor.

    LATENCY REDUCTION:
      Sequential (v9): 15 files × 3s avg = ~45s total
      Parallel  (v10): 15 files ÷ 6 workers × 3s avg = ~8s total

    Thread safety:
      Each worker calls _fetch_single_file() which creates its own
      requests.Session(). Sessions are NOT shared between threads.
      FileInfo objects are pre-allocated; each thread writes to a
      different object, so no locking needed.

    Windows safety:
      ThreadPoolExecutor uses threads (not processes), so no fork()
      issues on Windows. Fully supported on all platforms.
      Per Python docs: ThreadPoolExecutor is safe on all platforms.
    """
    total       = len(files)
    max_workers = min(config.CONCURRENT_FILE_FETCH, total)

    logger.info(
        f"[FETCHER] ── Parallel file fetch: {total} files | "
        f"workers={max_workers} ──"
    )

    results: List[FileInfo] = [None] * total  # type: ignore

    with ThreadPoolExecutor(
        max_workers=max_workers,
        thread_name_prefix="fetcher",
    ) as executor:
        # Submit all tasks and track which index each future maps to
        future_to_idx = {
            executor.submit(
                _fetch_single_file,
                owner, repo, files[i], branch, token, i + 1, total
            ): i
            for i in range(total)
        }

        completed = 0
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
                completed   += 1
                logger.debug(
                    f"[FETCHER] Progress: {completed}/{total} files fetched"
                )
            except Exception as e:
                logger.error(
                    f"[FETCHER] Future failed for file index {idx}: {e}"
                )
                results[idx] = files[idx]  # fallback: original without content

    fetched_count = sum(1 for f in results if f and f.content)
    logger.info(
        f"[FETCHER] ✅ Parallel fetch complete: "
        f"{fetched_count}/{total} files have content"
    )
    return results


# Legacy sequential fetch — kept for fallback/testing
def fetch_file_content(
    owner: str,
    repo: str,
    file_path: str,
    branch: str = "main",
    token: Optional[str] = None,
) -> Optional[str]:
    """
    Fetch a single file's content. Used by clone_repo_locally context.
    """
    fi = FileInfo(path=file_path, size_bytes=0, priority_score=0, reason="", language="")
    result = _fetch_single_file(owner, repo, fi, branch, token, 1, 1)
    return result.content if result else None


def clone_repo_locally(url: str, token: Optional[str] = None) -> Optional[str]:
    """
    Clone repo with --depth=1 for scanner tools (Snyk, Trivy).
    Returns the local clone path, or None on failure.
    """
    os.makedirs(config.TEMP_CLONE_DIR, exist_ok=True)
    clone_dir = tempfile.mkdtemp(
        prefix="swiftaudit_v10_",
        dir=config.TEMP_CLONE_DIR,
    )

    effective_token = token or config.GITHUB_TOKEN
    if effective_token:
        parsed    = urlparse(url)
        clone_url = f"https://{effective_token}@{parsed.netloc}{parsed.path}"
    else:
        clone_url = url

    logger.info(
        f"[FETCHER] Cloning → {clone_dir} "
        f"(--depth=1, timeout={config.GIT_CLONE_TIMEOUT}s)"
    )

    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", clone_url, clone_dir],
            capture_output=True,
            text=True,
            timeout=config.GIT_CLONE_TIMEOUT,
        )
        if result.returncode != 0:
            err = result.stderr.strip()[:400]
            logger.error(f"[FETCHER] Clone failed (exit {result.returncode}): {err}")
            _cleanup_clone(clone_dir)
            return None

        logger.info(f"[FETCHER] ✅ Clone complete: {clone_dir}")
        return clone_dir

    except subprocess.TimeoutExpired:
        logger.error(
            f"[FETCHER] Clone timed out after {config.GIT_CLONE_TIMEOUT}s"
        )
        _cleanup_clone(clone_dir)
        return None
    except FileNotFoundError:
        logger.error("[FETCHER] 'git' not found in PATH — install Git")
        _cleanup_clone(clone_dir)
        return None
    except Exception as e:
        logger.error(f"[FETCHER] Clone unexpected error: {e}")
        _cleanup_clone(clone_dir)
        return None


def _cleanup_clone(path: str) -> None:
    """Remove a temp clone directory, ignoring errors."""
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
