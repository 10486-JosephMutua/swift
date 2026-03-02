import json
import threading
from typing import List, Optional, Callable
from pathlib import Path
from datetime import datetime

from core.config import config
from core.logger import get_logger
from core.models import RepoMetadata, FileInfo
from tools.security_tools import score_file_priority
from utils.github_fetcher import (
    fetch_repo_metadata,
    fetch_repo_file_tree,
    fetch_file_contents_parallel,
)
from utils.chunker import detect_language

logger = get_logger("agents.navigator")

# Navigator hard timeout (seconds).
# The parallel fetching in v10 makes this much less likely to fire,
# but we keep it as a safety net.
NAVIGATOR_TIMEOUT_SECONDS = 180


def _is_dependency_file(file_path: str) -> bool:
    """Return True if the file is a package manager dependency/lock file."""
    p              = Path(file_path)
    filename_lower = p.name.lower()
    ext_lower      = p.suffix.lower()
    if filename_lower in config.DEPENDENCY_FILENAMES:
        return True
    if ext_lower in config.DEP_EXTENSIONS:
        return True
    if ext_lower == ".csproj":
        return True
    # deps.json is a .NET deps file
    if filename_lower.endswith(".deps.json"):
        return True
    return False


class NavigatorAgent:
    """
    Navigator: selects high-value files from a GitHub repo.

    v10: parallel file fetching via ThreadPoolExecutor for major latency reduction.
    v9: per-call (connect, read) timeout tuples + OS socket timeout.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ):
        self.token             = token or config.GITHUB_TOKEN
        self.progress_callback = progress_callback or (lambda p, s: None)
        logger.info(
            f"[NAVIGATOR] v10 initialized | "
            f"dep_files={len(config.DEPENDENCY_FILENAMES)} | "
            f"max_files={config.MAX_FILES_TO_ANALYZE} | "
            f"parallel_fetch={config.CONCURRENT_FILE_FETCH} workers"
        )

    def _progress(self, pct: int, step: str) -> None:
        logger.info(f"[NAVIGATOR] Progress {pct}%: {step}")
        try:
            self.progress_callback(pct, step)
        except Exception:
            pass

    def run(self, repo_url: str) -> dict:
        """
        Run navigator with a hard timeout.
        On timeout raises RuntimeError so pipeline can handle it gracefully.

        Threading pattern (verified safe on Windows):
          - threading.Thread with daemon=True
          - t.join(timeout=N) for hard timeout
          - result_box/error_box pattern for inter-thread communication
        """
        result_box: list = [None]
        error_box:  list = [None]

        def _run_target():
            logger.info("[NAVIGATOR] 🧵 Worker thread started — about to call _run_internal")
            try:
                result_box[0] = self._run_internal(repo_url)
            except Exception as exc:
                logger.error(f"[NAVIGATOR] 🧵 Worker thread exception: {exc}")
                error_box[0] = exc
            logger.info("[NAVIGATOR] 🧵 Worker thread finished")

        logger.info(f"[NAVIGATOR] Spawning worker thread (timeout={NAVIGATOR_TIMEOUT_SECONDS}s)")
        t = threading.Thread(target=_run_target, daemon=True, name="navigator-worker")
        t.start()
        logger.info("[NAVIGATOR] Worker thread spawned — joining with timeout")
        t.join(timeout=NAVIGATOR_TIMEOUT_SECONDS)
        logger.info(f"[NAVIGATOR] Join returned — thread alive: {t.is_alive()}")

        if t.is_alive():
            logger.error(
                f"[NAVIGATOR] ⏰ Timed out after {NAVIGATOR_TIMEOUT_SECONDS}s. "
                "GitHub API may be slow. Retry or check network."
            )
            raise RuntimeError(
                f"Navigator timed out after {NAVIGATOR_TIMEOUT_SECONDS}s. "
                "Try again — GitHub API may have been slow."
            )

        if error_box[0] is not None:
            logger.error(f"[NAVIGATOR] Error: {error_box[0]}")
            raise error_box[0]

        return result_box[0]

    def _run_internal(self, repo_url: str) -> dict:
        logger.info(f"[NAVIGATOR] ══ Starting navigation: {repo_url} ══")
        start_time = datetime.now()
        agent_logs = []

        # ── Step 1: Repository metadata ─────────────────────────
        self._progress(6, "Navigator: Fetching repository metadata...")
        agent_logs.append("🔍 Navigator: Fetching repository metadata...")
        logger.info("[NAVIGATOR] Step 1/5: Fetching repository metadata")

        try:
            metadata = fetch_repo_metadata(repo_url, self.token)
            agent_logs.append(
                f"✅ {metadata.owner}/{metadata.repo_name} | "
                f"lang={metadata.language} | "
                f"size={metadata.size_kb}KB | "
                f"⭐{metadata.stars}"
            )
            logger.info(
                f"[NAVIGATOR] ✅ Metadata: "
                f"{metadata.owner}/{metadata.repo_name} | "
                f"lang={metadata.language} | size={metadata.size_kb}KB"
            )
        except Exception as e:
            logger.error(f"[NAVIGATOR] Metadata failed: {e}")
            raise ValueError(f"Cannot access repository: {e}")

        # ── Step 2: File tree ────────────────────────────────────
        self._progress(8, "Navigator: Mapping file tree...")
        agent_logs.append("🗺️  Navigator: Fetching file tree...")
        logger.info("[NAVIGATOR] Step 2/5: Fetching file tree")

        try:
            raw_files = fetch_repo_file_tree(
                owner=metadata.owner,
                repo=metadata.repo_name,
                branch=metadata.default_branch,
                token=self.token,
            )
            logger.info(f"[NAVIGATOR] ✅ File tree: {len(raw_files)} blobs")
            agent_logs.append(f"📁 {len(raw_files)} files discovered")
        except Exception as e:
            logger.error(f"[NAVIGATOR] File tree failed: {e}")
            raise ValueError(f"Cannot fetch file tree: {e}")

        # ── Step 3: Prefilter ────────────────────────────────────
        self._progress(10, "Navigator: Filtering files...")
        logger.info("[NAVIGATOR] Step 3/5: Prefiltering files")
        candidates = self._prefilter_files(raw_files)
        skipped    = len(raw_files) - len(candidates)
        metadata.total_files_found = len(raw_files)
        metadata.files_skipped     = skipped
        logger.info(
            f"[NAVIGATOR] ✅ Prefilter: {len(candidates)} pass | {skipped} skipped"
        )
        agent_logs.append(
            f"🔎 {len(candidates)} files passed filter ({skipped} skipped)"
        )

        # ── Step 4: Score & select top files ─────────────────────
        self._progress(13, "Navigator: Scoring by security priority...")
        logger.info("[NAVIGATOR] Step 4/5: Scoring files by security priority")
        scored_files = self._score_files_directly(candidates)
        scored_files.sort(key=lambda f: f.priority_score, reverse=True)
        top_files            = scored_files[:config.MAX_FILES_TO_ANALYZE]
        metadata.files_selected = len(top_files)

        dep_count = sum(1 for f in top_files if _is_dependency_file(f.path))
        logger.info(
            f"[NAVIGATOR] ✅ Selected {len(top_files)} files "
            f"({dep_count} dep/lockfiles)"
        )
        agent_logs.append(
            f"📋 Selected {len(top_files)} targets ({dep_count} dep/lockfiles):\n"
            + "\n".join(
                f"  • {f.path} ({f.language}, priority={f.priority_score}/100)"
                for f in top_files
            )
        )

        # ── Step 5: Fetch file contents IN PARALLEL ───────────────
        self._progress(
            16,
            f"Navigator: Parallel-fetching {len(top_files)} files "
            f"({config.CONCURRENT_FILE_FETCH} workers)..."
        )
        logger.info(
            f"[NAVIGATOR] Step 5/5: Parallel file fetch — "
            f"{len(top_files)} files | {config.CONCURRENT_FILE_FETCH} workers"
        )
        agent_logs.append(
            f"📥 Navigator: Fetching {len(top_files)} files in parallel "
            f"({config.CONCURRENT_FILE_FETCH} workers)..."
        )

        files_with_content = fetch_file_contents_parallel(
            files=top_files,
            owner=metadata.owner,
            repo=metadata.repo_name,
            branch=metadata.default_branch,
            token=self.token,
        )

        fetched = sum(1 for f in files_with_content if f.content)
        agent_logs.append(
            f"✅ {fetched}/{len(top_files)} files fetched. "
            "Handing off to Researcher..."
        )
        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"[NAVIGATOR] ══ Complete in {elapsed:.2f}s | "
            f"{fetched}/{len(top_files)} files fetched ══"
        )

        return {
            "metadata":   metadata,
            "files":      files_with_content,
            "agent_logs": agent_logs,
        }

    def _prefilter_files(self, raw_files: List[dict]) -> List[dict]:
        """Filter raw GitHub tree blobs to security-relevant candidates."""
        candidates = []
        stats = {
            "dep": 0, "source": 0, "binary": 0,
            "too_large": 0, "ignored_dir": 0, "unknown": 0,
        }

        for item in raw_files:
            path = item.get("path", "")
            size = item.get("size", 0)

            if item.get("type") != "blob":
                continue

            p              = Path(path)
            filename_lower = p.name.lower()
            ext_lower      = p.suffix.lower()

            # Size filter
            if size > config.MAX_FILE_SIZE_BYTES:
                stats["too_large"] += 1
                continue

            # Always include dependency/lockfiles
            if _is_dependency_file(path):
                candidates.append(item)
                stats["dep"] += 1
                continue

            # Skip binary/media files
            if ext_lower in config.IGNORED_EXTENSIONS:
                stats["binary"] += 1
                continue

            # Skip ignored directories
            path_parts     = set(p.parts[:-1])
            in_ignored_dir = bool(path_parts & config.IGNORED_DIRS)
            if in_ignored_dir:
                stats["ignored_dir"] += 1
                continue

            # Include known source extensions
            if ext_lower in config.SOURCE_EXTENSIONS:
                candidates.append(item)
                stats["source"] += 1
                continue

            # Include high-value filename patterns (no extension)
            if not ext_lower and filename_lower in config.HIGH_VALUE_PATTERNS:
                candidates.append(item)
                stats["source"] += 1
                continue

            stats["unknown"] += 1

        logger.info(
            f"[NAVIGATOR] Prefilter stats: "
            f"dep={stats['dep']} "
            f"src={stats['source']} "
            f"binary={stats['binary']} "
            f"too_large={stats['too_large']} "
            f"ignored_dir={stats['ignored_dir']} "
            f"unknown={stats['unknown']}"
        )
        return candidates

    def _score_files_directly(self, candidates: List[dict]) -> List[FileInfo]:
        """
        Score files by security priority.
        Dependency files always get 100 (must-scan).
        Source files are scored by the security_tools.score_file_priority tool.
        """
        scored = []
        dep_count = 0
        src_count = 0

        for item in candidates:
            path = item.get("path", "")
            size = item.get("size", 0)

            # Dependency files always get highest priority
            if _is_dependency_file(path):
                scored.append(FileInfo(
                    path=path,
                    size_bytes=size,
                    priority_score=100,
                    reason="Dependency/lockfile — guaranteed scan by Trivy/Snyk",
                    language=detect_language(path),
                ))
                dep_count += 1
                continue

            # Source files scored by the security heuristic tool
            try:
                result_str = score_file_priority.invoke({
                    "file_path": path,
                    "file_size": size,
                })
                score_data = json.loads(result_str)
                score      = score_data.get("score", 0)
                if score > 0:
                    scored.append(FileInfo(
                        path=path,
                        size_bytes=size,
                        priority_score=score,
                        reason=score_data.get("reason", ""),
                        language=score_data.get("language", "unknown"),
                    ))
                    src_count += 1
            except Exception as e:
                logger.warning(f"[NAVIGATOR] Score tool failed for {path}: {e}")
                heuristic = self._heuristic_score(path)
                if heuristic > 0:
                    scored.append(FileInfo(
                        path=path,
                        size_bytes=size,
                        priority_score=heuristic,
                        reason="Heuristic fallback score",
                        language=detect_language(path),
                    ))
                    src_count += 1

        logger.info(
            f"[NAVIGATOR] Scoring complete: "
            f"{dep_count} dep files (priority=100) + "
            f"{src_count} source files scored = "
            f"{len(scored)} total candidates"
        )
        return scored

    def _heuristic_score(self, path: str) -> int:
        """Fallback heuristic score when the tool fails."""
        filename = Path(path).name.lower()
        if filename in config.HIGH_VALUE_PATTERNS:
            return 70
        for kw in {"auth", "login", "admin", "api", "secret", "token", "db", "sql",
                   "password", "key", "crypto", "jwt", "session", "cookie", "oauth"}:
            if kw in path.lower():
                return 40
        if Path(path).suffix.lower() in config.SOURCE_EXTENSIONS:
            return 10
        return 0
