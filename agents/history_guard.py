import os
import math
import subprocess
from typing import List

from core.logger import get_logger
from core.models import (
    VulnerabilityFinding, VulnCategory, Severity, DetectionSource
)

logger = get_logger("agents.history_guard")

# Entropy thresholds
_ENTROPY_CRITICAL = 4.5
_ENTROPY_HIGH     = 4.0

# Minimum string length to bother measuring entropy
_MIN_SECRET_LEN = 16

# Maximum chars from the raw line to log (avoid enormous base64 blobs in logs)
_MAX_LINE_LOG = 100


def _make_finding_id(commit_hash: str, snippet: str) -> str:
    import hashlib
    raw = f"historyguard::{commit_hash}::{snippet}"
    return "HG-" + hashlib.sha1(raw.encode()).hexdigest()[:10].upper()


class HistoryGuard:
    """
    Forensic Git scanner: detects secrets that were committed and then deleted.

    These are called 'Zombie Secrets' — the secret no longer exists in HEAD
    but is permanently embedded in git history. Anyone who clones the repo
    can run `git log` and recover it.

    Accepts a local repo_path (must contain .git directory).
    """

    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)

    def scan(
        self,
        scan_all: bool = True,
        max_commits: int = 200,
    ) -> List[VulnerabilityFinding]:
        """
        Scan git history for zombie secrets.

        Args:
            scan_all:    If True, scan ALL commits. If False, limit to max_commits.
            max_commits: Commit limit when scan_all=False.

        Returns:
            List of VulnerabilityFinding objects for each zombie secret found.
        """
        git_dir = os.path.join(self.repo_path, ".git")
        if not os.path.exists(git_dir):
            logger.warning(
                f"[HISTORY_GUARD] No .git directory at {self.repo_path}. "
                f"Skipping history scan."
            )
            return []

        cmd = [
            "git", "log",
            "-p", "-U0",        # Patch mode, 0 context lines
            "--no-merges",      # Skip merge commits
            "--pretty=format:COMMIT_HASH:%H|%an|%ad|%s",
        ]
        if not scan_all:
            cmd.insert(2, f"-n {max_commits}")
        else:
            logger.info("[HISTORY_GUARD] 🌊 Streaming FULL git history...")

        findings: List[VulnerabilityFinding] = []
        current_commit: dict = {}

        try:
            process = subprocess.Popen(
                cmd,
                cwd=self.repo_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            for line in process.stdout:
                line = line.rstrip("\n")

                # New commit block
                if line.startswith("COMMIT_HASH:"):
                    parts = line.split("|", 3)
                    if len(parts) >= 4:
                        current_commit = {
                            "hash":   parts[0].replace("COMMIT_HASH:", "").strip(),
                            "author": parts[1].strip(),
                            "date":   parts[2].strip(),
                            "msg":    parts[3].strip(),
                        }
                    continue

                # Only look at removed lines (-) from diffs
                if not line.startswith("-") or line.startswith("---"):
                    continue

                content = line[1:].strip()

                # Skip comments and empty
                if not content or content.startswith(("#", "//", "/*", "*")):
                    continue

                # Must contain assignment or key-value separators
                if "=" not in content and ":" not in content:
                    continue

                # Extract string literals
                for candidate in self._extract_string_literals(content):
                    if len(candidate) < _MIN_SECRET_LEN:
                        continue

                    entropy = self._shannon_entropy(candidate)

                    if entropy < _ENTROPY_HIGH:
                        continue  # Not interesting

                    if self._is_safe_hash(candidate):
                        continue  # Known-safe: git SHA, UUID, MD5

                    severity = (
                        Severity.CRITICAL if entropy >= _ENTROPY_CRITICAL
                        else Severity.HIGH
                    )

                    commit_hash = current_commit.get("hash", "unknown")
                    snippet     = f"{candidate[:4]}...{candidate[-4:]}"

                    logger.info(
                        f"[HISTORY_GUARD] 🔍 Zombie secret in commit "
                        f"{commit_hash[:8]}: '{snippet}' "
                        f"(entropy={entropy:.2f})"
                    )

                    findings.append(VulnerabilityFinding(
                        finding_id=_make_finding_id(commit_hash, candidate),
                        file_path=f"git:history:{commit_hash[:8]}",
                        line_number=None,
                        code_snippet=content[:200],
                        category=VulnCategory.HARDCODED_SECRET,
                        severity=severity,
                        title=f"Zombie Secret in Git History (commit {commit_hash[:8]})",
                        description=(
                            f"A high-entropy string was found in a deleted line in commit "
                            f"{commit_hash[:8]} by {current_commit.get('author', 'unknown')}. "
                            f"Entropy: {entropy:.2f} (threshold: {_ENTROPY_HIGH}). "
                            f"Secret snippet: {snippet}. "
                            f"Commit message: {current_commit.get('msg', '')[:100]}. "
                            f"Even though the line was deleted, the secret is permanently "
                            f"embedded in git history. Anyone who clones this repository "
                            f"can recover it with `git log -p`."
                        ),
                        cwe_id="CWE-540",
                        owasp_category="A07:2021",
                        confidence="HIGH",
                        detection_source=DetectionSource.HISTORY_GUARD,
                        tool_rule_id="history_guard_entropy",
                        tool_test_name="zombie_secret_detection",
                        reasoning_trace=(
                            f"Shannon entropy of string literal = {entropy:.2f}. "
                            f"Threshold: CRITICAL >= {_ENTROPY_CRITICAL}, "
                            f"HIGH >= {_ENTROPY_HIGH}. "
                            f"Not a git SHA, UUID, or MD5. "
                            f"Found in deleted diff line in commit {commit_hash}."
                        ),
                        patch_explanation=(
                            "1. Rotate the exposed secret immediately — it must be "
                            "considered compromised. "
                            "2. Remove it from git history using "
                            "`git filter-repo --path <file> --invert-paths` or "
                            "BFG Repo Cleaner. "
                            "3. Force-push all branches and require all collaborators "
                            "to re-clone."
                        ),
                        false_positive_risk="LOW",
                    ))

            process.wait()
            if process.returncode not in (0, 128):
                logger.warning(
                    f"[HISTORY_GUARD] git log exited with code {process.returncode}"
                )

        except FileNotFoundError:
            logger.warning("[HISTORY_GUARD] `git` binary not found. Skipping.")
            return []
        except Exception as e:
            logger.error(f"[HISTORY_GUARD] History scan failed: {e}")
            return []

        logger.info(
            f"[HISTORY_GUARD] ✅ Scan complete: "
            f"{len(findings)} zombie secrets found"
        )
        return findings

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    def _extract_string_literals(self, text: str) -> List[str]:
        """Extract all quoted string literals from a line of text."""
        literals = []
        in_quote   = False
        quote_char = ""
        current    = []

        for char in text:
            if char in ("'", '"'):
                if not in_quote:
                    in_quote   = True
                    quote_char = char
                elif char == quote_char:
                    in_quote = False
                    literals.append("".join(current))
                    current = []
            elif in_quote:
                current.append(char)

        return literals

    def _shannon_entropy(self, data: str) -> float:
        """Compute Shannon entropy of a string (bits per character)."""
        if not data:
            return 0.0
        entropy = 0.0
        length  = len(data)
        for x in range(256):
            p = data.count(chr(x)) / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _is_safe_hash(self, text: str) -> bool:
        """
        Return True for strings that look like known-safe hashes.
        These have high entropy by design but are NOT secrets.
        """
        # 40-char hex = Git SHA1
        if len(text) == 40 and all(c in "0123456789abcdef" for c in text.lower()):
            return True
        # 36-char UUID with dashes
        if len(text) == 36 and text.count("-") == 4:
            return True
        # 32-char MD5
        if len(text) == 32 and all(c in "0123456789abcdef" for c in text.lower()):
            return True
        return False
