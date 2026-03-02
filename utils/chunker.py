import re
from typing import List, Tuple, Optional
from pathlib import Path

from pygments.lexers import guess_lexer_for_filename, get_lexer_for_filename
from pygments.token import Token, Comment, Name, Keyword
from pygments.util import ClassNotFound

try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False

from core.config import config
from core.logger import get_logger

logger = get_logger("utils.chunker")


# ============================================================
# FIX #3b: Pygments-based language detection
# Replaces the primitive extension → language dict from v1
# ============================================================

def detect_language(file_path: str, content: str = "") -> str:
    """
    Detect programming language using Pygments.

    Per Pygments docs: guess_lexer_for_filename(filename, text)
    uses BOTH the filename pattern AND file content heuristics.
    Falls back to filename-only, then to "Unknown".

    IMPROVEMENT OVER v1:
    - Handles extensionless scripts (#!/usr/bin/python)
    - Handles ambiguous extensions (.conf, .tmpl)
    - Uses shebang lines for detection
    - 500+ languages supported

    Args:
        file_path: Relative or absolute file path
        content: File content for content-based guessing

    Returns:
        Language name string e.g. "Python", "JavaScript"
    """
    filename = Path(file_path).name

    # Strategy 1: filename + content (most accurate per docs)
    if content:
        try:
            lexer = guess_lexer_for_filename(filename, content)
            lang = lexer.name
            logger.debug(f"[CHUNKER] Language (filename+content): {file_path} → {lang}")
            return lang
        except ClassNotFound:
            pass

    # Strategy 2: filename only
    try:
        lexer = get_lexer_for_filename(filename)
        lang = lexer.name
        logger.debug(f"[CHUNKER] Language (filename only): {file_path} → {lang}")
        return lang
    except ClassNotFound:
        pass

    # Strategy 3: fallback to extension map for common cases
    ext = Path(file_path).suffix.lower()
    fallback_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".java": "Java", ".php": "PHP", ".rb": "Ruby",
        ".go": "Go", ".rs": "Rust", ".cs": "C#",
        ".sh": "Shell", ".env": "Environment",
    }
    lang = fallback_map.get(ext, "Unknown")
    logger.debug(f"[CHUNKER] Language (fallback map): {file_path} → {lang}")
    return lang


# ============================================================
# FIX #3a: Pygments token-based split-point detection
# Replaces hand-written regex from v1
# ============================================================

def find_logical_split_points(content: str, file_path: str) -> List[int]:
    """
    Find safe code split points using Pygments token analysis.

    WHAT V1 DID (fragile):
        Used regex like r"^class\\s+\\w+" and r"^def\\s+\\w+"
        Broke on: TypeScript generics, Java multi-line annotations,
        decorated functions spanning multiple lines, PHP classes.

    WHAT V2 DOES (robust):
        Uses Pygments to tokenize the file into a stream of
        (token_type, value) pairs. We find line numbers where
        Token.Keyword.Declaration or Token.Name.Class appear
        at the START of a line — language-aware and reliable.

    Per Pygments API docs:
        lexer = guess_lexer_for_filename(filename, content)
        tokens = list(lexer.get_tokens(content))

    Args:
        content: Raw file content
        file_path: For lexer selection

    Returns:
        Sorted list of line numbers that are safe split points
    """
    logger.debug(f"[CHUNKER] Finding logical split points for: {file_path}")
    filename = Path(file_path).name
    split_points = {0}  # Always include line 0

    try:
        lexer = guess_lexer_for_filename(filename, content)
        tokens = list(lexer.get_tokens(content))

        current_line = 0
        line_start = True

        for token_type, value in tokens:
            newlines = value.count("\n")

            if line_start:
                # Check if this token at line start is a declaration
                is_split = (
                    token_type in Token.Keyword.Declaration or
                    token_type in Token.Keyword or
                    token_type in Token.Name.Decorator or
                    token_type in Token.Comment.Special
                )

                # Also split on significant keywords that start blocks
                split_keywords = {
                    "class", "def", "async", "function", "interface",
                    "struct", "impl", "fn", "func", "public", "private",
                    "protected", "export", "module", "namespace",
                }
                if token_type in Token.Keyword and value.strip() in split_keywords:
                    is_split = True

                if is_split and current_line > 0:
                    split_points.add(current_line)
                    logger.debug(
                        f"[CHUNKER] Split point at line {current_line}: "
                        f"{token_type} '{value.strip()[:20]}'"
                    )

            line_start = value.endswith("\n")
            current_line += newlines

        logger.info(
            f"[CHUNKER] Pygments found {len(split_points)} split points "
            f"for {file_path}"
        )

    except ClassNotFound:
        logger.warning(
            f"[CHUNKER] Pygments has no lexer for {file_path}. "
            f"Falling back to regex split detection."
        )
        split_points.update(_regex_fallback_splits(content))

    except Exception as e:
        logger.error(f"[CHUNKER] Pygments split error for {file_path}: {e}")
        split_points.update(_regex_fallback_splits(content))

    return sorted(split_points)


def _regex_fallback_splits(content: str) -> List[int]:
    """
    Regex fallback for when Pygments cannot find a lexer.
    Less accurate but never crashes.
    """
    patterns = re.compile(
        r"^(class\s|def\s|async def\s|function\s|const\s+\w+\s*=|export\s|@\w+)",
        re.MULTILINE
    )
    lines = content.split("\n")
    splits = []
    for i, line in enumerate(lines):
        if patterns.match(line):
            splits.append(i)
    return splits


# ============================================================
# TOKEN COUNTING
# ============================================================

def count_tokens(text: str) -> int:
    """
    Count tokens using tiktoken (accurate) or char estimate (fallback).
    """
    if TIKTOKEN_AVAILABLE:
        try:
            encoding = tiktoken.get_encoding("cl100k_base")
            count = len(encoding.encode(text))
            logger.debug(f"[CHUNKER] Token count (tiktoken): {count}")
            return count
        except Exception as e:
            logger.warning(f"[CHUNKER] tiktoken failed: {e}")

    estimated = len(text) // 4
    logger.debug(f"[CHUNKER] Token count (char estimate): {estimated}")
    return estimated


# ============================================================
# MAIN CHUNKER
# ============================================================

def chunk_file_content(
    content: str,
    file_path: str,
    max_tokens: int = None
) -> List[Tuple[str, int, int]]:
    """
    Split file content into token-safe chunks using Pygments split points.

    Args:
        content: Raw file content
        file_path: File path (used for Pygments lexer selection)
        max_tokens: Max tokens per chunk

    Returns:
        List of tuples: (chunk_text, chunk_index, total_chunks)
    """
    if max_tokens is None:
        max_tokens = config.MAX_TOKENS_PER_FILE

    logger.info(f"[CHUNKER] Processing: {file_path}")
    total_tokens = count_tokens(content)
    logger.info(f"[CHUNKER] ~{total_tokens} tokens (limit: {max_tokens})")

    if total_tokens <= max_tokens:
        logger.info(f"[CHUNKER] Fits in single chunk")
        return [(content, 0, 1)]

    logger.warning(
        f"[CHUNKER] ⚠️  {file_path} exceeds limit "
        f"({total_tokens} > {max_tokens}). Splitting..."
    )

    lines = content.split("\n")
    # FIX: use Pygments-based split points instead of regex
    split_points = find_logical_split_points(content, file_path)
    split_points.append(len(lines))

    chunks_raw = []
    current_start = 0

    for end in split_points[1:]:
        chunk_lines = lines[current_start:end]
        chunk_text = "\n".join(chunk_lines)
        chunk_tokens = count_tokens(chunk_text)

        if chunk_tokens > max_tokens:
            logger.warning(
                f"[CHUNKER] Section too large ({chunk_tokens} tokens). Hard-splitting."
            )
            sub_chunks = _hard_split_by_lines(chunk_lines, max_tokens)
            chunks_raw.extend(sub_chunks)
        else:
            chunks_raw.append(chunk_text)

        current_start = end

    total = len(chunks_raw)
    result = []
    for idx, chunk in enumerate(chunks_raw):
        header = (
            f"# ===================================================\n"
            f"# SwiftAudit Analysis — Chunk {idx + 1}/{total}\n"
            f"# File: {file_path}\n"
            f"# ===================================================\n\n"
        )
        result.append((header + chunk, idx, total))

    logger.info(f"[CHUNKER] ✅ Split '{file_path}' into {total} chunks")
    return result


def _hard_split_by_lines(lines: List[str], max_tokens: int) -> List[str]:
    """Line-by-line hard split for oversized sections."""
    chunks = []
    current_lines = []
    current_tokens = 0

    for line in lines:
        line_tokens = count_tokens(line)
        if current_tokens + line_tokens > max_tokens and current_lines:
            chunks.append("\n".join(current_lines))
            current_lines = [line]
            current_tokens = line_tokens
        else:
            current_lines.append(line)
            current_tokens += line_tokens

    if current_lines:
        chunks.append("\n".join(current_lines))

    return chunks


def truncate_for_display(content: str, max_chars: int = 500) -> str:
    if len(content) <= max_chars:
        return content
    return content[:max_chars] + f"\n... [TRUNCATED — {len(content) - max_chars} chars remaining]"
