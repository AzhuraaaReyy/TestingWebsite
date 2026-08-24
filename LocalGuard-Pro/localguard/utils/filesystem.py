"""Filesystem utilities for LocalGuard-Pro."""

import fnmatch
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileInfo:
    """Information about a file."""

    path: Path
    relative_path: str
    size: int
    extension: str
    is_binary: bool


def should_exclude(path: Path, exclude_patterns: list[str]) -> bool:
    """
    Check if a path should be excluded based on glob patterns.

    Args:
        path: Path to check
        exclude_patterns: List of glob patterns

    Returns:
        True if path matches any exclude pattern
    """
    path_str = str(path)
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path.name, pattern):
            return True
        # Also check against parent directories
        for parent in path.parents:
            if fnmatch.fnmatch(str(parent), pattern):
                return True
    return False


def is_binary_file(path: Path, sample_size: int = 8192) -> bool:
    """
    Check if a file is binary by reading a sample.

    Args:
        path: File path
        sample_size: Number of bytes to read

    Returns:
        True if file appears to be binary
    """
    try:
        with open(path, "rb") as f:
            sample = f.read(sample_size)
        # Check for null bytes (common in binary files)
        if b"\x00" in sample:
            return True
        # Check for high ratio of non-printable characters
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x7F)))
        non_text = sum(1 for b in sample if b not in text_chars)
        return non_text / len(sample) > 0.3 if sample else False
    except Exception:
        return True  # Treat unreadable as binary


def get_file_info(path: Path, root: Path) -> FileInfo:
    """
    Get information about a file.

    Args:
        path: File path
        root: Root directory for relative path calculation

    Returns:
        FileInfo object
    """
    stat = path.stat()
    relative = path.relative_to(root)
    extension = path.suffix.lower()
    is_binary = is_binary_file(path)

    return FileInfo(
        path=path,
        relative_path=str(relative),
        size=stat.st_size,
        extension=extension,
        is_binary=is_binary,
    )


def iter_source_files(
    root: Path,
    exclude_patterns: list[str] | None = None,
    include_extensions: set[str] | None = None,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB default
) -> Iterator[FileInfo]:
    """
    Iterate over source files in a directory tree.

    Args:
        root: Root directory to scan
        exclude_patterns: Glob patterns to exclude
        include_extensions: File extensions to include (None = all)
        max_file_size: Maximum file size to process

    Yields:
        FileInfo for each matching file
    """
    if exclude_patterns is None:
        exclude_patterns = []

    if not root.exists() or not root.is_dir():
        return

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        # Check exclude patterns
        if should_exclude(path, exclude_patterns):
            continue

        # Check extension filter
        if include_extensions and path.suffix.lower() not in include_extensions:
            continue

        # Check file size
        try:
            if path.stat().st_size > max_file_size:
                continue
        except OSError:
            continue

        yield get_file_info(path, root)


def read_file_safely(
    path: Path, encoding: str = "utf-8", max_size: int = 10 * 1024 * 1024
) -> str | None:
    """
    Safely read a file with encoding fallback.

    Args:
        path: File path
        encoding: Primary encoding to try
        max_size: Maximum file size to read

    Returns:
        File content as string, or None if failed
    """
    try:
        if path.stat().st_size > max_size:
            return None

        # Try primary encoding
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            # Fallback encodings
            for fallback in ["latin-1", "cp1252", "iso-8859-1"]:
                try:
                    return path.read_text(encoding=fallback)
                except UnicodeDecodeError:
                    continue
        return None
    except Exception:
        return None


def write_file_safely(path: Path, content: str, encoding: str = "utf-8") -> bool:
    """
    Safely write a file, creating parent directories if needed.

    Args:
        path: File path
        content: Content to write
        encoding: Encoding to use

    Returns:
        True if successful
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding=encoding)
        return True
    except Exception:
        return False


def ensure_directory(path: Path) -> bool:
    """
    Ensure a directory exists.

    Args:
        path: Directory path

    Returns:
        True if directory exists or was created
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def get_project_root(start_path: Path | None = None) -> Path:
    """
    Find project root by looking for common markers.

    Args:
        start_path: Starting path (default: current directory)

    Returns:
        Project root path
    """
    if start_path is None:
        start_path = Path.cwd()

    markers = [
        ".git",
        "pyproject.toml",
        "setup.py",
        "requirements.txt",
        "package.json",
        "composer.json",
        "Cargo.toml",
        "go.mod",
    ]

    current = start_path.resolve()
    while current != current.parent:
        for marker in markers:
            if (current / marker).exists():
                return current
        current = current.parent

    return start_path.resolve()


def find_config_files(root: Path, names: list[str]) -> list[Path]:
    """
    Find configuration files in project.

    Args:
        root: Root directory
        names: Config file names to search for

    Returns:
        List of found config file paths
    """
    found = []
    for name in names:
        for path in root.rglob(name):
            if path.is_file():
                found.append(path)
    return found
