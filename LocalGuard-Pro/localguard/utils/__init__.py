"""Utilities module for LocalGuard-Pro."""

from localguard.utils.entropy import (
    analyze_string_entropy,
    find_high_entropy_substrings,
    is_high_entropy,
    normalized_entropy,
    shannon_entropy,
)
from localguard.utils.filesystem import (
    FileInfo,
    ensure_directory,
    find_config_files,
    get_file_info,
    get_project_root,
    is_binary_file,
    iter_source_files,
    read_file_safely,
    should_exclude,
    write_file_safely,
)
from localguard.utils.patterns import (
    CORS_HEADERS,
    SECRET_PATTERNS,
    SECURITY_HEADERS,
    VULN_PATTERNS,
    SecretPattern,
    compile_vuln_patterns,
    get_all_secret_patterns,
    get_patterns_by_severity,
)

__all__ = [
    # Patterns
    "SECRET_PATTERNS",
    "VULN_PATTERNS",
    "CORS_HEADERS",
    "SECURITY_HEADERS",
    "SecretPattern",
    "get_all_secret_patterns",
    "get_patterns_by_severity",
    "compile_vuln_patterns",
    # Entropy
    "shannon_entropy",
    "normalized_entropy",
    "is_high_entropy",
    "analyze_string_entropy",
    "find_high_entropy_substrings",
    # Filesystem
    "FileInfo",
    "should_exclude",
    "is_binary_file",
    "get_file_info",
    "iter_source_files",
    "read_file_safely",
    "write_file_safely",
    "ensure_directory",
    "get_project_root",
    "find_config_files",
]
