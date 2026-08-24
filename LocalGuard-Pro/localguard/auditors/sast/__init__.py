"""SAST Auditors for LocalGuard-Pro."""

from localguard.auditors.sast.secrets import SecretScanner

__all__ = [
    "SecretScanner",
]
