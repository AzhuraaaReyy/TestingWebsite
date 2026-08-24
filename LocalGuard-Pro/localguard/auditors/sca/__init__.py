"""SCA Auditors for LocalGuard-Pro."""

from localguard.auditors.sca.parsers import ComposerParser, NPMParser, PipParser
from localguard.auditors.sca.scanner import DependencyScanner
from localguard.auditors.sca.sources import OfflineCVESource, OSVCVESource

__all__ = [
    "DependencyScanner",
    "ComposerParser",
    "NPMParser",
    "PipParser",
    "OfflineCVESource",
    "OSVCVESource",
]
