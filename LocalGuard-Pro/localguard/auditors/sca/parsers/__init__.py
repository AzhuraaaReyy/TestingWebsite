"""SCA Parsers package for LocalGuard-Pro."""

from localguard.auditors.sca.parsers.composer import ComposerParser
from localguard.auditors.sca.parsers.npm import NPMParser
from localguard.auditors.sca.parsers.pip import PipParser

__all__ = [
    "ComposerParser",
    "NPMParser",
    "PipParser",
]
