"""DAST Auditors for LocalGuard-Pro."""

from localguard.auditors.dast.access_control import AccessControlAuditor
from localguard.auditors.dast.cors import CORSAuditor
from localguard.auditors.dast.forms_injection import FormInjectionAuditor
from localguard.auditors.dast.header_cookie import HeaderCookieAuditor
from localguard.auditors.dast.sensitive_paths import SensitivePathScanner

__all__ = [
    "HeaderCookieAuditor",
    "SensitivePathScanner",
    "FormInjectionAuditor",
    "AccessControlAuditor",
    "CORSAuditor",
]
