"""Interactive Consent Manager for LocalGuard-Pro."""

from localguard.core.constants import CONSENT_PROMPT, LEGAL_WARNING
from localguard.core.exceptions import ConsentError


class ConsentManager:
    """
    Manages interactive user consent before DAST scanning.

    Ensures explicit authorization for security testing.
    """

    def __init__(self, auto_consent: bool = False):
        self.auto_consent = auto_consent
        self._consent_given = False

    def request_consent(self, target_url: str, non_interactive: bool = False) -> bool:
        """
        Request user consent for scanning.

        Args:
            target_url: The target URL being scanned
            non_interactive: If True, skip prompt (for CI/CD with auto_consent)

        Returns:
            True if consent given, False otherwise

        Raises:
            ConsentError: If consent not given and not auto_consent
        """
        if self._consent_given:
            return True

        if self.auto_consent or non_interactive:
            if self.auto_consent:
                print(f"[AUTO-CONSENT] Scanning authorized for: {target_url}")
                self._consent_given = True
                return True
            raise ConsentError("Non-interactive mode requires --auto-consent flag")

        # Display legal warning
        print(LEGAL_WARNING)
        print(f"Target: {target_url}")
        print()

        # Get user input
        try:
            response = input(CONSENT_PROMPT).strip().upper()
        except (KeyboardInterrupt, EOFError):
            print("\n[ABORTED] User cancelled.")
            raise ConsentError("User cancelled consent prompt") from None

        if response == "Y":
            print("[AUTHORIZED] Consent granted. Starting scan...\n")
            self._consent_given = True
            return True

        print("[DENIED] Consent not granted. Scan aborted.")
        raise ConsentError("User did not provide consent (must type 'Y')")

    def reset(self) -> None:
        """Reset consent state (for multiple scans in same session)."""
        self._consent_given = False


def get_consent(target_url: str, auto_consent: bool = False, non_interactive: bool = False) -> bool:
    """
    Convenience function to get user consent.

    Args:
        target_url: Target URL
        auto_consent: Skip prompt (for CI/CD)
        non_interactive: Run in non-interactive mode

    Returns:
        True if consent given

    Raises:
        ConsentError: If consent not given
    """
    manager = ConsentManager(auto_consent=auto_consent)
    return manager.request_consent(target_url, non_interactive=non_interactive)
