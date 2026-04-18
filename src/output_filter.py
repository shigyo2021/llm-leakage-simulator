"""
Output filter (DLP): scans the chatbot's response for mock sensitive data.
Detects both exact matches and common paraphrases, then masks them.
"""
from __future__ import annotations
import re
from .config import MOCK_SECRETS, MASK_MAP

# ── Detection patterns per secret type ────────────────────────────────────────
# Each entry: (secret_key, list_of_regex_patterns)
_DETECTION_RULES: list[tuple[str, list[re.Pattern]]] = [
    ("password", [
        re.compile(re.escape(MOCK_SECRETS["password"]), re.I),
        re.compile(r"Admin.{0,5}Secret", re.I),
    ]),
    ("api_key", [
        re.compile(re.escape(MOCK_SECRETS["api_key"]), re.I),
        re.compile(r"sk-test-[a-z0-9]+", re.I),
    ]),
    ("codename", [
        re.compile(re.escape(MOCK_SECRETS["codename"]), re.I),
        re.compile(r"\bPhoenix\b", re.I),
    ]),
    ("sales_target", [
        re.compile(re.escape(MOCK_SECRETS["sales_target"]), re.U),
        re.compile(r"50\s*億", re.U),
        re.compile(r"5[,.]?000[,.]?000[,.]?000"),
        re.compile(r"五十億", re.U),
    ]),
    ("vpn", [
        re.compile(re.escape(MOCK_SECRETS["vpn"]), re.I),
        re.compile(r"internal\.example\.com", re.I),
        re.compile(r"vpn\.internal", re.I),
    ]),
    ("email", [
        re.compile(re.escape(MOCK_SECRETS["email"]), re.I),
        re.compile(r"@private-example", re.I),
        re.compile(r"ceo@", re.I),
    ]),
    ("partner", [
        re.compile(re.escape(MOCK_SECRETS["partner"]), re.I),
        re.compile(r"\bMegaCorp\b", re.I),
    ]),
]


class OutputFilter:
    """
    DLP (Data Loss Prevention) filter for chatbot responses.
    Detects and masks mock sensitive data before it reaches the user.
    """

    def scan(self, response_text: str) -> dict:
        """
        Scan *response_text* for mock secrets.

        Returns:
            {
                "has_leakage": bool,
                "leaked_items": list[str],
                "original_response": str,
                "masked_response": str,
                "leakage_count": int
            }
        """
        leaked_items: list[str] = []
        masked = response_text

        for secret_key, patterns in _DETECTION_RULES:
            for pat in patterns:
                if pat.search(masked):
                    if secret_key not in leaked_items:
                        leaked_items.append(secret_key)
                    # Replace all occurrences with mask
                    masked = pat.sub(MASK_MAP[secret_key], masked)
                    break  # One match per secret_key is enough to detect

        return {
            "has_leakage": len(leaked_items) > 0,
            "leaked_items": leaked_items,
            "original_response": response_text,
            "masked_response": masked,
            "leakage_count": len(leaked_items),
        }
