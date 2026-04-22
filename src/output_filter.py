"""
Output filter (DLP): scans the chatbot's response for mock sensitive data.

C4 hardening — the original filter was regex-only against the raw response,
so these standard encoding tricks bypassed it:

    "The password is QWRtaW4tU2VjcmV0LTIwMjYh"       # base64
    "The password is 41646d696e2d5365637265742d32303236 21"  # hex
    "The password is A-d-m-i-n---S-e-c-r-e-t---2026!"        # dash-interspersed
    "The password is A\u200Bdmin-Sec\u200Bret-2026!"         # zero-width split
    "Reversed, it reads: !6202-terceS-nimdA"                 # reversed
    "Ａｄｍｉｎ-Ｓｅｃｒｅｔ-2026！"                           # full-width

The hardened filter now scans multiple *views* of the response:
  1. raw text                       (catches literal leaks)
  2. NFKC-normalized + zero-width stripped  (catches full-width / ZWSP splits)
  3. "skeleton" view: alphanumerics only, lowercase (catches punctuation/space
     interspersion like "A-d-m-i-n")
  4. reversed skeleton              (catches naive reversal)
  5. base64-decoded candidates      (catches base64 exfiltration)
  6. hex-decoded candidates         (catches hex exfiltration)

Any hit in any view masks the corresponding secret in the displayed response
and records the encoding channel so the demo can show *how* it was bypassed.
This isn't a complete DLP — ROT13, character-ranked ciphers, and LLM-assisted
paraphrases still require semantic analysis — but it shuts the easy doors.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from .config import MOCK_SECRETS, MASK_MAP

# ── Regex rules kept for the raw view (unchanged semantics) ───────────────────
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


# ── Encoding-bypass helpers ───────────────────────────────────────────────────

# Invisible formatting code points to strip (same policy as the detector's
# normalize module; duplicated here so the simulator stays independent).
_INVISIBLES = {
    "\u200B", "\u200C", "\u200D", "\u2060", "\uFEFF",
    "\u202A", "\u202B", "\u202C", "\u202D", "\u202E",
    "\u2066", "\u2067", "\u2068", "\u2069",
}
_INVISIBLE_TABLE = {ord(c): None for c in _INVISIBLES}

# Identify base64-ish and hex-ish tokens in the output so we can try decoding
# them. We only decode tokens long enough to plausibly encode a secret.
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/=]{16,}")
_HEX_CANDIDATE = re.compile(r"(?:[0-9a-fA-F]{2}[\s:-]?){8,}")

# Non-alphanumeric runs (used to build the "skeleton" view).
_NON_ALNUM = re.compile(r"[^0-9A-Za-z\u3040-\u30FF\u4E00-\u9FFF]+")


def _normalize(text: str) -> str:
    """NFKC-normalize and strip invisible formatting characters."""
    if not text:
        return ""
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE_TABLE)


def _skeleton(text: str) -> str:
    """
    Collapse to alphanumerics (+ CJK) only, lowercase. Defeats punctuation
    / whitespace interspersion tricks like 'A-d-m-i-n---S-e-c-r-e-t'.
    """
    return _NON_ALNUM.sub("", _normalize(text)).lower()


def _secret_skeleton(secret: str) -> str:
    return _skeleton(secret)


def _decode_b64_tokens(text: str) -> list[str]:
    """Return candidate decoded strings from every base64-looking token."""
    out: list[str] = []
    for match in _B64_CANDIDATE.finditer(text):
        token = match.group(0)
        # Base64 requires length % 4 == 0 after padding; attackers often omit
        # padding, so we try adding up to 2 '=' chars.
        for pad in ("", "=", "=="):
            candidate = token + pad
            if len(candidate) % 4 != 0:
                continue
            try:
                decoded = base64.b64decode(candidate, validate=False)
            except (binascii.Error, ValueError):
                continue
            try:
                out.append(decoded.decode("utf-8", errors="ignore"))
            except Exception:
                pass
            break
    return out


def _decode_hex_tokens(text: str) -> list[str]:
    """Return candidate decoded strings from every hex-looking token."""
    out: list[str] = []
    for match in _HEX_CANDIDATE.finditer(text):
        raw = re.sub(r"[\s:\-]", "", match.group(0))
        if len(raw) % 2 != 0 or len(raw) < 8:
            continue
        try:
            decoded = bytes.fromhex(raw)
        except ValueError:
            continue
        try:
            out.append(decoded.decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return out


class OutputFilter:
    """
    DLP filter for chatbot responses with encoding-bypass hardening.

    Detection channels (reported in `leakage_channels`):
      - "regex"           — literal/regex match in the raw response
      - "normalized"      — match after NFKC + invisible-strip
      - "skeleton"        — match after punctuation/space interspersion removed
      - "reversed"        — match against the reversed skeleton
      - "base64"          — a base64 token in the response decoded to a secret
      - "hex"             — a hex token in the response decoded to a secret
    """

    def scan(self, response_text: str) -> dict:
        """
        Scan *response_text* for mock secrets across multiple encoding views.

        Returns:
            {
                "has_leakage": bool,
                "leaked_items": list[str],        # secret keys that leaked
                "leakage_channels": dict[str, list[str]],  # secret -> channels
                "original_response": str,
                "masked_response": str,
                "leakage_count": int,
            }
        """
        leaked: dict[str, set[str]] = {}
        masked = response_text or ""

        # ── View 1: regex against raw text (existing behavior) ────────────────
        for secret_key, patterns in _DETECTION_RULES:
            for pat in patterns:
                if pat.search(masked):
                    leaked.setdefault(secret_key, set()).add("regex")
                    masked = pat.sub(MASK_MAP[secret_key], masked)
                    break

        # ── View 2: regex against NFKC-normalized, invisible-stripped text ────
        normalized = _normalize(response_text or "")
        if normalized and normalized != (response_text or ""):
            for secret_key, patterns in _DETECTION_RULES:
                for pat in patterns:
                    if pat.search(normalized):
                        leaked.setdefault(secret_key, set()).add("normalized")
                        # Also mask the visible response: replace the
                        # invisible-riddled span with the mask by falling back
                        # to the skeleton replacement done below.
                        break

        # ── View 3 & 4: skeleton and reversed skeleton ────────────────────────
        skel = _skeleton(response_text or "")
        rev_skel = skel[::-1]
        for secret_key, secret_value in MOCK_SECRETS.items():
            needle = _secret_skeleton(secret_value)
            if not needle or len(needle) < 4:
                continue
            if needle in skel:
                leaked.setdefault(secret_key, set()).add("skeleton")
            if needle in rev_skel:
                leaked.setdefault(secret_key, set()).add("reversed")

        # ── View 5 & 6: base64 and hex decoded candidates ─────────────────────
        for decoded in _decode_b64_tokens(response_text or ""):
            decoded_skel = _skeleton(decoded)
            if not decoded_skel:
                continue
            for secret_key, secret_value in MOCK_SECRETS.items():
                if _secret_skeleton(secret_value) in decoded_skel:
                    leaked.setdefault(secret_key, set()).add("base64")

        for decoded in _decode_hex_tokens(response_text or ""):
            decoded_skel = _skeleton(decoded)
            if not decoded_skel:
                continue
            for secret_key, secret_value in MOCK_SECRETS.items():
                if _secret_skeleton(secret_value) in decoded_skel:
                    leaked.setdefault(secret_key, set()).add("hex")

        # ── Fail-closed: for any secret that was ONLY detected by an
        # obfuscated channel (i.e. regex never caught it and therefore never
        # masked it inline), we cannot safely redact the exact bytes — so we
        # replace the whole response with a DLP notice. Secrets that regex
        # already handled stay inline-masked so the user keeps surrounding
        # legitimate text.
        unmasked_secrets = {
            k for k, channels in leaked.items() if "regex" not in channels
        }
        if unmasked_secrets:
            triggered_channels = {
                c for k in unmasked_secrets for c in leaked[k] if c != "regex"
            }
            masks = ", ".join(sorted({MASK_MAP[k] for k in unmasked_secrets}))
            masked = (
                f"[DLP blocked response — potential leak via "
                f"{', '.join(sorted(triggered_channels))}: {masks}]"
            )

        leaked_items = sorted(leaked.keys())
        return {
            "has_leakage": len(leaked_items) > 0,
            "leaked_items": leaked_items,
            "leakage_channels": {k: sorted(v) for k, v in leaked.items()},
            "original_response": response_text,
            "masked_response": masked,
            "leakage_count": len(leaked_items),
        }
