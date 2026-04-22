"""
API-key handling utilities for the simulator (H2 fix).

Standalone copy of the detector's validator/redactor — keeping the simulator
independently importable. Kept in sync by convention.
"""
from __future__ import annotations

import os
import re


_KEY_PREFIXES = {
    "anthropic": ("sk-ant-",),
    "openai":    ("sk-", "sk-proj-"),
}

_MIN_KEY_LEN = 20


def validate_api_key(key: str | None, provider: str = "anthropic") -> tuple[bool, str]:
    if not key:
        return False, "API key is empty"
    key = key.strip()
    if len(key) < _MIN_KEY_LEN:
        return False, f"API key is too short (< {_MIN_KEY_LEN} chars)"
    prefixes = _KEY_PREFIXES.get(provider, ())
    if prefixes and not key.startswith(prefixes):
        return False, (
            f"API key does not match expected prefix for {provider!r}: {prefixes}"
        )
    if any(c.isspace() for c in key) or not key.isprintable():
        return False, "API key contains whitespace or non-printable characters"
    return True, "ok"


def resolve_api_key(
    explicit: str | None,
    env_var: str,
    *,
    provider: str = "anthropic",
    validate: bool = True,
) -> str | None:
    """Preference: explicit > env var. Invalid-shape keys → None."""
    candidate = (explicit or "").strip() or os.environ.get(env_var, "").strip()
    if not candidate:
        return None
    if validate:
        ok, _ = validate_api_key(candidate, provider=provider)
        if not ok:
            return None
    return candidate


_KEY_TOKEN = re.compile(r"sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{8,200}")


def redact_secrets(text: str) -> str:
    """Replace anything that looks like an API key with sk-***REDACTED***."""
    if not text:
        return text
    return _KEY_TOKEN.sub("sk-***REDACTED***", str(text))
