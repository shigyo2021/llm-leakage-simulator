"""
Shared attack heuristics for the simulator (H4 fix).

Before this module existed there were TWO copies of "what counts as an
attack pattern" inside the simulator:

  1. `InputFilter._FALLBACK_PATTERNS` — used when the main detector can't
     be imported, to still provide some defense.
  2. `MockChatbot._ATTACK_KEYWORDS` — used in demo mode (no API key) to
     decide whether to return the scripted "leaky" response vs the benign
     "legit" response.

Both answered the same question ("does this look adversarial?") with
different regex sets. That's the classic two-sources-of-truth bug:

  - Demo mode could claim "attack" for input that the input filter
    wouldn't block, or vice versa, making the educational story
    inconsistent.
  - Security updates to one list silently left the other stale.

This module is the single source of truth. Callers that want a richer
pipeline should still use the main MultiLayerDetector — these heuristics
are deliberately a low-recall, high-precision shortlist used only for
fallback and demo routing.
"""
from __future__ import annotations
import re
from typing import Optional

# Canonical pattern list. Ordered from most-common to least-common so the
# first match usually wins quickly; correctness doesn't depend on order.
_ATTACK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_prior_instructions_en",
        re.compile(r"ignore\s+(previous|all|prior|above)\s+instructions?", re.I)),
    ("ignore_prior_instructions_ja",
        # M2: bounded the lazy quantifier from `.*?` to `.{0,50}`. The
        # unbounded version produced O(n²) behavior on JA near-miss inputs
        # where "前の" recurred thousands of times without ever reaching the
        # terminal anchor. Real attacks place the trigger close to the prefix.
        re.compile(r"(前の|以前の|上記の|これまでの).{0,50}(指示|命令|ルール)\s*(を|は)\s*(無視|忘れ)", re.I | re.U)),
    ("role_override_en",
        re.compile(r"you\s+are\s+now\s+", re.I)),
    ("jailbreak_en",
        re.compile(r"\b(jailbreak|jail.?break|dan\s+mode)\b", re.I)),
    ("system_prompt_leak_en",
        re.compile(r"(show|reveal|print|output|display|tell)\s+(me\s+)?(your\s+|the\s+)?"
                   r"(system|initial|original)\s*prompt", re.I)),
    ("system_prompt_leak_ja",
        # Allow a short honorific bridge ("ご" / "お" / small filler) between the
        # target noun and the verb — "初期設定をご提示ください" has "ご" in front of 提示.
        re.compile(r"(システムプロンプト|初期プロンプト|初期設定)\s*(を|は)?\s*[ごお]?"
                   r"(見せ|表示|出力|教え|提示|お伝え)", re.U)),
    ("developer_mode",
        re.compile(r"(developer|debug|unrestricted|no.?filter)\s+mode", re.I)),
    ("act_as_persona",
        re.compile(r"act\s+as\s+(a|an|the)?\s*\w+", re.I)),
    ("secret_exfil_ja",
        re.compile(r"(パスワード|api\s*キー|apikey|api_key|vpn|提携先|コードネーム|売上|"
                   r"役員.*メール|機密|社内データ)", re.I | re.U)),
    ("translation_bypass",
        re.compile(r"(translate|翻訳).{0,40}(disregard|ignore|無視|指示)", re.I | re.U)),
    ("roleplay_bypass_ja",
        re.compile(r"(研修|シミュレーション|訓練).*(制限.?な|無制限|本来)", re.U)),
    ("authority_escalation",
        re.compile(r"\b(i\s+am\s+(the\s+)?(admin|administrator|developer|root)|"
                   r"sudo\b|management\s+override)\b", re.I)),
]


def looks_like_attack(text: str) -> dict:
    """
    Return a structured classification of *text*.

    Returns:
        {
            "is_attack": bool,
            "matched_pattern": str | None,   # name of the first matching rule
            "matched_regex":   str | None,   # the actual pattern for transparency
        }

    This is a cheap regex check — NOT a substitute for the main detector.
    It exists so that fallback-mode and demo-mode routing share one rule set.
    """
    if not text:
        return {"is_attack": False, "matched_pattern": None, "matched_regex": None}
    for name, pat in _ATTACK_PATTERNS:
        if pat.search(text):
            return {
                "is_attack": True,
                "matched_pattern": name,
                "matched_regex": pat.pattern,
            }
    return {"is_attack": False, "matched_pattern": None, "matched_regex": None}


def is_attack(text: str) -> bool:
    """Convenience boolean wrapper — the common case for demo-mode routing."""
    return looks_like_attack(text)["is_attack"]


def all_pattern_names() -> list[str]:
    """For tests / introspection — the canonical list of heuristic names."""
    return [name for name, _ in _ATTACK_PATTERNS]
