"""
M2: ReDoS regression for the simulator's attack_heuristics fallback set.

The sibling detector has its own suite; this one covers the 12 regexes in
`src/attack_heuristics.py` that are used as the fail-closed-but-fallback
last line of defense when the main detector can't load. That fallback is
the single path still exposed when the main import fails, so it's exactly
where a regex engine freeze would bite hardest.
"""
from __future__ import annotations

import re
import time

import pytest

from src.attack_heuristics import _ATTACK_PATTERNS
from src.config import MAX_INPUT_CHARS


PER_PROBE_BUDGET_SEC = 0.1


def _adversarial_corpus() -> list[tuple[str, str]]:
    n = MAX_INPUT_CHARS
    return [
        ("all_a",          "a" * n),
        ("all_space",      " " * n),
        ("near_miss_en",   ("ignore previous " * (n // 17))[:n]),
        ("near_miss_ja",   ("前の指示を" * (n // 5))[:n]),
        ("translate_bait", ("translate " + " " * 50) * (n // 61))[:n],
        ("act_as_probe",   ("act as the " * (n // 11))[:n]),
        ("show_prompt",    ("show me your " * (n // 14))[:n]),
        ("jpn_secret_run", ("パスワード" * (n // 5))[:n]),
    ]


@pytest.mark.parametrize(
    "entry",
    _ATTACK_PATTERNS,
    ids=[name for name, _ in _ATTACK_PATTERNS],
)
def test_heuristic_pattern_has_no_redos(entry):
    name, regex = entry
    for label, text in _adversarial_corpus():
        t0 = time.perf_counter()
        regex.search(text)
        elapsed = time.perf_counter() - t0
        assert elapsed < PER_PROBE_BUDGET_SEC, (
            f"Heuristic {name!r} took {elapsed*1000:.1f} ms on {label!r} "
            f"({len(text)} chars). Rewrite to remove backtracking."
        )


def test_heuristic_names_unique():
    names = [n for n, _ in _ATTACK_PATTERNS]
    assert len(names) == len(set(names))
