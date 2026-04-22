"""
M4: guard the pinning policy (simulator).

See prompt-injection-detector/tests/test_requirements_pinning.py for the
full rationale. Same policy applies here: both bounds required.
"""
from __future__ import annotations

import os
import re


REQ_PATH = os.path.join(os.path.dirname(__file__), "..", "requirements.txt")

_HAS_LOWER = re.compile(r">=?\s*\d")
_HAS_UPPER = re.compile(r"<=?\s*\d")


def _iter_requirement_lines():
    with open(REQ_PATH, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            yield line


def test_every_requirement_has_lower_and_upper_bound():
    offenders = []
    for line in _iter_requirement_lines():
        spec = line.split("#", 1)[0].strip()
        if not _HAS_LOWER.search(spec) or not _HAS_UPPER.search(spec):
            offenders.append(line)
    assert not offenders, (
        "Every requirement must have both a lower (>=) and upper (<) bound. "
        f"Unbounded lines: {offenders}"
    )


def test_requirements_file_exists_and_nonempty():
    assert os.path.exists(REQ_PATH)
    assert any(True for _ in _iter_requirement_lines())
