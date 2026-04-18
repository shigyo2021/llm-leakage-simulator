"""
Input filter: wraps the prompt-injection-detector (Week 2-3 tool).
Falls back to a lightweight rule-based filter if the detector is unavailable.
"""
from __future__ import annotations
import os
import sys
import re

# ── Fallback patterns (subset of the main detector) ───────────────────────────
_FALLBACK_PATTERNS = [
    re.compile(r"ignore\s+(previous|all|prior|above)\s+instructions?", re.I),
    re.compile(r"(前の|以前の|上記の).*?(指示|命令)\s*(を|は)\s*(無視|忘れ)", re.I | re.U),
    re.compile(r"you\s+are\s+now\s+", re.I),
    re.compile(r"\bjailbreak\b", re.I),
    re.compile(r"show\s+(me\s+)?your\s+system\s+prompt", re.I),
    re.compile(r"(システムプロンプト|初期プロンプト)\s*(を|は)\s*(見せ|表示|出力|教え)", re.U),
    re.compile(r"developer\s+mode", re.I),
    re.compile(r"act\s+as\s+(a|an|the)?\s*\w+", re.I),
]


def _fallback_detect(text: str) -> dict:
    for pat in _FALLBACK_PATTERNS:
        if pat.search(text):
            return {"passed": False, "blocked_reason": "fallback_rule_match",
                    "detection_details": {"matched": pat.pattern}}
    return {"passed": True, "blocked_reason": None, "detection_details": {}}


def _load_main_detector():
    """Try to import MultiLayerDetector from the sibling project."""
    detector_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__),
                     "..", "..", "prompt-injection-detector")
    )
    if detector_dir not in sys.path:
        sys.path.insert(0, detector_dir)
    try:
        from src.multi_layer_detector import MultiLayerDetector   # type: ignore
        return MultiLayerDetector(enable_ml=False, enable_llm=False)
    except Exception:
        return None


class InputFilter:
    """
    Wraps the prompt-injection-detector.
    Uses the full multi-layer detector when available, otherwise falls back.
    """

    def __init__(self) -> None:
        self._detector = _load_main_detector()
        self.using_main_detector = self._detector is not None

    def check(self, text: str) -> dict:
        """
        Returns:
            {
                "passed": bool,
                "blocked_reason": str | None,
                "detection_details": dict,
                "detector_used": "main" | "fallback"
            }
        """
        if self._detector is not None:
            result = self._detector.scan(text)
            passed = result["final_verdict"] == "PASSED"
            return {
                "passed": passed,
                "blocked_reason": result.get("blocked_by") if not passed else None,
                "detection_details": result,
                "detector_used": "main",
            }
        else:
            result = _fallback_detect(text)
            result["detector_used"] = "fallback"
            return result
