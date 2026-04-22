"""
Input filter: wraps the prompt-injection-detector (Week 2-3 tool).

Layer activation (C3 fix — "what actually runs at Level 2"):
  - Layer 1 (rule-based)  : always on
  - Layer 2 (ML / DeBERTa) : ON by default. Disable by setting
                             SIM_DISABLE_ML=1 (e.g. CI without the 400 MB model).
  - Layer 3 (LLM judge)   : auto — ON when ANTHROPIC_API_KEY is set, OFF otherwise.
                             Force off with SIM_DISABLE_LLM=1.

Failure policy (C5 fix — "fail closed, not fail open"):
  Previously, if the main detector failed to import or threw an exception,
  the filter silently fell through to an 8-pattern regex and reported "passed"
  for anything those 8 patterns missed. An operator deploying the simulator
  had no way to tell that Level 2 had degraded to "8 regexes and a prayer".

  The new defaults are strict:

  - If the main detector cannot be loaded AND no fallback is explicitly
    allowed, every `check()` call blocks with `blocked_reason="detector_unavailable"`.
  - If the main detector is loaded but `.scan()` raises mid-request, that
    request blocks with `blocked_reason="detector_error"` (the exception is
    recorded in `detection_details` for diagnostics — never swallowed silently).
  - The 8-pattern fallback is opt-in only, via `allow_fallback=True` or
    `SIM_ALLOW_FALLBACK=1`. When active, `detector_used="fallback"` and
    `active_layers=["fallback_rules_only"]` make the degraded mode visible.
  - The historical fail-open behavior can still be requested explicitly via
    `fail_closed=False` or `SIM_FAIL_OPEN=1` — useful for "what happens with
    no defense" demos, but never the default.

Rationale: earlier versions hard-coded enable_ml=False / enable_llm=False, which
made Level 2 silently Layer-1-only and contradicted the README. Now the defaults
reflect what an operator would deploy in production, and `active_layers` is
returned in every response so callers (and the UI) can show honestly which
layers evaluated the input.
"""
from __future__ import annotations
import os
import sys

# H4: shared attack heuristics — single source of truth for fallback-mode
# blocking (here) and demo-mode response routing (mock_chatbot).
from .attack_heuristics import looks_like_attack
from .audit_log import emit, hash_input, input_preview, monotonic_ms, new_turn_id
from .config import MAX_INPUT_CHARS


def _fallback_detect(text: str) -> dict:
    verdict = looks_like_attack(text)
    if verdict["is_attack"]:
        return {
            "passed": False,
            "blocked_reason": "fallback_rule_match",
            "detection_details": {
                "matched_pattern": verdict["matched_pattern"],
                "matched_regex":   verdict["matched_regex"],
            },
        }
    return {"passed": True, "blocked_reason": None, "detection_details": {}}


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _load_main_detector(enable_ml: bool, enable_llm: bool | None):
    """
    Try to import MultiLayerDetector from the sibling project.

    Returns ``(detector, error)``: on success ``(detector, None)``; on
    failure ``(None, "<error message>")``. We keep the error message so the
    caller can surface it — silent None-return was the old fail-open bug.
    """
    detector_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__),
                     "..", "..", "prompt-injection-detector")
    )
    if detector_dir not in sys.path:
        sys.path.insert(0, detector_dir)
    try:
        from src.multi_layer_detector import MultiLayerDetector   # type: ignore
        return MultiLayerDetector(enable_ml=enable_ml, enable_llm=enable_llm), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


class InputFilter:
    """
    Wraps the prompt-injection-detector.

    Args:
        enable_ml:       Override Layer 2 activation. Default: follow env
                         (SIM_DISABLE_ML=1 disables; otherwise ON).
        enable_llm:      Override Layer 3 activation. Default: follow env + API key
                         (SIM_DISABLE_LLM=1 disables; otherwise auto-detect via
                         ANTHROPIC_API_KEY inside MultiLayerDetector).
        fail_closed:     If True (default), detection failures / unavailability
                         BLOCK the input. If False, they fall through as passed.
                         Can also be flipped via SIM_FAIL_OPEN=1.
        allow_fallback:  If True, use the 8-pattern regex fallback when the
                         main detector can't load. If False (default), an
                         unloadable detector causes every request to block
                         (when fail_closed) or pass (when not).
                         Can also be enabled via SIM_ALLOW_FALLBACK=1.
    """

    def __init__(
        self,
        enable_ml: bool | None = None,
        enable_llm: bool | None = None,
        fail_closed: bool | None = None,
        allow_fallback: bool | None = None,
    ) -> None:
        # Defaults honor environment flags so CI / demo mode can opt out of
        # the 400 MB model download or API cost without code changes.
        if enable_ml is None:
            enable_ml = not _env_flag("SIM_DISABLE_ML")
        if enable_llm is None and _env_flag("SIM_DISABLE_LLM"):
            enable_llm = False
        # If enable_llm stays None, MultiLayerDetector auto-detects via API key.

        if fail_closed is None:
            fail_closed = not _env_flag("SIM_FAIL_OPEN")
        if allow_fallback is None:
            allow_fallback = _env_flag("SIM_ALLOW_FALLBACK")

        self._requested_ml = enable_ml
        self._requested_llm = enable_llm
        self.fail_closed = fail_closed
        self.allow_fallback = allow_fallback

        self._detector, self._load_error = _load_main_detector(
            enable_ml=enable_ml, enable_llm=enable_llm
        )
        self.using_main_detector = self._detector is not None

        # Record exactly which layers will run — single source of truth for
        # the UI and for honest reporting.
        if self._detector is not None:
            self.active_layers = ["rule_based"]
            if getattr(self._detector, "enable_ml", False):
                self.active_layers.append("ml_model")
            if getattr(self._detector, "enable_llm", False):
                self.active_layers.append("llm_judge")
        elif self.allow_fallback:
            self.active_layers = ["fallback_rules_only"]
        else:
            # Detector unavailable AND fallback not allowed: no layer will run.
            # check() will enforce fail_closed behavior.
            self.active_layers = []

    # ── internals ─────────────────────────────────────────────────────────────

    def _unavailable_response(self) -> dict:
        """Response when no detector could evaluate the input."""
        reason_detail = self._load_error or "main detector unavailable"
        if self.fail_closed:
            return {
                "passed": False,
                "blocked_reason": "detector_unavailable",
                "detection_details": {
                    "error": reason_detail,
                    "policy": "fail_closed",
                    "hint": "Install prompt-injection-detector, or set "
                            "SIM_ALLOW_FALLBACK=1 for the 8-pattern fallback, "
                            "or SIM_FAIL_OPEN=1 to disable blocking (unsafe).",
                },
                "detector_used": "none",
                "active_layers": self.active_layers,
            }
        # fail_open — legacy unsafe path, explicitly requested
        return {
            "passed": True,
            "blocked_reason": None,
            "detection_details": {
                "error": reason_detail,
                "policy": "fail_open",
                "warning": "detector unavailable — input NOT evaluated",
            },
            "detector_used": "none",
            "active_layers": self.active_layers,
        }

    # ── public API ────────────────────────────────────────────────────────────

    def check(self, text: str) -> dict:
        """
        Returns:
            {
                "passed": bool,
                "blocked_reason": str | None,
                "detection_details": dict,
                "detector_used": "main" | "fallback" | "none",
                "active_layers": list[str],   # which layers actually evaluated
            }

        Failure modes (see module docstring for full policy):
          - detector failed to import and fallback disabled → blocked
            ("detector_unavailable") if fail_closed, else passed with warning
          - detector.scan() raised mid-request → blocked ("detector_error")
            if fail_closed, else passed with warning
          - fallback active → reported as detector_used="fallback"
          - input over MAX_INPUT_CHARS → blocked as "input_too_large" before
            any detector path runs (M1: DoS / API-cost gate)

        Emits an `input_filter` audit event per call (M3). Off by default;
        enable with SIM_AUDIT_LOG=1.
        """
        # M3: one turn-id per check() so an analyst can follow the decision
        # through its nested events (filter, chatbot, output DLP).
        turn_id = new_turn_id()
        t_start = monotonic_ms()

        result = self._check_inner(text)
        _emit_input_filter_event(turn_id, text, result, monotonic_ms() - t_start)
        # Include turn_id in the response so the SimulatorEngine (or any
        # caller) can thread it through the rest of the pipeline.
        result["turn_id"] = turn_id
        return result

    def _check_inner(self, text: str) -> dict:
        # ── M1: size gate (runs before detector path) ───────────────────────
        # Fail fast on oversize inputs so neither the main detector nor the
        # fallback regex backtracking burns CPU / API credit on them.
        if text is not None and len(text) > MAX_INPUT_CHARS:
            return {
                "passed": False,
                "blocked_reason": "input_too_large",
                "detection_details": {
                    "input_length": len(text),
                    "limit": MAX_INPUT_CHARS,
                    "policy": "size_gate",
                },
                "detector_used": "size_gate",
                "active_layers": ["input_size_guard"],
            }

        if self._detector is not None:
            try:
                result = self._detector.scan(text)
            except Exception as exc:
                # Layer crashed on this input. Never silently pass — surface it.
                err = f"{type(exc).__name__}: {exc}"
                if self.fail_closed:
                    return {
                        "passed": False,
                        "blocked_reason": "detector_error",
                        "detection_details": {"error": err, "policy": "fail_closed"},
                        "detector_used": "main",
                        "active_layers": self.active_layers,
                    }
                return {
                    "passed": True,
                    "blocked_reason": None,
                    "detection_details": {
                        "error": err,
                        "policy": "fail_open",
                        "warning": "detector raised — input NOT evaluated",
                    },
                    "detector_used": "main",
                    "active_layers": self.active_layers,
                }

            passed = result["final_verdict"] == "PASSED"
            return {
                "passed": passed,
                "blocked_reason": result.get("blocked_by") if not passed else None,
                "detection_details": result,
                "detector_used": "main",
                "active_layers": self.active_layers,
            }

        # Main detector unavailable.
        if self.allow_fallback:
            result = _fallback_detect(text)
            result["detector_used"] = "fallback"
            result["active_layers"] = self.active_layers
            return result

        # No detector and no fallback → fail_closed (block) or fail_open (pass).
        return self._unavailable_response()


def _emit_input_filter_event(
    turn_id: str, text: str, result: dict, latency_ms: float
) -> None:
    """
    Emit one `input_filter` audit event. Extracted to a module-level helper
    so the check() path stays readable and the payload shape lives in one
    place. No-op when SIM_AUDIT_LOG is unset — `emit()` short-circuits.
    """
    emit("input_filter", {
        "turn_id": turn_id,
        "passed": result.get("passed"),
        "blocked_reason": result.get("blocked_reason"),
        "detector_used": result.get("detector_used"),
        "active_layers": result.get("active_layers", []),
        "input_hash": hash_input(text),
        "input_length": len(text) if text is not None else 0,
        "input_preview": input_preview(text),
        "latency_ms": round(latency_ms, 3),
    })
