"""
SimulatorEngine: orchestrates all components based on defense_level.

Defense levels:
  0 → No defense
  1 → System prompt rule only
  2 → System prompt rule + input filter
  3 → System prompt rule + input filter + output filter (DLP)
"""
from __future__ import annotations
from typing import Optional

from .audit_log import emit, hash_input, input_preview, monotonic_ms, new_turn_id
from .mock_chatbot import MockChatbot
from .input_filter import InputFilter
from .output_filter import OutputFilter


class SimulatorEngine:
    """
    Runs a single turn of the attack simulation at the specified defense level.

    Args:
        provider: "anthropic" (Claude) or "openai" (GPT)
        model:    Override the default model for the provider.
    """

    def __init__(
        self,
        provider: str = "anthropic",
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        """
        Args:
            provider: "anthropic" or "openai".
            model:    Override the default model.
            api_key:  Explicit API key for the chatbot's provider. Passed
                      straight through to MockChatbot — never written to
                      os.environ. When None, the matching env var is read.
        """
        self.provider = provider
        self._chatbot = MockChatbot(provider=provider, model=model, api_key=api_key)
        # The demo must still run when the sibling detector isn't installed,
        # so we opt into the 8-pattern fallback here. Fallback mode is
        # visibly reported (detector_used="fallback", active_layers shows it)
        # so the degraded state is never hidden — that was the original C5 bug.
        # Production embedders of InputFilter keep the safer fail_closed default.
        self._input_filter = InputFilter(allow_fallback=True)
        self._output_filter = OutputFilter()

    def run(self, user_input: str, defense_level: int) -> dict:
        """
        Simulate one attack attempt at *defense_level*.

        Returns:
            {
                "input_hash":    str,   # SHA-256 prefix (M5: no raw input)
                "input_length":  int,
                "input_preview": str,   # redacted + bounded (M5)
                "defense_level": int,
                "steps":         list[dict],
                "final_response": str,
                "leakage_detected": bool,
                "leaked_items":  list[str],
                "blocked_at":    str | None,
                "turn_id":       str,
            }
        """
        steps: list[dict] = []
        blocked_at: Optional[str] = None
        chatbot_response: Optional[str] = None
        output_scan: Optional[dict] = None

        # M3: one turn_id spans the whole run() so input_filter, chatbot, and
        # output_filter events can be correlated to a single user turn.
        turn_id = new_turn_id()
        t_start = monotonic_ms()

        # ── Level 2 & 3: Input filter ─────────────────────────────────────────
        if defense_level >= 2:
            filter_result = self._input_filter.check(user_input)
            steps.append({
                "step": "input_filter",
                "result": "blocked" if not filter_result["passed"] else "passed",
                "detail": filter_result,
            })
            if not filter_result["passed"]:
                blocked_at = "input_filter"
                _emit_simulator_turn_event(
                    turn_id=turn_id,
                    user_input=user_input,
                    defense_level=defense_level,
                    blocked_at=blocked_at,
                    leakage_detected=False,
                    leaked_items=[],
                    latency_ms=monotonic_ms() - t_start,
                )
                return _build_result(
                    user_input, defense_level, steps,
                    response="[入力フィルタによりブロックされました]",
                    leakage_detected=False,
                    leaked_items=[],
                    blocked_at=blocked_at,
                    turn_id=turn_id,
                )

        # ── All levels: Chatbot ───────────────────────────────────────────────
        chatbot_result = self._chatbot.chat(user_input, defense_level)
        chatbot_response = chatbot_result["response"]
        steps.append({
            "step": "chatbot",
            "result": "responded",
            "detail": {
                "response_preview": chatbot_response[:200],
                "defense_level": defense_level,
            },
        })

        # ── Level 3: Output filter (DLP) ──────────────────────────────────────
        if defense_level >= 3:
            output_scan = self._output_filter.scan(chatbot_response)
            steps.append({
                "step": "output_filter",
                "result": "leakage_masked" if output_scan["has_leakage"] else "clean",
                "detail": output_scan,
            })
            final_response = output_scan["masked_response"]
        else:
            # Still scan for analysis, but don't modify the response
            output_scan = self._output_filter.scan(chatbot_response)
            final_response = chatbot_response

        # ── Leakage analysis ──────────────────────────────────────────────────
        leakage_detected = output_scan["has_leakage"] if output_scan else False
        leaked_items = output_scan["leaked_items"] if output_scan else []

        # At Level 3, output filter masked the response → user doesn't see raw leak
        # But we still record that the chatbot internally leaked (for analysis)
        if defense_level >= 3 and leakage_detected:
            blocked_at = "output_filter"

        steps.append({
            "step": "leakage_analysis",
            "result": "leaked" if leakage_detected else "clean",
            "detail": {
                "leaked_items": leaked_items,
                "leakage_count": len(leaked_items),
            },
        })

        _emit_simulator_turn_event(
            turn_id=turn_id,
            user_input=user_input,
            defense_level=defense_level,
            blocked_at=blocked_at,
            leakage_detected=leakage_detected,
            leaked_items=leaked_items,
            latency_ms=monotonic_ms() - t_start,
        )
        return _build_result(
            user_input, defense_level, steps,
            response=final_response,
            leakage_detected=leakage_detected,
            leaked_items=leaked_items,
            blocked_at=blocked_at,
            turn_id=turn_id,
        )


def _build_result(
    user_input: str,
    defense_level: int,
    steps: list[dict],
    response: str,
    leakage_detected: bool,
    leaked_items: list[str],
    blocked_at: Optional[str],
    turn_id: Optional[str] = None,
) -> dict:
    # M5: never return the raw attacker-controlled user_input. Downstream
    # sinks (Streamlit session state, batch CSVs, test fixtures, analytics
    # dashboards) would each become a secondary leakage channel for the
    # very payloads this simulator exists to exercise. Hash correlates
    # repeat attempts; preview is redacted + bounded for operator debug.
    result = {
        "input_hash":    hash_input(user_input),
        "input_length":  len(user_input) if user_input is not None else 0,
        "input_preview": input_preview(user_input),
        "defense_level": defense_level,
        "steps":         steps,
        "final_response": response,
        "leakage_detected": leakage_detected,
        "leaked_items":  leaked_items,
        "blocked_at":    blocked_at,
    }
    if turn_id is not None:
        # M3: exposed so callers can correlate UI / API responses with log lines.
        result["turn_id"] = turn_id
    return result


def _emit_simulator_turn_event(
    *,
    turn_id: str,
    user_input: str,
    defense_level: int,
    blocked_at: Optional[str],
    leakage_detected: bool,
    leaked_items: list[str],
    latency_ms: float,
) -> None:
    """
    Emit one `simulator_turn` audit event per SimulatorEngine.run().

    No-op when SIM_AUDIT_LOG is unset — `emit()` short-circuits on the
    disabled logger. Leaked-item names (pattern labels like "api_key") are
    safe to log; the matched values themselves never leave output_filter.
    """
    emit("simulator_turn", {
        "turn_id": turn_id,
        "defense_level": defense_level,
        "blocked_at": blocked_at,
        "leakage_detected": leakage_detected,
        "leaked_items": leaked_items,
        "leakage_count": len(leaked_items),
        "input_hash": hash_input(user_input),
        "input_length": len(user_input) if user_input is not None else 0,
        "input_preview": input_preview(user_input),
        "latency_ms": round(latency_ms, 3),
    })
