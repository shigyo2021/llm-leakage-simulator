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

    def __init__(self, provider: str = "anthropic", model: str | None = None) -> None:
        self.provider = provider
        self._chatbot = MockChatbot(provider=provider, model=model)
        self._input_filter = InputFilter()
        self._output_filter = OutputFilter()

    def run(self, user_input: str, defense_level: int) -> dict:
        """
        Simulate one attack attempt at *defense_level*.

        Returns:
            {
                "input": str,
                "defense_level": int,
                "steps": list[dict],
                "final_response": str,
                "leakage_detected": bool,
                "leaked_items": list[str],
                "blocked_at": str | None
            }
        """
        steps: list[dict] = []
        blocked_at: Optional[str] = None
        chatbot_response: Optional[str] = None
        output_scan: Optional[dict] = None

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
                return _build_result(
                    user_input, defense_level, steps,
                    response="[入力フィルタによりブロックされました]",
                    leakage_detected=False,
                    leaked_items=[],
                    blocked_at=blocked_at,
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

        return _build_result(
            user_input, defense_level, steps,
            response=final_response,
            leakage_detected=leakage_detected,
            leaked_items=leaked_items,
            blocked_at=blocked_at,
        )


def _build_result(
    user_input: str,
    defense_level: int,
    steps: list[dict],
    response: str,
    leakage_detected: bool,
    leaked_items: list[str],
    blocked_at: Optional[str],
) -> dict:
    return {
        "input": user_input,
        "defense_level": defense_level,
        "steps": steps,
        "final_response": response,
        "leakage_detected": leakage_detected,
        "leaked_items": leaked_items,
        "blocked_at": blocked_at,
    }
