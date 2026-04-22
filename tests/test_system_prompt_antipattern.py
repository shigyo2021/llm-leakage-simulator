"""
Tests for H1: explicit anti-pattern labeling and the safe 'secrets-isolated'
variant of the system prompt.
"""
from src.config import MOCK_SECRETS
from src.mock_chatbot import (
    build_system_prompt,
    SYSTEM_PROMPTS,
    SYSTEM_PROMPTS_NO_SECRETS,
    MockChatbot,
)


def test_default_prompt_is_labeled_as_antipattern():
    prompt = SYSTEM_PROMPTS[0]
    # Must explicitly tell readers this is the anti-pattern.
    assert "anti-pattern" in prompt.lower() or "anti" in prompt.lower()


def test_antipattern_prompt_actually_contains_secret_values():
    # This is the point of the simulator: the secret value IS in the prompt.
    prompt = SYSTEM_PROMPTS[0]
    assert MOCK_SECRETS["password"] in prompt
    assert MOCK_SECRETS["api_key"] in prompt


def test_safe_variant_does_not_leak_secret_values():
    for level in range(4):
        prompt = SYSTEM_PROMPTS_NO_SECRETS[level]
        for key, value in MOCK_SECRETS.items():
            assert value not in prompt, (
                f"secret '{key}' value leaked into the 'safe' prompt at level {level}"
            )


def test_safe_variant_still_describes_categories():
    prompt = SYSTEM_PROMPTS_NO_SECRETS[0]
    # It must still reference the data shape so the chatbot knows what it can
    # look up via tools — just not the raw values.
    assert "パスワード" in prompt
    assert "APIキー" in prompt
    assert "lookup_secret" in prompt  # hints at the correct tool-based pattern


def test_security_rule_only_applies_from_level_1():
    assert "セキュリティルール" not in build_system_prompt(0)
    assert "セキュリティルール" in build_system_prompt(1)
    assert "セキュリティルール" in build_system_prompt(3)


def test_mock_chatbot_can_opt_into_safe_variant():
    bot = MockChatbot(secrets_in_prompt=False)
    # Peek at the resolved prompt path by reusing the module-level dict.
    assert bot.secrets_in_prompt is False


def test_mock_chatbot_default_uses_antipattern():
    bot = MockChatbot()
    assert bot.secrets_in_prompt is True
