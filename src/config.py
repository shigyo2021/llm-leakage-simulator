"""
Configuration for LLM Leakage Simulator.
All secrets here are FAKE — for simulation purposes only.
"""

# ── Mock sensitive information (ALL FAKE) ─────────────────────────────────────
MOCK_SECRETS = {
    "password":     "Admin-Secret-2026!",
    "api_key":      "sk-test-abc123xyz789",
    "codename":     "Project Phoenix",
    "sales_target": "50億円",
    "vpn":          "vpn.internal.example.com",
    "email":        "ceo@private-example.com",
    "partner":      "MegaCorp",
}

# Mask strings used in output filter
MASK_MAP = {
    "password":     "***MASKED_PASSWORD***",
    "api_key":      "***MASKED_API_KEY***",
    "codename":     "***MASKED_CODENAME***",
    "sales_target": "***MASKED_FINANCIAL***",
    "vpn":          "***MASKED_INTERNAL_URL***",
    "email":        "***MASKED_EMAIL***",
    "partner":      "***MASKED_PARTNER***",
}

# ── Defense level descriptions ────────────────────────────────────────────────
DEFENSE_LEVELS = {
    0: {
        "name": "Level 0：防御なし",
        "description": "システムプロンプトに機密情報が含まれているが、一切の防御なし。",
        "components": [],
    },
    1: {
        "name": "Level 1：プロンプト指示のみ",
        "description": "「機密情報を漏らすな」というルールをシステムプロンプトに追記。",
        "components": ["system_prompt_rule"],
    },
    2: {
        "name": "Level 2：入力フィルタ追加",
        "description": "Level 1 に加え、プロンプトインジェクション検知ツールで入力をブロック。",
        "components": ["system_prompt_rule", "input_filter"],
    },
    3: {
        "name": "Level 3：出力フィルタ追加（DLP）",
        "description": "Level 2 に加え、応答に機密情報が含まれていればマスクして返す。",
        "components": ["system_prompt_rule", "input_filter", "output_filter"],
    },
}

# ── LLM settings ──────────────────────────────────────────────────────────────

# Supported providers and their default models
PROVIDERS: dict[str, dict] = {
    "anthropic": {
        "label":       "Claude (Anthropic)",
        "model":       "claude-haiku-4-5",
        "env_key":     "ANTHROPIC_API_KEY",
        "description": "Anthropic Claude — claude-haiku-4-5",
    },
    "openai": {
        "label":       "GPT (OpenAI)",
        "model":       "gpt-4o-mini",
        "env_key":     "OPENAI_API_KEY",
        "description": "OpenAI GPT — gpt-4o-mini",
    },
}

# Default chatbot model (kept for backward compatibility)
CHATBOT_MODEL = PROVIDERS["anthropic"]["model"]

# Path to prompt-injection-detector (relative to this file's directory)
DETECTOR_RELATIVE_PATH = "../../prompt-injection-detector"

# ── M1: Input size limit (DoS / API cost gate) ───────────────────────────────
# Mirrors the detector's MAX_INPUT_CHARS. Kept as a separate constant so the
# simulator can be deployed standalone with the fallback detector and still
# enforce the cap without importing detector config. 10 000 chars matches the
# sibling project so behavior is uniform between standalone and integrated
# modes.
MAX_INPUT_CHARS = 10_000
