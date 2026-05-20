# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the Streamlit UI
streamlit run app.py

# Run all tests (no API key required — 102 passed, 4 skipped)
pytest tests/ -v

# Run a single test file
pytest tests/test_output_filter.py -v
```

All tests pass without any API key. The ML model (DeBERTa, ~400 MB) is not required — set `SIM_DISABLE_ML=1` to skip it.

## Architecture

The simulator demonstrates layered LLM defenses by running attacks through a pipeline at increasing defense levels (0–3):

```
User Input
  │
  ▼ (Level 2+)
[InputFilter] ──blocked──→ "[入力フィルタによりブロックされました]"
  │ passed
  ▼
[MockChatbot]  ← system prompt with fake secrets + (Level 1+) security rule
  │
  ▼ (Level 3)
[OutputFilter / DLP] → mask any secrets that slipped through
  │
  ▼
SimulatorEngine.run() result dict → LeakageAnalyzer.analyze()
```

**`SimulatorEngine`** (`src/simulator_engine.py`) is the single entry point — `engine.run(user_input, defense_level)` returns a result dict. It never returns the raw `user_input`; only `input_hash`, `input_length`, and `input_preview` (a redacted, bounded string) are returned. All components are instantiated once per `SimulatorEngine`.

**`MockChatbot`** (`src/mock_chatbot.py`) intentionally embeds fake secrets in its system prompt — this is the anti-pattern the simulator exists to demonstrate. In demo mode (no API key) it returns scripted responses. When an API key is valid, it calls Anthropic (`claude-haiku-4-5`) or OpenAI (`gpt-4o-mini`) directly. API keys are never written to `os.environ`.

**`InputFilter`** (`src/input_filter.py`) wraps the sibling project `prompt-injection-detector`, expected at `../../prompt-injection-detector`. When that project is not importable:
- Default (`fail_closed=True`): every `check()` call blocks with `blocked_reason="detector_unavailable"`.
- `allow_fallback=True` (or `SIM_ALLOW_FALLBACK=1`): falls back to the 8-pattern regex in `attack_heuristics.py`.
- `SimulatorEngine` explicitly constructs `InputFilter(allow_fallback=True)` for demo-mode resilience.

The filter checks `active_layers` in every response so callers can always see which layers actually evaluated the input (rule-based, ml_model, llm_judge, or fallback_rules_only).

**`OutputFilter`** (`src/output_filter.py`) scans responses across 6 encoding views: raw regex, NFKC-normalized, skeleton (alphanumerics only), reversed skeleton, base64-decoded tokens, and hex-decoded tokens. If a secret is detected by only a non-regex channel (i.e. inline masking can't safely redact it), the entire response is replaced with a DLP notice (fail-closed).

**`attack_heuristics.py`** is the single source of truth for "does this look adversarial?" used by both `InputFilter` (fallback path) and `MockChatbot` (demo-mode routing). The two were separate before H4 and drifted. Do not duplicate this logic.

**`config.py`** is the central configuration file. All fake secrets (`MOCK_SECRETS`), mask strings (`MASK_MAP`), defense level metadata (`DEFENSE_LEVELS`), provider/model settings (`PROVIDERS`), and `MAX_INPUT_CHARS` (10 000) live here.

**`audit_log.py`** emits structured JSON events (`simulator_turn`, `input_filter`) per run. Off by default; enable with `SIM_AUDIT_LOG=1`. Route to a file with `SIM_AUDIT_LOG_PATH=<path>`. Raw input is never logged — only hash, length, and a redacted preview.

## Key environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SIM_DISABLE_ML=1` | off | Skip DeBERTa ML layer (avoids 400 MB download) |
| `SIM_DISABLE_LLM=1` | off | Force-disable LLM-as-Judge layer |
| `SIM_ALLOW_FALLBACK=1` | off | Use 8-pattern regex when main detector unavailable |
| `SIM_FAIL_OPEN=1` | off | Legacy: pass inputs when detector unavailable (unsafe) |
| `SIM_AUDIT_LOG=1` | off | Enable structured JSON audit logging |
| `SIM_AUDIT_LOG_PATH=<path>` | stderr | Write audit events to a file |
| `ANTHROPIC_API_KEY` | — | Optional; demo mode works without it |
| `OPENAI_API_KEY` | — | Optional; demo mode works without it |

## Security invariants

These invariants are enforced by tests and must not be broken:

1. **No raw input echoed** (M5): `SimulatorEngine.run()` result must contain `input_hash`, `input_length`, `input_preview` — never a `"input"` key with the raw string. Tests: `test_raw_input_not_returned.py`.

2. **Fail closed** (C5): `InputFilter` with default settings blocks all input when the detector is unavailable. `fail_closed=False` must be explicit and intentional. Tests: `test_input_filter.py`.

3. **Size gate before detector** (M1): inputs over `MAX_INPUT_CHARS` block with `blocked_reason="input_too_large"` before the detector or fallback regex runs. Tests: `test_input_size_guard.py`.

4. **Single attack heuristic source** (H4): `attack_heuristics.py` is the only place where the regex patterns live. `InputFilter` fallback and `MockChatbot` demo routing must both use it. Tests: `test_attack_heuristics.py`.

5. **API keys never in os.environ** (H2): `MockChatbot` accepts `api_key` as a constructor argument and stores it in-memory only. `app.py` must not call `os.environ.__setitem__` with key values.

6. **Active layers always reported** (C3): `InputFilter.check()` always returns `active_layers` in its response. Tests: `test_input_filter.py`.
