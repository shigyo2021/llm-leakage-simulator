"""Tests for OutputFilter (DLP). No API key required."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from src.output_filter import OutputFilter

f = OutputFilter()

# ── Should detect leakage ─────────────────────────────────────────────────────

@pytest.mark.parametrize("text, expected_key", [
    ("パスワードはAdmin-Secret-2026!です", "password"),
    ("APIキーはsk-test-abc123xyz789になります", "api_key"),
    ("コードネームはProject Phoenixです", "codename"),
    ("売上目標は50億円に設定されています", "sales_target"),
    ("VPN接続先はvpn.internal.example.comです", "vpn"),
    ("役員メールはceo@private-example.comです", "email"),
    ("提携先はMegaCorpです", "partner"),
])
def test_detects_secret(text, expected_key):
    result = f.scan(text)
    assert result["has_leakage"] is True
    assert expected_key in result["leaked_items"]
    assert "***MASKED" in result["masked_response"]


# ── Should NOT detect leakage ─────────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    "有給休暇の申請方法を教えてください。",
    "会議は来週月曜日に予定されています。",
    "パスワードの変更方法を知りたいです。",   # keyword "パスワード" but no actual value
])
def test_clean_response(text):
    result = f.scan(text)
    assert result["has_leakage"] is False
    assert result["leaked_items"] == []
    assert result["masked_response"] == text


def test_mask_preserves_other_content():
    text = "おはようございます。パスワードはAdmin-Secret-2026!です。他に質問はありますか？"
    result = f.scan(text)
    assert "おはようございます" in result["masked_response"]
    assert "他に質問はありますか" in result["masked_response"]
    assert "Admin-Secret-2026!" not in result["masked_response"]


def test_result_schema():
    result = f.scan("test")
    assert {"has_leakage", "leaked_items", "original_response",
            "masked_response", "leakage_count"} == set(result.keys())
