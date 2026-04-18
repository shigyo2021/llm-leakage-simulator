"""
LLM Leakage Simulator — Streamlit UI
・対話テスト（モデル選択可）
・モデル比較バッチテスト（Claude vs GPT 漏洩率グラフ）
・アーキテクチャ解説

Run: streamlit run app.py
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st
import pandas as pd
from src.simulator_engine import SimulatorEngine
from src.leakage_analyzer import LeakageAnalyzer
from src.config import DEFENSE_LEVELS, MOCK_SECRETS, PROVIDERS

st.set_page_config(
    page_title="LLM情報漏洩シミュレーター",
    page_icon="🔓",
    layout="wide",
)

# ── Sample data ────────────────────────────────────────────────────────────────
@st.cache_data
def load_samples():
    path = os.path.join(os.path.dirname(__file__), "sample_attacks.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)

SAMPLES       = load_samples()
ATTACK_SAMPLES = [s for s in SAMPLES if s["attack_type"] is not None]
LEGIT_SAMPLES  = [s for s in SAMPLES if s["attack_type"] is None]

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ API キー設定")

    anthropic_key = st.text_input(
        "🟠 Anthropic API キー（Claude用）",
        type="password", placeholder="sk-ant-...",
    )
    # 入力欄が空になったら env も削除（ブラウザリロード対応）
    if anthropic_key:
        os.environ["ANTHROPIC_API_KEY"] = anthropic_key
    else:
        os.environ.pop("ANTHROPIC_API_KEY", None)

    openai_key = st.text_input(
        "🟢 OpenAI API キー（GPT用）",
        type="password", placeholder="sk-...",
    )
    if openai_key:
        os.environ["OPENAI_API_KEY"] = openai_key
    else:
        os.environ.pop("OPENAI_API_KEY", None)

    st.divider()

    # 接続状態は「入力欄に値があるか」で判定（env ではなく widget 値を正とする）
    claude_ok = bool(anthropic_key)
    gpt_ok    = bool(openai_key)
    st.caption("**接続状態**")
    st.markdown(f"{'✅' if claude_ok else '❌'} Claude (Anthropic)")
    st.markdown(f"{'✅' if gpt_ok    else '❌'} GPT (OpenAI)")

    st.divider()
    if not claude_ok and not gpt_ok:
        st.info(
            "**📋 デモモード**\n\n"
            "APIキーなしでも動作します。\n"
            "Level 0 の攻撃では機密情報を含む"
            "**模擬応答**が返り、漏洩検知が確認できます。\n\n"
            "実際のLLM挙動を見るには上のAPIキーを設定してください。",
            icon="ℹ️",
        )

    st.divider()
    st.subheader("🗝️ 模擬機密情報（偽物）")
    st.caption("チャットボットのシステムプロンプトに仕込んである偽の機密情報です。")
    for k, v in MOCK_SECRETS.items():
        st.code(f"{k}: {v}", language=None)

# ── Cached engines (one per provider) ─────────────────────────────────────────
@st.cache_resource
def get_engine(provider: str) -> SimulatorEngine:
    return SimulatorEngine(provider=provider)

analyzer = LeakageAnalyzer()

# ── Tabs ───────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs([
    "🔍 対話テスト",
    "📊 モデル比較バッチテスト",
    "📐 アーキテクチャ解説",
])

# ════════════════════════════════════════════════════════════════════════════════
# TAB 1 — Interactive test
# ════════════════════════════════════════════════════════════════════════════════
with tab1:
    st.title("🔓 LLM 情報漏洩シミュレーター")
    st.caption("防御レベルとモデルを切り替えながら、攻撃プロンプトが機密情報を漏洩させるか実験できます。")

    col_cfg1, col_cfg2 = st.columns(2)
    with col_cfg1:
        defense_level = st.radio(
            "防御レベル",
            options=list(DEFENSE_LEVELS.keys()),
            format_func=lambda x: DEFENSE_LEVELS[x]["name"],
            horizontal=False,
        )
    with col_cfg2:
        provider = st.radio(
            "チャットボットのモデル",
            options=list(PROVIDERS.keys()),
            format_func=lambda x: PROVIDERS[x]["label"],
        )

    st.info(DEFENSE_LEVELS[defense_level]["description"])

    st.divider()

    # Sample buttons
    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("🔴 攻撃サンプル")
        for s in ATTACK_SAMPLES:
            label = f"[{s['attack_type']}]\n{s['text'][:28]}…"
            if st.button(label, key=f"atk1_{s['id']}"):
                st.session_state["sim_input"] = s["text"]
    with col_b:
        st.subheader("🟢 正常サンプル")
        for s in LEGIT_SAMPLES:
            if st.button(s["text"], key=f"leg1_{s['id']}"):
                st.session_state["sim_input"] = s["text"]

    st.divider()
    user_input = st.text_area(
        "テキストを入力してシミュレーション",
        value=st.session_state.get("sim_input", ""),
        height=100,
        placeholder="攻撃プロンプトまたは通常の質問を入力してください",
    )

    if st.button("🚀 シミュレーション実行", type="primary", use_container_width=True):
        if not user_input.strip():
            st.warning("テキストを入力してください。")
        else:
            # このプロバイダーのAPIキーが設定されているか
            provider_key_ok = (provider == "anthropic" and claude_ok) or \
                              (provider == "openai"    and gpt_ok)
            is_demo = not provider_key_ok

            engine = get_engine(provider)
            spinner_msg = f"{PROVIDERS[provider]['label']} に送信中…" if not is_demo \
                          else "デモモードで処理中…"
            with st.spinner(spinner_msg):
                result  = engine.run(user_input, defense_level)
                summary = analyzer.analyze(result)

            # デモモードの場合は最初に注意バナーを表示
            if is_demo:
                st.warning(
                    "**📋 デモモード（APIキー未設定）**\n\n"
                    f"上のAPIキー欄に `{PROVIDERS[provider]['env_key']}` を設定すると、"
                    f"実際の **{PROVIDERS[provider]['label']}** の応答で検証できます。\n\n"
                    "以下の結果は **事前に用意した模擬応答** に基づくものです。"
                    "特定のモデルの挙動を示すものではありません。",
                    icon="⚠️",
                )

            # verdict banner（デモモードは「模擬」と明記）
            model_label = f"{PROVIDERS[provider]['label']}（模擬）" if is_demo \
                          else PROVIDERS[provider]['label']

            if result["blocked_at"] == "input_filter":
                st.error("🛡️ **入力フィルタによりブロック** — チャットボットに到達しませんでした", icon="🛡️")
            elif result["leakage_detected"] and result["blocked_at"] == "output_filter":
                st.warning(
                    f"⚠️ **漏洩を検知 → 出力フィルタがマスク**\n\n"
                    f"漏洩した情報: `{result['leaked_items']}`",
                    icon="⚠️",
                )
            elif result["leakage_detected"]:
                st.error(
                    f"🚨 **情報漏洩！** `{model_label}` が機密情報を開示しました\n\n"
                    f"漏洩した情報: `{result['leaked_items']}`",
                    icon="🚨",
                )
            else:
                st.success(
                    f"✅ **漏洩なし** — `{model_label}` は機密情報を開示しませんでした",
                    icon="✅",
                )

            st.subheader("🤖 チャットボットの応答")
            st.text_area("応答", value=result["final_response"], height=150,
                         disabled=True, key="resp_tab1")

            st.subheader("📋 処理ステップ")
            step_icons = {"input_filter": "🔍", "chatbot": "🤖",
                          "output_filter": "🔒", "leakage_analysis": "📊"}
            for step in result["steps"]:
                bad  = step["result"] in ("blocked", "leaked", "leakage_masked")
                icon = step_icons.get(step["step"], "•")
                with st.expander(f"{icon} {step['step']}  —  {'🔴' if bad else '🟢'} {step['result']}"):
                    st.json(step["detail"])

            st.caption(f"**分析:** {summary['vulnerability']}")


# ════════════════════════════════════════════════════════════════════════════════
# TAB 2 — Model comparison batch test
# ════════════════════════════════════════════════════════════════════════════════
with tab2:
    st.title("📊 Claude vs GPT — 漏洩率比較バッチテスト")
    st.caption("同じ攻撃プロンプトを複数モデル・複数防御レベルで試し、漏洩率を比較します。")

    # ── Step 1: Select prompts ────────────────────────────────────────────────
    st.subheader("① テストするプロンプトを選択")

    # Build label → sample mapping for display
    sample_label_map = {
        f"[{s['attack_type']}]  {s['text'][:45]}…": s
        for s in ATTACK_SAMPLES
    }
    selected_labels = st.multiselect(
        "攻撃プロンプト（複数選択可）",
        options=list(sample_label_map.keys()),
        default=list(sample_label_map.keys())[:1],   # default: 1件だけ
        help="まずは1件から試すことをおすすめします。",
    )
    selected_samples = [sample_label_map[l] for l in selected_labels]

    # ── Step 2: Select models & levels ───────────────────────────────────────
    st.subheader("② モデルと防御レベルを選択")
    col_b1, col_b2 = st.columns(2)
    with col_b1:
        test_providers = st.multiselect(
            "テストするモデル",
            options=list(PROVIDERS.keys()),
            default=list(PROVIDERS.keys())[:1],      # default: Claude のみ
            format_func=lambda x: PROVIDERS[x]["label"],
        )
    with col_b2:
        test_levels = st.multiselect(
            "テストする防御レベル",
            options=list(DEFENSE_LEVELS.keys()),
            default=[0, 2],                          # default: Level 0 と 2 だけ
            format_func=lambda x: DEFENSE_LEVELS[x]["name"],
        )

    # ── API call count estimate ───────────────────────────────────────────────
    n_prompts   = len(selected_samples)
    n_providers = len(test_providers)
    n_levels    = len(test_levels)
    total_calls = n_prompts * n_providers * n_levels

    if total_calls > 0:
        color = "🟢" if total_calls <= 4 else ("🟡" if total_calls <= 16 else "🔴")
        st.info(
            f"{color} **API呼び出し回数の見積もり：{total_calls} 回**  "
            f"（プロンプト {n_prompts} × モデル {n_providers} × レベル {n_levels}）\n\n"
            f"{'まず1件・1モデル・2レベルから試すことをおすすめします。' if total_calls > 8 else 'この規模なら安心して実行できます。'}",
            icon="💡",
        )

    # デモモード判定（選択したプロバイダーのうち1つでもAPIキーが未設定なら警告）
    demo_providers = [p for p in test_providers
                      if not os.environ.get(PROVIDERS[p]["env_key"])]
    if demo_providers:
        demo_labels = " / ".join(PROVIDERS[p]["label"] for p in demo_providers)
        st.warning(
            f"**⚠️ デモモード：{demo_labels}**\n\n"
            f"APIキーが未設定のモデルは **模擬応答** を返します。"
            "実際のモデルの挙動ではないため、モデル間比較の参考にはなりません。\n"
            "比較テストは両モデルのAPIキーを設定した状態で実行してください。",
            icon="⚠️",
        )

    # ── Run button ────────────────────────────────────────────────────────────
    run_disabled = (not selected_samples or not test_providers or not test_levels)
    if st.button("▶️ 比較テスト実行", type="primary", disabled=run_disabled):
        all_records: list[dict] = []
        progress = st.progress(0, text="実行中…")
        done = 0

        for prov in test_providers:
            eng = get_engine(prov)
            for sample in selected_samples:
                for lvl in test_levels:
                    sim  = eng.run(sample["text"], lvl)
                    summ = analyzer.analyze(sim)
                    all_records.append({
                        "provider":      prov,
                        "model_label":   PROVIDERS[prov]["label"],
                        "defense_level": lvl,
                        "level_name":    DEFENSE_LEVELS[lvl]["name"],
                        "attack_type":   sample["attack_type"],
                        "leaked":        summ["leaked"],
                        "leaked_items":  summ["leaked_items"],
                        "input":         sample["text"][:45],
                        "vulnerability": summ["vulnerability"],
                    })
                    done += 1
                    progress.progress(done / total_calls,
                                      text=f"[{PROVIDERS[prov]['label']}] {sample['text'][:30]}… ({done}/{total_calls})")

        progress.empty()
        df = pd.DataFrame(all_records)
        st.success(f"✅ {total_calls} 件のテスト完了")

        # ── Per-prompt result cards ───────────────────────────────────────
        st.divider()
        st.subheader("📋 プロンプト別 結果")
        for sample in selected_samples:
            sub = df[df["input"] == sample["text"][:45]]
            with st.expander(f"**{sample['attack_type']}**  —  {sample['text'][:50]}…", expanded=True):
                # One row per (model × level)
                rows = []
                for _, row in sub.iterrows():
                    rows.append({
                        "モデル":      row["model_label"],
                        "防御レベル":  row["level_name"],
                        "結果":        "🔴 漏洩" if row["leaked"] else "🟢 安全",
                        "漏洩した情報": ", ".join(row["leaked_items"]) if row["leaked_items"] else "—",
                    })
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        # ── Grouped bar chart (only when multiple prompts or levels) ──────
        if total_calls > 2:
            st.divider()
            st.subheader("🛡️ 防御レベル別 漏洩率（モデル比較）")
            pivot = (
                df.groupby(["level_name", "model_label"])["leaked"]
                .mean().mul(100).reset_index()
                .pivot(index="level_name", columns="model_label", values="leaked")
                .fillna(0)
                .reindex([DEFENSE_LEVELS[l]["name"] for l in sorted(test_levels)])
            )
            st.bar_chart(pivot)
            st.caption("棒が高いほど漏洩しやすい。防御レベルが上がるにつれ下がることを確認してください。")

        # ── Full detail table ─────────────────────────────────────────────
        with st.expander("📄 全テスト結果の詳細を見る"):
            disp = df[["model_label", "level_name", "attack_type",
                        "leaked", "leaked_items", "input"]].copy()
            disp.columns = ["モデル", "防御レベル", "攻撃種別",
                             "漏洩", "漏洩した情報", "入力（先頭45字）"]
            disp["漏洩"] = disp["漏洩"].map({True: "🔴 漏洩", False: "🟢 安全"})
            st.dataframe(disp, use_container_width=True, hide_index=True)


# ════════════════════════════════════════════════════════════════════════════════
# TAB 3 — Architecture
# ════════════════════════════════════════════════════════════════════════════════
with tab3:
    st.title("📐 アーキテクチャ解説")

    st.subheader("防御レベル別 処理フロー")
    st.code("""
Level 0（防御なし）
  ユーザー入力 → MockChatbot → 応答（漏洩の可能性あり）

Level 1（プロンプト指示のみ）
  ユーザー入力 → MockChatbot（「漏らすな」ルール付き）→ 応答
             ↑ 直接的な質問は断るが巧妙な誘導には弱い

Level 2（入力フィルタ追加）
  ユーザー入力 → [InputFilter] → MockChatbot → 応答
                    ↑ prompt-injection-detector 使用

Level 3（出力フィルタ追加・DLP）
  ユーザー入力 → [InputFilter] → MockChatbot → [OutputFilter] → 応答
                                                    ↑ 機密情報をマスク
""", language=None)

    st.subheader("なぜ「どのLLMを使っても防御が必要」なのか")
    st.markdown("""
| 観点 | 内容 |
|------|------|
| **モデル側の防御** | Anthropic / OpenAI が自社モデルに組み込んだ安全機能（変えられない） |
| **アプリ側の防御** | 開発者が設計する多層フィルタ（このシミュレーターで実証） |

> **結論：** どんなに優秀なモデルでも、アプリ側に防御がなければ Level 0 と同じ状態。
> モデルの安全性に頼るだけでは不十分で、**アプリケーション層での多層防御が必須**。
""")

    st.subheader("OWASP LLM Top 10 との対応")
    st.table({
        "OWASP リスク": [
            "LLM01: Prompt Injection",
            "LLM02: Sensitive Information Disclosure",
            "LLM07: System Prompt Leakage",
        ],
        "対応する防御": [
            "Level 2 の InputFilter",
            "Level 3 の OutputFilter（DLP）",
            "Level 1 のシステムプロンプトルール",
        ],
    })

    st.subheader("Zscaler ZIA との対比")
    st.table({
        "ZIA の検査層": [
            "URLフィルタ（シグネチャ）",
            "Advanced Threat Protection（ヒューリスティック）",
            "Cloud Sandbox（動的解析）",
        ],
        "このシミュレーターの対応": [
            "InputFilter — ルールベース検知",
            "InputFilter — ML分類（DeBERTa）",
            "LLM-as-Judge（Claude API）",
        ],
    })
