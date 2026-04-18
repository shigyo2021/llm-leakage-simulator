"""
LeakageAnalyzer: generates reports from simulation results.
Supports single-result analysis and batch (multi-attack) summaries.
"""
from __future__ import annotations
import json
from typing import Any


class LeakageAnalyzer:

    # ── Single result ─────────────────────────────────────────────────────────

    def analyze(self, sim_result: dict) -> dict:
        """
        Summarize a single SimulatorEngine.run() result.

        Returns:
            {
                "input_preview": str,
                "defense_level": int,
                "leaked": bool,
                "leaked_items": list[str],
                "blocked_by": str | None,
                "vulnerability": str
            }
        """
        leaked = sim_result["leakage_detected"]
        blocked = sim_result["blocked_at"]
        level = sim_result["defense_level"]
        items = sim_result["leaked_items"]

        if blocked == "input_filter":
            vuln = "Attack blocked by input filter before reaching chatbot."
        elif blocked == "output_filter":
            vuln = (f"Chatbot leaked {items} internally, but output filter masked it. "
                    "Paraphrased output could still carry intent.")
        elif leaked:
            vuln = (f"Chatbot response contained {items}. "
                    f"No output filter at Level {level}.")
        else:
            vuln = "No leakage detected. Chatbot followed security rules."

        return {
            "input_preview": sim_result["input"][:80],
            "defense_level": level,
            "leaked": leaked,
            "leaked_items": items,
            "blocked_by": blocked,
            "vulnerability": vuln,
        }

    # ── Batch result ──────────────────────────────────────────────────────────

    def batch_summary(self, results: list[dict]) -> dict:
        """
        Aggregate multiple analyze() results into a statistical summary.

        Args:
            results: list of analyze() return values (may include multiple levels)

        Returns:
            {
                "total_tests": int,
                "total_leaked": int,
                "leak_rate": float,
                "by_defense_level": { "0": {...}, ... },
                "by_attack_type": { "direct_instruction": {...}, ... },
                "most_effective_attacks": [...],
                "most_leaked_items": [...]
            }
        """
        total = len(results)
        leaked_results = [r for r in results if r["leaked"]]

        # By defense level
        by_level: dict[str, Any] = {}
        for lvl in range(4):
            lvl_results = [r for r in results if r["defense_level"] == lvl]
            lvl_leaked = [r for r in lvl_results if r["leaked"]]
            count = len(lvl_results)
            by_level[str(lvl)] = {
                "tests": count,
                "leaked": len(lvl_leaked),
                "leak_rate": round(len(lvl_leaked) / count, 3) if count else 0.0,
            }

        # By attack type (requires "attack_type" key in result)
        by_type: dict[str, Any] = {}
        for r in results:
            atype = r.get("attack_type", "unknown")
            if atype not in by_type:
                by_type[atype] = {"leaked": 0, "total": 0}
            by_type[atype]["total"] += 1
            if r["leaked"]:
                by_type[atype]["leaked"] += 1
        for atype, d in by_type.items():
            d["leak_rate"] = round(d["leaked"] / d["total"], 3) if d["total"] else 0.0

        # Most effective attacks (highest leak rate, top 5)
        attack_leak: dict[str, dict] = {}
        for r in results:
            key = r["input_preview"]
            if key not in attack_leak:
                attack_leak[key] = {"leaked_count": 0, "total": 0,
                                    "preview": r["input_preview"]}
            attack_leak[key]["total"] += 1
            if r["leaked"]:
                attack_leak[key]["leaked_count"] += 1
        most_effective = sorted(
            attack_leak.values(),
            key=lambda x: x["leaked_count"] / max(x["total"], 1),
            reverse=True,
        )[:5]

        # Most leaked items
        item_counts: dict[str, int] = {}
        for r in leaked_results:
            for item in r["leaked_items"]:
                item_counts[item] = item_counts.get(item, 0) + 1
        most_leaked = sorted(item_counts.items(), key=lambda x: -x[1])

        return {
            "total_tests": total,
            "total_leaked": len(leaked_results),
            "leak_rate": round(len(leaked_results) / total, 3) if total else 0.0,
            "by_defense_level": by_level,
            "by_attack_type": by_type,
            "most_effective_attacks": most_effective,
            "most_leaked_items": most_leaked,
        }
