"""
M3: Structured audit logging for the leakage simulator.

Standalone copy of the detector's audit module — same shape, same env
vars, renamed to `SIM_AUDIT_LOG*` so an operator running both tools in
one process can route them to different sinks. See
`prompt-injection-detector/src/audit_log.py` for the full design
rationale (why JSON, why no raw input, why UTC, etc.).

Events emitted:
  - `simulator_turn`  : one per SimulatorEngine.run(), includes the
                        defense_level, whether leakage was detected,
                        which step blocked (if any), and the input hash
                        (never the raw input).
  - `input_filter`    : one per InputFilter.check() call — useful for
                        base-rate analysis of Level 2 in isolation.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .secrets_util import redact_secrets


_LOGGER_NAME = "llm_leakage_simulator.audit"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, dict):
            payload = dict(record.msg)
        else:
            payload = {"message": record.getMessage()}
        payload.setdefault("level", record.levelname)
        payload.setdefault("ts", _utc_now_iso())
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _configure_once(logger: logging.Logger) -> None:
    if any(getattr(h, "_is_audit_handler", False) for h in logger.handlers):
        return
    path = os.environ.get("SIM_AUDIT_LOG_PATH", "").strip()
    if path:
        try:
            handler: logging.Handler = logging.FileHandler(
                path, mode="a", encoding="utf-8"
            )
        except OSError as exc:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(_JsonFormatter())
            handler._is_audit_handler = True  # type: ignore[attr-defined]
            logger.addHandler(handler)
            logger.error({
                "event": "audit_log_init_error",
                "error": str(exc),
                "path": path,
                "fallback": "stderr",
            })
            return
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonFormatter())
    handler._is_audit_handler = True  # type: ignore[attr-defined]
    logger.addHandler(handler)


def get_audit_logger() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    logger.propagate = False
    if _env_flag("SIM_AUDIT_LOG"):
        _configure_once(logger)
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.CRITICAL + 1)
    return logger


def hash_input(text: Optional[str]) -> str:
    if text is None:
        return "none"
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def input_preview(text: Optional[str]) -> str:
    if text is None:
        return ""
    try:
        n = int(os.environ.get("SIM_AUDIT_LOG_PREVIEW_CHARS", "80"))
    except ValueError:
        n = 80
    if n <= 0:
        return ""
    return redact_secrets(text[:n])


def new_turn_id() -> str:
    return uuid.uuid4().hex[:12]


def emit(event: str, payload: dict[str, Any]) -> None:
    """
    Generic emit. Callers pre-build the payload; this function adds
    common envelope fields (`event`, `ts`) and routes to the logger.
    Kept permissive because the simulator has more event shapes than
    the detector (per-turn, per-input-filter, per-batch, etc.).
    """
    logger = get_audit_logger()
    if not logger.isEnabledFor(logging.INFO):
        return
    envelope = {"event": event, "ts": _utc_now_iso()}
    # Never let payload fields overwrite envelope — same rationale as detector.
    for k, v in payload.items():
        if k in envelope:
            continue
        envelope[k] = v
    logger.info(envelope)


def monotonic_ms() -> float:
    return time.perf_counter() * 1000.0
