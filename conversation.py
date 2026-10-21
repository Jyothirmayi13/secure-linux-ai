"""Lightweight JSON-file conversation history store.

Persists chat turns between CLI invocations so follow-up
queries have context from the previous exchange.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

# Store conversation alongside other app state.
_STATE_DIR = (
    Path.home()
    / ".local"
    / "state"
    / "linux-ai-ssm"
)

_HISTORY_FILE = _STATE_DIR / "conversation.json"

# Auto-expire history older than 30 minutes.
_EXPIRY_SECONDS = 30 * 60

# Keep at most 10 turns to prevent token bloat.
_MAX_TURNS = 10


def _ensure_dir() -> None:
    """Create the state directory if it doesn't exist."""
    _STATE_DIR.mkdir(parents=True, exist_ok=True)


def load_history() -> list[dict[str, Any]]:
    """Load conversation history from disk.

    Returns a list of ``{"role": "user"|"model", "text": "...",
    "timestamp": float}`` dicts.  Automatically clears history
    that is older than ``_EXPIRY_SECONDS``.
    """

    if not _HISTORY_FILE.exists():
        return []

    try:
        data = json.loads(
            _HISTORY_FILE.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError):
        # Corrupted file — start fresh.
        clear_history()
        return []

    if not isinstance(data, list) or not data:
        return []

    # Auto-expire: check the most recent turn's timestamp.
    last_ts = data[-1].get("timestamp", 0)

    if time.time() - last_ts > _EXPIRY_SECONDS:
        clear_history()
        return []

    return data


def append_turn(role: str, text: str) -> None:
    """Append a single turn and persist to disk.

    Parameters
    ----------
    role:
        ``"user"`` or ``"model"``.
    text:
        The message content.
    """

    history = load_history()

    history.append({
        "role": role,
        "text": text,
        "timestamp": time.time(),
    })

    # Trim to the most recent turns.
    if len(history) > _MAX_TURNS:
        history = history[-_MAX_TURNS:]

    _ensure_dir()
    _HISTORY_FILE.write_text(
        json.dumps(history, indent=2),
        encoding="utf-8",
    )


def clear_history() -> None:
    """Delete the conversation history file."""

    try:
        _HISTORY_FILE.unlink(missing_ok=True)
    except OSError:
        pass
