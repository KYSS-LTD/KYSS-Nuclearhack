"""Persistent Telegram credentials storage."""

from __future__ import annotations

import json
from pathlib import Path


def config_path() -> Path:
    return Path.home() / ".config" / "secrethawk" / "telegram.json"


def save_telegram_credentials(token: str, chat_id: str) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"token": token, "chat_id": chat_id}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_telegram_credentials() -> tuple[str | None, str | None]:
    path = config_path()
    if not path.exists() or not path.is_file():
        return None, None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    token = payload.get("token")
    chat_id = payload.get("chat_id")
    if not isinstance(token, str) or not isinstance(chat_id, str):
        return None, None
    return token, chat_id

