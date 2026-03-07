from pathlib import Path

from secrethawk.telegram_config import load_telegram_credentials, save_telegram_credentials


def test_save_and_load_telegram_credentials(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    save_telegram_credentials("token123", "chat456")
    token, chat_id = load_telegram_credentials()

    assert token == "token123"
    assert chat_id == "chat456"
