from pathlib import Path

from secrethawk.models import Finding
from secrethawk.notifier import _write_artifacts, send_telegram_alert


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            file_path="app.py",
            line_number=7,
            detector="regex",
            secret_type="aws_access_key",
            severity="critical",
            snippet='key="AKIA1234567890ABCDEF"',
            explanation="Ключ может дать доступ",
            remediation=["Убрать из кода", "Ротировать"],
        )
    ]


def test_write_artifacts_creates_expected_files(tmp_path: Path) -> None:
    files = _write_artifacts(tmp_path, "repo", _sample_findings(), "2026-01-01T00:00:00+00:00")
    names = sorted(path.name.split(".")[-1] for path in files)
    assert names == ["csv", "html", "json", "txt"]
    for path in files:
        assert path.exists()
        assert path.read_text(encoding="utf-8")


def test_send_telegram_alert_includes_date_and_sends_documents(monkeypatch) -> None:
    calls: list[tuple[str, str, dict]] = []
    docs: list[str] = []

    def fake_post_json(bot_token: str, method: str, payload: dict) -> bool:
        calls.append((bot_token, method, payload))
        return True

    def fake_post_multipart(bot_token: str, method: str, fields: dict[str, str], file_field: str, file_path: Path) -> bool:
        docs.append(file_path.suffix)
        return True

    monkeypatch.setattr("secrethawk.notifier._post_telegram_json", fake_post_json)
    monkeypatch.setattr("secrethawk.notifier._post_telegram_multipart", fake_post_multipart)

    ok = send_telegram_alert(
        bot_token="t",
        chat_id="1",
        repo="repo",
        findings=_sample_findings(),
        scanned_at="2026-01-01T00:00:00+00:00",
    )

    assert ok is True
    assert calls and calls[0][1] == "sendMessage"
    assert "2026-01-01T00:00:00+00:00" in calls[0][2]["text"]
    assert sorted(docs) == [".csv", ".html", ".json", ".txt"]
