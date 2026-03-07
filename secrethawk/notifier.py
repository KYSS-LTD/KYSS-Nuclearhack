"""Notification integrations."""

from __future__ import annotations

import json
import urllib.request

from .models import Finding


def _post_telegram_json(bot_token: str, method: str, payload: dict) -> bool:
    request = urllib.request.Request(
        url=f"https://api.telegram.org/bot{bot_token}/{method}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def send_telegram_alert(
    bot_token: str,
    chat_id: str,
    repo: str,
    findings: list[Finding],
    ai_summary: str | None = None,
) -> bool:
    high_findings = [f for f in findings if f.severity in {"critical", "high"}]
    if not high_findings:
        return True

    preview = "\n".join(
        f"- {f.severity.upper()} {f.secret_type}: {f.file_path}:{f.line_number}" for f in high_findings[:10]
    )
    if len(high_findings) > 10:
        preview += f"\n... and {len(high_findings) - 10} more"

    message = f"[SecretHawk] Secrets detected in {repo}\n{preview}"
    if ai_summary:
        message += f"\n\n🤖 AI summary:\n{ai_summary}"

    payload = {
        "chat_id": chat_id,
        "text": message,
        "reply_markup": {
            "inline_keyboard": [
                [{"text": "Сохранить .excel", "callback_data": "save_excel"}],
                [{"text": "Сохранить .docx", "callback_data": "save_docx"}],
                [{"text": "Сохранить .txt", "callback_data": "save_txt"}],
            ]
        },
    }
    return _post_telegram_json(bot_token, "sendMessage", payload)
