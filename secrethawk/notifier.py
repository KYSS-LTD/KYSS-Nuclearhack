"""Notification integrations."""

from __future__ import annotations

import json
import urllib.request

from .models import Finding


def send_telegram_alert(bot_token: str, chat_id: str, repo: str, findings: list[Finding]) -> bool:
    high_findings = [f for f in findings if f.severity in {"critical", "high"}]
    if not high_findings:
        return True

    preview = "\n".join(
        f"- {f.severity.upper()} {f.secret_type}: {f.file_path}:{f.line_number}" for f in high_findings[:10]
    )
    if len(high_findings) > 10:
        preview += f"\n... and {len(high_findings) - 10} more"

    message = f"[SecretHawk] Secrets detected in {repo}\n{preview}"
    payload = json.dumps({"chat_id": chat_id, "text": message}).encode("utf-8")

    request = urllib.request.Request(
        url=f"https://api.telegram.org/bot{bot_token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return 200 <= response.status < 300
    except Exception:
        return False
