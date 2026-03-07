"""Notification integrations."""

from __future__ import annotations

import csv
import json
import uuid
from datetime import datetime
from html import escape
from pathlib import Path
from tempfile import TemporaryDirectory
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


def _post_telegram_multipart(
    bot_token: str,
    method: str,
    fields: dict[str, str],
    file_field: str,
    file_path: Path,
) -> bool:
    boundary = f"----SecretHawk{uuid.uuid4().hex}"
    body = bytearray()

    for key, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")

    content_type = "application/octet-stream"
    if file_path.suffix == ".txt":
        content_type = "text/plain"
    elif file_path.suffix == ".json":
        content_type = "application/json"
    elif file_path.suffix == ".html":
        content_type = "text/html"
    elif file_path.suffix == ".csv":
        content_type = "text/csv"

    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(
        (
            f'Content-Disposition: form-data; name="{file_field}"; '
            f'filename="{file_path.name}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("utf-8")
    )
    body.extend(file_path.read_bytes())
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))

    request = urllib.request.Request(
        url=f"https://api.telegram.org/bot{bot_token}/{method}",
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def _build_preview(findings: list[Finding]) -> str:
    preview = "\n".join(
        f"• {f.severity.upper()} | {f.secret_type} | {f.file_path}:{f.line_number}" for f in findings[:10]
    )
    if len(findings) > 10:
        preview += f"\n• ... и ещё {len(findings) - 10}"
    return preview


def _render_text_report(repo: str, findings: list[Finding], scanned_at: str) -> str:
    lines = [f"SecretHawk report", f"Repository: {repo}", f"Scanned at: {scanned_at}", ""]
    for finding in findings:
        lines.append(
            f"[{finding.severity.upper()}] {finding.secret_type} @ {finding.file_path}:{finding.line_number}\n"
            f"Snippet: {finding.snippet}\nWhy: {finding.explanation}\nFix: {'; '.join(finding.remediation[:2])}\n"
        )
    return "\n".join(lines)


def _render_html_report(repo: str, findings: list[Finding], scanned_at: str) -> str:
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{escape(finding.severity)}</td>"
            f"<td>{escape(finding.secret_type)}</td>"
            f"<td>{escape(f'{finding.file_path}:{finding.line_number}')}</td>"
            f"<td><pre>{escape(finding.snippet)}</pre></td>"
            f"<td>{escape(finding.explanation)}</td>"
            f"<td>{escape('; '.join(finding.remediation[:2]))}</td>"
            "</tr>"
        )
    table = "\n".join(rows)
    return (
        "<html><body>"
        f"<h2>SecretHawk report</h2><p>Repository: {escape(repo)}<br>Scanned at: {escape(scanned_at)}</p>"
        "<table border='1' cellspacing='0' cellpadding='6'>"
        "<tr><th>Severity</th><th>Type</th><th>Location</th><th>Snippet</th><th>Why</th><th>Fix</th></tr>"
        f"{table}</table></body></html>"
    )


def _write_artifacts(temp_dir: Path, repo: str, findings: list[Finding], scanned_at: str) -> list[Path]:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    txt_path = temp_dir / f"secrethawk-{stamp}.txt"
    json_path = temp_dir / f"secrethawk-{stamp}.json"
    html_path = temp_dir / f"secrethawk-{stamp}.html"
    csv_path = temp_dir / f"secrethawk-{stamp}.csv"

    txt_path.write_text(_render_text_report(repo, findings, scanned_at), encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {
                "repository": repo,
                "scanned_at": scanned_at,
                "total": len(findings),
                "findings": [f.to_dict() for f in findings],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    html_path.write_text(_render_html_report(repo, findings, scanned_at), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["severity", "type", "location", "snippet", "why", "fix"])
        for finding in findings:
            writer.writerow(
                [
                    finding.severity,
                    finding.secret_type,
                    f"{finding.file_path}:{finding.line_number}",
                    finding.snippet,
                    finding.explanation,
                    "; ".join(finding.remediation[:2]),
                ]
            )
    return [txt_path, json_path, html_path, csv_path]


def send_telegram_alert(
    bot_token: str,
    chat_id: str,
    repo: str,
    findings: list[Finding],
    ai_summary: str | None = None,
    scanned_at: str | None = None,
) -> bool:
    high_findings = [f for f in findings if f.severity in {"critical", "high"}]
    if not high_findings:
        return True

    scanned_label = scanned_at or datetime.now().isoformat()
    preview = _build_preview(high_findings)
    message = (
        "🚨 *SecretHawk обнаружил утечки*\n"
        f"📦 Repo: `{repo}`\n"
        f"🗓 Дата сканирования: `{scanned_label}`\n"
        f"🔥 High/Critical: *{len(high_findings)}*\n\n"
        f"{preview}"
    )
    if ai_summary:
        message += f"\n\n🤖 AI summary:\n{ai_summary}"

    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
    }
    if not _post_telegram_json(bot_token, "sendMessage", payload):
        return False

    with TemporaryDirectory(prefix="secrethawk-tg-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        files = _write_artifacts(temp_dir, repo, high_findings, scanned_label)
        success = True
        for file_path in files:
            ok = _post_telegram_multipart(
                bot_token=bot_token,
                method="sendDocument",
                fields={"chat_id": chat_id, "caption": f"Report file: {file_path.name}"},
                file_field="document",
                file_path=file_path,
            )
            success = success and ok
        return success
