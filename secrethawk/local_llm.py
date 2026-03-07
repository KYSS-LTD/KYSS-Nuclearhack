"""Optional local LLM integration (Ollama-compatible HTTP API)."""

from __future__ import annotations

import json
from urllib import error, request

from .models import Finding


def _build_prompt(finding: Finding, context: str) -> str:
    return (
        "Ты помощник по безопасности кода. Ответь на русском. "
        "Кратко объясни риск и дай 2-4 шага исправления. "
        "Верни JSON с ключами explanation (string) и remediation (array of strings).\n\n"
        f"Тип секрета: {finding.secret_type}\n"
        f"Severity: {finding.severity}\n"
        f"Файл/строка: {finding.file_path}:{finding.line_number}\n"
        f"Фрагмент: {finding.snippet}\n"
        f"Контекст: {context}"
    )


def explain_finding_with_ollama(
    finding: Finding,
    model: str,
    endpoint: str = "http://127.0.0.1:11434/api/generate",
) -> Finding:
    prompt = _build_prompt(finding, context=finding.snippet)
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": {
            "type": "object",
            "properties": {
                "explanation": {"type": "string"},
                "remediation": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["explanation", "remediation"],
        },
    }
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(endpoint, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with request.urlopen(req, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return finding

    raw_response = body.get("response", "")
    try:
        parsed = json.loads(raw_response)
    except json.JSONDecodeError:
        return finding

    explanation = parsed.get("explanation")
    remediation = parsed.get("remediation")
    if isinstance(explanation, str) and explanation.strip():
        finding.explanation = explanation.strip()
    if isinstance(remediation, list):
        finding.remediation = [str(item).strip() for item in remediation if str(item).strip()]
    return finding


def summarize_findings_with_ollama(
    findings: list[Finding],
    model: str,
    endpoint: str = "http://127.0.0.1:11434/api/generate",
) -> str | None:
    preview = "\n".join(
        f"- {f.severity.upper()} {f.secret_type} {f.file_path}:{f.line_number}" for f in findings[:20]
    )
    prompt = (
        "Сделай очень краткую сводку по утечкам секретов на русском языке. "
        "Формат: 3-6 пунктов, сначала риски, затем что исправить в первую очередь.\n\n"
        f"Находки:\n{preview}"
    )
    payload = {"model": model, "prompt": prompt, "stream": False}
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(endpoint, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with request.urlopen(req, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None
    response_text = body.get("response")
    if not isinstance(response_text, str):
        return None
    summary = response_text.strip()
    return summary or None
