"""Human-readable explanations and remediation guidance for findings."""

from __future__ import annotations

from .models import Finding

_GUIDANCE: dict[str, tuple[str, list[str]]] = {
    "aws_access_key": (
        "Возможный AWS Access Key. Такой ключ может дать доступ к облачной инфраструктуре и не должен храниться в коде.",
        [
            "Переместите ключ в переменные окружения или секретный менеджер (AWS Secrets Manager, Vault).",
            "Удалите секрет из Git-истории (git filter-repo/BFG) и перевыпустите ключ.",
            "Добавьте файл с локальными секретами в .gitignore/.secretignore.",
        ],
    ),
    "github_token": (
        "Найден GitHub токен. Он может дать доступ к репозиториям, package registry и CI.",
        [
            "Отзовите текущий токен и создайте новый с минимальными scope.",
            "Используйте GitHub Actions secrets/переменные окружения вместо хранения в коде.",
        ],
    ),
    "private_key_header": (
        "В коде обнаружен заголовок приватного ключа. Это критическая утечка с риском компрометации доступа.",
        [
            "Немедленно удалите ключ из репозитория и Git-истории.",
            "Пересоздайте ключевую пару и храните ключ только в защищённом хранилище.",
        ],
    ),
    "unknown_high_entropy": (
        "Строка с высокой энтропией похожа на секрет или токен случайного вида.",
        [
            "Проверьте назначение строки: если это ключ/токен — вынесите в переменные окружения.",
            "Добавьте безопасный шаблон конфигурации (например, .env.example) без реальных значений.",
        ],
    ),
}

_DEFAULT_BY_SEVERITY: dict[str, tuple[str, list[str]]] = {
    "critical": (
        "Обнаружен потенциально критический секрет в исходном коде.",
        [
            "Уберите секрет из кода и истории Git.",
            "Ротируйте секрет и перенесите хранение в секретный менеджер.",
        ],
    ),
    "high": (
        "Обнаружен вероятный секрет, который может дать доступ к внешним сервисам.",
        ["Перенесите значение в переменные окружения или защищённое хранилище."],
    ),
    "medium": (
        "Подозрительная строка требует ручной проверки.",
        ["Проверьте назначение строки и при необходимости вынесите секрет из репозитория."],
    ),
    "low": (
        "Низкоприоритетная потенциальная утечка.",
        ["Проверьте контекст и добавьте исключение в .secretignore при необходимости."],
    ),
}


def enrich_with_guidance(finding: Finding) -> Finding:
    explanation, remediation = _GUIDANCE.get(
        finding.secret_type,
        _DEFAULT_BY_SEVERITY.get(finding.severity, _DEFAULT_BY_SEVERITY["low"]),
    )
    finding.explanation = explanation
    finding.remediation = remediation
    return finding
