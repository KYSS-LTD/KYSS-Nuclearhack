# KYSS-Nuclearhack — SecretHawk

Система автоматического обнаружения утечек секретов в исходном коде и Git-истории.

## Возможности

- CLI-сканер на Python для локального запуска и CI/CD.
- Рекурсивный обход репозитория с исключением служебных директорий (`.git`, `node_modules`, `venv`, и т.д.).
- Анализ по **regex-паттернам** (AWS/GitHub/Slack/private key/password/API token).
- Анализ по **энтропии Шеннона** для неизвестных токенов.
- Классификация находок по критичности (`critical`, `high`, `medium`, `low`).
- Отчёт в консольной таблице и JSON.
- Интеграция с Git через pre-commit hook.
- Интеграция с GitHub Actions.
- Опциональные Telegram-уведомления для high/critical находок.
- Опциональное сканирование истории Git.

## Установка

```bash
pip install .
```

## Использование CLI

Сканировать весь репозиторий:

```bash
secrethawk . --json-out artifacts/secret-report.json --fail-on high
```

Сканировать только staged-файлы (для pre-commit):

```bash
secrethawk . --only-staged --fail-on high
```

Сканировать историю Git (опционально ограничить число коммитов):

```bash
secrethawk . --scan-history --max-commits 200 --fail-on high
```

Параметры:

- `--entropy-threshold` — порог энтропии (по умолчанию `4.5`).
- `--json-out` — путь для JSON отчёта.
- `--fail-on [critical|high|medium|never]` — условие кода возврата.
- `--telegram-bot-token`, `--telegram-chat-id` — уведомления в Telegram.

## Выходные коды

- `0` — ошибок уровня порога `--fail-on` не найдено.
- `2` — найдены секреты с уровнем `--fail-on` или выше.

## Pre-commit интеграция

Установка hook:

```bash
bash scripts/install_pre_commit_hook.sh
```

После установки перед каждым commit запускается сканирование staged файлов.

## CI/CD (GitHub Actions)

Workflow: `.github/workflows/secret-scan.yml`

- устанавливает Python,
- устанавливает пакет,
- запускает `secrethawk`,
- публикует JSON-отчёт как artifact.

## Базовая архитектура

- `secrethawk/cli.py` — CLI, orchestration, exit codes.
- `secrethawk/scanner.py` — обход файловой системы и staged файлов.
- `secrethawk/analyzer.py` — regex + entropy анализ.
- `secrethawk/patterns.py` — шаблоны известных секретов.
- `secrethawk/git_history.py` — анализ history через `git show`.
- `secrethawk/notifier.py` — Telegram уведомления.
- `secrethawk/models.py` — модели Finding/ScanReport.
