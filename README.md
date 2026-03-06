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

## Быстрый старт

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

## Полный справочник по CLI

```bash
secrethawk [path] [OPTIONS]
```

Где `path` — путь к репозиторию/проекту (по умолчанию `.`).

Параметры:

- `--entropy-threshold` — порог энтропии (по умолчанию `4.5`). Чем ниже порог, тем больше потенциальных срабатываний по неизвестным токенам.
- `--json-out` — путь для JSON отчёта.
- `--only-staged` — сканировать только индексацию Git (`git diff --cached`).
- `--scan-history` — анализировать Git-историю через `git show`.
- `--max-commits` — ограничить число коммитов при `--scan-history`.
- `--fail-on [critical|high|medium|never]` — условие кода возврата.
- `--telegram-bot-token`, `--telegram-chat-id` — отправить краткое уведомление в Telegram по high/critical находкам.

## Что именно умеет находить

### Regex-детекторы

- AWS access key (`AKIA...`) — `critical`.
- GitHub токены (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) — `high`.
- Slack токены (`xox...`) — `high`.
- Заголовки private key (`-----BEGIN ... PRIVATE KEY-----`) — `critical`.
- Присвоение пароля (`password=...`, `passwd: ...`) — `high`.
- Обобщённые `api_key` / `token` / `secret` присвоения — `high`.

### Энтропийный детектор

- Ищет последовательности длиной 20+ символов (`[A-Za-z0-9+/=_-]`) и считает энтропию Шеннона.
- Если энтропия выше порога, помечает как `unknown_high_entropy` со значением энтропии в отчёте.

## Выходные коды

- `0` — ошибок уровня порога `--fail-on` не найдено.
- `2` — найдены секреты с уровнем `--fail-on` или выше.

## Форматы отчётов

- **Таблица в stdout**: severity, detector, type, location, snippet.
- **JSON** (если указан `--json-out`):
  - `repository`, `scanned_at`, `summary`, `total_findings`, `findings[]`.

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
- `secrethawk/models.py` — модели `Finding`/`ScanReport`.

## Идеи для улучшения

1. **Снижение false positive**
   - добавить allowlist (`.secrethawkignore`) и inline-ignore-комментарии.
2. **Точнее severity-модель**
   - разделить severity для разных источников (prod/dev/test), добавить confidence score.
3. **Более быстрый scan**
   - распараллелить чтение файлов и добавить инкрементальный кэш по хешам.
4. **Поддержка baseline**
   - фиксировать существующие находки и падать только на новых.
5. **Более богатые интеграции**
   - SARIF-выгрузка для GitHub Code Scanning, Slack/Webhook нотификации.
6. **Улучшение проверки истории**
   - учитывать rename/копии, гибко настраивать глубину и ветки.
7. **Тесты и качество**
   - добавить unit-тесты для `scanner`, `cli`, `git_history`, а также e2e на sample-репозитории
