# KYSS-Nuclearhack — SecretHawk

Система автоматического обнаружения утечек секретов в исходном коде и Git-истории.

## Возможности

- CLI-сканер на Python для локального запуска и CI/CD.
- Рекурсивный обход репозитория с исключением служебных директорий (`.git`, `node_modules`, `venv`, и т.д.).
- Анализ по **regex-паттернам** (AWS/GitHub/Slack/private key/password/API token).
- Анализ по **энтропии Шеннона** для неизвестных токенов.
- Классификация находок по критичности (`critical`, `high`, `medium`, `low`).
- Пояснения риска и рекомендации по исправлению для каждой находки.
- Опциональное обогащение находок через полностью локальную LLM (Ollama API).
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

Показывать только одно резюме Why/Fix в конце (поведение по умолчанию):

```bash
secrethawk . --explain summary
```

Показывать пояснения у каждой находки:

```bash
secrethawk . --explain each
```

## Telegram: как запустить с ботом

1. Создайте бота через `@BotFather` и получите token.
2. Добавьте бота в нужный чат/группу и узнайте `chat_id`.
3. Один раз сохраните данные в SecretHawk:

```bash
secrethawk . --token <BOT_TOKEN> --id <CHAT_ID>
```

4. Дальше для отправки сводки достаточно:

```bash
secrethawk . --tg
```

Что приходит в Telegram:
- красивое сообщение со сводкой `high/critical` и датой сканирования;
- автоматически прикреплённые готовые файлы отчёта: `.txt`, `.json`, `.html`, `.csv`.

5. Если нужна AI-сводка в Telegram (локальная LLM/Ollama):

```bash
secrethawk . --tg --ai --llm-model llama3.2:3b
```


## Web-интерфейс (локальный FastAPI)

Запуск локального web-интерфейса:

```bash
secrethawk-web
```

После запуска откройте `http://127.0.0.1:8000`.

Основные разделы:
- Dashboard: сводка последнего сканирования, запуск скана и загрузка JSON отчёта от CLI.
- Если web-база пуста, Dashboard автоматически пытается импортировать существующие JSON-отчёты CLI (`secret-report.json`, `secrethawk*.json`), также доступна ручная синхронизация отчётов с диска.
- Findings: таблица находок с фильтрацией, сортировкой, bulk-действиями (ignore/false-positive/Jira).
- Finding details: детальная карточка, контекст, рекомендации и кнопка `Explain with AI` (Ollama).
- Scan history: история всех запусков с сохранением в SQLite (`.secrethawk-web.db`).
- Git History Leaks: отдельный просмотр утечек, найденных в истории Git.
- Settings: настройка scanner-конфига, Jira, локальной LLM (сохранение в `nuclear.toml`).
- Notifications: Telegram-настройки и тестовое уведомление.
- Export: JSON/HTML/SARIF выгрузка отчётов.

Web-часть полностью локальная, внешние интеграции (Ollama/Jira/Telegram) опциональны.

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
- `--explain-with-llm` — дополнительно генерировать пояснения через локальную LLM.
- `--explain [summary|each|none]` — вывод подсказок: одна сводка в конце (по умолчанию), у каждой находки, или отключить.
- `--llm-model` — имя локальной модели Ollama (по умолчанию `llama3.2:3b`).
- `--llm-endpoint` — локальный HTTP endpoint API генерации.
- `--token`, `--id` — сохранить Telegram token/chat id для последующих запусков.
- `--tg` — отправить сводку в Telegram, используя сохранённые (или переданные) token/id.
- `--ai` — добавить к Telegram-сообщению AI-сводку (локальная LLM через Ollama).
- `--fail-on [critical|high|medium|never]` — условие кода возврата.
- `--config` — путь к TOML-конфигу (по умолчанию `nuclear.toml`).
- `--no-color` — отключить ANSI-цвета severity в таблице.
- `--no-progress` — отключить индикатор прогресса сканирования.
- `--telegram-bot-token`, `--telegram-chat-id` — отправить краткое уведомление в Telegram по high/critical находкам.


## Конфигурация проекта

Поддерживается файл `nuclear.toml` (секция `[secrethawk]`):

```toml
[secrethawk]
entropy_threshold = 4.5
fail_on = "high"
max_commits = 200
exclude_dirs = ["generated", "tmp"]
ignore_patterns = ["docs/examples/*", "*.snap"]
```

Дополнительно можно создать `.nuclearignore` или `.secretignore` с путями/паттернами (по одному на строку), которые нужно исключить из обхода.

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
- Дополнительные эвристики учитывают длину, формат (hex/base64) и типичные префиксы токенов.

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
