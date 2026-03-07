"""Local FastAPI web interface for SecretHawk."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import tempfile
import threading
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
from urllib import error, request

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from .local_llm import explain_finding_with_ollama
from .models import Finding

DB_PATH = Path(".secrethawk-web.db")
AUTO_IMPORT_GLOBS = [
    "**/secret-report.json",
    "**/secrethawk*.json",
    "**/*secret*report*.json",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_path TEXT NOT NULL,
                source TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                status_message TEXT DEFAULT '',
                total_findings INTEGER DEFAULT 0,
                scanned_files INTEGER DEFAULT 0,
                scanned_commits INTEGER DEFAULT 0,
                summary_json TEXT DEFAULT '{}',
                report_json TEXT DEFAULT '{}'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER NOT NULL,
                severity TEXT,
                secret_type TEXT,
                detector TEXT,
                file_path TEXT,
                line_number INTEGER,
                snippet TEXT,
                entropy REAL,
                explanation TEXT,
                remediation_json TEXT,
                status TEXT DEFAULT 'open',
                commit_hash TEXT,
                commit_author TEXT,
                commit_date TEXT,
                llm_explanation TEXT,
                FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def save_setting(key: str, value: dict[str, Any] | list[Any] | str | float | int) -> None:
    payload = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(payload)),
        )


def load_setting(key: str, default: Any) -> Any:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if not row:
        return default
    raw = row["value"]
    if isinstance(default, str):
        return raw
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default


def ingest_report(report_data: dict[str, Any], source: str, repo_path: str) -> int:
    findings = report_data.get("findings", [])
    summary = report_data.get("summary") or {}
    scanned_commits = len({f.get("file_path", "") for f in findings if "@" in str(f.get("file_path", ""))})
    scanned_files = len({f.get("file_path", "") for f in findings})

    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO scan_runs(
                repo_path, source, started_at, finished_at, status, total_findings,
                scanned_files, scanned_commits, summary_json, report_json
            ) VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?)
            """,
            (
                repo_path,
                source,
                report_data.get("scanned_at", now_iso()),
                now_iso(),
                len(findings),
                scanned_files,
                scanned_commits,
                json.dumps(summary, ensure_ascii=False),
                json.dumps(report_data, ensure_ascii=False),
            ),
        )
        run_id = int(cur.lastrowid)
        for finding in findings:
            file_path = str(finding.get("file_path", ""))
            commit_hash = None
            if "@" in file_path:
                file_path, commit_hash = file_path.rsplit("@", 1)
            conn.execute(
                """
                INSERT INTO findings(
                    scan_run_id, severity, secret_type, detector, file_path, line_number,
                    snippet, entropy, explanation, remediation_json, commit_hash, commit_author, commit_date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    finding.get("severity", "low"),
                    finding.get("secret_type", "unknown"),
                    finding.get("detector", "regex"),
                    file_path,
                    int(finding.get("line_number", 0)),
                    finding.get("snippet", ""),
                    finding.get("entropy"),
                    finding.get("explanation", ""),
                    json.dumps(finding.get("remediation", []), ensure_ascii=False),
                    commit_hash,
                    finding.get("commit_author"),
                    finding.get("commit_date"),
                ),
            )
    return run_id


def _is_secrethawk_report(data: dict[str, Any]) -> bool:
    findings = data.get("findings")
    return isinstance(findings, list) and "repository" in data


def _scan_count() -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM scan_runs").fetchone()
    return int(row["c"] if row else 0)


def _report_already_ingested(report_data: dict[str, Any]) -> bool:
    report_payload = json.dumps(report_data, ensure_ascii=False, sort_keys=True)
    with get_conn() as conn:
        row = conn.execute("SELECT 1 FROM scan_runs WHERE report_json = ? LIMIT 1", (report_payload,)).fetchone()
    return row is not None


def _auto_import_reports_if_needed(base_dir: Path | None = None, force: bool = False) -> int:
    if not force and _scan_count() > 0:
        return 0

    root = base_dir or Path.cwd()
    imported = 0
    seen_paths: set[Path] = set()

    for pattern in AUTO_IMPORT_GLOBS:
        for candidate in root.glob(pattern):
            if candidate in seen_paths or not candidate.is_file():
                continue
            seen_paths.add(candidate)
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict) or not _is_secrethawk_report(data):
                continue
            if _report_already_ingested(data):
                continue
            repo_path = str(data.get("repository") or candidate.parent)
            ingest_report(data, source="auto_import_json", repo_path=repo_path)
            imported += 1
    return imported


def _layout(title: str, body: str) -> str:
    return f"""
    <!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <title>{escape(title)} - SecretHawk Web</title>
      <style>
        body {{ font-family: Arial, sans-serif; margin: 0; background: #fafafa; color: #222; }}
        nav {{ background: #111827; padding: 12px 18px; }}
        nav a {{ color: #fff; text-decoration: none; margin-right: 14px; font-size: 14px; }}
        main {{ padding: 16px 24px; max-width: 1200px; margin: auto; }}
        .grid {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 10px; margin: 14px 0; }}
        .card {{ background: #fff; border: 1px solid #e5e7eb; padding: 12px; border-radius: 8px; }}
        table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e5e7eb; }}
        th, td {{ border-bottom: 1px solid #ececec; text-align: left; padding: 8px; font-size: 13px; }}
        th {{ background: #f3f4f6; }}
        .sev-critical {{ color: #b91c1c; font-weight: bold; }}
        .sev-high {{ color: #92400e; font-weight: bold; }}
        .sev-medium {{ color: #1d4ed8; }}
        .pill {{ background: #e5e7eb; border-radius: 999px; padding: 3px 8px; font-size: 12px; }}
        form.inline {{ display:inline; }}
        textarea, input, select {{ width: 100%; padding: 8px; margin: 6px 0 10px; box-sizing: border-box; }}
        button {{ padding: 8px 12px; border: none; border-radius: 6px; cursor: pointer; background:#111827; color:#fff; }}
      </style>
    </head>
    <body>
      <nav>
        <a href="/">Dashboard</a>
        <a href="/findings">Findings</a>
        <a href="/scans">Scan History</a>
        <a href="/git-history-leaks">Git History Leaks</a>
        <a href="/settings">Settings</a>
        <a href="/notifications">Notifications</a>
      </nav>
      <main>{body}</main>
    </body>
    </html>
    """


def _severity_class(sev: str) -> str:
    return f"sev-{sev}" if sev in {"critical", "high", "medium"} else ""


def _risk_chart_data(rows: list[sqlite3.Row]) -> str:
    counts = Counter(row["secret_type"] for row in rows)
    return " ".join(f"<span class='pill'>{escape(k)}: {v}</span>" for k, v in counts.most_common(8))


def _top_files_data(rows: list[sqlite3.Row]) -> str:
    counts = Counter(row["file_path"] for row in rows)
    items = "".join(f"<li>{escape(k)} — {v}</li>" for k, v in counts.most_common(10))
    return f"<ul>{items}</ul>"


def _run_scan_async(run_id: int, repo_path: str, entropy_threshold: float, scan_history: bool, max_commits: int | None) -> None:
    json_path = Path(tempfile.gettempdir()) / f"secrethawk-web-{run_id}.json"
    cmd = [
        "secrethawk",
        repo_path,
        "--json-out",
        str(json_path),
        "--entropy-threshold",
        str(entropy_threshold),
        "--no-color",
        "--no-progress",
    ]
    if scan_history:
        cmd.append("--scan-history")
    if max_commits:
        cmd.extend(["--max-commits", str(max_commits)])

    with get_conn() as conn:
        conn.execute("UPDATE scan_runs SET status='running', status_message=? WHERE id=?", ("Scanning...", run_id))

    process = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if process.returncode not in (0, 2) or not json_path.exists():
        with get_conn() as conn:
            conn.execute(
                "UPDATE scan_runs SET status='failed', finished_at=?, status_message=? WHERE id=?",
                (now_iso(), process.stderr[-4000:], run_id),
            )
        return

    report_data = json.loads(json_path.read_text(encoding="utf-8"))
    findings = report_data.get("findings", [])
    summary = report_data.get("summary") or {}

    with get_conn() as conn:
        conn.execute(
            """
            UPDATE scan_runs SET status='completed', finished_at=?, status_message=?, total_findings=?,
                scanned_files=?, scanned_commits=?, summary_json=?, report_json=?
            WHERE id=?
            """,
            (
                now_iso(),
                "Completed",
                len(findings),
                len({f.get("file_path") for f in findings}),
                len({f.get("file_path") for f in findings if "@" in str(f.get("file_path", ""))}),
                json.dumps(summary, ensure_ascii=False),
                json.dumps(report_data, ensure_ascii=False),
                run_id,
            ),
        )
        conn.execute("DELETE FROM findings WHERE scan_run_id=?", (run_id,))
        for finding in findings:
            file_path = str(finding.get("file_path", ""))
            commit_hash = None
            if "@" in file_path:
                file_path, commit_hash = file_path.rsplit("@", 1)
            conn.execute(
                """
                INSERT INTO findings(scan_run_id, severity, secret_type, detector, file_path, line_number, snippet,
                                     entropy, explanation, remediation_json, commit_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    finding.get("severity", "low"),
                    finding.get("secret_type", "unknown"),
                    finding.get("detector", "regex"),
                    file_path,
                    int(finding.get("line_number", 0)),
                    finding.get("snippet", ""),
                    finding.get("entropy"),
                    finding.get("explanation", ""),
                    json.dumps(finding.get("remediation", []), ensure_ascii=False),
                    commit_hash,
                ),
            )


app = FastAPI(title="SecretHawk Web")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    imported_count = _auto_import_reports_if_needed()
    with get_conn() as conn:
        run = conn.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1").fetchone()
        rows = conn.execute("SELECT * FROM findings WHERE scan_run_id=?", (run["id"],)).fetchall() if run else []

    status_note = ""
    if imported_count:
        status_note = f"<p class='card'>Авто-импортировано отчётов CLI: <b>{imported_count}</b>.</p>"

    if not run:
        body = f"""
          <h1>Dashboard</h1>
          <p class='card'>Сканирования в web-базе не найдены. Вы можете запустить скан или загрузить JSON-отчёт CLI.</p>
          {status_note}
          <h3>Start scan</h3>
          <form method='post' action='/api/scan/start'>
            <label>Repository path</label><input name='repo_path' value='.' />
            <label>Entropy threshold</label><input name='entropy_threshold' value='4.5' />
            <label><input type='checkbox' name='scan_history' value='1' /> Scan git history</label>
            <label>Max commits</label><input name='max_commits' value='200' />
            <button type='submit'>Run scan</button>
          </form>
          <h3>Upload JSON report</h3>
          <form method='post' enctype='multipart/form-data' action='/api/reports/upload'>
            <input type='file' name='report_file' />
            <input type='text' name='repo_path' placeholder='repo path' value='.' />
            <button type='submit'>Upload</button>
          </form>
          <h3>Sync existing CLI reports</h3>
          <form method='post' action='/api/reports/sync'>
            <input type='text' name='base_dir' placeholder='base dir (optional)' value='.' />
            <button type='submit'>Sync reports from disk</button>
          </form>
        """
        return _layout("Dashboard", body)

    summary = json.loads(run["summary_json"] or "{}")
    body = f"""
      <h1>Dashboard</h1>
      {status_note}
      <div class='grid'>
        <div class='card'><b>Total findings</b><div>{run['total_findings']}</div></div>
        <div class='card'><b>Critical/High</b><div>{summary.get('critical',0)}/{summary.get('high',0)}</div></div>
        <div class='card'><b>Scanned files</b><div>{run['scanned_files']}</div></div>
        <div class='card'><b>Scanned commits</b><div>{run['scanned_commits']}</div></div>
      </div>
      <div class='card'><b>Last scan:</b> {escape(run['finished_at'] or run['started_at'])}</div>
      <h3>Secret types</h3>
      <div>{_risk_chart_data(rows)}</div>
      <h3>Top files</h3>
      {_top_files_data(rows)}
      <hr/>
      <h3>Start scan</h3>
      <form method='post' action='/api/scan/start'>
        <label>Repository path</label><input name='repo_path' value='{escape(run['repo_path'])}' />
        <label>Entropy threshold</label><input name='entropy_threshold' value='4.5' />
        <label><input type='checkbox' name='scan_history' value='1' /> Scan git history</label>
        <label>Max commits</label><input name='max_commits' value='200' />
        <button type='submit'>Run scan</button>
      </form>
      <h3>Upload JSON report</h3>
      <form method='post' enctype='multipart/form-data' action='/api/reports/upload'>
        <input type='file' name='report_file' />
        <input type='text' name='repo_path' placeholder='repo path' />
        <button type='submit'>Upload</button>
      </form>
      <h3>Sync existing CLI reports</h3>
      <form method='post' action='/api/reports/sync'>
        <input type='text' name='base_dir' placeholder='base dir (optional)' value='.' />
        <button type='submit'>Sync reports from disk</button>
      </form>
    """
    return _layout("Dashboard", body)


@app.get("/findings", response_class=HTMLResponse)
def findings_page(
    severity: str | None = None,
    secret_type: str | None = None,
    filename: str | None = None,
    sort: str = "id",
    order: str = "desc",
) -> str:
    allowed_sort = {"id", "severity", "secret_type", "file_path", "line_number", "entropy"}
    sort_col = sort if sort in allowed_sort else "id"
    direction = "ASC" if order == "asc" else "DESC"

    query = "SELECT * FROM findings WHERE 1=1"
    params: list[Any] = []
    if severity:
        query += " AND severity=?"
        params.append(severity)
    if secret_type:
        query += " AND secret_type=?"
        params.append(secret_type)
    if filename:
        query += " AND file_path LIKE ?"
        params.append(f"%{filename}%")
    query += f" ORDER BY {sort_col} {direction}"

    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()

    table_rows = []
    for row in rows:
        sev_cls = _severity_class(row["severity"])
        table_rows.append(
            f"<tr>"
            f"<td><input type='checkbox' name='finding_ids' value='{row['id']}' form='bulk-form'/></td>"
            f"<td class='{sev_cls}'>{escape(row['severity'] or '')}</td>"
            f"<td>{escape(row['secret_type'] or '')}</td>"
            f"<td>{escape(row['detector'] or '')}</td>"
            f"<td>{escape(row['file_path'] or '')}</td>"
            f"<td>{row['line_number']}</td>"
            f"<td>{'' if row['entropy'] is None else row['entropy']}</td>"
            f"<td><code>{escape((row['snippet'] or '')[:140])}</code></td>"
            f"<td><a href='/findings/{row['id']}'>open</a></td>"
            f"</tr>"
        )

    body = f"""
    <h1>Findings</h1>
    <form method='get'>
      <div class='grid'>
        <div><label>Severity</label><input name='severity' value='{escape(severity or '')}' /></div>
        <div><label>Secret type</label><input name='secret_type' value='{escape(secret_type or '')}' /></div>
        <div><label>Filename</label><input name='filename' value='{escape(filename or '')}' /></div>
        <div><label>Sort</label><input name='sort' value='{escape(sort)}' /></div>
      </div>
      <button type='submit'>Apply filters</button>
    </form>
    <form id='bulk-form' method='post' action='/api/findings/bulk-action'>
      <select name='action'>
        <option value='ignore'>Ignore</option>
        <option value='false_positive'>Mark as false positive</option>
        <option value='jira'>Create Jira issue</option>
      </select>
      <input name='project_key' placeholder='Jira project key' />
      <input name='issue_type' value='Task' />
      <input name='priority' value='Medium' />
      <input name='assignee' placeholder='assignee (optional)' />
      <button type='submit'>Apply for selected</button>
    </form>
    <table>
      <tr><th></th><th>Severity</th><th>Type</th><th>Detector</th><th>File</th><th>Line</th><th>Entropy</th><th>Snippet</th><th></th></tr>
      {''.join(table_rows)}
    </table>
    """
    return _layout("Findings", body)


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(finding_id: int) -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    remediation = json.loads(row["remediation_json"] or "[]")
    rem_html = "".join(f"<li>{escape(item)}</li>" for item in remediation)
    llm_block = (
        f"<h3>AI explanation</h3><div class='card'>{escape(row['llm_explanation'])}</div>" if row["llm_explanation"] else ""
    )
    body = f"""
      <h1>Finding #{row['id']}</h1>
      <p><span class='{_severity_class(row['severity'])}'>{escape(row['severity'])}</span> {escape(row['secret_type'])}</p>
      <p><b>Detector:</b> {escape(row['detector'] or '')}</p>
      <p><b>File:</b> {escape(row['file_path'] or '')}:{row['line_number']}</p>
      <p><b>Entropy:</b> {'' if row['entropy'] is None else row['entropy']}</p>
      <h3>Code context</h3>
      <pre>{escape(row['snippet'] or '')}</pre>
      <h3>Risk explanation</h3><p>{escape(row['explanation'] or '')}</p>
      <h3>Remediation</h3><ul>{rem_html}</ul>
      {llm_block}
      <form method='post' action='/api/findings/{row['id']}/explain-ai'><button>Explain with AI</button></form>
    """
    return _layout("Finding detail", body)


@app.post("/api/findings/{finding_id}/explain-ai")
def explain_with_ai(finding_id: int) -> Response:
    llm_cfg = load_setting("llm", {"enabled": False, "model": "llama3.2:3b", "endpoint": "http://127.0.0.1:11434/api/generate"})
    if not llm_cfg.get("enabled"):
        raise HTTPException(status_code=400, detail="LLM disabled in settings")

    with get_conn() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Finding not found")
        finding = Finding(
            file_path=row["file_path"],
            line_number=row["line_number"],
            detector=row["detector"],
            secret_type=row["secret_type"],
            severity=row["severity"],
            snippet=row["snippet"],
            explanation=row["explanation"] or "",
            remediation=json.loads(row["remediation_json"] or "[]"),
            entropy=row["entropy"],
        )
    updated = explain_finding_with_ollama(finding, model=llm_cfg.get("model", "llama3.2:3b"), endpoint=llm_cfg.get("endpoint", "http://127.0.0.1:11434/api/generate"))
    with get_conn() as conn:
        conn.execute(
            "UPDATE findings SET explanation=?, remediation_json=?, llm_explanation=? WHERE id=?",
            (updated.explanation, json.dumps(updated.remediation, ensure_ascii=False), updated.explanation, finding_id),
        )
    return Response(status_code=303, headers={"Location": f"/findings/{finding_id}"})


@app.post("/api/findings/bulk-action")
def bulk_action(
    request: Request,
    action: str = Form(...),
    finding_ids: list[int] = Form(default=[]),
    project_key: str | None = Form(default=None),
    issue_type: str = Form(default="Task"),
    priority: str = Form(default="Medium"),
    assignee: str | None = Form(default=None),
) -> Response:
    if not finding_ids:
        return Response(status_code=303, headers={"Location": "/findings"})
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM findings WHERE id IN ({','.join('?' for _ in finding_ids)})",
            finding_ids,
        ).fetchall()

    if action in {"ignore", "false_positive"}:
        with get_conn() as conn:
            conn.execute(
                f"UPDATE findings SET status=? WHERE id IN ({','.join('?' for _ in finding_ids)})",
                [action, *finding_ids],
            )
        if action == "ignore":
            _append_ignore_rules(rows)
    elif action == "jira":
        _create_jira_issues(rows, project_key, issue_type, priority, assignee)

    return Response(status_code=303, headers={"Location": "/findings"})


def _append_ignore_rules(rows: list[sqlite3.Row]) -> None:
    by_repo: dict[int, list[str]] = {}
    with get_conn() as conn:
        for row in rows:
            run = conn.execute("SELECT repo_path FROM scan_runs WHERE id=?", (row["scan_run_id"],)).fetchone()
            if not run:
                continue
            by_repo.setdefault(row["scan_run_id"], [])
            by_repo[row["scan_run_id"]].append(f"{row['file_path']}")

    for run_id, patterns in by_repo.items():
        with get_conn() as conn:
            run = conn.execute("SELECT repo_path FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        if not run:
            continue
        repo = Path(run["repo_path"])
        target = repo / ".secretignore"
        existing = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
        merged = sorted(set(existing + patterns))
        target.write_text("\n".join(merged) + "\n", encoding="utf-8")


def _create_jira_issues(rows: list[sqlite3.Row], project_key: str | None, issue_type: str, priority: str, assignee: str | None) -> None:
    cfg = load_setting("jira", {"url": "", "email": "", "api_token": "", "default_project": ""})
    jira_url = cfg.get("url", "").rstrip("/")
    key = project_key or cfg.get("default_project")
    if not jira_url or not key:
        return

    for row in rows:
        description = (
            f"Secret leak detected\n"
            f"Severity: {row['severity']}\n"
            f"Type: {row['secret_type']}\n"
            f"Location: {row['file_path']}:{row['line_number']}\n"
            f"Snippet: {row['snippet']}\n"
            f"Recommendation: {row['explanation']}"
        )
        payload = {
            "fields": {
                "project": {"key": key},
                "summary": f"SecretHawk: {row['severity']} {row['secret_type']} in {row['file_path']}",
                "issuetype": {"name": issue_type},
                "priority": {"name": priority},
                "description": description,
            }
        }
        if assignee:
            payload["fields"]["assignee"] = {"name": assignee}

        auth = f"{cfg.get('email')}:{cfg.get('api_token')}".encode("utf-8")
        import base64

        req = request.Request(
            f"{jira_url}/rest/api/2/issue",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {base64.b64encode(auth).decode('utf-8')}",
            },
        )
        try:
            with request.urlopen(req, timeout=10):
                pass
        except Exception:
            continue


@app.post("/api/reports/upload")
async def upload_report(report_file: UploadFile = File(...), repo_path: str = Form(default=".")) -> Response:
    payload = json.loads((await report_file.read()).decode("utf-8"))
    run_id = ingest_report(payload, source="uploaded_json", repo_path=repo_path)
    return Response(status_code=303, headers={"Location": f"/scans/{run_id}"})


@app.post("/api/reports/sync")
def sync_reports(base_dir: str = Form(default=".")) -> Response:
    imported = _auto_import_reports_if_needed(Path(base_dir).resolve(), force=True)
    if imported == 0 and _scan_count() == 0:
        return Response(status_code=303, headers={"Location": "/"})
    return Response(status_code=303, headers={"Location": "/scans"})


@app.post("/api/scan/start")
def start_scan(
    repo_path: str = Form(...),
    entropy_threshold: float = Form(default=4.5),
    scan_history: str | None = Form(default=None),
    max_commits: int | None = Form(default=None),
) -> Response:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scan_runs(repo_path, source, started_at, status, status_message) VALUES (?, 'web_cli', ?, 'queued', 'Queued')",
            (repo_path, now_iso()),
        )
        run_id = int(cur.lastrowid)
    th = threading.Thread(
        target=_run_scan_async,
        args=(run_id, repo_path, entropy_threshold, bool(scan_history), max_commits),
        daemon=True,
    )
    th.start()
    return Response(status_code=303, headers={"Location": f"/scans/{run_id}"})


@app.get("/api/scans/{run_id}/status")
def scan_status(run_id: int) -> JSONResponse:
    with get_conn() as conn:
        run = conn.execute("SELECT id, status, status_message, total_findings, finished_at FROM scan_runs WHERE id=?", (run_id,)).fetchone()
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(dict(run))


@app.get("/scans", response_class=HTMLResponse)
def scans_history() -> str:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 100").fetchall()

    body_rows = []
    for row in rows:
        summary = json.loads(row["summary_json"] or "{}")
        body_rows.append(
            f"<tr><td>{row['id']}</td><td>{escape(row['started_at'])}</td><td>{escape(row['status'])}</td>"
            f"<td>{row['total_findings']}</td><td>{summary.get('critical',0)}/{summary.get('high',0)}/{summary.get('medium',0)}/{summary.get('low',0)}</td>"
            f"<td><a href='/scans/{row['id']}'>Open</a></td></tr>"
        )
    body = f"""
    <h1>Scan history</h1>
    <table>
      <tr><th>ID</th><th>Date</th><th>Status</th><th>Total</th><th>Severity</th><th>Report</th></tr>
      {''.join(body_rows)}
    </table>
    """
    return _layout("Scans", body)


@app.get("/scans/{run_id}", response_class=HTMLResponse)
def scan_detail(run_id: int) -> str:
    with get_conn() as conn:
        run = conn.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")

    body = f"""
      <h1>Scan #{run['id']}</h1>
      <p><b>Status:</b> {escape(run['status'])} — {escape(run['status_message'] or '')}</p>
      <p><b>Repository:</b> {escape(run['repo_path'])}</p>
      <p><b>Total findings:</b> {run['total_findings']}</p>
      <p><a href='/findings'>Open all findings</a></p>
      <p>Export: <a href='/api/export/{run_id}?format=json'>JSON</a> | <a href='/api/export/{run_id}?format=html'>HTML</a> | <a href='/api/export/{run_id}?format=sarif'>SARIF</a></p>
      <script>
        setInterval(async () => {{
          const r = await fetch('/api/scans/{run_id}/status');
          const data = await r.json();
          if (data.status === 'running' || data.status === 'queued') {{ location.reload(); }}
        }}, 3000);
      </script>
    """
    return _layout("Scan detail", body)


@app.get("/git-history-leaks", response_class=HTMLResponse)
def git_history_leaks() -> str:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM findings WHERE commit_hash IS NOT NULL ORDER BY id DESC").fetchall()
    trs = []
    for row in rows:
        trs.append(
            f"<tr><td>{escape(row['commit_hash'] or '')[:12]}</td><td>{escape(row['commit_author'] or '')}</td><td>{escape(row['commit_date'] or '')}</td>"
            f"<td>{escape(row['file_path'] or '')}</td><td>{row['line_number']}</td><td><a href='/findings/{row['id']}'>Open</a></td></tr>"
        )
    body = f"""
      <h1>Git History Leaks</h1>
      <table>
        <tr><th>Commit</th><th>Author</th><th>Date</th><th>File</th><th>Line</th><th></th></tr>
        {''.join(trs)}
      </table>
    """
    return _layout("Git history leaks", body)


@app.get("/settings", response_class=HTMLResponse)
def settings_page() -> str:
    scanner = load_setting("scanner", {"entropy_threshold": 4.5, "fail_on": "high", "exclude_dirs": [], "ignore_patterns": []})
    jira = load_setting("jira", {"url": "", "email": "", "api_token": "", "default_project": ""})
    llm = load_setting("llm", {"enabled": False, "model": "llama3.2:3b", "endpoint": "http://127.0.0.1:11434/api/generate"})
    body = f"""
      <h1>Settings</h1>
      <form method='post' action='/settings'>
        <h3>Scanner config (nuclear.toml)</h3>
        <label>Entropy threshold</label><input name='entropy_threshold' value='{scanner.get('entropy_threshold', 4.5)}' />
        <label>Fail on</label><input name='fail_on' value='{escape(scanner.get('fail_on', 'high'))}' />
        <label>Excluded directories (comma separated)</label><input name='exclude_dirs' value='{escape(','.join(scanner.get('exclude_dirs', [])))}' />
        <label>Ignore patterns (comma separated)</label><input name='ignore_patterns' value='{escape(','.join(scanner.get('ignore_patterns', [])))}' />

        <h3>Jira</h3>
        <label>URL</label><input name='jira_url' value='{escape(jira.get('url', ''))}' />
        <label>Email</label><input name='jira_email' value='{escape(jira.get('email', ''))}' />
        <label>API token</label><input name='jira_api_token' value='{escape(jira.get('api_token', ''))}' />
        <label>Default project key</label><input name='jira_default_project' value='{escape(jira.get('default_project', ''))}' />

        <h3>Local LLM (Ollama)</h3>
        <label>Enabled (true/false)</label><input name='llm_enabled' value='{str(llm.get('enabled', False)).lower()}' />
        <label>Model</label><input name='llm_model' value='{escape(llm.get('model', 'llama3.2:3b'))}' />
        <label>Endpoint</label><input name='llm_endpoint' value='{escape(llm.get('endpoint', 'http://127.0.0.1:11434/api/generate'))}' />
        <button type='submit'>Save settings</button>
      </form>
    """
    return _layout("Settings", body)


@app.post("/settings")
def save_settings(
    entropy_threshold: float = Form(...),
    fail_on: str = Form(...),
    exclude_dirs: str = Form(default=""),
    ignore_patterns: str = Form(default=""),
    jira_url: str = Form(default=""),
    jira_email: str = Form(default=""),
    jira_api_token: str = Form(default=""),
    jira_default_project: str = Form(default=""),
    llm_enabled: str = Form(default="false"),
    llm_model: str = Form(default="llama3.2:3b"),
    llm_endpoint: str = Form(default="http://127.0.0.1:11434/api/generate"),
) -> Response:
    scanner_cfg = {
        "entropy_threshold": entropy_threshold,
        "fail_on": fail_on,
        "exclude_dirs": [item.strip() for item in exclude_dirs.split(",") if item.strip()],
        "ignore_patterns": [item.strip() for item in ignore_patterns.split(",") if item.strip()],
    }
    save_setting("scanner", scanner_cfg)
    save_setting(
        "jira",
        {
            "url": jira_url,
            "email": jira_email,
            "api_token": jira_api_token,
            "default_project": jira_default_project,
        },
    )
    save_setting(
        "llm",
        {
            "enabled": llm_enabled.lower() == "true",
            "model": llm_model,
            "endpoint": llm_endpoint,
        },
    )

    toml_text = (
        "[secrethawk]\n"
        f"entropy_threshold = {entropy_threshold}\n"
        f"fail_on = \"{fail_on}\"\n"
        f"exclude_dirs = {json.dumps(scanner_cfg['exclude_dirs'])}\n"
        f"ignore_patterns = {json.dumps(scanner_cfg['ignore_patterns'])}\n"
    )
    Path("nuclear.toml").write_text(toml_text, encoding="utf-8")

    ignore_rules = scanner_cfg["ignore_patterns"]
    if ignore_rules:
        Path(".nuclearignore").write_text("\n".join(ignore_rules) + "\n", encoding="utf-8")

    return Response(status_code=303, headers={"Location": "/settings"})


@app.get("/notifications", response_class=HTMLResponse)
def notifications_page() -> str:
    cfg = load_setting("telegram", {"bot_token": "", "chat_id": "", "notify_severity": ["high", "critical"]})
    body = f"""
      <h1>Notifications</h1>
      <form method='post' action='/notifications'>
        <label>Telegram bot token</label><input name='bot_token' value='{escape(cfg.get('bot_token',''))}' />
        <label>Telegram chat id</label><input name='chat_id' value='{escape(cfg.get('chat_id',''))}' />
        <label>Notify severities (comma separated)</label><input name='notify_severity' value='{escape(','.join(cfg.get('notify_severity',['high','critical'])))}' />
        <button type='submit'>Save</button>
      </form>
      <form method='post' action='/api/notifications/test'>
        <button type='submit'>Send test notification</button>
      </form>
    """
    return _layout("Notifications", body)


@app.post("/notifications")
def save_notifications(bot_token: str = Form(...), chat_id: str = Form(...), notify_severity: str = Form(default="high,critical")) -> Response:
    save_setting(
        "telegram",
        {
            "bot_token": bot_token,
            "chat_id": chat_id,
            "notify_severity": [item.strip() for item in notify_severity.split(",") if item.strip()],
        },
    )
    return Response(status_code=303, headers={"Location": "/notifications"})


@app.post("/api/notifications/test")
def send_test_notification() -> Response:
    cfg = load_setting("telegram", {"bot_token": "", "chat_id": ""})
    if not cfg.get("bot_token") or not cfg.get("chat_id"):
        raise HTTPException(status_code=400, detail="Telegram settings are incomplete")

    payload = {
        "chat_id": cfg["chat_id"],
        "text": "✅ SecretHawk test notification: Telegram integration is configured.",
    }
    req = request.Request(
        f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with request.urlopen(req, timeout=10):
            pass
    except error.URLError as exc:
        raise HTTPException(status_code=502, detail=f"Telegram request failed: {exc}") from exc

    return Response(status_code=303, headers={"Location": "/notifications"})


@app.get("/api/export/{run_id}")
def export_report(run_id: int, format: str = Query(default="json")) -> Response:
    with get_conn() as conn:
        run = conn.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        rows = conn.execute("SELECT * FROM findings WHERE scan_run_id=?", (run_id,)).fetchall()
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")

    if format == "json":
        return Response(run["report_json"], media_type="application/json")

    if format == "html":
        trs = "".join(
            f"<tr><td>{escape(r['severity'] or '')}</td><td>{escape(r['secret_type'] or '')}</td><td>{escape(r['file_path'] or '')}:{r['line_number']}</td><td>{escape((r['snippet'] or '')[:200])}</td></tr>"
            for r in rows
        )
        html = f"<html><body><h1>SecretHawk report #{run_id}</h1><table border='1'><tr><th>Severity</th><th>Type</th><th>Location</th><th>Snippet</th></tr>{trs}</table></body></html>"
        return HTMLResponse(html)

    if format == "sarif":
        results = []
        for row in rows:
            results.append(
                {
                    "ruleId": row["secret_type"],
                    "level": row["severity"],
                    "message": {"text": row["explanation"] or row["snippet"]},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": row["file_path"]},
                                "region": {"startLine": row["line_number"]},
                            }
                        }
                    ],
                }
            )
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "SecretHawk"}}, "results": results}],
        }
        return Response(json.dumps(sarif, ensure_ascii=False, indent=2), media_type="application/json")

    return PlainTextResponse("Unsupported format", status_code=400)


def run() -> None:
    import uvicorn

    uvicorn.run("secrethawk.webapp:app", host="127.0.0.1", port=8000, reload=False)
