"""CLI entrypoint for secret scanning."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    tomllib = None

from .git_history import scan_git_history
from .local_llm import explain_finding_with_ollama, summarize_findings_with_ollama
from .models import ScanReport
from .notifier import send_telegram_alert
from .scanner import DEFAULT_IGNORES, iter_files, list_staged_files, load_ignore_patterns, scan_files
from .telegram_config import load_telegram_credentials, save_telegram_credentials

SEVERITY_COLORS = {
    "critical": "\033[31m",  # red
    "high": "\033[33m",  # yellow
    "medium": "\033[34m",  # blue
    "low": "",
}
RESET = "\033[0m"
MASK_CANDIDATE_RE = re.compile(r"[A-Za-z0-9_./+\-=]{16,}")


def _colorize(text: str, severity: str, enabled: bool) -> str:
    if not enabled:
        return text
    color = SEVERITY_COLORS.get(severity, "")
    if not color:
        return text
    return f"{color}{text}{RESET}"


def mask_sensitive_text(snippet: str) -> str:
    def _looks_sensitive(candidate: str) -> bool:
        if len(candidate) < 16:
            return False
        if candidate.isalpha():
            return False
        return True

    def _replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if not _looks_sensitive(candidate):
            return candidate
        return f"{candidate[:4]}**{candidate[-4:]}"

    return MASK_CANDIDATE_RE.sub(_replace, snippet)


def render_guidance_summary(report: ScanReport) -> str:
    if not report.findings:
        return ""
    top = sorted(report.findings, key=lambda item: {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(item.severity, 0), reverse=True)[0]
    fix_summary = "; ".join(top.remediation[:2])
    return f"Why: {top.explanation}\nFix: {fix_summary}"


def render_table(report: ScanReport, use_color: bool = True, explain_mode: str = "summary") -> str:
    lines = []
    summary = report.by_severity()
    lines.append(
        "Summary: "
        + ", ".join(f"{severity}={count}" for severity, count in summary.items())
        + f", total={len(report.findings)}"
    )
    lines.append("-" * 120)
    lines.append(f"{'Severity':<10} {'Detector':<8} {'Type':<24} {'Location':<45} Details")
    lines.append("-" * 120)
    mode = explain_mode if explain_mode in {"summary", "each", "none"} else "summary"

    for finding in report.findings:
        location = f"{finding.file_path}:{finding.line_number}"
        severity = _colorize(f"{finding.severity:<10}", finding.severity, use_color)
        lines.append(
            f"{severity} {finding.detector:<8} {finding.secret_type:<24} {location:<45} "
            f"{mask_sensitive_text(finding.snippet)}"
        )

        if mode == "each":
            fix_summary = "; ".join(finding.remediation[:2])
            lines.append(f"{'':<10} {'':<8} {'':<24} {'':<45} Hint: {finding.explanation} | Fix: {fix_summary}")

    if mode == "summary" and report.findings:
        lines.append("-" * 120)
        lines.append(render_guidance_summary(report))

    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect secrets in code repositories")
    parser.add_argument("path", nargs="?", default=".", help="Path to repository or project")
    parser.add_argument("--config", default="nuclear.toml", help="Path to TOML config file")
    parser.add_argument("--entropy-threshold", type=float, default=None)
    parser.add_argument("--json-out", help="Write report JSON to file")
    parser.add_argument("--only-staged", action="store_true", help="Scan only staged files")
    parser.add_argument("--scan-history", action="store_true", help="Scan git history")
    parser.add_argument("--max-commits", type=int, default=None, help="Max commits for history scan")
    parser.add_argument("--explain-with-llm", action="store_true", help="Enrich findings with local LLM")
    parser.add_argument(
        "--explain",
        choices=["summary", "each", "none"],
        default="summary",
        help="How to show guidance in CLI output",
    )
    parser.add_argument("--llm-model", default="llama3.2:3b", help="Local model name for Ollama")
    parser.add_argument("--llm-endpoint", default="http://127.0.0.1:11434/api/generate", help="Local LLM endpoint")
    parser.add_argument("--telegram-bot-token", "--token", dest="telegram_bot_token", default=None)
    parser.add_argument("--telegram-chat-id", "--id", dest="telegram_chat_id", default=None)
    parser.add_argument("--tg", action="store_true", help="Send Telegram summary using saved token/chat id")
    parser.add_argument("--ai", action="store_true", help="Include local AI summary in Telegram message")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in table output")
    parser.add_argument("--no-progress", action="store_true", help="Disable file scanning progress indicator")
    parser.add_argument("--web", action="store_true", help="Start local web UI instead of running scan")
    parser.add_argument("--web-host", default="127.0.0.1", help="Web UI host")
    parser.add_argument("--web-port", type=int, default=8000, help="Web UI port")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "never"],
        default=None,
        help="Fail process when this severity or higher is found",
    )
    return parser.parse_args(argv)


def load_project_config(root: Path, config_path: str) -> dict:
    path = root / config_path
    if not path.exists() or not path.is_file() or tomllib is None:
        return {}
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except OSError:
        return {}
    return raw.get("secrethawk", raw)


def should_fail(report: ScanReport, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    threshold = rank[fail_on]
    return any(rank.get(f.severity, 0) >= threshold for f in report.findings)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.web:
        from .webapp import run as run_webapp

        run_webapp(host=args.web_host, port=args.web_port)
        return 0

    root = Path(args.path).resolve()
    config = load_project_config(root, args.config)

    entropy_threshold = args.entropy_threshold
    if entropy_threshold is None:
        entropy_threshold = float(config.get("entropy_threshold", 4.5))

    fail_on = args.fail_on or config.get("fail_on", "high")
    exclude_dirs = set(DEFAULT_IGNORES)
    exclude_dirs.update(config.get("exclude_dirs", []))

    ignore_patterns = load_ignore_patterns(root)
    ignore_patterns.extend(config.get("ignore_patterns", []))

    if args.only_staged:
        files = list_staged_files(root)
    else:
        files = iter_files(root, exclude_dirs, ignore_patterns)

    def _print_progress(current: int, total: int, path: Path) -> None:
        if args.no_progress:
            return
        print(f"\rScanning files: {current}/{total} ({path.name})", end="", file=sys.stderr, flush=True)

    findings = scan_files(
        files,
        base_root=root,
        entropy_threshold=entropy_threshold,
        progress_callback=_print_progress if files else None,
    )
    if files and not args.no_progress:
        print(file=sys.stderr)

    if args.scan_history:
        max_commits = args.max_commits if args.max_commits is not None else config.get("max_commits")
        findings.extend(
            scan_git_history(root, entropy_threshold=entropy_threshold, max_commits=max_commits)
        )

    report = ScanReport.create(repository=str(root), findings=findings)

    if args.explain_with_llm:
        for finding in report.findings:
            explain_finding_with_ollama(finding, model=args.llm_model, endpoint=args.llm_endpoint)

    print(render_table(report, use_color=not args.no_color, explain_mode=args.explain))

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

    if args.telegram_bot_token and args.telegram_chat_id:
        save_telegram_credentials(args.telegram_bot_token, str(args.telegram_chat_id))

    saved_token, saved_chat_id = load_telegram_credentials()
    tg_token = args.telegram_bot_token or saved_token
    tg_chat_id = args.telegram_chat_id or saved_chat_id

    if args.tg and tg_token and tg_chat_id:
        ai_summary = None
        if args.ai:
            ai_summary = summarize_findings_with_ollama(
                findings,
                model=args.llm_model,
                endpoint=args.llm_endpoint,
            )
        send_telegram_alert(
            bot_token=tg_token,
            chat_id=str(tg_chat_id),
            repo=root.name,
            findings=findings,
            ai_summary=ai_summary,
            scanned_at=report.scanned_at,
        )

    return 2 if should_fail(report, fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
