"""CLI entrypoint for secret scanning."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .git_history import scan_git_history
from .models import ScanReport
from .notifier import send_telegram_alert
from .scanner import DEFAULT_IGNORES, iter_files, list_staged_files, scan_files


def render_table(report: ScanReport) -> str:
    lines = []
    summary = report.by_severity()
    lines.append(
        "Summary: "
        + ", ".join(f"{severity}={count}" for severity, count in summary.items())
        + f", total={len(report.findings)}"
    )
    lines.append("-" * 120)
    lines.append(f"{'Severity':<10} {'Detector':<8} {'Type':<24} {'Location':<45} Snippet")
    lines.append("-" * 120)
    for finding in report.findings:
        location = f"{finding.file_path}:{finding.line_number}"
        lines.append(
            f"{finding.severity:<10} {finding.detector:<8} {finding.secret_type:<24} {location:<45} {finding.snippet}"
        )
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect secrets in code repositories")
    parser.add_argument("path", nargs="?", default=".", help="Path to repository or project")
    parser.add_argument("--entropy-threshold", type=float, default=4.5)
    parser.add_argument("--json-out", help="Write report JSON to file")
    parser.add_argument("--only-staged", action="store_true", help="Scan only staged files")
    parser.add_argument("--scan-history", action="store_true", help="Scan git history")
    parser.add_argument("--max-commits", type=int, default=None, help="Max commits for history scan")
    parser.add_argument("--telegram-bot-token", default=None)
    parser.add_argument("--telegram-chat-id", default=None)
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "never"],
        default="high",
        help="Fail process when this severity or higher is found",
    )
    return parser.parse_args(argv)


def should_fail(report: ScanReport, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    threshold = rank[fail_on]
    return any(rank.get(f.severity, 0) >= threshold for f in report.findings)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.path).resolve()

    if args.only_staged:
        files = list_staged_files(root)
    else:
        files = iter_files(root, DEFAULT_IGNORES)

    findings = scan_files(files, base_root=root, entropy_threshold=args.entropy_threshold)

    if args.scan_history:
        findings.extend(
            scan_git_history(root, entropy_threshold=args.entropy_threshold, max_commits=args.max_commits)
        )

    report = ScanReport.create(repository=str(root), findings=findings)

    print(render_table(report))

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

    if args.telegram_bot_token and args.telegram_chat_id:
        send_telegram_alert(
            bot_token=args.telegram_bot_token,
            chat_id=args.telegram_chat_id,
            repo=root.name,
            findings=findings,
        )

    return 2 if should_fail(report, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
