"""Git history scanning utilities."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .analyzer import analyze_line
from .models import Finding


def _decode_output(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def _run_git(cmd: list[str], repo_root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=repo_root,
        capture_output=True,
        text=False,
        check=False,
    )


def list_commits(repo_root: Path, limit: int | None = None) -> list[str]:
    cmd = ["git", "rev-list", "--all"]
    if limit:
        cmd.extend(["--max-count", str(limit)])
    result = _run_git(cmd, repo_root)
    if result.returncode != 0:
        return []
    stdout = _decode_output(result.stdout)
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def scan_git_history(repo_root: Path, entropy_threshold: float, max_commits: int | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for commit in list_commits(repo_root, max_commits):
        show = _run_git(
            ["git", "show", "--pretty=format:", "--unified=0", commit],
            repo_root,
        )
        if show.returncode != 0:
            continue

        current_file = "unknown"
        new_line_no = 0
        show_output = _decode_output(show.stdout)
        for line in show_output.splitlines():
            if line.startswith("+++ b/"):
                current_file = line.removeprefix("+++ b/")
            elif line.startswith("@@"):
                # example: @@ -1,0 +3,2 @@
                try:
                    after_plus = line.split("+", 1)[1]
                    line_info = after_plus.split(" ", 1)[0]
                    new_line_no = int(line_info.split(",")[0])
                except (IndexError, ValueError):
                    new_line_no = 0
            elif line.startswith("+") and not line.startswith("+++"):
                code_line = line[1:]
                found = analyze_line(
                    file_path=f"{current_file}@{commit[:12]}",
                    line_number=max(new_line_no, 1),
                    line=code_line,
                    entropy_threshold=entropy_threshold,
                )
                findings.extend(found)
                new_line_no += 1
            elif line.startswith("-") and not line.startswith("---"):
                continue
            else:
                if new_line_no:
                    new_line_no += 1
    return findings
