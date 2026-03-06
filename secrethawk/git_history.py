"""Git history scanning utilities."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .analyzer import analyze_line
from .models import Finding


def list_commits(repo_root: Path, limit: int | None = None) -> list[str]:
    cmd = ["git", "rev-list", "--all"]
    if limit:
        cmd.extend(["--max-count", str(limit)])
    result = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def scan_git_history(repo_root: Path, entropy_threshold: float, max_commits: int | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for commit in list_commits(repo_root, max_commits):
        show = subprocess.run(
            ["git", "show", "--pretty=format:", "--unified=0", commit],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        if show.returncode != 0:
            continue

        current_file = "unknown"
        new_line_no = 0
        for line in show.stdout.splitlines():
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
