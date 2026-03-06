"""Filesystem and git-aware scanner."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .analyzer import analyze_line
from .models import Finding

DEFAULT_IGNORES = {
    ".git",
    ".idea",
    ".vscode",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
    "__pycache__",
}
TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rs",
    ".env",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".conf",
    ".md",
    ".txt",
    ".sh",
    ".cfg",
}


def is_probably_text(file_path: Path) -> bool:
    if file_path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    try:
        chunk = file_path.read_bytes()[:1024]
    except OSError:
        return False
    return b"\x00" not in chunk


def iter_files(root: Path, ignore_dirs: set[str]) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in ignore_dirs for part in path.parts):
            continue
        if path.is_file() and is_probably_text(path):
            files.append(path)
    return files


def scan_files(paths: list[Path], base_root: Path, entropy_threshold: float) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in paths:
        try:
            with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line_number, line in enumerate(handle, start=1):
                    findings.extend(
                        analyze_line(
                            file_path=str(file_path.relative_to(base_root)),
                            line_number=line_number,
                            line=line,
                            entropy_threshold=entropy_threshold,
                        )
                    )
        except OSError:
            continue
    return findings


def list_staged_files(repo_root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRT"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    files = [repo_root / line.strip() for line in result.stdout.splitlines() if line.strip()]
    return [p for p in files if p.exists() and p.is_file() and is_probably_text(p)]
