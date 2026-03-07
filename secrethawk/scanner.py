"""Filesystem and git-aware scanner."""

from __future__ import annotations

import fnmatch
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

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


ProgressCallback = Callable[[int, int, Path], None]


def _read_ignore_file(path: Path) -> list[str]:
    if not path.exists() or not path.is_file():
        return []
    patterns: list[str] = []
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                patterns.append(line.rstrip("/"))
    except OSError:
        return []
    return patterns


def load_ignore_patterns(root: Path, filename: str = ".nuclearignore") -> list[str]:
    patterns = _read_ignore_file(root / filename)
    for alias in (".secretignore",):
        patterns.extend(_read_ignore_file(root / alias))
    return patterns


def is_probably_text(file_path: Path) -> bool:
    if file_path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    try:
        chunk = file_path.read_bytes()[:1024]
    except OSError:
        return False
    return b"\x00" not in chunk


def _matches_ignore(path: Path, root: Path, ignore_dirs: set[str], ignore_patterns: list[str]) -> bool:
    if any(part in ignore_dirs for part in path.parts):
        return True

    rel_posix = path.relative_to(root).as_posix()
    for pattern in ignore_patterns:
        normalized = pattern.lstrip("./")
        if "/" not in normalized:
            if normalized in path.parts:
                return True
        if fnmatch.fnmatch(rel_posix, normalized) or fnmatch.fnmatch(path.name, normalized):
            return True
    return False


def iter_files(root: Path, ignore_dirs: set[str], ignore_patterns: list[str] | None = None) -> list[Path]:
    patterns = ignore_patterns or []
    files: list[Path] = []
    for path in root.rglob("*"):
        if _matches_ignore(path, root, ignore_dirs, patterns):
            continue
        if path.is_file() and is_probably_text(path):
            files.append(path)
    return files


def scan_files(
    paths: list[Path],
    base_root: Path,
    entropy_threshold: float,
    progress_callback: ProgressCallback | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    total = len(paths)

    def _scan_single(file_path: Path) -> list[Finding]:
        local_findings: list[Finding] = []
        try:
            with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line_number, line in enumerate(handle, start=1):
                    local_findings.extend(
                        analyze_line(
                            file_path=str(file_path.relative_to(base_root)),
                            line_number=line_number,
                            line=line,
                            entropy_threshold=entropy_threshold,
                        )
                    )
        except OSError:
            return []
        return local_findings

    with ThreadPoolExecutor() as executor:
        for index, file_findings in enumerate(executor.map(_scan_single, paths), start=1):
            file_path = paths[index - 1]
            findings.extend(file_findings)
            if progress_callback:
                progress_callback(index, total, file_path)

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
