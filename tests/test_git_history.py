from pathlib import Path
from types import SimpleNamespace
import re

from secrethawk.git_history import list_commits, scan_git_history
from secrethawk.patterns import SecretPattern


def test_list_commits_handles_none_stdout(monkeypatch, tmp_path: Path) -> None:
    def fake_run(cmd: list[str], repo_root: Path):
        return SimpleNamespace(returncode=0, stdout=None)

    monkeypatch.setattr("secrethawk.git_history._run_git", fake_run)

    commits = list_commits(tmp_path)
    assert commits == []


def test_scan_git_history_decodes_bytes_with_replacement(monkeypatch, tmp_path: Path) -> None:
    calls = {"n": 0}

    def fake_run(cmd: list[str], repo_root: Path):
        calls["n"] += 1
        if cmd[:3] == ["git", "rev-list", "--all"]:
            return SimpleNamespace(returncode=0, stdout=b"abc123\n")
        # invalid utf-8 byte 0x98 in content + valid added line with AWS key
        stdout = b"+++ b/app.py\n@@ -0,0 +1,1 @@\n+AKIA1234567890ABCDEF\x98\n"
        return SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr("secrethawk.git_history._run_git", fake_run)

    findings = scan_git_history(tmp_path, entropy_threshold=4.5)
    assert any(f.secret_type == "aws_access_key" for f in findings)


def test_scan_git_history_supports_custom_patterns(monkeypatch, tmp_path: Path) -> None:
    def fake_run(cmd: list[str], repo_root: Path):
        if cmd[:3] == ["git", "rev-list", "--all"]:
            return SimpleNamespace(returncode=0, stdout=b"abc123\n")
        stdout = b"+++ b/app.py\n@@ -0,0 +1,1 @@\n+INT_ABCDEF1234\n"
        return SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr("secrethawk.git_history._run_git", fake_run)

    patterns = (SecretPattern(name="internal", pattern=re.compile(r"INT_[A-Z0-9]{10}"), severity="medium"),)
    findings = scan_git_history(tmp_path, entropy_threshold=4.5, extra_patterns=patterns)
    assert any(f.secret_type == "internal" for f in findings)
