from pathlib import Path

from secrethawk.cli import mask_sensitive_text, render_table
from secrethawk.models import Finding, ScanReport
from secrethawk.scanner import iter_files, load_ignore_patterns


def test_mask_sensitive_text_masks_long_values() -> None:
    source = "token=abcdefghijklmnopqrstuvwxyz123456"
    masked = mask_sensitive_text(source)
    assert masked.startswith("toke")
    assert "3456" in masked
    assert "**" in masked
    assert "***" not in masked
    assert "abcdefghijklmnopqrstuvwxyz123456" not in masked


def test_render_table_prints_hint_on_next_line_with_each_mode() -> None:
    report = ScanReport.create(
        repository=".",
        findings=[
            Finding(
                file_path="app.py",
                line_number=12,
                detector="regex",
                secret_type="aws_access_key",
                severity="critical",
                snippet="token=abcdefghijklmnopqrstuvwxyz123456",
                explanation="Почему это проблема",
                remediation=["Шаг 1", "Шаг 2"],
            )
        ],
    )

    table = render_table(report, use_color=False, explain_mode="each")
    lines = table.splitlines()
    finding_line_index = next(i for i, value in enumerate(lines) if "aws_access_key" in value)
    assert "| Why:" not in lines[finding_line_index]
    assert "Hint:" in lines[finding_line_index + 1]


def test_render_table_prints_single_summary_by_default() -> None:
    report = ScanReport.create(
        repository=".",
        findings=[
            Finding(
                file_path="app.py",
                line_number=12,
                detector="regex",
                secret_type="aws_access_key",
                severity="critical",
                snippet="token=abcdefghijklmnopqrstuvwxyz123456",
                explanation="Почему это проблема",
                remediation=["Шаг 1", "Шаг 2"],
            ),
            Finding(
                file_path="service.py",
                line_number=5,
                detector="regex",
                secret_type="github_token",
                severity="high",
                snippet="token=ghp_abcdefghijklmnopqrstuvwxyz123456",
                explanation="Тоже проблема",
                remediation=["Сделать A"],
            ),
        ],
    )

    table = render_table(report, use_color=False)
    assert table.count("Hint:") == 0
    assert table.count("Why:") == 1
    assert table.count("Fix:") == 1


def test_nuclearignore_excludes_paths(tmp_path: Path) -> None:
    (tmp_path / ".nuclearignore").write_text("secrets/*\n", encoding="utf-8")
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "key.txt").write_text("AKIA1234567890ABCDEF", encoding="utf-8")
    (tmp_path / "keep.txt").write_text("hello", encoding="utf-8")

    patterns = load_ignore_patterns(tmp_path)
    files = iter_files(tmp_path, ignore_dirs=set(), ignore_patterns=patterns)

    relative = {p.relative_to(tmp_path).as_posix() for p in files}
    assert "keep.txt" in relative
    assert "secrets/key.txt" not in relative


def test_secretignore_excludes_paths(tmp_path: Path) -> None:
    (tmp_path / ".secretignore").write_text("private/*\n", encoding="utf-8")
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / "a.txt").write_text("token=12345678901234567890", encoding="utf-8")
    (tmp_path / "ok.txt").write_text("ok", encoding="utf-8")

    patterns = load_ignore_patterns(tmp_path)
    files = iter_files(tmp_path, ignore_dirs=set(), ignore_patterns=patterns)
    relative = {p.relative_to(tmp_path).as_posix() for p in files}
    assert "ok.txt" in relative
    assert "private/a.txt" not in relative
