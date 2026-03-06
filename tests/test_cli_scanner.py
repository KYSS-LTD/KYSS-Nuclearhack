from pathlib import Path

from secrethawk.cli import mask_sensitive_text
from secrethawk.scanner import iter_files, load_ignore_patterns


def test_mask_sensitive_text_masks_long_values() -> None:
    source = "token=abcdefghijklmnopqrstuvwxyz123456"
    masked = mask_sensitive_text(source)
    assert masked.startswith("toke")
    assert "3456" in masked
    assert "*" in masked
    assert "abcdefghijklmnopqrstuvwxyz123456" not in masked


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
