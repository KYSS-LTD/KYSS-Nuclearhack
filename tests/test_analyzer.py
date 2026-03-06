from secrethawk.analyzer import analyze_line, shannon_entropy


def test_entropy_non_zero_for_mixed_token() -> None:
    value = shannon_entropy("aA1234567890bBcCdD")
    assert value > 3.0


def test_regex_aws_detection() -> None:
    line = 'AWS_KEY="AKIA1234567890ABCDEF"'
    findings = analyze_line("app.py", 10, line, entropy_threshold=4.5)
    assert any(f.secret_type == "aws_access_key" for f in findings)


def test_high_entropy_detection() -> None:
    line = "token = q1w2e3r4t5y6u7i8o9p0AaBbCcDdEeFf"
    findings = analyze_line("app.py", 20, line, entropy_threshold=3.5)
    assert any(f.detector == "entropy" for f in findings)
