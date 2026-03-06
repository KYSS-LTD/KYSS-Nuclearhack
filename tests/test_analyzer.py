from secrethawk.analyzer import analyze_line, shannon_entropy


def test_entropy_non_zero_for_mixed_token() -> None:
    value = shannon_entropy("aA1234567890bBcCdD")
    assert value > 3.0


def test_regex_aws_detection() -> None:
    line = 'AWS_KEY="AKIA1234567890ABCDEF"'
    findings = analyze_line("app.py", 10, line, entropy_threshold=4.5)
    assert any(f.secret_type == "aws_access_key" for f in findings)
    aws = next(f for f in findings if f.secret_type == "aws_access_key")
    assert aws.explanation
    assert aws.remediation


def test_high_entropy_detection() -> None:
    line = "token = q1w2e3r4t5y6u7i8o9p0AaBbCcDdEeFf"
    findings = analyze_line("app.py", 20, line, entropy_threshold=3.5)
    assert any(f.detector == "entropy" for f in findings)
    assert any(f.severity == "high" for f in findings if f.detector == "entropy")


def test_test_data_is_ignored_for_entropy() -> None:
    line = "token = sample_1234567890ABCDEFGHIJKLMNOP"
    findings = analyze_line("app.py", 30, line, entropy_threshold=3.0)
    assert not any(f.detector == "entropy" for f in findings)


def test_regex_jwt_detection() -> None:
    line = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc12345xyz98765.def12345xyz98765"
    findings = analyze_line("app.py", 40, line, entropy_threshold=4.5)
    assert any(f.secret_type == "jwt_token" for f in findings)


def test_entropy_heuristics_raise_severity_for_likely_token() -> None:
    line = "data = 0123456789abcdef0123456789abcdef"
    findings = analyze_line("a.py", 1, line, entropy_threshold=3.0)
    entropy_findings = [f for f in findings if f.detector == "entropy"]
    assert entropy_findings
    assert entropy_findings[0].severity == "high"
