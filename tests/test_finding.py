from cidag.core.finding import Finding, Severity


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_severity_parse_string_and_int():
    assert Severity.parse("critical") is Severity.CRITICAL
    assert Severity.parse("HIGH") is Severity.HIGH
    assert Severity.parse(2) is Severity.MEDIUM
    assert Severity.parse(Severity.LOW) is Severity.LOW


def test_finding_stable_id():
    a = Finding(module="s3", check_id="S3-001", severity="CRITICAL", title="t", target="bucket")
    b = Finding(module="s3", check_id="S3-001", severity="HIGH", title="other", target="bucket")
    assert a.id == b.id  # same module+check+target -> same id regardless of title/severity
    c = Finding(module="s3", check_id="S3-001", severity="HIGH", title="t", target="other-bucket")
    assert a.id != c.id


def test_finding_to_dict_serialisable():
    f = Finding(module="iam", check_id="ESC-01", severity="CRITICAL", title="t",
                target="ident", chain=["a", "b"], remediation="fix")
    d = f.to_dict()
    assert d["severity"] == "CRITICAL"
    assert d["chain"] == ["a", "b"]
    # None/empty fields dropped
    assert "cve" not in d


def test_finding_from_dict_roundtrip():
    f = Finding(module="net", check_id="NET-OPEN", severity="LOW", title="t",
                target="1.2.3.4:80", cve="CVE-2020-0001")
    f2 = Finding.from_dict(f.to_dict())
    assert f2.cve == "CVE-2020-0001"
    assert f2.severity is Severity.LOW
