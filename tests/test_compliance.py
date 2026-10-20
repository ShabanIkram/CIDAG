import json

from cidag.core.finding import Finding, Severity
from cidag.reports.compliance import attach, filter_by, summary, tags_for


def _finding(check_id: str, module: str = "s3") -> Finding:
    return Finding(module=module, check_id=check_id, severity=Severity.HIGH,
                   title="t", target="x")


def test_tags_for_known_controls():
    assert tags_for("S3-002")["cis"] == ["2.1.1"]
    assert "1.3" in tags_for("S3-002")["pci"]


def test_tags_for_escalation_and_cve():
    assert tags_for("ESC-04", "iam")["pci"] == ["7.2"]
    assert tags_for("CVE-2021-41773", "net")["pci"] == ["6.3"]
    assert tags_for("some-template", "import:nuclei")["pci"] == ["6.3"]


def test_unknown_check_has_no_tags():
    assert tags_for("S3-999") == {}


def test_attach_and_summary():
    findings = [_finding("S3-002"), _finding("S3-002"), _finding("EC2-005", "ec2")]
    attach(findings)
    assert findings[0].compliance["cis"] == ["2.1.1"]
    data = summary(findings)
    assert data["cis"]["2.1.1"] == 2
    assert data["pci"]["3.5"] == 1


def test_filter_by_framework():
    findings = [_finding("S3-002"), _finding("S3-007")]
    attach(findings)
    assert len(filter_by(findings, None)) == 2
    assert [f.check_id for f in filter_by(findings, "cis")] == ["S3-002", "S3-007"]
    assert filter_by([_finding("S3-999")], "cis") == []


def test_sarif_export_includes_compliance():
    from cidag.reports.exporter import to_sarif

    f = _finding("S3-002")
    attach([f])
    doc = json.loads(to_sarif([f]))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["compliance"]["cis"] == ["2.1.1"]


def test_report_markdown_has_compliance_section(capsys):
    from cidag.cli.main import main

    main(["report", "--format", "md", "--modules", "s3"])
    out = capsys.readouterr().out
    assert "## Compliance Coverage" in out
    assert "CIS AWS Foundations" in out


def test_report_can_filter_by_framework(capsys):
    from cidag.cli.main import main

    main(["report", "--format", "json", "--modules", "iam,s3,ec2", "--compliance", "pci"])
    data = json.loads(capsys.readouterr().out)
    assert data["findings"]
    assert all("pci" in f.get("compliance", {}) for f in data["findings"])
