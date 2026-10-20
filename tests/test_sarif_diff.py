import json

from cidag.cli.main import main
from cidag.core.finding import Finding, Severity
from cidag.reports.exporter import to_sarif


def test_sarif_structure():
    findings = [
        Finding(module="net", check_id="NET-OPEN", severity=Severity.HIGH,
                title="Open port 22", target="10.0.0.1:22"),
        Finding(module="cve", check_id="CVE-2011-2523", severity=Severity.CRITICAL,
                title="vsftpd backdoor", target="vsftpd:2.3.4", cve="CVE-2011-2523"),
    ]
    doc = json.loads(to_sarif(findings))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "CIDAG"
    assert len(run["results"]) == 2
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["NET-OPEN"] == "error"
    assert levels["CVE-2011-2523"] == "error"
    rules = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rules == {"NET-OPEN", "CVE-2011-2523"}
    cve_result = [r for r in run["results"] if r["ruleId"] == "CVE-2011-2523"][0]
    assert cve_result["properties"]["cve"] == "CVE-2011-2523"


def test_cli_report_sarif(capsys):
    assert main(["report", "--format", "sarif"]) is None
    doc = json.loads(capsys.readouterr().out)
    assert doc["runs"][0]["results"]


def _write(tmp_path, name, findings):
    path = tmp_path / name
    path.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return str(path)


_BASE = [
    {"id": "a", "module": "net", "check_id": "NET-OPEN", "severity": "HIGH",
     "target": "1.1.1.1:22", "title": "Open port 22"},
    {"id": "b", "module": "s3", "check_id": "S3-001", "severity": "HIGH",
     "target": "bucket", "title": "Public bucket"},
]


def test_diff_text_new_and_fixed(tmp_path, capsys):
    after = [_BASE[1], {"id": "c", "module": "cve", "check_id": "CVE-2011-2523",
                        "severity": "CRITICAL", "target": "vsftpd:2.3.4",
                        "title": "Backdoor"}]
    before = _write(tmp_path, "before.json", _BASE)
    after_path = _write(tmp_path, "after.json", after)
    main(["diff", "--before", before, "--after", after_path])
    out = capsys.readouterr().out
    assert "1 new" in out
    assert "1 fixed" in out
    assert "0 changed" in out
    assert "CVE-2011-2523" in out
    assert "NET-OPEN" in out


def test_diff_severity_change(tmp_path, capsys):
    after = [dict(_BASE[0], severity="MEDIUM"), _BASE[1]]
    before = _write(tmp_path, "before.json", _BASE)
    after_path = _write(tmp_path, "after.json", after)
    main(["diff", "--before", before, "--after", after_path])
    out = capsys.readouterr().out
    assert "1 changed" in out
    assert "HIGH->MEDIUM" in out


def test_diff_json_format(tmp_path, capsys):
    before = _write(tmp_path, "before.json", _BASE)
    after_path = _write(tmp_path, "after.json", _BASE[1:])
    main(["diff", "--before", before, "--after", after_path, "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"] == {"new": 0, "fixed": 1, "changed": 0}


def test_diff_falls_back_to_module_check_target_key(tmp_path, capsys):
    before = _write(tmp_path, "before.json", [{"module": "net", "check_id": "NET-OPEN",
                                               "severity": "HIGH", "target": "x:1",
                                               "title": "Open 1"}])
    after_path = _write(tmp_path, "after.json", [])
    main(["diff", "--before", before, "--after", after_path])
    assert "1 fixed" in capsys.readouterr().out
