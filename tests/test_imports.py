import json

from cidag.core.finding import Severity
from cidag.scanners.imports.files import (
    ImportScanner, parse_nmap_xml, parse_nuclei_json, parse_prowler_json)
from cidag.scanners.imports.inspector import _finding_from_inspector
from cidag.scanners.imports.sechub import _finding_from_sechub, _severity_of
from cidag.core.context import ScanContext


def test_parse_nmap_xml(tmp_path):
    xml = """<?xml version="1.0"?><nmaprun>
      <host><address addr="10.0.0.5"/>
        <ports>
          <port protocol="tcp" portid="22"><state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.4"/></port>
          <port protocol="tcp" portid="25"><state state="closed"/></port>
        </ports></host></nmaprun>"""
    p = tmp_path / "scan.xml"
    p.write_text(xml)
    findings = parse_nmap_xml(str(p))
    assert len(findings) == 1  # closed port skipped
    assert findings[0].target == "10.0.0.5:22"


def test_parse_nuclei_json(tmp_path):
    lines = [
        json.dumps({"template-id": "CVE-2021-44228",
                    "info": {"severity": "critical", "name": "Log4j",
                             "classification": {"cve-id": ["CVE-2021-44228"]}},
                    "matched-at": "http://h"}), 
        json.dumps({"template-id": "tpl-2", "info": {"severity": "info"}, "matched-at": "http://x"}),
    ]
    p = tmp_path / "nuclei.json"
    p.write_text("\n".join(lines))
    findings = parse_nuclei_json(str(p))
    assert findings[0].cve == "CVE-2021-44228"
    assert findings[0].severity is Severity.CRITICAL


def test_parse_prowler_json(tmp_path):
    data = [
        {"CheckID": "check_1", "Status": "FAIL", "Severity": "high",
         "CheckTitle": "bad thing", "ResourceId": "arn:x", "Remediation": "fix it"},
        {"CheckID": "check_2", "Status": "PASS", "Severity": "low",
         "CheckTitle": "ok", "ResourceId": "arn:y"},
    ]
    p = tmp_path / "prowler.json"
    p.write_text(json.dumps(data))
    findings = parse_prowler_json(str(p))
    assert len(findings) == 1  # PASS rows filtered out
    assert findings[0].check_id == "check_1" and findings[0].severity is Severity.HIGH


def test_import_scanner_unknown_format(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hi")
    ctx = ScanContext(options={"import_path": str(p), "import_format": "nope"},
                      log=lambda m: None)
    assert ImportScanner().run(ctx) == []


def test_inspector_mapper_extracts_cve():
    item = {"findingArn": "arn:aws:inspector2:...", "severity": "CRITICAL",
            "title": "curl vuln",
            "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2023-0001",
                                            "vulnerablePackage": {"packageName": "curl",
                                                                  "fixedInVersion": "8.0"}},
            "resources": [{"resourceId": "i-123"}]}
    f = _finding_from_inspector(item)
    assert f[0].cve == "CVE-2023-0001" and f[0].severity is Severity.CRITICAL
    assert f[0].evidence["fixed_version"] == "8.0"


def test_sechub_mapper_cve_and_severity():
    item = {"Id": "f1", "Title": "t",
            "Severity": {"Label": "HIGH"},
            "Vulnerabilities": [{"VulnerabilityId": "CVE-2022-9999"}],
            "Resources": [{"Id": "arn:aws:ec2:..."}]}
    f = _finding_from_sechub(item)
    assert f[0].cve == "CVE-2022-9999" and f[0].severity is Severity.HIGH


def test_sechub_severity_normalized_fallback():
    assert _severity_of({"Severity": {"Normalized": 95}}) is Severity.CRITICAL
    assert _severity_of({"Severity": {"Normalized": 50}}) is Severity.MEDIUM
