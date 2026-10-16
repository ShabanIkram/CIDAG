"""File importers: nmap XML, nuclei JSON, Prowler JSON -> unified Findings.

Lets CIDAG ingest results from tools you already run, so an engagement can mix
CIDAG's own scans with existing tool output. Registered as the ``import`` module
driven by ``options['import_path']`` + ``options['import_format']``.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from ...core.context import ScanContext
from ...core.finding import Finding, Severity
from ...core.registry import register


def parse_nmap_xml(path: str) -> list[Finding]:
    """Parse nmap -oX output into open-port findings."""
    findings: list[Finding] = []
    root = ET.parse(path).getroot()
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "unknown"
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            service = port.find("service")
            svc_name = service.get("name") if service is not None else ""
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            label = f"{svc_name} {product} {version}".strip()
            findings.append(Finding(
                module="import:nmap", check_id="NET-OPEN",
                severity=Severity.LOW if svc_name in ("http", "https") else Severity.INFO,
                title=f"nmap: open {portid}/{port.get('protocol','tcp')} {label}".strip(),
                target=f"{ip}:{portid}",
                remediation="Confirm the service is required; restrict exposure.",
                evidence={"ip": ip, "port": portid, "service": svc_name,
                          "product": product, "version": version},
            ))
    return findings


def parse_nuclei_json(path: str) -> list[Finding]:
    """Parse nuclei -json output into findings with real CVE/template ids."""
    findings: list[Finding] = []
    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
               "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        sev = sev_map.get(str(item.get("info", {}).get("severity", "info")).lower(), Severity.INFO)
        template_id = item.get("template-id") or item.get("templateID") or "nuclei"
        matched = item.get("matched-at") or item.get("host", "")
        cve = None
        for cid in (item.get("info", {}).get("classification", {}) or {}).get("cve-id", []) or []:
            if cid and cid.startswith("CVE-"):
                cve = cid
                break
        if not cve and template_id.startswith("CVE-"):
            cve = template_id
        findings.append(Finding(
            module="import:nuclei", check_id=cve or template_id, severity=sev,
            title=item.get("name") or template_id, target=matched,
            remediation=item.get("info", {}).get("remediation", ""),
            cve=cve,
            evidence={"template": template_id, "matched_at": matched,
                      "curl": item.get("curl-command", "")},
        ))
    return findings


def parse_prowler_json(path: str) -> list[Finding]:
    """Parse Prowler (prowler -M json) output into findings."""
    findings: list[Finding] = []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data if isinstance(data, list) else data.get("findings", [])
    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
               "medium": Severity.MEDIUM, "low": Severity.LOW}
    for row in rows:
        status = str(row.get("Status", "")).upper()
        if status not in ("FAIL", "WARNING"):
            continue
        sev = sev_map.get(str(row.get("Severity", "low")).lower(), Severity.LOW)
        findings.append(Finding(
            module="import:prowler",
            check_id=row.get("CheckID") or row.get("check_id", "PROWLER"),
            severity=sev,
            title=row.get("CheckTitle") or row.get("check_title", "Prowler finding"),
            target=row.get("ResourceId") or row.get("resource_id", ""),
            remediation=row.get("Remediation") or row.get("remediation", ""),
            evidence={"check": row.get("CheckID"), "service": row.get("ServiceName")},
        ))
    return findings


_PARSERS = {
    "nmap": parse_nmap_xml,
    "nuclei": parse_nuclei_json,
    "prowler": parse_prowler_json,
}


@register("import")
class ImportScanner:
    name = "import"
    description = "Import findings from nmap XML / nuclei JSON / Prowler JSON"

    def run(self, context: ScanContext) -> list[Finding]:
        path = context.opt("import_path")
        fmt = str(context.opt("import_format", "")).lower()
        if not path or not Path(path).exists():
            context.log(f"    import: file not found: {path}")
            return []
        if fmt not in _PARSERS:
            context.log(f"    import: unknown format {fmt!r}; choose from {list(_PARSERS)}")
            return []
        findings = _PARSERS[fmt](path)
        context.log(f"    import: parsed {len(findings)} findings from {fmt} ({path})")
        return findings
