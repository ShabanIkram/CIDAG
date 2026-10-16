"""AWS Security Hub importer -- aggregates CVE/control findings from Security Hub.

Security Hub consolidates findings from AWS native services (Inspector, GuardDuty,
Config, Macie) and third-party products. This maps its ``GetFindings`` output
into CIDAG Findings, preserving CVE ids where present.
Read-only: ``securityhub:GetFindings``.
"""
from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from ...core.context import ScanContext
from ...core.finding import Finding, Severity
from ...core.registry import register

_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFO,
}


def _severity_of(item: dict) -> Severity:
    label = (item.get("Severity") or {}).get("Label", "")
    if label in _SEV:
        return _SEV[label]
    # fall back to normalized 0-100 score
    norm = (item.get("Severity") or {}).get("Normalized")
    if isinstance(norm, (int, float)):
        if norm >= 90:
            return Severity.CRITICAL
        if norm >= 70:
            return Severity.HIGH
        if norm >= 40:
            return Severity.MEDIUM
        if norm >= 1:
            return Severity.LOW
    return Severity.MEDIUM


def _finding_from_sechub(item: dict) -> list[Finding]:
    severity = _severity_of(item)
    title = item.get("Title") or "Security Hub finding"
    finding_id = item.get("Id", "")
    resources = item.get("Resources", [])
    target = resources[0].get("Id", finding_id) if resources else finding_id
    remediation = ((item.get("Remediation") or {}).get("Recommendation") or {}).get("Text", "")
    product = item.get("ProductArn", "").split("/")[-1]

    # CVEs may live under Vulnerabilities or as GeneratorId / Types
    cves: list[str] = []
    for v in (item.get("Vulnerabilities") or []):
        vid = v.get("VulnerabilityId", "")
        if vid.startswith("CVE-") and vid not in cves:
            cves.append(vid)

    if not cves:
        return [Finding(
            module="import:sechub", check_id=product or "SECHUB",
            severity=severity, title=title, target=str(target),
            remediation=remediation,
            evidence={"finding_id": finding_id, "product": product,
                      "description": (item.get("Description") or "")[:300]},
        )]

    out = []
    for cve in cves:
        out.append(Finding(
            module="import:sechub", check_id=cve, severity=severity,
            title=f"{cve}: {title}", target=str(target),
            remediation=remediation, cve=cve,
            evidence={"finding_id": finding_id, "product": product,
                      "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
        ))
    return out


@register("sechub")
class SecurityHubScanner:
    name = "sechub"
    description = "Import findings from AWS Security Hub (read-only)"

    def run(self, context: ScanContext) -> list[Finding]:
        import boto3
        profile = context.opt("profile")
        region = context.opt("region", "us-east-1")
        session = boto3.Session(profile_name=profile, region_name=region)
        try:
            client = session.client("securityhub")
        except (ClientError, BotoCoreError) as e:
            context.log(f"    sechub: client error {e}")
            return []
        findings: list[Finding] = []
        try:
            paginator = client.get_paginator("get_findings")
            for page in paginator.paginate():
                for item in page.get("Findings", []):
                    findings.extend(_finding_from_sechub(item))
        except (ClientError, BotoCoreError) as e:
            context.log(f"    sechub: {e}")
        context.log(f"    sechub: imported {len(findings)} findings")
        return findings
