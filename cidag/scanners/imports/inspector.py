"""AWS Inspector v2 importer -- real CVE findings straight from AWS's scanner.

Inspector2 enumerates known CVEs in your EC2/ECR workloads. This pulls them
into CIDAG's unified Finding schema so cloud workload CVEs sit alongside the
network/config findings. Read-only: ``inspector2:ListFindings``.
"""
from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from ...core.context import ScanContext
from ...core.finding import Finding, Severity
from ...core.registry import register

# AWS Inspector severity -> our Severity
_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNAVAILABLE": Severity.INFO,
}


def _finding_from_inspector(item: dict) -> list[Finding]:
    out: list[Finding] = []
    severity = _SEV.get(item.get("severity", "").upper(), Severity.MEDIUM)
    title = item.get("title") or item.get("description", "Inspector finding")[:120]
    finding_arn = item.get("findingArn", "")
    resources = item.get("resources", [])
    target = resources[0].get("resourceId", finding_arn) if resources else finding_arn

    pkg = item.get("packageVulnerabilityDetails") or {}
    code = item.get("codeVulnerabilityDetails") or {}

    cves: list[str] = []
    if pkg.get("vulnerabilityId"):
        cves.append(pkg["vulnerabilityId"])
    for v in (code.get("vulnerabilities") or []):
        for cid in (v.get("cveIds") or []):
            if cid not in cves:
                cves.append(cid)

    remediation = item.get("remediation", "") or item.get("description", "")[:300]

    if not cves:
        # non-CVE Inspector finding (e.g. network reachability) -- still surface it
        out.append(Finding(
            module="import:inspector", check_id="INSPECTOR",
            severity=severity, title=title, target=str(target),
            remediation=remediation,
            evidence={"finding_arn": finding_arn, "type": item.get("type")},
        ))
        return out

    for cve in cves:
        out.append(Finding(
            module="import:inspector", check_id=cve, severity=severity,
            title=f"{cve}: {title}", target=str(target),
            remediation=remediation, cve=cve,
            evidence={
                "finding_arn": finding_arn,
                "resource": str(target),
                "package": pkg.get("vulnerablePackage", {}).get("packageName"),
                "installed_version": pkg.get("vulnerablePackage", {}).get("installedVersion"),
                "fixed_version": pkg.get("vulnerablePackage", {}).get("fixedInVersion"),
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            },
        ))
    return out


@register("inspector")
class InspectorScanner:
    name = "inspector"
    description = "Import CVE findings from AWS Inspector v2 (read-only)"

    def run(self, context: ScanContext) -> list[Finding]:
        import boto3
        profile = context.opt("profile")
        region = context.opt("region", "us-east-1")
        session = boto3.Session(profile_name=profile, region_name=region)
        try:
            client = session.client("inspector2")
        except (ClientError, BotoCoreError) as e:
            context.log(f"    inspector: client error {e}")
            return []
        findings: list[Finding] = []
        try:
            paginator = client.get_paginator("list_findings")
            for page in paginator.paginate():
                for item in page.get("findings", []):
                    findings.extend(_finding_from_inspector(item))
        except (ClientError, BotoCoreError) as e:
            context.log(f"    inspector: {e}")
        context.log(f"    inspector: imported {len(findings)} findings")
        return findings
