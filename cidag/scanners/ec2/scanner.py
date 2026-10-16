"""EC2 scanner module: security groups, EBS, IMDS, RDS, CloudTrail."""
from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Finding
from ...core.registry import register
from . import checks


@register("ec2")
class EC2Scanner:
    name = "ec2"
    description = "EC2 security groups, EBS encryption, IMDS, RDS, and CloudTrail checks"

    def run(self, context: ScanContext) -> list[Finding]:
        inv = context.inventory
        findings: list[Finding] = []
        sgs = inv.get("security_groups", [])
        for sg in sgs:
            findings.extend(checks.SG_CHECK(sg))
        for vol in inv.get("volumes", []):
            findings.extend(checks.check_unencrypted_ebs(vol))
        for inst in inv.get("instances", []):
            findings.extend(checks.check_imdsv1(inst))
        for db in inv.get("rds_instances", []):
            findings.extend(checks.check_rds_public(db))
            findings.extend(checks.check_rds_unencrypted(db))
            findings.extend(checks.check_rds_backup(db))
        findings.extend(checks.check_cloudtrail(inv.get("cloud_trails", [])))
        context.log(
            f"    ec2: {len(sgs)} sg / {len(inv.get('instances', []))} inst / "
            f"{len(inv.get('rds_instances', []))} rds -> {len(findings)} findings"
        )
        return findings
