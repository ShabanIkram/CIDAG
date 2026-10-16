"""S3 scanner module: runs the configuration checks over collected buckets."""
from __future__ import annotations

from ...core.context import ScanContext
from ...core.finding import Finding, Severity
from ...core.registry import register
from . import checks


@register("s3")
class S3Scanner:
    name = "s3"
    description = "S3 bucket configuration checks (public access, encryption, logging, versioning)"

    def run(self, context: ScanContext) -> list[Finding]:
        buckets = context.inventory.get("s3_buckets", [])
        account_pab = context.inventory.get("account_public_access_block")
        findings: list[Finding] = []
        for bucket in buckets:
            for chk in checks.ALL_CHECKS:
                findings.extend(chk(bucket, account_pab))
        # Account-level public access block reported once.
        findings.extend(_account_pab_check(account_pab))
        context.log(f"    s3: {len(buckets)} buckets -> {len(findings)} findings")
        return findings


def _account_pab_check(pab: dict | None) -> list[Finding]:
    missing = [k for k in checks.PAB_KEYS if not (pab or {}).get(k)]
    if missing:
        return [Finding(
            module="s3", check_id="S3-009", severity=Severity.HIGH,
            title=f"Account-level S3 public access block incomplete ({len(missing)} off)",
            target="s3-account-public-access-block",
            remediation="Enable all four account-level S3 public-access-block settings in the AWS console/API.",
            evidence={"disabled": missing},
        )]
    return []
