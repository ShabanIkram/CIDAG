"""S3 bucket configuration checks.

Each check is a pure function ``(bucket: dict, account_pab: dict|None) -> list[Finding]``
so they are trivially unit-testable offline against fixture buckets.

Normalized bucket shape (produced by the collector / mock):
{
  "name", "arn", "region",
  "acl_grants": [{"grantee_type","grantee","permission"}],
  "policy": dict|None, "policy_is_public": bool|None,
  "encryption": {"sse_algorithm","kms_master_key_id"}|None,
  "logging": {"target_bucket"}|None,
  "versioning": {"status","mfadelete"}|None,
  "public_access_block": {4 bools}|None,
}
"""
from __future__ import annotations

from ...core.finding import Finding, Severity

PAB_KEYS = ("block_public_acls", "ignore_public_acls", "block_public_policy",
            "restrict_public_buckets")

_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers (public)",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers (any AWS account)",
}


def _grant_is_public(grant: dict) -> str | None:
    """Return a human label if this ACL grant exposes the bucket, else None."""
    gt = grant.get("grantee_type", "")
    if gt == "Group" and grant.get("grantee") in _GROUP_URIS:
        return _GROUP_URIS[grant["grantee"]]
    return None


def _policy_principal_wildcard(policy: dict | None) -> bool:
    if not policy:
        return False
    stmts = policy.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for st in stmts:
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS")
            if aws == "*" or (isinstance(aws, list) and "*" in aws):
                return True
    return False


def _pab_complete(pab: dict | None) -> bool:
    if not pab:
        return False
    return all(bool(pab.get(k)) for k in PAB_KEYS)


def _loc(bucket: dict) -> str:
    return bucket.get("name") or bucket.get("arn", "unknown")


# --------------------------------------------------------------------- checks

def check_acl_public(bucket: dict, account_pab=None) -> list[Finding]:
    out = []
    for grant in bucket.get("acl_grants", []):
        label = _grant_is_public(grant)
        if label:
            out.append(Finding(
                module="s3", check_id="S3-001", severity=Severity.CRITICAL,
                title=f"Public ACL grant to {label}",
                target=_loc(bucket),
                remediation="Remove the AllUsers/AuthenticatedUsers ACL grant; use bucket policies with specific principals.",
                evidence={"grantee": grant.get("grantee"), "permission": grant.get("permission")},
            ))
    return out


def check_policy_public(bucket: dict, account_pab=None) -> list[Finding]:
    is_public = bucket.get("policy_is_public")
    if is_public is None:
        is_public = _policy_principal_wildcard(bucket.get("policy"))
    if is_public:
        return [Finding(
            module="s3", check_id="S3-002", severity=Severity.CRITICAL,
            title="Bucket policy allows public access (Principal *)",
            target=_loc(bucket),
            remediation="Scope the policy to specific principals; add restrictive aws:SourceVpaws/SourceIp/PrincipalOrgID conditions.",
            evidence={"policy": bucket.get("policy")},
        )]
    return []


def check_no_encryption(bucket: dict, account_pab=None) -> list[Finding]:
    if not bucket.get("encryption"):
        return [Finding(
            module="s3", check_id="S3-003", severity=Severity.HIGH,
            title="Bucket has no default encryption",
            target=_loc(bucket),
            remediation="Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.",
            evidence={},
        )]
    return []


def check_pab_incomplete(bucket: dict, account_pab=None) -> list[Finding]:
    pab = bucket.get("public_access_block")
    missing = [k for k in PAB_KEYS if not (pab or {}).get(k)]
    if missing:
        return [Finding(
            module="s3", check_id="S3-004", severity=Severity.HIGH,
            title=f"Public access block incomplete ({len(missing)} of 4 settings off)",
            target=_loc(bucket),
            remediation="Enable all four public-access-block settings: block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets.",
            evidence={"disabled": missing},
        )]
    return []


def check_insecure_transport(bucket: dict, account_pab=None) -> list[Finding]:
    policy = bucket.get("policy")
    if not policy:
        # No policy -> nothing denies plaintext; flag as low/medium advisory
        return [Finding(
            module="s3", check_id="S3-005", severity=Severity.MEDIUM,
            title="No policy denying unencrypted transport (aws:SecureTransport=false)",
            target=_loc(bucket),
            remediation="Add a Deny statement for s3:* when aws:SecureTransport is false.",
            evidence={},
        )]
    stmts = policy.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    denies_tls = any(
        st.get("Effect") == "Deny"
        and st.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") in (False, "false")
        for st in stmts
    )
    if not denies_tls:
        return [Finding(
            module="s3", check_id="S3-005", severity=Severity.MEDIUM,
            title="Policy does not deny unencrypted transport",
            target=_loc(bucket),
            remediation="Add a Deny statement for s3:* when aws:SecureTransport is false.",
            evidence={},
        )]
    return []


def check_no_logging(bucket: dict, account_pab=None) -> list[Finding]:
    if not bucket.get("logging"):
        return [Finding(
            module="s3", check_id="S3-006", severity=Severity.MEDIUM,
            title="Server access logging disabled",
            target=_loc(bucket),
            remediation="Enable server access logging to a dedicated log bucket.",
            evidence={},
        )]
    return []


def check_versioning_disabled(bucket: dict, account_pab=None) -> list[Finding]:
    status = (bucket.get("versioning") or {}).get("status")
    if status != "Enabled":
        return [Finding(
            module="s3", check_id="S3-007", severity=Severity.LOW,
            title="Object versioning not enabled",
            target=_loc(bucket),
            remediation="Enable versioning to protect against accidental deletion/overwrite.",
            evidence={"versioning": bucket.get("versioning")},
        )]
    return []


def check_mfa_delete_disabled(bucket: dict, account_pab=None) -> list[Finding]:
    mfadel = (bucket.get("versioning") or {}).get("mfadelete")
    if mfadel != "Enabled":
        return [Finding(
            module="s3", check_id="S3-008", severity=Severity.LOW,
            title="MFA delete not enabled",
            target=_loc(bucket),
            remediation="Enable MFA delete so permanent deletions require a multi-factor token.",
            evidence={"mfadelete": mfadel},
        )]
    return []


def check_account_pab_off(bucket: dict, account_pab=None) -> list[Finding]:
    # reported once per account by the scanner, not per bucket (see scanner.py)
    return []


def check_wildcard_s3_admin(bucket: dict, account_pab=None) -> list[Finding]:
    policy = bucket.get("policy")
    if not policy:
        return []
    stmts = policy.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    out = []
    for st in stmts:
        if st.get("Effect") != "Allow":
            continue
        actions = st.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        principal = st.get("Principal")
        principal_wild = principal == "*" or (
            isinstance(principal, dict) and
            (principal.get("AWS") == "*" or (isinstance(principal.get("AWS"), list) and "*" in principal.get("AWS")))
        )
        if principal_wild and any(a in ("s3:*", "*") for a in actions):
            out.append(Finding(
                module="s3", check_id="S3-010", severity=Severity.MEDIUM,
                title="Policy grants s3:* to a wildcard principal",
                target=_loc(bucket),
                remediation="Restrict actions to required s3:GetObject/s3:PutObject and scope principals.",
                evidence={"statement": st},
            ))
    return out


ALL_CHECKS = [
    check_acl_public,
    check_policy_public,
    check_no_encryption,
    check_pab_incomplete,
    check_insecure_transport,
    check_no_logging,
    check_versioning_disabled,
    check_mfa_delete_disabled,
    check_wildcard_s3_admin,
]
