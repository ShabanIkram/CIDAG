"""Live S3 collector: normalizes AWS bucket config into the check schema.

Read-only API calls only:
  s3:ListAllMyBuckets, s3:GetBucketAcl, s3:GetBucketPolicy,
  s3:GetBucketPolicyStatus, s3:GetBucketEncryption, s3:GetBucketLogging,
  s3:GetBucketVersioning, s3:GetPublicAccessBlock, s3:GetBucketLocation,
  s3:GetAccountPublicAccessBlock
"""
from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError


def _grants(acl: dict) -> list[dict]:
    out = []
    for g in acl.get("Grants", []):
        grantee = g.get("Grantee", {})
        gt = grantee.get("Type", "")
        label = grantee.get("URI") or grantee.get("EmailAddress") or grantee.get("DisplayName") or ""
        out.append({"grantee_type": gt, "grantee": label,
                    "permission": g.get("Permission", "")})
    return out


def collect_s3(session) -> tuple[list[dict], dict | None]:
    """Return (buckets, account_public_access_block)."""
    s3 = session.client("s3")
    s3control = session.client("s3control")
    region = session.region_name or "us-east-1"

    account_id = session.client("sts").get_caller_identity()["Account"]

    account_pab = None
    try:
        pab = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
        account_pab = {k: bool(pab.get(k, False)) for k in
                       ("block_public_acls", "ignore_public_acls",
                        "block_public_policy", "restrict_public_buckets")}
    except (ClientError, BotoCoreError):
        account_pab = None

    buckets: list[dict] = []
    try:
        names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    except (ClientError, BotoCoreError) as e:
        print(f"[!] s3 list_buckets: {e}")
        return [], account_pab

    for name in names:
        b: dict = {"name": name, "arn": f"arn:aws:s3:::{name}", "region": region}
        try:
            b["region"] = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        except (ClientError, BotoCoreError):
            pass
        try:
            b["acl_grants"] = _grants(s3.get_bucket_acl(Bucket=name))
        except (ClientError, BotoCoreError):
            b["acl_grants"] = []
        try:
            b["policy"] = s3.get_bucket_policy(Bucket=name)["Policy"]
            import json as _json
            b["policy"] = _json.loads(b["policy"])
        except (ClientError, BotoCoreError):
            b["policy"] = None
        try:
            b["policy_is_public"] = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]
        except (ClientError, BotoCoreError):
            b["policy_is_public"] = None
        try:
            enc = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
            b["encryption"] = {"sse_algorithm": enc.get("SSEAlgorithm"),
                               "kms_master_key_id": enc.get("KMSMasterKeyID")}
        except (ClientError, BotoCoreError):
            b["encryption"] = None
        try:
            lg = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
            b["logging"] = {"target_bucket": lg.get("TargetBucket")} if lg else None
        except (ClientError, BotoCoreError):
            b["logging"] = None
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            b["versioning"] = {"status": ver.get("Status"), "mfadelete": ver.get("MFADelete")}
        except (ClientError, BotoCoreError):
            b["versioning"] = None
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            b["public_access_block"] = {k: bool(pab.get(k, False)) for k in
                                        ("block_public_acls", "ignore_public_acls",
                                         "block_public_policy", "restrict_public_buckets")}
        except (ClientError, BotoCoreError):
            b["public_access_block"] = None
        buckets.append(b)

    return buckets, account_pab
