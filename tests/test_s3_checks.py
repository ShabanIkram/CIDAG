from cidag.core.finding import Severity
from cidag.scanners.s3 import checks
from cidag.scanners.s3.scanner import S3Scanner
from cidag.core.context import ScanContext


def _bucket(**over):
    base = {
        "name": "b", "arn": "arn:aws:s3:::b", "region": "us-east-1",
        "acl_grants": [], "policy": None, "policy_is_public": None,
        "encryption": None, "logging": None, "versioning": None,
        "public_access_block": None,
    }
    base.update(over)
    return base


def test_public_acl():
    b = _bucket(acl_grants=[{"grantee_type": "Group",
                             "grantee": "http://acs.amazonaws.com/groups/global/AllUsers",
                             "permission": "READ"}])
    f = checks.check_acl_public(b)
    assert f and f[0].check_id == "S3-001" and f[0].severity is Severity.CRITICAL


def test_private_acl_no_finding():
    b = _bucket(acl_grants=[{"grantee_type": "CanonicalUser", "grantee": "owner",
                             "permission": "FULL_CONTROL"}])
    assert checks.check_acl_public(b) == []


def test_public_policy_wildcard():
    b = _bucket(policy={"Statement": [{"Effect": "Allow", "Principal": "*",
                                       "Action": "s3:*", "Resource": "*"}]})
    assert checks.check_policy_public(b)


def test_policy_public_flag_from_collector():
    b = _bucket(policy_is_public=True)
    assert checks.check_policy_public(b)


def test_no_encryption():
    f = checks.check_no_encryption(_bucket())
    assert f and f[0].check_id == "S3-003"


def test_encrypted_no_finding():
    assert checks.check_no_encryption(_bucket(encryption={"sse_algorithm": "AES256"})) == []


def test_pab_incomplete_and_complete():
    incomplete = _bucket(public_access_block={"block_public_acls": True})
    assert checks.check_pab_incomplete(incomplete)
    complete = _bucket(public_access_block={k: True for k in checks.PAB_KEYS})
    assert checks.check_pab_incomplete(complete) == []


def test_insecure_transport_detects_tls_deny():
    policy = {"Statement": [{"Effect": "Deny", "Principal": "*",
                             "Action": "s3:*",
                             "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
    assert checks.check_insecure_transport(_bucket(policy=policy)) == []


def test_mfa_delete_and_versioning():
    assert checks.check_versioning_disabled(_bucket())
    assert checks.check_mfa_delete_disabled(_bucket())
    ok = _bucket(versioning={"status": "Enabled", "mfadelete": "Enabled"})
    assert checks.check_versioning_disabled(ok) == []
    assert checks.check_mfa_delete_disabled(ok) == []


def test_scanner_runs_over_inventory():
    inv = {"s3_buckets": [_bucket(name="pub")],
           "account_public_access_block": None}
    ctx = ScanContext(inventory=inv, log=lambda m: None)
    findings = S3Scanner().run(ctx)
    # a default empty bucket triggers no-encryption, no-logging, versioning,
    # mfa-delete, insecure-transport, incomplete PAB
    ids = {f.check_id for f in findings}
    assert {"S3-003", "S3-004", "S3-005", "S3-006", "S3-007", "S3-008"} <= ids
