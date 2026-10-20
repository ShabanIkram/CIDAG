from cidag.core.context import ScanContext
from cidag.scanners.policy.scanner import PolicyScanner


def _run(inventory: dict):
    ctx = ScanContext(inventory=inventory, options={}, log=lambda m: None, offline=True)
    return PolicyScanner().run(ctx)


def _finding(check_id: str, inventory: dict):
    return [f for f in _run(inventory) if f.check_id == check_id]


def test_wildcard_admin_policy():
    inv = {"policies": [{"name": "AdminPolicy", "arn": "arn:aws:iam::1:policy/AdminPolicy",
                         "statements": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}]}
    findings = _finding("POL-001", inv)
    assert len(findings) == 1
    assert findings[0].severity.name == "CRITICAL"
    assert "AdminPolicy" in findings[0].title


def test_privilege_escalation_policy():
    inv = {"policies": [{"name": "Deployer", "arn": "arn:aws:iam::1:policy/Deployer",
                         "statements": [{"Effect": "Allow",
                                         "Action": ["iam:PassRole", "iam:UpdateAssumeRolePolicy"],
                                         "Resource": "*"}]}]}
    findings = _finding("POL-002", inv)
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"
    assert set(findings[0].evidence["actions"]) == {
        "iam:passrole", "iam:updateassumerolepolicy"}


def test_data_exfil_policy():
    inv = {"policies": [{"name": "Reader", "arn": "arn:aws:iam::1:policy/Reader",
                         "statements": [{"Effect": "Allow",
                                         "Action": ["s3:GetObject", "secretsmanager:GetSecretValue"],
                                         "Resource": "*"}]}]}
    findings = _finding("POL-003", inv)
    assert len(findings) == 1
    assert "secretsmanager:getsecretvalue" in findings[0].evidence["actions"]


def test_wildcard_admin_suppresses_secondary_findings():
    inv = {"policies": [{"name": "Admin", "arn": "arn:aws:iam::1:policy/Admin",
                         "statements": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}]}
    ids = {f.check_id for f in _run(inv)}
    assert ids == {"POL-001"}


def test_wildcard_trust_principal():
    inv = {"identities": [{
        "name": "open-role", "arn": "arn:aws:iam::1:role/open-role", "type": "role",
        "trust_policy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                                        "Action": "sts:AssumeRole"}]},
    }]}
    findings = _finding("POL-004", inv)
    assert len(findings) == 1
    assert findings[0].severity.name == "CRITICAL"


def test_scoped_policy_has_no_findings():
    inv = {"policies": [{"name": "Scoped", "arn": "arn:aws:iam::1:policy/Scoped",
                         "statements": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                                         "Resource": "arn:aws:s3:::my-bucket/*"}]}]}
    assert _run(inv) == []


def test_deny_statements_ignored():
    inv = {"policies": [{"name": "DenyAll", "arn": "arn:aws:iam::1:policy/DenyAll",
                         "statements": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}]}
    assert _run(inv) == []


def test_service_wildcard_counts_as_exfil():
    inv = {"policies": [{"name": "S3Read", "arn": "arn:aws:iam::1:policy/S3Read",
                         "statements": [{"Effect": "Allow", "Action": "s3:Get*",
                                         "Resource": "*"}]}]}
    assert _finding("POL-003", inv)


def test_condition_removes_exfil_finding():
    inv = {"policies": [{"name": "Guarded", "arn": "arn:aws:iam::1:policy/Guarded",
                         "statements": [{"Effect": "Allow", "Action": "s3:GetObject",
                                         "Resource": "*",
                                         "Condition": {"StringEquals": {"aws:PrincipalTag/team": "ci"}}}]}]}
    assert _finding("POL-003", inv) == []
