import json

import cidag.collectors.aws as aws_mod
from cidag.analysis.engine import run_analysis
from cidag.collectors.aws import AwsCollector
from cidag.normalizer.evaluator import compute_effective

ACCT = "111122223333"
IDENT = f"arn:aws:iam::{ACCT}:role/contractor"
ESC_POLICY = f"arn:aws:iam::{ACCT}:policy/Escalate"
BOUNDARY = f"arn:aws:iam::{ACCT}:policy/S3Boundary"
ADMIN = f"arn:aws:iam::{ACCT}:role/admin"
ADMIN_POLICY = f"arn:aws:iam::{ACCT}:policy/Admin"


def _policy(arn, actions, effect="Allow"):
    return {"arn": arn, "name": arn.rsplit("/", 1)[-1],
            "statements": [{"Effect": effect, "Action": actions, "Resource": "*"}]}


def _identity(attached=None, boundary=None, inline_boundary=None):
    ident = {"type": "role", "name": "contractor", "arn": IDENT,
             "attached_policies": attached or []}
    if boundary:
        ident["boundary_policy"] = boundary
    if inline_boundary:
        ident["permissions_boundary"] = inline_boundary
    return ident


def _inventory(ident, policies, scps=None):
    return {"account_id": ACCT, "identities": [ident], "policies": policies,
            "resources": [], "scps": scps or []}


def build(inv):
    from cidag.graph.builder import build_graph
    return build_graph(inv)


def _types(inv):
    return {f["type"] for f in run_analysis(build(inv), inv)["findings"]}


def test_boundary_blocks_escalation():
    inv = _inventory(
        _identity([ESC_POLICY], boundary=BOUNDARY),
        [_policy(ESC_POLICY, ["iam:CreatePolicyVersion"]),
         _policy(BOUNDARY, ["s3:GetObject"])],
    )
    ep = compute_effective(inv)[IDENT]
    assert ep.allowed("iam:CreatePolicyVersion") is False
    assert "ESC-04" not in _types(inv)


def test_boundary_permitting_action_keeps_escalation():
    inv = _inventory(
        _identity([ESC_POLICY], boundary=BOUNDARY),
        [_policy(ESC_POLICY, ["iam:CreatePolicyVersion"]),
         _policy(BOUNDARY, ["iam:CreatePolicyVersion"])],
    )
    assert compute_effective(inv)[IDENT].allowed("iam:CreatePolicyVersion")
    assert "ESC-04" in _types(inv)


def test_scp_deny_blocks_escalation():
    scps = [{"arn": "arn:scp", "name": "deny", "statements": [
        {"Effect": "Deny", "Action": ["iam:CreatePolicyVersion"], "Resource": "*"}]}]
    inv = _inventory(_identity([ESC_POLICY]),
                     [_policy(ESC_POLICY, ["iam:CreatePolicyVersion"])], scps)
    ep = compute_effective(inv)[IDENT]
    assert ep.allowed("iam:CreatePolicyVersion") is False
    assert "ESC-04" not in _types(inv)


def test_deny_only_scp_keeps_admin():
    scps = [{"arn": "arn:scp", "name": "deny-keys", "statements": [
        {"Effect": "Deny", "Action": ["iam:CreateAccessKey"], "Resource": "*"}]}]
    inv = _inventory(_identity([ADMIN_POLICY]),
                     [_policy(ADMIN_POLICY, ["*"])], scps)
    result = run_analysis(build(inv), inv)
    assert result["admin_arns"] == [IDENT]
    assert "WILDCARD_POLICY" in {f["type"] for f in result["findings"]}


def test_restrictive_scp_allowlist_removes_admin():
    scps = [{"arn": "arn:scp", "name": "s3-only", "statements": [
        {"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}]
    inv = _inventory(_identity([ADMIN_POLICY]),
                     [_policy(ADMIN_POLICY, ["*"])], scps)
    result = run_analysis(build(inv), inv)
    assert not result["admin_arns"]
    assert "WILDCARD_POLICY" not in {f["type"] for f in result["findings"]}


def test_boundary_suppresses_wildcard_admin():
    inv = _inventory(
        _identity([ADMIN_POLICY], boundary=BOUNDARY),
        [_policy(ADMIN_POLICY, ["*"]), _policy(BOUNDARY, ["s3:*"])],
    )
    ep = compute_effective(inv)[IDENT]
    assert ep.is_admin() is False
    result = run_analysis(build(inv), inv)
    assert "WILDCARD_POLICY" not in {f["type"] for f in result["findings"]}


def test_unresolvable_boundary_denies():
    inv = _inventory(_identity([ESC_POLICY], boundary=BOUNDARY),
                     [_policy(ESC_POLICY, ["iam:CreatePolicyVersion"])])
    assert compute_effective(inv)[IDENT].allowed("iam:CreatePolicyVersion") is False


def test_inline_boundary_document_supported():
    inline = {"Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}
    inv = _inventory(_identity([ESC_POLICY], inline_boundary=inline),
                     [_policy(ESC_POLICY, ["iam:CreatePolicyVersion"])])
    assert compute_effective(inv)[IDENT].allowed("iam:CreatePolicyVersion") is False


def test_boundary_blocks_passrole_edge():
    passrole = f"arn:aws:iam::{ACCT}:policy/PassRole"
    inv = _inventory(
        _identity([passrole], boundary=BOUNDARY),
        [_policy(passrole, ["iam:PassRole", "lambda:UpdateFunctionCode"]),
         _policy(BOUNDARY, ["s3:GetObject"])],
    )
    inv["identities"].append({"type": "role", "name": "admin", "arn": ADMIN,
                              "attached_policies": [ADMIN_POLICY]})
    inv["policies"].append(_policy(ADMIN_POLICY, ["*"]))
    g = build(inv)
    result = run_analysis(g, inv)
    assert result["admin_arns"] == [ADMIN]
    assert not g.has_edge(IDENT, ADMIN)
    assert "ATTACK_PATH" not in {f["type"] for f in result["findings"]}


def test_collector_captures_boundary_policy(monkeypatch):
    class FakeIam:
        def list_user_policies(self, UserName):
            return {"PolicyNames": []}

        def list_groups_for_user(self, UserName):
            return {"Groups": []}

        def get_policy(self, PolicyArn):
            return {"Policy": {"PolicyName": "Boundary", "DefaultVersionId": "v1"}}

        def get_policy_version(self, PolicyArn, VersionId):
            return {"PolicyVersion": {"Document": {
                "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}}

    def fake_paginate(client, method, key, **kwargs):
        if method == "list_users":
            return iter([{"UserName": "u", "Arn": "arn:u",
                          "PermissionsBoundary": {"PermissionsBoundaryArn": BOUNDARY}}])
        return iter([])

    monkeypatch.setattr(aws_mod, "_paginate", fake_paginate)
    users = AwsCollector()._collect_users(FakeIam())
    assert users[0]["boundary_policy"] == BOUNDARY

    policies: list[dict] = []
    AwsCollector()._collect_boundary_policies(FakeIam(), users, policies)
    assert policies[0]["arn"] == BOUNDARY
    assert policies[0]["statements"][0]["Action"] == "s3:*"


def test_collector_walks_scp_ancestry(monkeypatch):
    class FakeOrg:
        def describe_policy(self, PolicyId):
            content = json.dumps({"Statement": [
                {"Effect": "Deny", "Action": ["iam:CreateAccessKey"], "Resource": "*"}]})
            return {"Policy": {"Content": content}}

        def list_parents(self, TargetId):
            return {"Parents": {"111122223333": [{"Id": "ou-1"}],
                                "ou-1": [{"Id": "r-root"}]}.get(TargetId, [])}

    def fake_paginate(client, method, key, **kwargs):
        target = kwargs.get("TargetId")
        ids = {"111122223333": "acct", "ou-1": "ou", "r-root": "root"}
        if method == "list_policies_for_target" and target in ids:
            tag = ids[target]
            return iter([{"Id": f"p-{tag}", "Arn": f"arn:{tag}", "Name": f"{tag}-scp"}])
        return iter([])

    class FakeSession:
        def client(self, name):
            assert name == "organizations"
            return FakeOrg()

    monkeypatch.setattr(aws_mod, "_paginate", fake_paginate)
    scps = AwsCollector()._collect_scps(FakeSession(), "111122223333")
    assert {s["name"] for s in scps} == {"acct-scp", "ou-scp", "root-scp"}
