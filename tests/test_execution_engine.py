import io
import json
from pathlib import Path

import pytest

import cidag.execution.techniques as tech_mod
from cidag.execution.audit import AuditLog, redact, redact_text
from cidag.execution.canary import run_canary
from cidag.execution.cleanup import apply_cleanups
from cidag.execution.context import ExploitContext
from cidag.execution.detections import all_detections
from cidag.execution.findings import load_report, matching_findings
from cidag.execution.guard import AuthorizationGuard, ExploitError, GuardError
from cidag.execution.pacu_bridge import PacuBridge, PacuBridgeError, parse_whoami
from cidag.execution.report import demo_report, render_report, write_report
from cidag.execution.runner import ExploitRunner
from cidag.execution.session import canonical_iam_arn

ACCT = "123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCT}:role/attacker"
USER_ARN = f"arn:aws:iam::{ACCT}:user/attacker"
ADMIN_POLICY = f"arn:aws:iam::{ACCT}:policy/AdministratorAccess"


class FakeClient:
    def __init__(self, service, recorder):
        self.service = service
        self.recorder = recorder
        self.responses = {}

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def call(**kwargs):
            self.recorder.append((self.service, name, kwargs))
            response = self.responses.get(name, {})
            return response(kwargs) if callable(response) else response

        return call


class FakeAWS:
    def __init__(self):
        self.recorder = []
        self.clients = {}

    def client(self, service, region=None):
        return self.clients.setdefault(service, FakeClient(service, self.recorder))

    def methods(self):
        return [m for _, m, _ in self.recorder]


class FakeSession:
    def __init__(self, arn=ROLE_ARN, account=ACCT):
        self.region = "us-east-1"
        self.aws = FakeAWS()
        self.identity = {"account": account, "arn": arn, "user_id": "AIDAEXAMPLE"}

    def caller_identity(self, refresh=False):
        return self.identity

    def client(self, service, region=None):
        return self.aws.client(service, region)


def _allow_simulation(kwargs):
    return {"EvaluationResults": [
        {"EvalActionName": a, "EvalDecision": "allowed"}
        for a in kwargs.get("ActionNames", [])]}


class FakeBotoSession:
    last = None

    def __init__(self, **kwargs):
        FakeBotoSession.last = kwargs

    def client(self, service, region_name=None):
        class STS:
            def get_caller_identity(self):
                return {"Account": ACCT, "Arn": USER_ARN, "UserId": "AIDAASSUMED"}

        return STS()


def _runner(session, tmp_path, **kwargs):
    guard = AuthorizationGuard(session, [ACCT], assume_yes=True)
    kwargs.setdefault("allow_unproven", True)
    return ExploitRunner(session, guard, audit_root=str(tmp_path), **kwargs)


def test_canonical_arn_and_role_name():
    assert canonical_iam_arn(f"arn:aws:sts::{ACCT}:assumed-role/attacker/sess") == ROLE_ARN


def test_guard_refuses_without_explicit_authorization():
    session = FakeSession()
    with pytest.raises(GuardError):
        AuthorizationGuard(session, []).authorize()
    assert session.aws.recorder == []


def test_guard_refuses_account_mismatch():
    with pytest.raises(GuardError):
        AuthorizationGuard(FakeSession(), ["999999999999"]).authorize()


def test_guard_wraps_credential_errors():
    from botocore.exceptions import NoCredentialsError

    class NoCreds(FakeSession):
        def caller_identity(self, refresh=False):
            raise NoCredentialsError()

    with pytest.raises(GuardError) as exc:
        AuthorizationGuard(NoCreds(), [ACCT]).authorize()
    assert "caller identity" in str(exc.value)


def test_guard_confirmation_phrase():
    guard = AuthorizationGuard(FakeSession(), [ACCT], input_fn=lambda _: "EXECUTE nope",
                               tty_check=lambda: True)
    with pytest.raises(GuardError):
        guard.confirm("test")
    guard_yes = AuthorizationGuard(FakeSession(), [ACCT], input_fn=lambda _: f"EXECUTE {ACCT}",
                                   tty_check=lambda: True)
    guard_yes.confirm("test")


def test_guard_refuses_non_tty():
    guard = AuthorizationGuard(FakeSession(), [ACCT], tty_check=lambda: False)
    with pytest.raises(GuardError):
        guard.confirm("test")


def test_guard_simulation_denied_and_unknown():
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = {
        "EvaluationResults": [{"EvalActionName": "iam:AttachUserPolicy",
                               "EvalDecision": "implicitDeny"}]}
    guard = AuthorizationGuard(session, [ACCT], assume_yes=True)
    with pytest.raises(GuardError):
        guard.simulate(["iam:AttachUserPolicy"])
    unknown = AuthorizationGuard(session, [ACCT], accept_unknown=True)
    session.aws.client("iam").responses["simulate_principal_policy"] = {
        "EvaluationResults": []}
    assert unknown.simulate(["iam:AttachUserPolicy"])["status"] == "unknown"


def test_redaction_of_secret_fields_and_text():
    data = {"SecretAccessKey": "abc123", "AccessKeyId": "AKIAEXAMPLE"}
    assert redact(data)["SecretAccessKey"] == "***REDACTED***"
    assert redact(data)["AccessKeyId"] == "AKIAEXAMPLE"
    text = '{"SecretAccessKey": "abc123", "Password": "hunter2"}'
    scrubbed = redact_text(text)
    assert "abc123" not in scrubbed
    assert "hunter2" not in scrubbed
    assert "AKIAEXAMPLE" in redact_text("AccessKeyId: AKIAEXAMPLE")


def _report(tmp_path, technique="ESC-05", identity_arn=ROLE_ARN,
            account=ACCT, sarif=False):
    if sarif:
        data = {"version": "2.1.0", "runs": [{"results": [{
            "ruleId": technique,
            "message": {"text": "finding"},
            "properties": {"account": account,
                           "identityArn": identity_arn}}]}]}
    else:
        data = {"account_id": account, "findings": [{
            "id": "finding-1", "check_id": technique, "type": technique,
            "identity": "attacker", "identity_arn": identity_arn,
            "account": account, "title": "test finding"}]}
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(data))
    return path


def test_run_requires_scan_evidence(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    with pytest.raises(ExploitError, match="no scan evidence"):
        _runner(session, tmp_path, allow_unproven=False).run("ESC-05")
    assert "attach_role_policy" not in session.aws.methods()


def test_run_uses_matching_report_finding(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    report = load_report(_report(tmp_path))
    result = _runner(session, tmp_path, findings=report,
                     allow_unproven=False).run("ESC-05")
    manifest = json.loads(Path(result.manifest_path).read_text())
    assert manifest["finding_evidence"]["status"] == "matched"
    assert manifest["finding_evidence"]["finding_ids"] == ["finding-1"]


def test_run_refuses_report_without_matching_principal(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    report = load_report(_report(
        tmp_path, identity_arn=f"arn:aws:iam::{ACCT}:user/someone-else"))
    with pytest.raises(ExploitError, match="was not found"):
        _runner(session, tmp_path, findings=report,
                allow_unproven=False).run("ESC-05")
    assert "attach_role_policy" not in session.aws.methods()


def test_load_sarif_report_and_match():
    import tempfile
    path = Path(tempfile.mkdtemp()) / "scan.sarif"
    path.write_text(json.dumps({"runs": [{"results": [{
        "ruleId": "ESC-05",
        "properties": {"account": ACCT, "identityArn": ROLE_ARN}}]}]}))
    findings = load_report(path)
    assert findings[0]["technique"] == "ESC-05"
    identity = {"account": ACCT, "arn": ROLE_ARN}
    assert matching_findings(findings, "esc-05", identity)


def test_plan_only_entries_are_listed_and_runnable_only_as_plans(tmp_path):
    from cidag.execution.runner import list_techniques
    rows = {row["id"]: row for row in list_techniques()}
    assert len(rows) == 15
    assert rows["AZ-01"]["provider"] == "azure"
    assert rows["GCP-01"]["provider"] == "gcp"
    assert rows["ESC-01"]["executable"] is False
    assert rows["ESC-03"]["executable"] is False
    assert rows["ESC-13"]["executable"] is False
    runner = _runner(FakeSession(), tmp_path)
    plan = runner.plan("ESC-01")
    assert plan["status"] == "plan-only"
    assert plan["steps"]
    with pytest.raises(ExploitError, match="plan-only"):
        runner.run("ESC-01")


def test_plan_is_read_only(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    plan = _runner(session, tmp_path).plan("ESC-05")
    assert plan["actions"]
    assert all(m in {"simulate_principal_policy", "list_attached_role_policies"}
               for m in session.aws.methods())


def test_plan_uses_principal_specific_preflight(tmp_path):
    role = FakeSession()
    role.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    _runner(role, tmp_path).plan("ESC-05")
    role_sim = [k for _, m, k in role.aws.recorder
                if m == "simulate_principal_policy"][0]
    assert role_sim["ActionNames"] == ["iam:AttachRolePolicy"]

    user = FakeSession(arn=USER_ARN)
    user.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    _runner(user, tmp_path).plan("ESC-05")
    user_sim = [k for _, m, k in user.aws.recorder
                if m == "simulate_principal_policy"][0]
    assert user_sim["ActionNames"] == ["iam:AttachUserPolicy"]


def test_esc11_plan_uses_full_role_arn_as_resource(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    session.aws.client("iam").responses["get_role"] = {"Role": {
        "RoleName": "target", "Arn": f"arn:aws:iam::{ACCT}:role/target",
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}}
    _runner(session, tmp_path).plan("ESC-11", {"target_role": "target"})
    sim = [k for _, m, k in session.aws.recorder
           if m == "simulate_principal_policy"][0]
    assert sim["ResourceArns"] == [f"arn:aws:iam::{ACCT}:role/target"]


def test_esc05_refuses_when_policy_already_attached(tmp_path):
    session = FakeSession()
    iam = session.aws.client("iam")
    iam.responses["simulate_principal_policy"] = _allow_simulation
    iam.responses["list_attached_role_policies"] = {"AttachedPolicies": [
        {"PolicyArn": ADMIN_POLICY}]}
    with pytest.raises(Exception, match="already attached"):
        _runner(session, tmp_path).run(
            "ESC-05", {"admin_policy_arn": ADMIN_POLICY})
    assert "attach_role_policy" not in session.aws.methods()


def test_esc10_refuses_existing_group_membership(tmp_path):
    session = FakeSession(arn=USER_ARN)
    iam = session.aws.client("iam")
    iam.responses["simulate_principal_policy"] = _allow_simulation
    iam.responses["list_groups_for_user"] = {"Groups": [{"GroupName": "admins"}]}
    with pytest.raises(Exception, match="already a member"):
        _runner(session, tmp_path).run("ESC-10", {"target_group": "admins"})
    assert "add_user_to_group" not in session.aws.methods()


def test_keep_refused_for_credential_issuing_techniques(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    with pytest.raises(Exception, match="secret is never written"):
        _runner(session, tmp_path, keep=True).run("ESC-07")


def test_esc05_attaches_verifies_and_rolls_back(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    result = _runner(session, tmp_path).run("ESC-05")
    assert result.status == "rolled-back"
    methods = session.aws.methods()
    assert "attach_role_policy" in methods
    assert methods[-1] == "detach_role_policy"
    manifest = json.loads(Path(result.manifest_path).read_text())
    assert manifest["status"] == "rolled-back"
    assert manifest["verification"]["proved"] is True
    assert manifest["artifacts"][0]["cleanup"]["op"] == "detach_role_policy"
    assert "***REDACTED***" not in Path(result.manifest_path).read_text()


def test_esc05_verification_failure_rolls_back(tmp_path):
    session = FakeSession()
    calls = {"sim": 0}

    def simulate(kwargs):
        calls["sim"] += 1
        if calls["sim"] == 1:
            return _allow_simulation(kwargs)
        return {"EvaluationResults": [
            {"EvalActionName": a, "EvalDecision": "implicitDeny"}
            for a in kwargs.get("ActionNames", [])]}

    session.aws.client("iam").responses["simulate_principal_policy"] = simulate
    with pytest.raises(Exception):
        _runner(session, tmp_path).run("ESC-05")
    assert "detach_role_policy" in session.aws.methods()


def test_esc04_creates_sets_and_restores_version(tmp_path):
    session = FakeSession()
    iam = session.aws.client("iam")
    iam.responses["get_policy"] = {
        "Policy": {"Arn": ADMIN_POLICY, "DefaultVersionId": "v1"}}
    iam.responses["create_policy_version"] = {"PolicyVersion": {"VersionId": "v2"}}
    iam.responses["simulate_principal_policy"] = _allow_simulation
    result = _runner(session, tmp_path).run(
        "ESC-04", {"target_policy": ADMIN_POLICY})
    assert result.status == "rolled-back"
    updates = [(m, k) for _, m, k in session.aws.recorder
               if m in ("set_default_policy_version", "delete_policy_version")]
    assert updates[-2][1]["VersionId"] == "v1"
    assert updates[-1][1]["VersionId"] == "v2"


def test_esc07_secret_never_persisted(tmp_path, monkeypatch):
    monkeypatch.setattr(tech_mod.boto3, "Session", FakeBotoSession)
    session = FakeSession(arn=USER_ARN)
    iam = session.aws.client("iam")
    iam.responses["create_access_key"] = {
        "AccessKey": {"AccessKeyId": "AKIAEXAMPLE", "SecretAccessKey": "top-secret"}}
    iam.responses["simulate_principal_policy"] = _allow_simulation
    result = _runner(session, tmp_path).run("ESC-07")
    assert result.evidence["arn"] == USER_ARN
    assert "delete_access_key" in session.aws.methods()
    for path in Path(result.audit_dir).rglob("*"):
        if path.is_file():
            assert "top-secret" not in path.read_text()
    assert FakeBotoSession.last["aws_secret_access_key"] == "top-secret"


def test_esc11_trust_hijack_restores_original_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(tech_mod.boto3, "Session", FakeBotoSession)
    original = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
         "Action": "sts:AssumeRole"}]}
    session = FakeSession()
    iam = session.aws.client("iam")
    iam.responses["get_role"] = {"Role": {
        "RoleName": "target", "Arn": f"arn:aws:iam::{ACCT}:role/target",
        "AssumeRolePolicyDocument": original}}
    iam.responses["simulate_principal_policy"] = _allow_simulation
    session.aws.client("sts").responses["assume_role"] = {"Credentials": {
        "AccessKeyId": "AKIA", "SecretAccessKey": "s", "SessionToken": "t"}}
    result = _runner(session, tmp_path).run(
        "ESC-11", {"target_role": "target"})
    assert result.evidence["assumed_arn"] == USER_ARN
    updates = [k for _, m, k in session.aws.recorder
               if m == "update_assume_role_policy"]
    assert len(updates) == 2
    restored = updates[-1]["PolicyDocument"]
    assert json.loads(restored) == original


def test_esc02_lambda_probe_creates_invokes_and_deletes(tmp_path):
    session = FakeSession()
    lam = session.aws.client("lambda")
    lam.responses["create_function"] = {
        "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCT}:function:cidag-probe"}
    lam.responses["invoke"] = {"Payload": json.dumps(
        {"Account": ACCT, "Arn": f"arn:aws:sts::{ACCT}:assumed-role/admin/sess"}
    ).encode()}
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    result = _runner(session, tmp_path).run(
        "ESC-02", {"pass_role": f"arn:aws:iam::{ACCT}:role/admin"})
    assert result.status == "rolled-back"
    assert "create_function" in session.aws.methods()
    assert session.aws.methods()[-1] == "delete_function"
    assert result.evidence["probe_account"] == ACCT


def test_esc06_put_inline_policy_and_rollback(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    result = _runner(session, tmp_path).run("ESC-06")
    assert result.status == "rolled-back"
    methods = session.aws.methods()
    assert "put_role_policy" in methods
    assert methods[-1] == "delete_role_policy"


def test_esc08_sets_default_and_restores_it(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    session.aws.client("iam").responses["get_policy"] = {
        "Policy": {"DefaultVersionId": "v1"}}
    result = _runner(session, tmp_path).run(
        "ESC-08", {"target_policy": ADMIN_POLICY, "policy_version": "v2"})
    assert result.status == "rolled-back"
    versions = [k["VersionId"] for _, m, k in session.aws.recorder
                if m == "set_default_policy_version"]
    assert versions == ["v2", "v1"]


def test_esc09_removes_boundary_and_restores_it(tmp_path):
    session = FakeSession()
    boundary = f"arn:aws:iam::{ACCT}:policy/Boundary"
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    session.aws.client("iam").responses["get_role"] = {"Role": {
        "RoleName": "attacker",
        "PermissionsBoundary": {"PermissionsBoundaryArn": boundary}}}
    result = _runner(session, tmp_path).run("ESC-09")
    assert result.status == "rolled-back"
    calls = [(m, k) for _, m, k in session.aws.recorder
             if m in ("delete_role_permissions_boundary",
                      "put_role_permissions_boundary")]
    assert calls[0][0] == "delete_role_permissions_boundary"
    assert calls[-1] == ("put_role_permissions_boundary",
                         {"RoleName": "attacker", "PermissionsBoundary": boundary})


def test_esc10_adds_group_and_removes_itself(tmp_path):
    session = FakeSession(arn=USER_ARN)
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    result = _runner(session, tmp_path).run("ESC-10", {"target_group": "admins"})
    assert result.status == "rolled-back"
    assert "add_user_to_group" in session.aws.methods()
    assert session.aws.methods()[-1] == "remove_user_from_group"


def test_esc12_creates_login_profile_and_deletes_it(tmp_path):
    class NoSuchEntity(Exception):
        response = {"Error": {"Code": "NoSuchEntity"}}

    session = FakeSession(arn=USER_ARN)
    iam = session.aws.client("iam")
    iam.responses["simulate_principal_policy"] = _allow_simulation
    state = {"reads": 0}

    def get_login_profile(kwargs):
        state["reads"] += 1
        if state["reads"] == 1:
            raise NoSuchEntity()
        return {"LoginProfile": {"PasswordResetRequired": True}}

    iam.responses["get_login_profile"] = get_login_profile
    result = _runner(session, tmp_path).run("ESC-12")
    assert result.status == "rolled-back"
    assert result.evidence["login_profile"] is True
    assert "create_login_profile" in session.aws.methods()
    assert session.aws.methods()[-1] == "delete_login_profile"
    for path in Path(result.audit_dir).rglob("*"):
        if path.is_file():
            text = path.read_text()
            assert "Cidag!7" not in text


def test_rollback_failure_is_reported_not_hidden(tmp_path):
    session = FakeSession()
    iam = session.aws.client("iam")
    iam.responses["simulate_principal_policy"] = _allow_simulation

    def denied(kwargs):
        raise RuntimeError("AccessDenied")

    iam.responses["detach_role_policy"] = denied
    result = _runner(session, tmp_path).run("ESC-05")
    assert result.status == "rollback-incomplete"
    manifest = json.loads(Path(result.manifest_path).read_text())
    assert manifest["rollback"][-1]["ok"] is False


def test_plan_read_error_becomes_exploit_error(tmp_path):
    from botocore.exceptions import ClientError

    session = FakeSession()
    iam = session.aws.client("iam")
    iam.responses["simulate_principal_policy"] = _allow_simulation

    def denied(kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied",
                                     "Message": "no list"}}, "ListAttachedRolePolicies")

    iam.responses["list_attached_role_policies"] = denied
    with pytest.raises(ExploitError, match="could not plan"):
        _runner(session, tmp_path).plan("ESC-05")


def test_keep_leaves_artifact_and_cleanup_manifest_restores(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    result = _runner(session, tmp_path, keep=True).run("ESC-05")
    assert result.status == "succeeded-kept"
    assert "detach_role_policy" not in session.aws.methods()
    manifest = json.loads(Path(result.manifest_path).read_text())
    entries = [a["cleanup"] for a in manifest["artifacts"] if a.get("cleanup")]
    assert entries
    apply_cleanups(session, entries)
    assert session.aws.methods()[-1] == "detach_role_policy"


def test_esc09_requires_a_boundary_or_explicit_replacement(tmp_path):
    session = FakeSession()
    session.aws.client("iam").responses["get_role"] = {"Role": {"RoleName": "attacker"}}
    session.aws.client("iam").responses["simulate_principal_policy"] = _allow_simulation
    with pytest.raises(Exception):
        _runner(session, tmp_path).run("ESC-09")


def test_canary_is_read_back_and_deleted():
    session = FakeSession()
    client = session.aws.client("secretsmanager")
    state = {}

    def create(kwargs):
        state["marker"] = kwargs["SecretString"]
        return {"ARN": "arn:aws:secretsmanager:us-east-1:123:secret:canary"}

    client.responses["create_secret"] = create
    client.responses["get_secret_value"] = lambda kwargs: {
        "SecretString": state["marker"]}
    evidence = run_canary(ExploitContext(session, session.caller_identity()),
                          "secretsmanager")
    assert evidence["status"] == "verified"
    assert evidence["read_back"] is True
    assert state["marker"] not in json.dumps(evidence)
    methods = session.aws.methods()
    assert methods == ["create_secret", "get_secret_value", "delete_secret"]


def test_canary_auto_falls_back_to_s3():
    session = FakeSession()
    secrets = session.aws.client("secretsmanager")
    s3 = session.aws.client("s3")
    state = {}

    def denied(kwargs):
        raise RuntimeError("AccessDenied")

    secrets.responses["create_secret"] = denied
    s3.responses["put_object"] = lambda kwargs: state.update(body=kwargs["Body"]) or {}
    s3.responses["get_object"] = lambda kwargs: {"Body": io.BytesIO(state["body"])}
    evidence = run_canary(ExploitContext(session, session.caller_identity()), "auto")
    assert evidence["service"] == "s3"
    assert evidence["status"] == "verified"
    assert evidence["read_back"] is True


def test_cleanup_applies_in_reverse_order():
    session = FakeSession()
    entries = [
        {"op": "delete_policy_version",
         "params": {"PolicyArn": ADMIN_POLICY, "VersionId": "v2"}},
        {"op": "set_default_policy_version",
         "params": {"PolicyArn": ADMIN_POLICY, "VersionId": "v1"}},
    ]
    results = apply_cleanups(session, entries)
    assert all(r["ok"] for r in results)
    assert session.aws.methods() == ["set_default_policy_version",
                                     "delete_policy_version"]


def test_cleanup_encodes_trust_policy_document():
    session = FakeSession()
    doc = {"Version": "2012-10-17", "Statement": []}
    results = apply_cleanups(session, [{
        "op": "update_assume_role_policy",
        "params": {"RoleName": "target", "PolicyDocument": doc}}])
    assert results[0]["ok"] is True
    assert json.loads(session.aws.recorder[0][2]["PolicyDocument"]) == doc


def test_detections_cover_every_technique():
    detections = all_detections()
    assert len(detections) == 15
    providers = {d["provider"] for d in detections}
    assert providers == {"aws", "azure", "gcp"}
    for d in detections:
        if d["provider"] == "aws":
            assert d["sigma"].startswith("title: CIDAG")
            assert "detection:" in d["sigma"]
            assert d["insights"].startswith("fields")
            assert d["eventbridge"]["detail"]["eventName"]
        else:
            assert d["sigma"] is None
            assert d["eventbridge"] is None
            assert d["insights"]


def test_audit_log_redacts_and_writes(tmp_path):
    audit = AuditLog(tmp_path, ACCT, ROLE_ARN, "ESC-05")
    audit.event("test", SecretAccessKey="top-secret", note="ok")
    path = audit.save("succeeded")
    content = Path(path).read_text()
    assert "top-secret" not in content
    assert "succeeded" in content
    assert Path(audit.audit_path).read_text().count("top-secret") == 0


def test_report_and_demo_mask_accounts(tmp_path):
    audit = AuditLog(tmp_path, ACCT, ROLE_ARN, "ESC-05")
    audit.plan([], {"status": "allowed"})
    audit.verification({"proved": True})
    manifest_path = audit.save("rolled-back")
    manifest = json.loads(Path(manifest_path).read_text())
    report = render_report(manifest, audit.dir, mask=True)
    assert "1234****9012" in report
    assert ACCT not in report
    out = write_report(manifest_path)
    assert Path(out).exists()
    demo = demo_report(tmp_path, tmp_path / "demo.md")
    assert "Portfolio Demo" in Path(demo).read_text()


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_pacu_whoami_parse_and_module_allowlist():
    assert parse_whoami('{"Account": "123456789012", "Arn": "arn:aws:iam::1:user/x"}')[
        "account"] == ACCT
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        if "--whoami" in argv:
            return FakeProc(stdout='{"Account": "%s"}' % ACCT)
        return FakeProc(stdout="module output SecretAccessKey: abc123")

    bridge = PacuBridge(pacu_path="/usr/local/bin/pacu", runner=runner)
    result = bridge.run_module("demo", "iam__enum_permissions",
                               module_args="--all", expected_account=ACCT)
    assert result["account"] == ACCT
    assert "abc123" not in result["output"]
    assert calls[0][0][-1] == "--whoami"
    assert calls[1][0][-2:] == ["--module-args", "--all"]
    assert calls[1][1]["shell"] is False
    with pytest.raises(PacuBridgeError):
        bridge.run_module("demo", "iam__backdoor_users_keys")


def test_pacu_account_mismatch_refused():
    def runner(argv, **kwargs):
        return FakeProc(stdout='{"Account": "999999999999"}')

    bridge = PacuBridge(pacu_path="/usr/local/bin/pacu", runner=runner)
    with pytest.raises(PacuBridgeError):
        bridge.run_module("demo", "iam__enum_permissions", expected_account=ACCT)


def test_pacu_missing_binary_refused():
    bridge = PacuBridge(pacu_path=None)
    bridge.pacu_path = None
    with pytest.raises(PacuBridgeError):
        bridge.whoami("demo")


AZ_SUB = "00000000-0000-0000-0000-000000000001"
AZ_PRINCIPAL = "00000000-0000-0000-0000-000000000002"
GCP_PROJECT = "cidag-lab"
GCP_MEMBER = "user:analyst@example.com"


class _Model:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class FakeRoleAssignments:
    def __init__(self):
        self.assignments = []
        self.methods = []

    def list_for_scope(self, scope):
        self.methods.append("list")
        return list(self.assignments)

    def create(self, scope, name, parameters):
        self.methods.append("create")
        assignment = _Model(
            id=f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
            properties=_Model(
                role_definition_id=parameters.role_definition_id,
                principal_id=parameters.principal_id))
        self.assignments.append(assignment)
        return assignment

    def get(self, scope, name):
        self.methods.append("get")
        for assignment in self.assignments:
            if assignment.id.endswith(name):
                return assignment
        raise KeyError(name)

    def delete(self, scope, name):
        self.methods.append("delete")
        self.assignments = [a for a in self.assignments
                            if not a.id.endswith(name)]


class FakeAzure:
    def __init__(self):
        self.role_assignments = FakeRoleAssignments()


class FakeAzureSession:
    provider = "azure"
    region = ""
    account = AZ_SUB

    def __init__(self):
        self.azure = FakeAzure()
        self.identity = {"account": AZ_SUB,
                         "arn": f"azure:{AZ_SUB}:principal:{AZ_PRINCIPAL}",
                         "user_id": AZ_PRINCIPAL}

    def caller_identity(self):
        return self.identity

    def client(self, service):
        return self.azure

    def role_assignment_parameters(self, role_id, principal_id):
        return _Model(role_definition_id=role_id, principal_id=principal_id)


class FakeBindings(list):
    def add(self):
        binding = _Model(role="", members=[])
        self.append(binding)
        return binding


class _Policy:
    def __init__(self, bindings=None):
        self.bindings = FakeBindings(bindings or [])

    def ClearField(self, name):
        if name == "bindings":
            self.bindings.clear()


class FakeProjects:
    def __init__(self):
        self.policy = _Policy()
        self.methods = []

    def get_iam_policy(self, request):
        self.methods.append("get")
        import copy
        return copy.deepcopy(self.policy)

    def set_iam_policy(self, request):
        self.methods.append("set")
        import copy
        self.policy = copy.deepcopy(request["policy"])


class FakeGcpSession:
    provider = "gcp"
    region = ""
    account = GCP_PROJECT

    def __init__(self):
        self.projects = FakeProjects()
        self.identity = {"account": GCP_PROJECT, "arn": GCP_MEMBER,
                         "user_id": GCP_MEMBER}

    def caller_identity(self):
        return self.identity

    def client(self, service):
        return self.projects


def _cloud_runner(session, account, tmp_path):
    guard = AuthorizationGuard(session, [account], assume_yes=True)
    return ExploitRunner(session, guard, audit_root=str(tmp_path),
                         allow_unproven=True)


def test_azure_owner_assignment_runs_and_rolls_back(tmp_path):
    session = FakeAzureSession()
    runner = _cloud_runner(session, AZ_SUB, tmp_path)
    plan = runner.plan("AZ-01")
    assert plan["preflight"]["status"] == "skipped"
    assert plan["actions"] == ["Assign Owner role to caller"]
    assert session.azure.role_assignments.assignments == []
    session.azure.role_assignments.methods.clear()

    result = runner.run("AZ-01")
    assert result.status == "rolled-back"
    assert result.evidence["effect"] == "Owner at scope"
    assert session.azure.role_assignments.assignments == []
    assert session.azure.role_assignments.methods == [
        "list", "create", "get", "delete"]


def test_azure_technique_rejected_on_aws_session(tmp_path):
    session = FakeSession()
    with pytest.raises(ExploitError, match="targets azure"):
        _runner(session, tmp_path).plan("AZ-01")


def test_gcp_owner_binding_runs_and_restores_policy(tmp_path):
    session = FakeGcpSession()
    runner = _cloud_runner(session, GCP_PROJECT, tmp_path)
    plan = runner.plan("GCP-01", {"member": GCP_MEMBER})
    assert plan["preflight"]["status"] == "skipped"
    assert plan["actions"] == ["Grant roles/owner to member"]

    result = runner.run("GCP-01", {"member": GCP_MEMBER})
    assert result.status == "rolled-back"
    assert result.evidence["member"] == GCP_MEMBER
    owners = [b for b in session.projects.policy.bindings
              if b.role == "roles/owner"]
    assert owners == []


def test_gcp_keep_is_refused(tmp_path):
    session = FakeGcpSession()
    guard = AuthorizationGuard(session, [GCP_PROJECT], assume_yes=True)
    runner = ExploitRunner(session, guard, audit_root=str(tmp_path),
                           allow_unproven=True, keep=True)
    with pytest.raises(ExploitError, match="AWS-only"):
        runner.run("GCP-01", {"member": GCP_MEMBER})


def test_azure_scope_cannot_leave_authorized_subscription(tmp_path):
    session = FakeAzureSession()
    runner = _cloud_runner(session, AZ_SUB, tmp_path)
    with pytest.raises(ExploitError, match="authorized subscription"):
        runner.plan("AZ-01", {"scope": "/subscriptions/other-sub"})
    assert session.azure.role_assignments.methods == []
