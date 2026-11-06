"""Azure deny assignments and GCP organization policy constraints.

Both are *cloud guardrails*: deny-only and principal-scoped. They must
suppress escalation findings, wildcard-admin detection, and PassRole edges for
exactly the identities they name -- never grant a permission, never leak onto
an unnamed identity.
"""
from types import SimpleNamespace

from cidag.analysis.engine import run_analysis
from cidag.collectors.azure import AzureCollector
from cidag.collectors.azure import normalize as normalize_azure
from cidag.collectors.base import MockCollector
from cidag.collectors.gcp import GcpCollector
from cidag.collectors.gcp import normalize as normalize_gcp
from cidag.collectors.gcp import normalize_org_policies
from cidag.graph.builder import build_graph
from cidag.normalizer.evaluator import compute_effective

ACCT = "111122223333"
IDENT = f"arn:aws:iam::{ACCT}:role/contractor"
ADMIN = f"arn:aws:iam::{ACCT}:role/admin"
ADMIN_POLICY = f"arn:aws:iam::{ACCT}:policy/Admin"

SUB = "9f8e7d6c-5b4a-4938-8271-0a1b2c3d4e5f"
AZ_ARNS = f"azure:{SUB}:principal:"
ROLE_WRITE = "Microsoft.Authorization/roleAssignments/write"
ROLE_DEF_WRITE = "Microsoft.Authorization/roleDefinitions/write"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _policy(arn, actions, effect="Allow"):
    return {"arn": arn, "name": arn.rsplit("/", 1)[-1],
            "statements": [{"Effect": effect, "Action": actions, "Resource": "*"}]}


def _inventory(ident, policies, guardrails=None):
    return {"account_id": ACCT, "identities": [ident], "policies": policies,
            "resources": [], "guardrails": guardrails or []}


def _guardrail(principals, actions, not_actions=None, effect="Deny"):
    guardrail = {"id": "g", "name": "g", "source": "test",
                 "statements": [{"Effect": effect, "Action": actions,
                                 "NotAction": not_actions or [], "Resource": "*"}]}
    if principals is not None:
        guardrail["principals"] = principals
    return guardrail


def _types(inv):
    return {f["type"] for f in run_analysis(build_graph(inv), inv)["findings"]}


def _azure_inv(actions, deny_assignments=None, principals=("admins",)):
    """An Azure inventory whose principals hold a role granting ``actions``."""
    role_id = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/r1"
    role_defs = [SimpleNamespace(
        id=role_id, role_name="Custom",
        permissions=[SimpleNamespace(actions=list(actions), not_actions=[],
                                     data_actions=[], not_data_actions=[])])]
    assignments = [SimpleNamespace(principal_id=p, principal_type="Group",
                                   role_definition_id=role_id)
                   for p in principals]
    return normalize_azure(SUB, role_defs, assignments, deny_assignments)


def _azure_deny(principals=("admins",), excluded=(), actions=None,
                not_actions=()):
    return SimpleNamespace(
        id=f"/subscriptions/{SUB}/providers/Microsoft.Authorization/denyAssignments/d1",
        display_name="block role writes",
        description="block role writes",
        scope=f"/subscriptions/{SUB}",
        principals=[SimpleNamespace(object_id=p) for p in principals],
        exclude_principals=[SimpleNamespace(object_id=p) for p in excluded],
        permissions=[SimpleNamespace(
            actions=list(actions or [ROLE_WRITE, ROLE_DEF_WRITE]),
            not_actions=list(not_actions), data_actions=[], not_data_actions=[])],
    )


# --------------------------------------------------------------------------
# Azure deny assignments
# --------------------------------------------------------------------------

def test_azure_deny_assignment_normalizes_to_guardrail():
    inv = _azure_inv([ROLE_WRITE], [_azure_deny()])
    guardrail = inv["guardrails"][0]
    assert guardrail["source"] == "azure_deny_assignment"
    assert guardrail["scope"] == f"/subscriptions/{SUB}"
    assert guardrail["principals"] == [f"{AZ_ARNS}admins"]
    assert guardrail["exclude_principals"] == []
    assert guardrail["statements"][0]["Effect"] == "Deny"
    assert ROLE_WRITE in guardrail["statements"][0]["Action"]


def test_azure_deny_assignment_without_permissions_is_dropped():
    deny = _azure_deny()
    deny.permissions = []
    inv = _azure_inv([ROLE_WRITE], [deny])
    assert inv["guardrails"] == []


def test_azure_deny_assignment_suppresses_az01():
    assert "AZ-01" in _types(_azure_inv([ROLE_WRITE]))  # baseline
    inv = _azure_inv([ROLE_WRITE], [_azure_deny()])
    assert compute_effective(inv)[f"{AZ_ARNS}admins"].allowed(ROLE_WRITE) is False
    assert "AZ-01" not in _types(inv)


def test_azure_deny_assignment_exclusion_keeps_az01():
    inv = _azure_inv([ROLE_WRITE], [_azure_deny(excluded=("admins",))])
    assert compute_effective(inv)[f"{AZ_ARNS}admins"].allowed(ROLE_WRITE) is True
    assert "AZ-01" in _types(inv)


def test_azure_deny_assignment_not_actions_carve_out():
    inv = _azure_inv([ROLE_WRITE, ROLE_DEF_WRITE],
                     [_azure_deny(not_actions=(ROLE_WRITE,))])
    ep = compute_effective(inv)[f"{AZ_ARNS}admins"]
    assert ep.allowed(ROLE_WRITE) is True      # carved out of the deny
    assert ep.allowed(ROLE_DEF_WRITE) is False  # still denied


def test_azure_deny_assignment_scoped_to_named_principals():
    inv = _azure_inv([ROLE_WRITE, ROLE_DEF_WRITE],
                     [_azure_deny(principals=("admins",))],
                     principals=("admins", "other"))
    perms = compute_effective(inv)
    assert perms[f"{AZ_ARNS}admins"].allowed(ROLE_WRITE) is False
    assert perms[f"{AZ_ARNS}other"].allowed(ROLE_WRITE) is True
    # Only the named principal loses AZ-01.
    identities = {f["identity"] for f in
                  run_analysis(build_graph(inv), inv)["findings"]
                  if f["type"] == "AZ-01"}
    assert identities == {"other"}


def test_azure_deny_assignment_applies_data_actions():
    inv = _azure_inv(["Microsoft.KeyVault/vaults/secrets/read"],
                     [_azure_deny(actions=["Microsoft.KeyVault/vaults/secrets/read"])])
    ep = compute_effective(inv)[f"{AZ_ARNS}admins"]
    assert ep.allowed("Microsoft.KeyVault/vaults/secrets/read") is False


def test_azure_deny_assignment_collection_degrades_to_warning(capsys):
    class DenyAssignments:
        def list_for_subscription(self):
            raise RuntimeError("403 Forbidden")

    class FakeClient:
        deny_assignments = DenyAssignments()

    assert AzureCollector()._collect_deny_assignments(FakeClient()) == []
    out = capsys.readouterr().out
    assert "[!] deny assignments: unavailable (403 Forbidden)" in out
    assert "guardrail evaluation skipped" in out


# --------------------------------------------------------------------------
# GCP organization policy constraints
# --------------------------------------------------------------------------

def test_gcp_org_policy_enforced_rule_becomes_guardrail():
    guardrails = normalize_org_policies([
        {"constraint": "constraints/iam.disableServiceAccountKeyCreation",
         "enforce": True},
        {"constraint": "constraints/iam.disableServiceAccountKeyCreation",
         "enforce": False},
    ])
    assert len(guardrails) == 1  # an unenforced rule denies nothing
    guardrail = guardrails[0]
    assert guardrail["source"] == "gcp_org_policy"
    assert guardrail["principals"] == ["*"]  # org policies bind resources
    assert guardrail["statements"][0]["Effect"] == "Deny"
    assert "iam.serviceAccounts.keys.create" in guardrail["statements"][0]["Action"]


def test_gcp_org_policy_blocks_key_creation_only():
    inv = normalize_gcp(
        "p", [{"role": "roles/owner", "members": ["user:admin@example.com"]}],
        {"roles/owner": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        org_policies=[{"constraint": "constraints/iam.disableServiceAccountKeyCreation",
                       "enforce": True}])
    ep = compute_effective(inv)["user:admin@example.com"]
    assert ep.allowed("iam.serviceAccounts.keys.create") is False
    assert ep.allowed("iam.serviceAccounts.keys.createWithPublicKey") is False
    # One denied action does not turn wildcard admin into a non-admin.
    assert ep.allowed("resourcemanager.projects.setIamPolicy") is True
    assert ep.is_admin() is True


def test_gcp_custom_constraint_maps_resource_and_method():
    guardrails = normalize_org_policies(
        [{"constraint": "customConstraints/custom.denyServiceAccountCreation",
          "enforce": True}],
        constraints={"custom.denyServiceAccountCreation": {
            "resource_types": ["iam.googleapis.com/ServiceAccount"],
            "method_types": ["CREATE"],
            "action_type": "DENY",
        }})
    assert guardrails[0]["statements"][0]["Action"] == ["iam.serviceAccounts.create"]


def test_gcp_allow_custom_constraint_is_not_expressed():
    # An ALLOW constraint is an allow-list gated on a CEL expression over the
    # resource under review; CIDAG evaluates actions, so it records the
    # constraint but denies nothing.
    guardrails = normalize_org_policies(
        [{"constraint": "customConstraints/custom.allowFoo", "enforce": True}],
        constraints={"custom.allowFoo": {
            "resource_types": ["iam.googleapis.com/ServiceAccount"],
            "method_types": ["CREATE"],
            "action_type": "ALLOW",
        }})
    assert guardrails[0]["statements"] == []


def test_gcp_unmapped_constraint_recorded_without_statements():
    guardrails = normalize_org_policies(
        [{"constraint": "constraints/compute.requireOsLogin", "enforce": True}])
    assert len(guardrails) == 1
    assert guardrails[0]["statements"] == []
    assert guardrails[0]["name"] == "constraints/compute.requireOsLogin"


def test_gcp_org_policy_collection_is_best_effort(capsys):
    policies, constraints = GcpCollector()._collect_org_policies("p", credentials=None)
    assert policies == [] and constraints == {}
    assert "[!] org polic" in capsys.readouterr().out


# --------------------------------------------------------------------------
# guardrail semantics shared by both clouds
# --------------------------------------------------------------------------

def test_guardrail_statement_never_grants():
    ident = {"type": "user", "name": "u", "arn": IDENT, "attached_policies": ["p"]}
    inv = _inventory(ident, [_policy("p", ["s3:GetObject"])],
                     [_guardrail(["*"], ["iam:PassRole"], effect="Allow")])
    assert compute_effective(inv)[IDENT].allowed("iam:PassRole") is False


def test_guardrail_without_principals_applies_to_everyone():
    ident = {"type": "user", "name": "u", "arn": IDENT, "attached_policies": ["p"]}
    inv = _inventory(ident, [_policy("p", ["s3:GetObject"])],
                     [_guardrail(None, ["s3:GetObject"])])
    assert compute_effective(inv)[IDENT].allowed("s3:GetObject") is False


def test_guardrail_without_matching_principals_touches_nobody():
    ident = {"type": "user", "name": "u", "arn": IDENT, "attached_policies": ["p"]}
    inv = _inventory(ident, [_policy("p", ["s3:GetObject"])],
                     [_guardrail(["arn:aws:iam::999988887777:role/other"],
                                 ["s3:GetObject"])])
    assert compute_effective(inv)[IDENT].allowed("s3:GetObject") is True


def test_inventory_without_guardrails_key_is_unchanged():
    ident = {"type": "user", "name": "u", "arn": IDENT, "attached_policies": ["p"]}
    inv = {"account_id": ACCT, "identities": [ident],
           "policies": [_policy("p", ["*"])], "resources": []}
    ep = compute_effective(inv)[IDENT]
    assert ep.guardrails == []
    assert ep.allowed("iam:PassRole") is True


def test_guardrail_blocks_passrole_edge_and_escalation():
    passrole = f"arn:aws:iam::{ACCT}:policy/PassRole"
    ident = {"type": "role", "name": "contractor", "arn": IDENT,
             "attached_policies": [passrole]}
    inv = _inventory(
        ident,
        [_policy(passrole, ["iam:PassRole", "lambda:UpdateFunctionCode"]),
         _policy(ADMIN_POLICY, ["*"])],
        [_guardrail([IDENT], ["iam:PassRole"])])
    inv["identities"].append({"type": "role", "name": "admin", "arn": ADMIN,
                              "attached_policies": [ADMIN_POLICY]})
    g = build_graph(inv)
    result = run_analysis(g, inv)
    assert not g.has_edge(IDENT, ADMIN)
    assert "ESC-02" not in {f["type"] for f in result["findings"]}
    assert "ATTACK_PATH" not in {f["type"] for f in result["findings"]}


def test_guardrail_suppresses_wildcard_admin_finding():
    ident = {"type": "user", "name": "u", "arn": IDENT, "attached_policies": ["p"]}
    inv = _inventory(ident, [_policy("p", ["*"])], [_guardrail(["*"], ["*"])])
    ep = compute_effective(inv)[IDENT]
    assert ep.is_admin() is False
    assert ep.wildcard_findings() == []


# --------------------------------------------------------------------------
# bundled cloud mocks
# --------------------------------------------------------------------------

def test_mock_azure_deny_assignment_suppresses_platform_admin():
    inv = MockCollector(cloud="azure").collect()
    identities = {f["identity"] for f in
                  run_analysis(build_graph(inv), inv)["findings"]
                  if f["type"] == "AZ-01"}
    assert "ci-deployer" in identities        # not named by the deny assignment
    assert "platform-admins" not in identities  # named by it


def test_mock_gcp_org_policy_blocks_service_account_key_creation():
    inv = MockCollector(cloud="gcp").collect()
    perms = compute_effective(inv)
    owner = perms["user:admin@example.com"]
    assert owner.allowed("iam.serviceAccounts.keys.create") is False
    assert owner.allowed("iam.serviceAccounts.keys.createWithPublicKey") is False
    assert owner.allowed("resourcemanager.projects.setIamPolicy") is True
    # The deployer role still escalates: the constraint does not touch it.
    deployer = perms["serviceAccount:ci-deployer@cidag-demo.iam.gserviceaccount.com"]
    assert deployer.allowed("resourcemanager.projects.setIamPolicy") is True
