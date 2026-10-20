import json
from types import SimpleNamespace

import pytest

from cidag.cli.main import main
from cidag.collectors.azure import normalize as normalize_azure
from cidag.collectors.base import MockCollector
from cidag.collectors.gcp import normalize as normalize_gcp


def test_azure_normalize_role_defs_and_assignments():
    role_defs = [
        SimpleNamespace(
            id="/subs/1/providers/Microsoft.Authorization/roleDefinitions/owner",
            role_name="Owner",
            permissions=[SimpleNamespace(actions=["*"], data_actions=[])],
        ),
        SimpleNamespace(
            id="/subs/1/providers/Microsoft.Authorization/roleDefinitions/kv",
            role_name="KV Reader",
            permissions=[SimpleNamespace(
                actions=[], data_actions=["Microsoft.KeyVault/vaults/secrets/getSecret/action"])],
        ),
    ]
    assignments = [
        SimpleNamespace(principal_id="u1", principal_type="User",
                        role_definition_id=role_defs[0].id),
        SimpleNamespace(principal_id="sp1", principal_type="ServicePrincipal",
                        role_definition_id=role_defs[1].id),
        SimpleNamespace(principal_id="sp1", principal_type="ServicePrincipal",
                        role_definition_id=role_defs[0].id),
    ]

    inv = normalize_azure("subs-1", role_defs, assignments)

    assert inv["cloud"] == "azure"
    assert inv["account_id"] == "subs-1"
    by_name = {i["name"]: i for i in inv["identities"]}
    assert by_name["u1"]["type"] == "user"
    assert by_name["sp1"]["type"] == "service_principal"
    assert len(by_name["sp1"]["attached_policies"]) == 2
    assert inv["policies"][0]["statements"][0]["Action"] == ["*"]
    assert "Microsoft.KeyVault/vaults/secrets/getSecret/action" in \
        inv["policies"][1]["statements"][0]["Action"]


def test_gcp_normalize_bindings_and_roles():
    bindings = [
        {"role": "roles/owner", "members": ["user:admin@example.com"]},
        {"role": "projects/p/roles/deployer",
         "members": ["serviceAccount:ci@p.iam.gserviceaccount.com",
                     "group:devs@example.com"]},
    ]
    roles = {
        "roles/owner": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        "projects/p/roles/deployer": [{"Effect": "Allow",
                                        "Action": ["resourcemanager.projects.setIamPolicy"],
                                        "Resource": "*"}],
    }

    inv = normalize_gcp("p", bindings, roles)

    assert inv["cloud"] == "gcp"
    assert inv["account_id"] == "p"
    kinds = {i["name"]: i["type"] for i in inv["identities"]}
    assert kinds["serviceAccount:ci@p.iam.gserviceaccount.com"] == "service_account"
    assert kinds["group:devs@example.com"] == "group"
    sa = next(i for i in inv["identities"] if i["name"].startswith("serviceAccount"))
    assert sa["attached_policies"] == ["gcp:role:projects/p/roles/deployer"]
    assert {p["arn"] for p in inv["policies"]} == {
        "gcp:role:roles/owner", "gcp:role:projects/p/roles/deployer"}


def test_mock_collector_selects_cloud_file():
    assert MockCollector(cloud="azure").collect()["cloud"] == "azure"
    assert MockCollector(cloud="gcp").collect()["account_id"] == "cidag-demo"


def test_azure_scan_offline_policy_findings(capsys):
    main(["scan", "--cloud", "azure", "--modules", "iam,policy", "--json"])
    data = json.loads(capsys.readouterr().out)
    checks = {f["check_id"] for f in data["findings"]}
    assert "POL-001" in checks
    assert "POL-002" in checks
    assert data["account_id"].startswith("9f8e7d6c")


def test_gcp_scan_offline_policy_findings(capsys):
    main(["scan", "--cloud", "gcp", "--modules", "iam,policy", "--json"])
    data = json.loads(capsys.readouterr().out)
    checks = {f["check_id"] for f in data["findings"]}
    assert "POL-001" in checks
    assert "POL-002" in checks
    assert "POL-003" in checks
    assert data["account_id"] == "cidag-demo"


def test_graph_renders_azure_inventory(capsys):
    main(["graph", "--cloud", "azure"])
    out = capsys.readouterr().out
    assert "Owner" in out
    assert "ci-deployer" in out


def test_aws_only_module_rejected_for_azure():
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--cloud", "azure", "--modules", "s3"])
    assert "AWS-only" in str(exc.value)


def test_cloud_mock_report(capsys):
    main(["report", "--cloud", "gcp", "--modules", "iam,policy", "--format", "md"])
    out = capsys.readouterr().out
    assert "cidag-demo" in out
    assert "POL-001" in out
