from cidag.analysis.engine import run_analysis, blast_radius
from cidag.graph.builder import build_graph


def test_wildcard_finding(inventory):
    g = build_graph(inventory)
    result = run_analysis(g, inventory)
    wild = [f for f in result["findings"] if f["type"] == "WILDCARD_POLICY"]
    assert any(f["identity"] == "admin-role" for f in wild)


def test_passrole_escalation_detected(inventory):
    g = build_graph(inventory)
    result = run_analysis(g, inventory)
    esc = [f for f in result["findings"] if f["type"] == "ESC-02"]
    assert any(f["identity"] == "ci-deployer" for f in esc)


def test_attack_path_found(inventory):
    g = build_graph(inventory)
    result = run_analysis(g, inventory)
    paths = [f for f in result["findings"] if f["type"] == "ATTACK_PATH"]
    assert paths
    assert any("admin-role" in f["chain"] for f in paths)


def test_deny_suppresses_escalation(inventory):
    for p in inventory["policies"]:
        if p["name"] == "CIDeployerPolicy":
            p["statements"].append(
                {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"})
    g = build_graph(inventory)
    result = run_analysis(g, inventory)
    esc = [f for f in result["findings"]
           if f["type"] in {"ESC-01", "ESC-02", "ESC-03"} and f["identity"] == "ci-deployer"]
    assert not esc


def test_blast_radius(inventory):
    g = build_graph(inventory)
    run_analysis(g, inventory)
    items = blast_radius(g, "lambda-exec-role")
    labels = [i["label"] for i in items]
    assert "admin-role" in labels


def test_can_pass_has_no_self_loop(inventory):
    """A wildcard PassRole must not emit an identity -> itself can-pass edge."""
    g = build_graph(inventory)
    run_analysis(g, inventory)
    self_loops = [(u, v) for u, v in g.edges() if u == v]
    assert self_loops == []

def _grant(inventory, identity_name, actions):
    arn = f"arn:aws:iam::123456789012:policy/TestGrant{len(inventory['policies'])}"
    inventory["policies"].append({
        "name": f"TestGrant{len(inventory['policies'])}", "arn": arn,
        "statements": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    })
    for ident in inventory["identities"]:
        if ident["name"] == identity_name:
            ident.setdefault("attached_policies", []).append(arn)


def _esc_types(inventory):
    g = build_graph(inventory)
    result = run_analysis(g, inventory)
    return {(f["type"], f["identity"]) for f in result["findings"]}


def test_update_assume_role_policy_escalation(inventory):
    _grant(inventory, "readonly-auditor", ["iam:UpdateAssumeRolePolicy"])
    assert ("ESC-11", "readonly-auditor") in _esc_types(inventory)


def test_login_profile_escalation(inventory):
    _grant(inventory, "readonly-auditor", ["iam:UpdateLoginProfile"])
    assert ("ESC-12", "readonly-auditor") in _esc_types(inventory)


def test_glue_dev_endpoint_escalation(inventory):
    _grant(inventory, "readonly-auditor", ["glue:CreateDevEndpoint"])
    assert ("ESC-13", "readonly-auditor") in _esc_types(inventory)


def test_esc_rules_do_not_fire_without_permission(inventory):
    types = _esc_types(inventory)
    offenders = {(t, ident) for t, ident in types
                 if t in {"ESC-11", "ESC-12", "ESC-13"} and ident != "admin-role"}
    assert offenders == set()
