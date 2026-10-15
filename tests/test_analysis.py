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