from cidag.graph.builder import build_graph, graph_summary


def test_graph_builds(inventory):
    g = build_graph(inventory)
    assert g.number_of_nodes() > 0
    assert g.number_of_edges() > 0


def test_attached_to_edge_exists(inventory):
    g = build_graph(inventory)
    ci = "arn:aws:iam::123456789012:user/ci-deployer"
    pol = "arn:aws:iam::123456789012:policy/CIDeployerPolicy"
    assert g.has_edge(ci, pol)
    assert g.edges[ci, pol]["rel"] == "attached-to"


def test_can_assume_edge_exists(inventory):
    g = build_graph(inventory)
    lam = "arn:aws:iam::123456789012:role/lambda-exec-role"
    adm = "arn:aws:iam::123456789012:role/admin-role"
    assert g.has_edge(lam, adm)
    assert g.edges[lam, adm]["rel"] == "can-assume"


def test_summary(inventory):
    g = build_graph(inventory)
    s = graph_summary(g)
    assert s["nodes"] == g.number_of_nodes()
    assert "user" in s["by_kind"]