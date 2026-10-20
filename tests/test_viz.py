import xml.etree.ElementTree as ET

from cidag.cli.main import main
from cidag.graph.builder import build_graph
from cidag.graph.viz import to_dot, to_mermaid, to_mermaid_paths, to_svg


def test_mermaid_lists_nodes_and_edges(inventory):
    g = build_graph(inventory)
    m = to_mermaid(g)
    assert m.startswith("flowchart TD")
    assert '["ci-deployer"]' in m
    assert "-->|contains|" in m
    assert "classDef" in m


def test_mermaid_escapes_quotes(inventory):
    g = build_graph(inventory)
    g.add_node("x", kind="policy", label='Weird "Name"')
    assert 'Weird \'Name\'' in to_mermaid(g)


def test_svg_valid_xml_with_all_labels(inventory):
    g = build_graph(inventory)
    svg = to_svg(g)
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    for n in g:
        assert g.nodes[n]["label"] in svg
    assert f"{g.number_of_nodes()} nodes" in svg


def test_svg_highlights_admin_nodes(inventory):
    g = build_graph(inventory)
    plain = to_svg(g)
    admin = {n for n in g if g.nodes[n].get("label") == "admin-role"}
    assert admin
    hl = to_svg(g, highlight=admin)
    assert "#ef4444" in hl
    assert hl != plain


def test_svg_handles_cycles(inventory):
    g = build_graph(inventory)
    nodes = list(g)
    g.add_edge(nodes[1], nodes[2])
    g.add_edge(nodes[2], nodes[1])
    ET.fromstring(to_svg(g))


def test_dot_output(inventory):
    d = to_dot(build_graph(inventory))
    assert d.startswith("digraph cidag {")
    assert d.rstrip().endswith("}")
    assert 'label="contains"' in d


def test_paths_mermaid_merges_shared_targets():
    m = to_mermaid_paths({"a": ["a", "admin"], "b": ["b", "admin"]})
    assert m.startswith("flowchart LR")
    assert m.count("-->") == 2
    assert m.count('["admin"]') == 1


def test_cli_graph_mermaid_stdout(capsys):
    assert main(["graph", "--format", "mermaid"]) is None
    assert capsys.readouterr().out.startswith("flowchart TD")


def test_cli_graph_svg_to_file(tmp_path, capsys):
    out = tmp_path / "graph.svg"
    main(["graph", "--format", "svg", "-o", str(out)])
    assert f"wrote {out}" in capsys.readouterr().out
    assert out.read_text(encoding="utf-8").lstrip().startswith("<svg")


def test_cli_paths_mermaid(capsys):
    main(["paths", "--format", "mermaid"])
    assert capsys.readouterr().out.startswith("flowchart LR")


def test_cli_graph_text_default_unchanged(capsys):
    main(["graph"])
    out = capsys.readouterr().out
    assert "--contains-->" in out
