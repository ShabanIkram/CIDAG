import networkx as nx


def build_graph(inventory: dict) -> nx.DiGraph:
    g = nx.DiGraph()
    account = inventory.get("account_id", "unknown")
    g.add_node(f"account:{account}", kind="account", label=account)

    for policy in inventory.get("policies", []):
        g.add_node(policy["arn"], kind="policy", label=policy["name"],
                   statements=policy["statements"])
        g.add_edge(f"account:{account}", policy["arn"], rel="contains")

    for identity in inventory.get("identities", []):
        node_id = identity["arn"]
        g.add_node(node_id, kind=identity["type"], label=identity["name"])
        g.add_edge(f"account:{account}", node_id, rel="contains")

        for policy_arn in identity.get("attached_policies", []) + identity.get("inline_policies", []):
            g.add_edge(node_id, policy_arn, rel="attached-to")

        for stmt in identity.get("trust_policy", {}).get("Statement", []):
            principal = stmt.get("Principal", {})
            aws_principals = principal.get("AWS", []) if isinstance(principal, dict) else []
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for p_arn in aws_principals:
                g.add_edge(p_arn, node_id, rel="can-assume")

        for group_arn in identity.get("groups", []):
            g.add_edge(group_arn, node_id, rel="has-member")

    for resource in inventory.get("resources", []):
        g.add_node(resource["arn"], kind=resource["type"], label=resource["name"])
        g.add_edge(f"account:{account}", resource["arn"], rel="contains")

    return g


def graph_summary(g: nx.DiGraph) -> dict:
    kinds: dict[str, int] = {}
    for _, data in g.nodes(data=True):
        k = data.get("kind", "unknown")
        kinds[k] = kinds.get(k, 0) + 1
    return {"nodes": g.number_of_nodes(), "edges": g.number_of_edges(), "by_kind": kinds}
