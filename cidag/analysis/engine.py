import networkx as nx

from cidag.normalizer.evaluator import (
    EffectivePermissions, compute_effective, resource_matches,
)
from cidag.graph.builder import graph_summary
from .rules import ESCALATION_RULES


def _add_can_pass_edges(g: nx.DiGraph, perms: dict[str, EffectivePermissions]) -> None:
    role_arns = [n for n, d in g.nodes(data=True) if d.get("kind") == "role"]
    for arn, ep in perms.items():
        if ep.kind not in {"user", "role"}:
            continue
        for pattern in ep.passrole_targets():
            for role_arn in role_arns:
                if role_arn == arn:
                    # An identity cannot "pass" itself; a wildcard PassRole
                    # pattern would otherwise emit a meaningless self-loop.
                    continue
                if resource_matches(pattern, role_arn):
                    g.add_edge(arn, role_arn, rel="can-pass")


def _rule_matches(ep: EffectivePermissions, rule: dict, admin_arns: list[str]) -> bool:
    for group in rule["requires"]:
        if not any(ep.allowed(action) for action in group):
            return False
    if rule.get("requires_privileged_passrole"):
        targets = ep.passrole_targets()
        if not any(resource_matches(p, admin) for p in targets for admin in admin_arns):
            return False
    return True


def _path_findings(g: nx.DiGraph, perms: dict[str, EffectivePermissions],
                   admin_arns: list[str]) -> list[dict]:
    findings = []
    label_of = {n: d.get("label", n) for n, d in g.nodes(data=True)}
    for arn, ep in perms.items():
        if ep.kind not in {"user", "role"} or ep.is_admin():
            continue
        for admin in admin_arns:
            if not nx.has_path(g, arn, admin):
                continue
            path = nx.shortest_path(g, arn, admin)
            chain = [label_of.get(n, n) for n in path]
            if len(chain) < 2:
                continue
            findings.append({
                "severity": "HIGH",
                "type": "ATTACK_PATH",
                "identity": ep.label,
                "identity_arn": arn,
                "chain": chain,
                "reason": f"Path to admin role found ({len(chain) - 1} hops)",
                "remediation": "Break the chain: remove one edge (assume/pass/attach)",
            })
            break
    return findings


def run_analysis(g: nx.DiGraph, inventory: dict) -> dict:
    perms = compute_effective(inventory)
    _add_can_pass_edges(g, perms)
    admin_arns = [a for a, ep in perms.items() if ep.is_admin()]

    # Cloud identities are not always IAM users/roles: Azure service
    # principals and GCP service accounts can also escalate.
    escalation_kinds = {
        "user", "role", "group", "service_principal", "service_account",
    }
    findings: list[dict] = []
    for ep in perms.values():
        if ep.kind not in escalation_kinds:
            continue
        if ep.kind in {"user", "role"}:
            findings.extend(ep.wildcard_findings())
        if ep.is_admin():
            continue
        for rule in ESCALATION_RULES:
            if _rule_matches(ep, rule, admin_arns):
                findings.append({
                    "severity": rule["severity"],
                    "type": rule["id"],
                    "identity": ep.label,
                    "identity_arn": ep.arn,
                    "reason": rule["name"],
                    "remediation": rule["remediation"],
                })

    findings.extend(_path_findings(g, perms, admin_arns))

    summary = graph_summary(g)
    summary["admins"] = len(admin_arns)
    summary["findings"] = len(findings)
    return {"summary": summary, "findings": findings, "admin_arns": admin_arns}


def blast_radius(g: nx.DiGraph, identity: str) -> list[dict]:
    node = identity
    if node not in g:
        matches = [n for n, d in g.nodes(data=True) if d.get("label") == identity]
        if not matches:
            raise ValueError(f"identity not found: {identity}")
        node = matches[0]
    out = []
    for desc in nx.descendants(g, node):
        data = g.nodes[desc]
        if data.get("kind") == "account":
            continue
        out.append({"label": data.get("label", desc), "kind": data.get("kind"),
                    "arn": desc})
    return sorted(out, key=lambda x: (x["kind"], x["label"]))


def admin_paths(g: nx.DiGraph, admin_arns: list[str]) -> dict[str, list[str]]:
    label_of = {n: d.get("label", n) for n, d in g.nodes(data=True)}
    result: dict[str, list[str]] = {}
    for node, data in g.nodes(data=True):
        if data.get("kind") not in {"user", "role"} or node in admin_arns:
            continue
        for admin in admin_arns:
            if nx.has_path(g, node, admin):
                result[data.get("label", node)] = [
                    label_of.get(n, n) for n in nx.shortest_path(g, node, admin)]
                break
    return result
