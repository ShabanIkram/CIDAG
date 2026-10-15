import argparse 
import json 
import sys
from pathlib import Path 

from cidag.analysis.engine import admin_paths, blast_radius, run_analysis
from cidag.collectors.aws import AwsCollector
from cidag.collectors.base import MockCollector
from cidag.graph.builder import build_graph
from cidag.reports.exporter import to_csv, to_json, to_markdown


def _get_inventory(args) -> dict:
    if getattr(args, "profile", None) or getattr(args, "live", False):
        print("[*] Collecting from AWS (read-only)...")
        inv = AwsCollector(profile=args.profile, region=args.region).collect()
        if args.save:
            Path(args.save).write_text(json.dumps(inv, indent=2, default=str))
            print(f"[*] Saved Inventory -> {args.save}")
        return inv
    path = getattr(args, "input", None)
    return MockCollector(path).collect()


def _analyze(args):
    inventory = _get_inventory(args)
    g = build_graph(inventory)
    result = run_analysis(g, inventory)
    return inventory, g, result

def cmd_scan(args):
    inventory, g, result = _analyze(args)
    if args.json:
        print(to_json(result))
        return
    s = result["summary"]
    print("=" * 60)
    print(f"  CIDAG v1.0  (account {inventory.get('account_id')})")
    print("=" * 60)
    print(f"  Nodes: {s['nodes']}  Edges: {s['edges']}  Admins: {s['admins']}")
    print(f"  Findings: {s['findings']}")
    print("-" * 60)
    for i, f in enumerate(result["findings"], 1):
        print(f"\n [{i}] {f['severity']} - {f['type']}")
        print(f"    Identity: {f.get('identity')}")
        if f.get("chain"):
            print(f"    Chain: {' -> '.join(f['chain'])}")
        print(f"    Reason: {f.get('reason')}")
        print(f"    Fix:  {f.get('remediation')}")
    print()
    

def cmd_graph(args):
    inventory = _get_inventory(args)
    g = build_graph(inventory)
    for u, v, data in g.edges(data=True):
        print(f"{g.nodes[u]['label']:>25} --{data['rel']}--> {g.nodes[v]['label']}")


def cmd_paths(args):
    inventory, g, result = _analyze(args)
    paths = admin_paths(g, result["admin_arns"])
    if not paths:
        print("[OK] No paths to admin found.")
        return
    for ident, chain in paths.items():
        print(f"{ident}: {' -> '.join(chain)}")


def cmd_blast(args):
    inventory, g, result = _analyze(args)
    try:
        items = blast_radius(g, args.identity)
    except ValueError as e:
        print(f"[!] {e}")
        return
    print(f"Blast radius of '{args.identity}': {len(items)} reachable objects")
    for item in items:
        print(f" {item['kind']:>10} {item['label']}")


def cmd_report(args):
    inventory, g, result = _analyze(args)
    if args.format == "json":
        content = to_json(result)
    elif args.format == "csv":
        content = to_csv(result["findings"])
    else:
        content = to_markdown(inventory, result)
    if args.output:
        Path(args.output).write_text(content)
        print(f"[*] Report Written -> {args.output}")
    else:
        print(content)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cidag", description="Cloud Identity Attack Graph")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text, func in [
        ("scan", "Run analysis", cmd_scan),
        ("graph", "Print graph edges", cmd_graph),
        ("paths", "List attack paths to admin", cmd_paths),
        ("blast", "Blast radius of an identity", cmd_blast),
        ("report", "Generate report (md/json/csv)", cmd_report),
    ]:

        p = sub.add_parser(name, help=help_text)
        p.add_argument("--input", "-i", help="Inventory JSON (default: built-in mock)")
        p.add_argument("--profile", "-p", help="AWS profile")
        p.add_argument("--region", "-r", default="us-east-1")
        p.add_argument("--live", action="store_true", help="Use default AWS credentials")
        p.add_argument("--save", help="Save collected inventory to file")
        if name == "scan":
            p.add_argument("--json", action="store_true")
        if name == "blast":
            p.add_argument("--identity", required=True)
        if name == "report":
            p.add_argument("--format", choices=["md", "json", "csv"], default="md")
            p.add_argument("--output", "-o")
        p.set_defaults(func=func)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())