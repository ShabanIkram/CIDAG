import argparse
import json
import sys
from pathlib import Path

from cidag.analysis.engine import admin_paths, blast_radius, run_analysis
from cidag.collectors.aws import AwsCollector
from cidag.collectors.base import MockCollector
from cidag.core.finding import Finding, Severity
from cidag.core.context import ScanContext
from cidag.core.scope import ScopeGuard, OutOfScopeError
from cidag.graph.builder import build_graph
from cidag.reports.exporter import to_csv, to_json, to_markdown

# Register every bundled scanner.
import cidag.scanners  # noqa: F401
from cidag.core.registry import all_scanners, run_scanners

SCANNER_MODULES = ("s3", "ec2", "net", "inspector", "sechub", "import")
ALL_MODULES = ("iam",) + SCANNER_MODULES
# modules that need AWS creds but no pre-collected inventory
_LIVE_API_MODULES = ("inspector", "sechub")


def _log(msg: str) -> None:
    """Status/progress messages go to stderr so stdout stays machine-clean."""
    print(msg, file=sys.stderr)


def _parse_ports(spec: str | None) -> list[int] | None:
    if not spec:
        return None
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def _modules(args) -> list[str]:
    raw = getattr(args, "modules", None)
    if not raw:
        return ["iam"]
    mods = [m.strip() for m in raw.split(",") if m.strip()]
    for m in mods:
        if m not in ALL_MODULES:
            raise SystemExit(f"[!] unknown module {m!r}; choose from {', '.join(ALL_MODULES)}")
    return mods


def _merge_scanner_mock(inv: dict) -> dict:
    """Fill scanner inventory keys from the bundled scanner mock when absent."""
    needed = ("s3_buckets", "security_groups", "instances", "rds_instances")
    if any(k in inv for k in needed):
        return inv
    mock_path = Path(__file__).resolve().parents[1] / "data" / "mock_scanners.json"
    if mock_path.exists():
        scanner_mock = json.loads(mock_path.read_text(encoding="utf-8"))
        for key in ("account_public_access_block", "s3_buckets", "security_groups",
                    "instances", "volumes", "rds_instances", "cloud_trails"):
            scanner_mock.setdefault(key, inv.get(key))
            inv.setdefault(key, scanner_mock[key])
    return inv


def _get_inventory(args, modules: list[str] | None = None) -> dict:
    modules = modules or ["iam"]
    live = getattr(args, "profile", None) or getattr(args, "live", False)
    if live:
        _log("[*] Collecting from AWS (read-only)...")
        inv = AwsCollector(profile=args.profile, region=args.region).collect()
        _collect_live_scanners(args, inv, modules)
        if args.save:
            Path(args.save).write_text(json.dumps(inv, indent=2, default=str))
            _log(f"[*] Saved Inventory -> {args.save}")
        return inv
    path = getattr(args, "input", None)
    inv = MockCollector(path).collect()
    if not path and any(m in modules for m in ("s3", "ec2")):
        inv = _merge_scanner_mock(inv)
    return inv


def _collect_live_scanners(args, inv: dict, modules: list[str]) -> None:
    import boto3
    if not any(m in modules for m in SCANNER_MODULES):
        return
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if "s3" in modules:
        try:
            from cidag.scanners.s3.collector import collect_s3
            buckets, pab = collect_s3(session)
            inv["s3_buckets"] = buckets
            inv["account_public_access_block"] = pab
            _log(f"[*] Collected {len(buckets)} S3 buckets")
        except Exception as e:
            print(f"[!] s3 collection failed: {e}")
    if "ec2" in modules:
        try:
            from cidag.scanners.ec2.collector import (
                collect_cloudtrail, collect_ec2, collect_rds)
            inv.update(collect_ec2(session))
            inv["rds_instances"] = collect_rds(session)
            inv["cloud_trails"] = collect_cloudtrail(session)
            _log(f"[*] Collected {len(inv.get('security_groups', []))} SGs, "
                  f"{len(inv.get('instances', []))} instances, "
                  f"{len(inv.get('rds_instances', []))} RDS")
        except Exception as e:
            print(f"[!] ec2 collection failed: {e}")


def _build_scope(args) -> ScopeGuard:
    targets = getattr(args, "targets", None) or []
    allow_private = bool(getattr(args, "allow_private", False))
    # Every --targets CIDR is explicitly authorized.
    return ScopeGuard(networks=targets, allow_private=allow_private)


def _iam_finding(f: dict) -> Finding:
    return Finding(
        module="iam",
        check_id=str(f.get("type", "IAM")),
        severity=Severity.parse(f.get("severity", "INFO")),
        title=f.get("reason") or f.get("type", "IAM finding"),
        target=f.get("identity") or "unknown",
        remediation=f.get("remediation", ""),
        identity=f.get("identity"),
        identity_arn=f.get("identity_arn"),
        chain=f.get("chain"),
        reason=f.get("reason"),
        evidence={"raw": {k: v for k, v in f.items()
                          if k not in ("severity", "type", "remediation")}},
    )


def _run_unified(args, modules: list[str]):
    """Return (inventory, g, iam_result_or_None, findings[Finding])."""
    inventory = _get_inventory(args, modules)
    g = iam_result = None
    findings: list[Finding] = []
    if "iam" in modules:
        g = build_graph(inventory)
        iam_result = run_analysis(g, inventory)
        findings.extend(_iam_finding(f) for f in iam_result["findings"])
    scanner_mods = [m for m in modules if m in SCANNER_MODULES]
    if scanner_mods:
        scope = _build_scope(args)
        ctx = ScanContext(
            inventory=inventory,
            scope=scope,
            options={
                "targets": getattr(args, "targets", None) or [],
                "ports": _parse_ports(getattr(args, "ports", None)),
                "max_hosts": getattr(args, "max_hosts", 1024),
                "nvd_network": not getattr(args, "no_nvd", False),
                "profile": getattr(args, "profile", None),
                "region": getattr(args, "region", "us-east-1"),
                "import_path": getattr(args, "import_path", None),
                "import_format": getattr(args, "import_format", None),
            },
            log=_log,
            offline=bool(getattr(args, "no_nvd", False)),
        )
        findings.extend(run_scanners(scanner_mods, ctx))
    min_sev = getattr(args, "min_severity", None)
    if min_sev:
        floor = Severity.parse(min_sev)
        findings = [f for f in findings if f.severity >= floor]
    return inventory, g, iam_result, findings


def cmd_scan(args):
    modules = _modules(args)
    try:
        inventory, g, iam_result, findings = _run_unified(args, modules)
    except OutOfScopeError as e:
        print(f"[!] SCOPE DENIED: {e}", file=sys.stderr)
        return 2
    if args.json:
        # Backward-compatible: iam-only keeps the original analysis payload.
        if iam_result is not None and all(m == "iam" for m in modules):
            print(to_json(iam_result))
            return
        payload = {
            "account_id": inventory.get("account_id"),
            "modules": modules,
            "summary": {"findings": len(findings), **_counts(findings)},
            "findings": [f.to_dict() for f in findings],
            "counts": _counts(findings),
        }
        print(json.dumps(payload, indent=2, default=str))
        return
    _print_findings(inventory, modules, findings)
    return 0


def _counts(findings: list[Finding]) -> dict:
    counts = {s.name: 0 for s in Severity}
    for f in findings:
        counts[f.severity.name] += 1
    return counts


def _print_findings(inventory, modules, findings: list[Finding]) -> None:
    counts = _counts(findings)
    print("=" * 60)
    print(f"  CIDAG v2.0  (account {inventory.get('account_id')})")
    print(f"  Modules: {', '.join(modules)}")
    print("=" * 60)
    print("  " + "  ".join(f"{k}: {v}" for k, v in
                          sorted(counts.items(), key=lambda kv: -Severity[kv[0]].value) if v))
    print("-" * 60)
    order = sorted(findings, key=lambda f: (-int(f.severity), f.module, f.check_id))
    for i, f in enumerate(order, 1):
        cve = f"  [{f.cve}]" if f.cve else ""
        print(f"\n [{i}] {f.severity.name} - {f.check_id}{cve}  ({f.module})")
        print(f"    Target: {f.target}")
        if f.chain:
            print(f"    Chain: {' -> '.join(f.chain)}")
        print(f"    Title: {f.title}")
        if f.remediation:
            print(f"    Fix:  {f.remediation}")
    print()


def cmd_graph(args):
    inventory = _get_inventory(args, ["iam"])
    g = build_graph(inventory)
    for u, v, data in g.edges(data=True):
        print(f"{g.nodes[u]['label']:>25} --{data['rel']}--> {g.nodes[v]['label']}")


def cmd_paths(args):
    inventory = _get_inventory(args, ["iam"])
    g = build_graph(inventory)
    result = run_analysis(g, inventory)
    paths = admin_paths(g, result["admin_arns"])
    if not paths:
        print("[OK] No paths to admin found.")
        return
    for ident, chain in paths.items():
        print(f"{ident}: {' -> '.join(chain)}")


def cmd_blast(args):
    inventory = _get_inventory(args, ["iam"])
    g = build_graph(inventory)
    run_analysis(g, inventory)
    try:
        items = blast_radius(g, args.identity)
    except ValueError as e:
        print(f"[!] {e}")
        return
    print(f"Blast radius of '{args.identity}': {len(items)} reachable objects")
    for item in items:
        print(f" {item['kind']:>10} {item['label']}")


def cmd_report(args):
    modules = _modules(args)
    inventory, g, iam_result, findings = _run_unified(args, modules)
    if args.format == "json":
        content = json.dumps({
            "account_id": inventory.get("account_id"),
            "modules": modules,
            "findings": [f.to_dict() for f in findings],
        }, indent=2, default=str)
    elif args.format == "csv":
        # unified CSV across all modules
        import csv as _csv
        import io as _io
        buf = _io.StringIO()
        w = _csv.writer(buf)
        w.writerow(["severity", "module", "check_id", "target", "title", "cve", "remediation"])
        for f in sorted(findings, key=lambda x: (-int(x.severity), x.check_id)):
            w.writerow([f.severity.name, f.module, f.check_id, f.target,
                        f.title, f.cve or "", f.remediation])
        content = buf.getvalue()
    else:
        if iam_result is None:
            # markdown for non-IAM modules
            content = _md_findings(inventory, modules, findings)
        else:
            content = to_markdown(inventory, iam_result)
    if args.output:
        Path(args.output).write_text(content)
        _log(f"[*] Report Written -> {args.output}")
    else:
        print(content)


def _md_findings(inventory, modules, findings) -> str:
    lines = [
        "# CIDAG Scan Report",
        "",
        f"- **Account:** {inventory.get('account_id')}",
        f"- **Modules:** {', '.join(modules)}",
        f"- **Findings:** {len(findings)}",
        "",
        "## Findings",
        "",
    ]
    for i, f in enumerate(sorted(findings, key=lambda x: (-int(x.severity), x.check_id)), 1):
        cve = f" ({f.cve})" if f.cve else ""
        lines.append(f"### {i}. [{f.severity.name}] {f.check_id}{cve} — {f.target}")
        lines.append(f"- **Module:** {f.module}")
        lines.append(f"- **Title:** {f.title}")
        if f.remediation:
            lines.append(f"- **Remediation:** {f.remediation}")
        lines.append("")
    return "\n".join(lines)


def cmd_nvd(args):
    from cidag.cve.nvd import NVDClient
    client = NVDClient()
    if args.nvd_command == "count":
        print(f"Local NVD mirror: {client.count()} CVEs")
        print(f"Last sync: {client.last_sync() or 'never'}")
    elif args.nvd_command == "sync":
        client.sync(days=args.days, log=print)
    client.close()


def _add_common(p):
    p.add_argument("--input", "-i", help="Inventory JSON (default: built-in mock)")
    p.add_argument("--profile", "-p", help="AWS profile")
    p.add_argument("--region", "-r", default="us-east-1")
    p.add_argument("--live", action="store_true", help="Use default AWS credentials")
    p.add_argument("--save", help="Save collected inventory to file")


def _add_scan_flags(p):
    p.add_argument("--modules", "-m", default="iam",
                   help=f"Comma modules to run ({', '.join(ALL_MODULES)}); default: iam")
    p.add_argument("--targets", "-t", action="append", default=[],
                   help="Authorized CIDR for net scan (repeatable). Required for net.")
    p.add_argument("--ports", help="Ports/ranges for net scan, e.g. 22,80,443,8000-9000")
    p.add_argument("--allow-private", action="store_true",
                   help="Allow scanning private IPs listed in --targets")
    p.add_argument("--max-hosts", type=int, default=1024,
                   help="Refuse net scans that expand beyond this many hosts (default 1024)")
    p.add_argument("--no-nvd", action="store_true",
                   help="Skip live NVD queries (offline CVE seeds only)")
    p.add_argument("--min-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Filter findings below this severity")
    p.add_argument("--import-path", help="Path to nmap XML / nuclei JSON / Prowler JSON to import")
    p.add_argument("--import-format", choices=["nmap", "nuclei", "prowler"],
                   help="Format of --import-path")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cidag",
        description="CIDAG — cloud identity attack graph + multi-domain security scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text, func in [
        ("scan", "Run scan (IAM attack graph + s3/ec2/net/cve modules)", cmd_scan),
        ("graph", "Print IAM graph edges", cmd_graph),
        ("paths", "List attack paths to admin", cmd_paths),
        ("blast", "Blast radius of an identity", cmd_blast),
        ("report", "Generate report (md/json/csv)", cmd_report),
    ]:
        p = sub.add_parser(name, help=help_text)
        _add_common(p)
        _add_scan_flags(p)
        if name == "scan":
            p.add_argument("--json", action="store_true")
        if name == "blast":
            p.add_argument("--identity", required=True)
        if name == "report":
            p.add_argument("--format", choices=["md", "json", "csv"], default="md")
            p.add_argument("--output", "-o")
        p.set_defaults(func=func)

    p_nvd = sub.add_parser("nvd", help="Manage the local NVD CVE mirror")
    nvd_sub = p_nvd.add_subparsers(dest="nvd_command", required=True)
    p_sync = nvd_sub.add_parser("sync", help="Sync CVEs from NVD into the local mirror")
    p_sync.add_argument("--days", type=int, default=120,
                        help="Pull CVEs modified in the last N days (first run)")
    p_sync.set_defaults(func=cmd_nvd)
    p_count = nvd_sub.add_parser("count", help="Show local NVD mirror size")
    p_count.set_defaults(func=cmd_nvd)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
