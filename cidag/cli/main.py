import argparse
import json
import sys
from pathlib import Path

from cidag.analysis.engine import admin_paths, blast_radius, run_analysis
from cidag.collectors.aws import (
    AwsCollectionError,
    AwsCollector,
    AwsCredentialsError,
    verify_credentials,
)
from cidag.collectors.azure import AzureCollector
from cidag.collectors.base import CloudCollectionError, CloudCredentialsError, MockCollector
from cidag.collectors.gcp import GcpCollector
from cidag.core.finding import Finding, Severity
from cidag.core.context import ScanContext
from cidag.core.scope import ScopeGuard, OutOfScopeError
from cidag.graph.builder import build_graph
from cidag.graph.viz import to_dot, to_mermaid, to_mermaid_paths, to_svg
from cidag.reports.compliance import attach as attach_compliance
from cidag.reports.compliance import filter_by as filter_compliance
from cidag.reports.compliance import summary as compliance_summary
from cidag.execution.guard import ExploitError
from cidag.reports.exporter import to_csv, to_json, to_markdown, to_sarif

# Register every bundled scanner.
import cidag.scanners  # noqa: F401
from cidag.core.registry import all_scanners, run_scanners

SCANNER_MODULES = ("s3", "ec2", "net", "policy", "nuclei", "inspector", "sechub", "import")
ALL_MODULES = ("iam",) + SCANNER_MODULES
AWS_ONLY_MODULES = ("s3", "ec2", "inspector", "sechub")
# modules that need AWS creds but no pre-collected inventory
_LIVE_API_MODULES = ("inspector", "sechub")


def _log(msg: str) -> None:
    """Status/progress messages go to stderr so stdout stays machine-clean."""
    print(msg, file=sys.stderr)


def _emit(text: str, args) -> None:
    path = getattr(args, "output", None)
    if path:
        Path(path).write_text(text if text.endswith("\n") else text + "\n",
                              encoding="utf-8")
        print(f"[+] wrote {path}")
    else:
        print(text)


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
    cloud = getattr(args, "cloud", "aws")
    blocked = sorted(set(mods) & set(AWS_ONLY_MODULES)) if cloud != "aws" else []
    if blocked:
        raise SystemExit(
            f"[!] module(s) {', '.join(blocked)} are AWS-only and cannot run "
            f"with --cloud {cloud}; use iam/policy/net/nuclei/import")
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
    cloud = getattr(args, "cloud", "aws")
    if cloud != "aws":
        return _get_cloud_inventory(args, cloud)
    live = getattr(args, "profile", None) or getattr(args, "live", False)
    if live:
        # Fail fast: an empty inventory from dead credentials must never be
        # rendered as "these resources are absent" findings.
        verify_credentials(args.profile, args.region)
        _log("[*] Collecting from AWS (read-only)...")
        inv = AwsCollector(profile=args.profile, region=args.region).collect()
        _collect_live_scanners(args, inv, modules)
        if args.save:
            Path(args.save).write_text(json.dumps(inv, indent=2, default=str))
            _log(f"[*] Saved Inventory -> {args.save}")
        return inv
    path = getattr(args, "input", None)
    inv = MockCollector(path, cloud=cloud).collect()
    if not path and any(m in modules for m in ("s3", "ec2")):
        inv = _merge_scanner_mock(inv)
    return inv


def _get_cloud_inventory(args, cloud: str) -> dict:
    """Azure/GCP inventory: live collectors or the bundled cloud mock."""
    if getattr(args, "live", False):
        if cloud == "azure":
            _log("[*] Collecting Azure RBAC (read-only)...")
            inv = AzureCollector(
                subscription_id=getattr(args, "subscription_id", None),
                region=args.region).collect()
        else:
            _log("[*] Collecting GCP project IAM (read-only)...")
            inv = GcpCollector(project=getattr(args, "project", None),
                               region=args.region).collect()
        if getattr(args, "save", None):
            Path(args.save).write_text(json.dumps(inv, indent=2, default=str))
            _log(f"[*] Saved Inventory -> {args.save}")
        return inv
    return MockCollector(getattr(args, "input", None), cloud=cloud).collect()


def _collect_live_scanners(args, inv: dict, modules: list[str], session=None) -> None:
    import boto3
    if not any(m in modules for m in SCANNER_MODULES):
        return
    session = session or boto3.Session(profile_name=args.profile,
                                       region_name=args.region)
    if "s3" in modules:
        try:
            from cidag.scanners.s3.collector import collect_s3
            buckets, pab = collect_s3(session)
            inv["s3_buckets"] = buckets
            inv["account_public_access_block"] = pab
            _log(f"[*] Collected {len(buckets)} S3 buckets")
        except Exception as e:
            raise AwsCollectionError(f"s3 collection failed: {e}") from e
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
            raise AwsCollectionError(f"ec2 collection failed: {e}") from e


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


def _scan_inventory(args, inventory: dict, modules: list[str]):
    """Run IAM analysis + scanner modules against one inventory."""
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
                "allow_private": bool(getattr(args, "allow_private", False)),
                "nvd_network": not getattr(args, "no_nvd", False),
                "profile": getattr(args, "profile", None),
                "region": getattr(args, "region", "us-east-1"),
                "import_path": getattr(args, "import_path", None),
                "import_format": getattr(args, "import_format", None),
                "nuclei_templates": getattr(args, "nuclei_templates", None),
                "nuclei_severity": getattr(args, "nuclei_severity", None),
            },
            log=_log,
            offline=bool(getattr(args, "no_nvd", False)),
        )
        findings.extend(run_scanners(scanner_mods, ctx))
    min_sev = getattr(args, "min_severity", None)
    if min_sev:
        floor = Severity.parse(min_sev)
        findings = [f for f in findings if f.severity >= floor]
    attach_compliance(findings)
    return g, iam_result, findings


def _run_org(args, modules: list[str]):
    """Scan every active account in AWS Organizations via an assumed role."""
    if not getattr(args, "live", False):
        raise AwsCollectionError(
            "--all-accounts requires --live and AWS Organizations credentials")
    import boto3

    from cidag.collectors.org import assume_role_session, list_accounts

    base = boto3.Session(profile_name=args.profile, region_name=args.region)
    try:
        accounts = list_accounts(base)
    except Exception as e:
        raise AwsCollectionError(f"organizations:ListAccounts failed: {e}") from e
    wanted = set(getattr(args, "account_ids", None) or [])
    if wanted:
        accounts = [a for a in accounts if a["id"] in wanted]
    if not accounts:
        raise AwsCollectionError("no active organization accounts to scan")

    role_name = getattr(args, "role_name", "OrganizationAccountAccessRole")
    # net/nuclei targets are external to the accounts: run them once, untagged.
    network_mods = [m for m in modules if m in ("net", "nuclei")]
    aws_modules = [m for m in modules if m not in network_mods]
    findings: list[Finding] = []
    for acct in accounts:
        try:
            session = assume_role_session(base, acct["id"], role_name, args.region)
        except Exception as e:
            raise AwsCollectionError(
                f"cannot assume {role_name} in account {acct['id']}: {e}") from e
        _log(f"[*] Scanning account {acct['id']} ({acct.get('name', '')})")
        try:
            inventory = AwsCollector(region=args.region, session=session).collect()
            _collect_live_scanners(args, inventory, modules, session=session)
        except AwsCollectionError:
            raise
        except Exception as e:
            raise AwsCollectionError(
                f"collection failed in account {acct['id']}: {e}") from e
        inventory["account_id"] = acct["id"]
        inventory["account_name"] = acct.get("name", acct["id"])
        _, _, acct_findings = _scan_inventory(args, inventory, aws_modules)
        for f in acct_findings:
            f.set_account(acct["id"])
        findings.extend(acct_findings)

    summary = {
        "account_id": f"org:{len(accounts)}",
        "region": args.region,
        "accounts": [{"id": a["id"], "name": a.get("name")} for a in accounts],
        "identities": [],
        "policies": [],
        "resources": [],
    }
    if network_mods:
        _, _, network_findings = _scan_inventory(args, summary, network_mods)
        findings.extend(network_findings)
    return summary, None, None, findings


def _run_unified(args, modules: list[str]):
    """Return (inventory, g, iam_result_or_None, findings[Finding])."""
    if getattr(args, "all_accounts", False):
        if getattr(args, "cloud", "aws") != "aws":
            raise CloudCollectionError(
                "--all-accounts is AWS Organizations only; use --cloud aws")
        return _run_org(args, modules)
    inventory = _get_inventory(args, modules)
    g, iam_result, findings = _scan_inventory(args, inventory, modules)
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
        if f.account:
            print(f"    Account: {f.account}")
        if f.chain:
            print(f"    Chain: {' -> '.join(f.chain)}")
        print(f"    Title: {f.title}")
        if f.remediation:
            print(f"    Fix:  {f.remediation}")
    print()


def cmd_graph(args):
    inventory = _get_inventory(args, ["iam"])
    g = build_graph(inventory)
    fmt = getattr(args, "format", "text")
    if fmt == "mermaid":
        out = to_mermaid(g)
    elif fmt == "dot":
        out = to_dot(g)
    elif fmt == "svg":
        highlight = set(run_analysis(g, inventory).get("admin_arns", []))
        out = to_svg(g, highlight=highlight)
    else:
        out = "\n".join(
            f"{g.nodes[u]['label']:>25} --{data['rel']}--> {g.nodes[v]['label']}"
            for u, v, data in g.edges(data=True))
    _emit(out, args)


def cmd_paths(args):
    inventory = _get_inventory(args, ["iam"])
    g = build_graph(inventory)
    result = run_analysis(g, inventory)
    paths = admin_paths(g, result["admin_arns"])
    if not paths:
        print("[OK] No paths to admin found.")
        return
    if getattr(args, "format", "text") == "mermaid":
        _emit(to_mermaid_paths(paths), args)
        return
    out = "\n".join(f"{ident}: {' -> '.join(chain)}" for ident, chain in paths.items())
    _emit(out, args)


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
    findings = filter_compliance(findings, getattr(args, "compliance", None))
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
    elif args.format == "sarif":
        content = to_sarif(findings)
    else:
        # Legacy markdown payload only for the original iam-only report; any
        # scanner module or compliance filter uses the unified renderer so
        # findings are never dropped from the report.
        if iam_result is not None and all(m == "iam" for m in modules) \
                and not getattr(args, "compliance", None):
            content = to_markdown(inventory, iam_result)
            extra = _compliance_md(findings)
            if extra:
                content = content.rstrip() + "\n" + extra
        else:
            content = _md_findings(inventory, modules, findings)
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
        if f.account:
            lines.append(f"- **Account:** {f.account}")
        lines.append(f"- **Title:** {f.title}")
        if f.remediation:
            lines.append(f"- **Remediation:** {f.remediation}")
        lines.append("")
    content = "\n".join(lines)
    extra = _compliance_md(findings)
    return content.rstrip() + "\n" + extra if extra else content


def _compliance_md(findings) -> str:
    data = compliance_summary(findings)
    if not data:
        return ""
    lines = ["", "## Compliance Coverage", ""]
    labels = {"cis": "CIS AWS Foundations", "pci": "PCI DSS v4.0"}
    for framework in sorted(data):
        lines.append(f"### {labels.get(framework, framework)}")
        lines.append("")
        for control, count in sorted(data[framework].items()):
            lines.append(f"- `{control}` — {count} finding(s)")
        lines.append("")
    return "\n".join(lines)


def _diff_key(finding: dict) -> str:
    if finding.get("id"):
        return str(finding["id"])
    return f"{finding.get('module')}|{finding.get('check_id')}|{finding.get('target')}"


def _load_findings(path: str) -> dict[str, dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data.get("findings", []) if isinstance(data, dict) else data
    return {_diff_key(f): f for f in items if isinstance(f, dict)}


def _diff_sev(finding: dict) -> Severity:
    try:
        return Severity.parse(finding.get("severity", "INFO"))
    except ValueError:
        return Severity.INFO


def cmd_diff(args):
    before = _load_findings(args.before)
    after = _load_findings(args.after)
    added = [after[k] for k in after.keys() - before.keys()]
    fixed = [before[k] for k in before.keys() - after.keys()]
    changed = [(before[k], after[k]) for k in before.keys() & after.keys()
               if before[k].get("severity") != after[k].get("severity")]
    added.sort(key=lambda f: -int(_diff_sev(f)))
    fixed.sort(key=lambda f: -int(_diff_sev(f)))
    if args.format == "json":
        out = json.dumps({
            "summary": {"new": len(added), "fixed": len(fixed), "changed": len(changed)},
            "new": added,
            "fixed": fixed,
            "changed": [{"before": b, "after": a} for b, a in changed],
        }, indent=2, default=str)
    else:
        def line(tag: str, severity: str, f: dict) -> str:
            return (f"{tag:<8} {severity:<12} {str(f.get('module', '')):<6} "
                    f"{str(f.get('check_id', '')):<12} {str(f.get('target', ''))}  "
                    f"{f.get('title', '')}")

        lines = [f"[+] {len(added)} new  [-] {len(fixed)} fixed  [~] {len(changed)} changed"]
        lines += [line("NEW", str(f.get("severity", "?")), f) for f in added]
        lines += [line("FIXED", str(f.get("severity", "?")), f) for f in fixed]
        for b, a in changed:
            lines.append(line("CHANGED", f"{b.get('severity')}->{a.get('severity')}", a))
        out = "\n".join(lines)
    _emit(out, args)


def cmd_nvd(args):
    from cidag.cve.nvd import NVDClient
    client = NVDClient()
    if args.nvd_command == "count":
        print(f"Local NVD mirror: {client.count()} CVEs")
        print(f"Last sync: {client.last_sync() or 'never'}")
    elif args.nvd_command == "sync":
        client.sync(days=args.days, log=print)
    client.close()


def _exploit_session(args):
    from cidag.execution.session import (AzureEngagementSession,
                                         EngagementSession,
                                         GcpEngagementSession)
    cloud = getattr(args, "cloud", "aws")
    if cloud == "azure":
        if not args.subscription_id:
            raise ExploitError("--cloud azure requires --subscription-id")
        return AzureEngagementSession(args.subscription_id)
    if cloud == "gcp":
        if not args.project:
            raise ExploitError("--cloud gcp requires --project")
        return GcpEngagementSession(args.project, member=args.member)
    return EngagementSession(profile=args.profile, region=args.region)


def _exploit_guard(args, session):
    from cidag.execution.guard import AuthorizationGuard
    accounts = [args.authorize_exploitation] if args.authorize_exploitation else []
    return AuthorizationGuard(
        session, accounts,
        assume_yes=getattr(args, "yes_i_have_written_authorization", False),
        accept_unknown=getattr(args, "accept_unknown", False))


def _exploit_params(args):
    names = ("admin_policy_arn", "target_policy", "policy_version",
             "boundary_arn", "target_group", "target_role", "pass_role",
             "member", "scope", "principal_id")
    return {name: getattr(args, name) for name in names
            if getattr(args, name, None)}


def _exploit_runner(args):
    from cidag.execution.findings import load_report
    from cidag.execution.runner import ExploitRunner
    session = _exploit_session(args)
    findings = None
    if getattr(args, "from_report", None):
        findings = load_report(args.from_report)
    return ExploitRunner(
        session, _exploit_guard(args, session),
        audit_root=getattr(args, "audit_dir", ".cidag/engagements"),
        keep=getattr(args, "keep", False), demo=getattr(args, "demo", False),
        findings=findings,
        allow_unproven=getattr(args, "allow_unproven", False))


def cmd_exploit(args):
    command = args.exploit_command
    if command == "list":
        from cidag.execution.runner import list_techniques
        techniques = list_techniques()
        if args.json:
            print(json.dumps(techniques, indent=2))
            return 0
        for t in techniques:
            required = ", ".join(t["required"]) or "none"
            suffix = "" if t["executable"] else "  [plan-only]"
            cloud = "" if t.get("provider", "aws") == "aws" else f"  [{t['provider']}]"
            print(f"{t['id']}  {t['name']}{cloud}{suffix}\n"
                  f"        {t['description']}\n"
                  f"        required args: {required}")
        return 0

    if command == "plan":
        plan = _exploit_runner(args).plan(args.technique, _exploit_params(args))
        print(json.dumps(plan, indent=2))
        return 0

    if command == "run":
        result = _exploit_runner(args).run(
            args.technique, _exploit_params(args), canary=args.canary)
        print(json.dumps(result.__dict__, indent=2))
        return 0

    if command == "canary":
        if getattr(args, "cloud", "aws") != "aws":
            raise ExploitError("canary checks are AWS-only")
        from cidag.execution.canary import run_canary
        from cidag.execution.context import ExploitContext
        session = _exploit_session(args)
        guard = _exploit_guard(args, session)
        identity = guard.authorize()
        guard.confirm(f"create and delete an impact canary in {identity['account']}")
        evidence = run_canary(ExploitContext(session, identity), args.canary_service)
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "verified" else 1

    if command == "detections":
        from cidag.execution.detections import detection_for, render_markdown
        if args.technique:
            try:
                body = render_markdown([detection_for(args.technique)])
            except KeyError:
                raise ExploitError(
                    f"unknown technique {args.technique!r}; run "
                    f"'cidag exploit list'") from None
        else:
            body = render_markdown()
        if args.output:
            Path(args.output).write_text(body, encoding="utf-8")
            _log(f"Wrote {args.output}")
        else:
            print(body)
        return 0

    if command == "report":
        from cidag.execution.report import write_report
        try:
            path = write_report(args.manifest, args.output, mask=args.mask)
        except (OSError, ValueError) as e:
            raise ExploitError(f"could not read manifest: {e}") from e
        _log(f"Wrote {path}")
        return 0

    if command == "demo":
        from cidag.execution.report import demo_report
        try:
            path = demo_report(args.root, args.output)
        except (OSError, ValueError) as e:
            raise ExploitError(str(e)) from e
        _log(f"Wrote {path}")
        return 0

    if command == "cleanup":
        from cidag.execution.cleanup import apply_cleanups
        from cidag.execution.guard import GuardError
        from cidag.execution.report import load_manifest
        try:
            manifest = load_manifest(args.manifest)
        except (OSError, ValueError) as e:
            raise ExploitError(f"could not read manifest: {e}") from e
        if manifest.get("provider", "aws") != "aws":
            raise ExploitError(
                f"cleanup is AWS-only; {manifest.get('provider')} runs always "
                "roll back automatically")
        session = _exploit_session(args)
        guard = _exploit_guard(args, session)
        identity = guard.authorize()
        if str(identity["account"]) != str(manifest.get("account")):
            raise GuardError(
                f"caller account {identity['account']} does not match manifest "
                f"account {manifest.get('account')}; refusing cleanup")
        if manifest.get("status") in {"rolled-back", "aborted"}:
            raise ExploitError(
                f"manifest status is {manifest.get('status')!r}; no artifacts "
                f"should remain (inspect the report or audit log first)")
        entries = [a.get("cleanup") for a in manifest.get("artifacts", [])
                   if a.get("cleanup")]
        guard.confirm(f"apply {len(entries)} cleanup operations in "
                      f"{identity['account']}")
        results = apply_cleanups(session, entries)
        print(json.dumps(results, indent=2))
        return 0 if all(r.get("ok") for r in results) else 1

    if command == "pacu":
        if getattr(args, "cloud", "aws") != "aws":
            raise ExploitError("Pacu is AWS-only")
        from cidag.execution.pacu_bridge import PacuBridge
        session = _exploit_session(args)
        guard = _exploit_guard(args, session)
        identity = guard.authorize()
        guard.confirm(f"run Pacu module {args.module} in session "
                      f"{args.pacu_session} against {identity['account']}")
        result = PacuBridge().run_module(
            args.pacu_session, args.module, args.module_args or "",
            expected_account=identity["account"])
        print(json.dumps(result, indent=2))
        return 0

    raise ExploitError(f"unknown exploit command {command}")



def _add_common(p):
    p.add_argument("--input", "-i", help="Inventory JSON (default: built-in cloud mock)")
    p.add_argument("--cloud", choices=["aws", "azure", "gcp"], default="aws",
                   help="Cloud provider for mock/live inventory (default: aws)")
    p.add_argument("--profile", "-p", help="AWS profile")
    p.add_argument("--region", "-r", default="us-east-1")
    p.add_argument("--live", action="store_true", help="Use default AWS credentials")
    p.add_argument("--all-accounts", action="store_true",
                   help="Scan every active AWS Organizations account (live only)")
    p.add_argument("--role-name", default="OrganizationAccountAccessRole",
                   help="Role to assume in member accounts (default: %(default)s)")
    p.add_argument("--account-id", action="append", dest="account_ids", default=[],
                   help="Limit --all-accounts to an account id (repeatable)")
    p.add_argument("--subscription-id",
                   help="Azure subscription id (default: AZURE_SUBSCRIPTION_ID or first enabled)")
    p.add_argument("--project",
                   help="GCP project id (default: GOOGLE_CLOUD_PROJECT or credential default)")
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
    p.add_argument("--nuclei-templates",
                   help="Templates dir for the live nuclei bridge (module nuclei)")
    p.add_argument("--nuclei-severity",
                   help="Severity filter for nuclei, e.g. critical,high")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cidag",
        description="CIDAG — cloud identity attack graph + multi-domain security scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text, func in [
        ("scan", "Run scan (IAM attack graph + s3/ec2/net/cve modules)", cmd_scan),
        ("graph", "Render IAM attack graph (text/mermaid/svg/dot)", cmd_graph),
        ("paths", "List attack paths to admin", cmd_paths),
        ("blast", "Blast radius of an identity", cmd_blast),
        ("report", "Generate report (md/json/csv/sarif)", cmd_report),
        ("diff", "Diff two report JSON files (new/fixed/changed findings)", cmd_diff),
    ]:
        p = sub.add_parser(name, help=help_text)
        _add_common(p)
        _add_scan_flags(p)
        if name == "scan":
            p.add_argument("--json", action="store_true")
        if name in ("graph", "paths"):
            choices = ["text", "mermaid"] + (["svg", "dot"] if name == "graph" else [])
            p.add_argument("--format", choices=choices, default="text",
                           help="Output format (mermaid for READMEs, svg for a visual graph)")
            p.add_argument("--output", "-o", help="Write output to a file instead of stdout")
        if name == "blast":
            p.add_argument("--identity", required=True)
        if name == "report":
            p.add_argument("--format", choices=["md", "json", "csv", "sarif"], default="md")
            p.add_argument("--compliance", choices=["cis", "pci"],
                           help="Only report findings mapped to this framework")
            p.add_argument("--output", "-o")
        if name == "diff":
            p.add_argument("--before", required=True, help="Report JSON before the change")
            p.add_argument("--after", required=True, help="Report JSON after the change")
            p.add_argument("--format", choices=["text", "json"], default="text")
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

    p_exploit = sub.add_parser(
        "exploit", help="Authorized escalation execution, canaries, detections")
    ex = p_exploit.add_subparsers(dest="exploit_command", required=True)

    def _auth_flags(p, targets=False):
        p.add_argument("--authorize-exploitation", metavar="ACCOUNT_ID",
                       help="Account/subscription/project id you may test")
        p.add_argument("--cloud", choices=["aws", "azure", "gcp"], default="aws",
                       help="Execution target cloud (default: aws)")
        p.add_argument("--profile", "-p", help="AWS profile")
        p.add_argument("--region", "-r", default="us-east-1")
        p.add_argument("--subscription-id", help="Azure subscription id")
        p.add_argument("--project", help="GCP project id")
        p.add_argument("--member", help="GCP member to grant (user:/serviceAccount:)")
        p.add_argument("--principal-id", help="Azure principal object id override")
        p.add_argument("--scope", help="Azure scope (default: subscription)")
        p.add_argument("--yes-i-have-written-authorization", action="store_true",
                       help="Skip the TTY confirmation phrase (unattended demo)")
        p.add_argument("--accept-unknown", action="store_true",
                       help="Proceed when IAM policy simulation has no decision")
        if targets:
            p.add_argument("--admin-policy-arn",
                           help="Managed admin policy ARN (default: AdministratorAccess)")
            p.add_argument("--target-policy", help="Target policy ARN (ESC-04/ESC-08)")
            p.add_argument("--policy-version", help="Policy version id (ESC-08)")
            p.add_argument("--boundary-arn", help="Replacement permissions boundary (ESC-09)")
            p.add_argument("--target-group", help="Privileged IAM group (ESC-10)")
            p.add_argument("--target-role", help="Target role name or ARN (ESC-11)")
            p.add_argument("--pass-role", help="Admin role ARN for the Lambda probe (ESC-02)")

    p_list = ex.add_parser("list", help="List executable techniques")
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_exploit)

    p_plan = ex.add_parser("plan", help="Dry-run authorization, simulation, and actions")
    p_plan.add_argument("technique")
    _auth_flags(p_plan, targets=True)
    p_plan.add_argument("--from-report",
                        help="CIDAG JSON/SARIF report to check for the finding")
    p_plan.set_defaults(func=cmd_exploit)

    p_run = ex.add_parser("run", help="Execute one technique with rollback")
    p_run.add_argument("technique")
    _auth_flags(p_run, targets=True)
    p_run.add_argument("--from-report",
                       help="CIDAG JSON/SARIF report that contains the finding")
    p_run.add_argument("--allow-unproven", action="store_true",
                       help="Run without a matching scan finding (explicit override)")
    p_run.add_argument("--keep", action="store_true",
                       help="Leave artifacts in place and print cleanup manifest")
    p_run.add_argument("--canary", choices=["auto", "s3", "secretsmanager"],
                       help="Prove impact with a self-deleting canary")
    p_run.add_argument("--audit-dir", default=".cidag/engagements")
    p_run.set_defaults(func=cmd_exploit)

    p_canary = ex.add_parser("canary", help="Create, read, and delete an impact canary")
    _auth_flags(p_canary)
    p_canary.add_argument("--canary-service", choices=["auto", "s3", "secretsmanager"],
                          default="auto")
    p_canary.set_defaults(func=cmd_exploit)

    p_det = ex.add_parser("detections", help="Emit Sigma/Insights/EventBridge detections")
    p_det.add_argument("--technique", help="Limit to one technique id")
    p_det.add_argument("--output", "-o")
    p_det.set_defaults(func=cmd_exploit)

    p_report = ex.add_parser("report", help="Render a markdown evidence pack")
    p_report.add_argument("manifest", help="Path to manifest.json")
    p_report.add_argument("--output", "-o")
    p_report.add_argument("--mask", action="store_true", help="Mask account ids")
    p_report.set_defaults(func=cmd_exploit)

    p_demo = ex.add_parser("demo", help="Build a masked portfolio report from history")
    p_demo.add_argument("--root", default=".cidag/engagements")
    p_demo.add_argument("--output", "-o", default="cidag-demo.md")
    p_demo.set_defaults(func=cmd_exploit)

    p_cleanup = ex.add_parser("cleanup", help="Apply a manifest's cleanup operations")
    p_cleanup.add_argument("manifest")
    _auth_flags(p_cleanup)
    p_cleanup.set_defaults(func=cmd_exploit)

    p_pacu = ex.add_parser("pacu", help="Run an allowlisted module in an existing Pacu session")
    _auth_flags(p_pacu)
    p_pacu.add_argument("--pacu-session", required=True)
    p_pacu.add_argument("--module", required=True)
    p_pacu.add_argument("--module-args", default="")
    p_pacu.set_defaults(func=cmd_exploit)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (CloudCredentialsError, CloudCollectionError) as e:
        # One catch point: every subcommand that touches AWS stops here
        # instead of reporting a plausible-looking but fabricated scan.
        print(f"[!] LIVE SCAN ABORTED: {e}", file=sys.stderr)
        return 2
    except ExploitError as e:
        print(f"[!] EXPLOIT ABORTED: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
