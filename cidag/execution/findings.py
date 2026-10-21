"""Bind authorized runs to escalation findings from a prior CIDAG scan."""
from __future__ import annotations

import json
from pathlib import Path

from .guard import ExploitError
from .session import canonical_iam_arn


def _norm_technique(value) -> str:
    return str(value or "").strip().upper()


def _normalize(finding: dict) -> dict | None:
    technique = _norm_technique(
        finding.get("check_id") or finding.get("type")
        or finding.get("ruleId"))
    if not technique:
        return None
    props = finding.get("properties") or {}
    identity = (finding.get("identity_arn") or finding.get("identityArn")
                or props.get("identityArn") or finding.get("identity"))
    return {
        "technique": technique,
        "identity_arn": str(identity) if identity else "",
        "account": str(finding.get("account") or props.get("account") or ""),
        "id": str(finding.get("id") or finding.get("partialFingerprints", {}).get(
            "cidagFindingId") or ""),
        "target": str(finding.get("target") or ""),
        "title": str(finding.get("title") or
                     (finding.get("message") or {}).get("text") or ""),
    }


def load_report(path: str | Path) -> list[dict]:
    """Load findings from a CIDAG JSON report, SARIF file, or findings list."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ExploitError(f"could not read findings report {path}: {e}") from e
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict) and "runs" in data:
        items = []
        for run in data.get("runs", []):
            items.extend(run.get("results", []))
    elif isinstance(data, dict):
        items = data.get("findings", [])
    else:
        raise ExploitError(f"unsupported findings report format in {path}")
    findings = [f for f in (_normalize(i) for i in items if isinstance(i, dict)) if f]
    if not findings:
        raise ExploitError(f"no findings found in {path}")
    return findings


def matching_findings(findings: list[dict], technique_id: str,
                      identity: dict | None = None) -> list[dict]:
    technique = _norm_technique(technique_id)
    matches = [f for f in findings if f["technique"] == technique]
    if not matches:
        return []
    if identity:
        account = str(identity.get("account", ""))
        matches = [f for f in matches
                   if not f["account"] or f["account"] == account]
        arn = identity.get("arn") or ""
        if arn:
            canonical = canonical_iam_arn(str(arn))
            exact = [f for f in matches if f["identity_arn"]
                     and canonical_iam_arn(f["identity_arn"]) == canonical]
            unknown = [f for f in matches if not f["identity_arn"]]
            matches = exact or unknown
    return matches


def evidence_for(findings: list[dict], technique_id: str,
                 identity: dict, allow_unproven: bool = False) -> dict:
    if allow_unproven:
        return {"status": "unproven", "source": "override",
                "reason": "--allow-unproven"}
    if findings is None:
        raise ExploitError(
            "no scan evidence supplied; generate one with "
            "'cidag report -m iam --format json -o scan.json' and pass "
            "--from-report scan.json, or explicitly use --allow-unproven")
    matched = matching_findings(findings, technique_id, identity)
    if not matched:
        available = sorted({f["technique"] for f in findings})
        raise ExploitError(
            f"technique {technique_id} was not found for this principal/account "
            f"in the scan report (reported escalation ids: "
            f"{', '.join(available) or 'none'}); rerun the scan or use "
            f"--allow-unproven")
    return {
        "status": "matched",
        "source": "report",
        "technique": _norm_technique(technique_id),
        "finding_ids": [f["id"] for f in matched if f["id"]],
        "identities": sorted({f["identity_arn"] for f in matched
                              if f["identity_arn"]}),
        "titles": sorted({f["title"] for f in matched if f["title"]}),
    }
