"""Best-effort CIS AWS Foundations / PCI DSS mappings for CIDAG checks.

Mappings are curated at control level, not per benchmark version: control IDs
are stable across CIS AWS Foundations v1.4/v1.5/v2.0 and PCI DSS v4.0. They are
meant to help triage and auditor conversations, not to certify compliance.
Verify every mapping against the benchmark version your auditor uses.
"""
from __future__ import annotations

FRAMEWORKS = {"cis": "CIS AWS Foundations", "pci": "PCI DSS v4.0"}

_MAP: dict[str, dict[str, list[str]]] = {
    # IAM / privilege
    "WILDCARD_POLICY": {"cis": ["1.16"], "pci": ["7.2"]},
    "ATTACK_PATH": {"pci": ["7.2"]},
    "POL-001": {"cis": ["1.16"], "pci": ["7.2"]},
    "POL-002": {"pci": ["7.2"]},
    "POL-003": {"pci": ["7.2"]},
    "POL-004": {"pci": ["7.2"]},
    # S3
    "S3-001": {"cis": ["2.1.1"], "pci": ["1.3"]},
    "S3-002": {"cis": ["2.1.1"], "pci": ["1.3"]},
    "S3-003": {"cis": ["2.1.5"], "pci": ["3.5"]},
    "S3-004": {"cis": ["2.1.1"], "pci": ["1.3"]},
    "S3-005": {"cis": ["2.1.1"], "pci": ["4.2"]},
    "S3-006": {"cis": ["2.1.4"], "pci": ["10.2"]},
    "S3-007": {"cis": ["2.1.3"]},
    "S3-008": {"cis": ["2.1.2"]},
    "S3-010": {"cis": ["2.1.1"], "pci": ["1.3"]},
    # EC2 / networking
    "EC2-001": {"cis": ["5.2"], "pci": ["1.3"]},
    "EC2-002": {"cis": ["5.3"], "pci": ["1.3"]},
    "EC2-003": {"pci": ["1.3"]},
    "EC2-004": {"cis": ["5.2", "5.3"], "pci": ["1.3"]},
    "EC2-005": {"cis": ["2.2.1"], "pci": ["3.5"]},
    "EC2-006": {"pci": ["2.2"]},
    "NET-OPEN": {"pci": ["1.3"]},
    # RDS
    "RDS-001": {"cis": ["2.3.1"], "pci": ["1.3"]},
    "RDS-002": {"cis": ["2.3.2"], "pci": ["3.5"]},
    # CloudTrail / logging
    "CT-001": {"cis": ["3.1"], "pci": ["10.2"]},
    "CT-002": {"cis": ["3.1"], "pci": ["10.2"]},
    "CT-003": {"cis": ["3.2"], "pci": ["10.3"]},
    "CT-004": {"cis": ["3.7"], "pci": ["10.3"]},
}

_ESCALATION = {"pci": ["7.2"]}
_CVE = {"pci": ["6.3"]}


def tags_for(check_id: str, module: str = "") -> dict[str, list[str]]:
    """Return {"cis": [...], "pci": [...]} tags for a finding (possibly empty)."""
    if check_id in _MAP:
        return {k: list(v) for k, v in _MAP[check_id].items()}
    if check_id.startswith("ESC-"):
        return dict(_ESCALATION)
    if check_id.startswith("CVE-") or module.startswith("cve"):
        return dict(_CVE)
    if module.startswith("import"):
        return dict(_CVE)
    return {}


def attach(findings) -> None:
    """Populate ``Finding.compliance`` for findings that lack tags."""
    for f in findings:
        if not f.compliance:
            tags = tags_for(f.check_id, f.module)
            if tags:
                f.compliance = tags


def summary(findings) -> dict[str, dict[str, int]]:
    """Count findings per framework control: {"cis": {"1.16": 3}, "pci": {...}}."""
    out: dict[str, dict[str, int]] = {}
    for f in findings:
        for framework, controls in (f.compliance or {}).items():
            counts = out.setdefault(framework, {})
            for control in controls:
                counts[control] = counts.get(control, 0) + 1
    return out


def filter_by(findings, framework: str | None):
    """Return only findings mapped to ``framework`` (no-op when None/empty)."""
    if not framework:
        return findings
    return [f for f in findings if (f.compliance or {}).get(framework)]
