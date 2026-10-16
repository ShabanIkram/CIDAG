"""EC2 / Security Group / EBS / RDS / CloudTrail configuration checks.

Pure functions over normalized inventory dicts -- offline-testable.
"""
from __future__ import annotations

from ...core.finding import Finding, Severity

# Ports that should essentially never be open to the whole internet.
_CRIT_PORTS = {22: "SSH", 3389: "RDP"}
_HIGH_PORTS = {389: "LDAP", 636: "LDAPS", 445: "SMB", 3306: "MySQL",
               5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
               9200: "Elasticsearch", 11211: "Memcached", 5984: "CouchDB"}
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _ingress_open(ing: dict) -> list[str]:
    """Return the cidrs that expose this rule to the world."""
    return [c for c in (ing.get("cidrs", []) + ing.get("ipv6", [])) if c in _OPEN_CIDRS]


def _sg_findings(sg: dict) -> list[Finding]:
    out: list[Finding] = []
    loc = f"{sg['group_id']} ({sg.get('group_name','')})"
    for ing in sg.get("ingress", []):
        open_cidrs = _ingress_open(ing)
        if not open_cidrs:
            continue
        proto = ing.get("protocol", "")
        frm, to = ing.get("from_port"), ing.get("to_port")
        # all-traffic / all-ports
        if proto == "-1" or (frm in (0, None) and to in (65535, None)) or (frm == 0 and to == 0):
            out.append(Finding(
                module="ec2", check_id="EC2-004", severity=Severity.CRITICAL,
                title=f"Security group allows ALL traffic from the internet",
                target=loc,
                remediation="Restrict the security group to required ports and source CIDRs.",
                evidence={"rule": ing, "cidrs": open_cidrs},
            ))
            continue
        for port in port_in_range(frm, to, _CRIT_PORTS):
            out.append(Finding(
                module="ec2", check_id="EC2-001" if port == 22 else "EC2-002",
                severity=Severity.CRITICAL,
                title=f"Security group exposes {_CRIT_PORTS[port]} ({port}) to the internet",
                target=loc,
                remediation=f"Restrict port {port} to known admin CIDRs or use a bastion/VPN.",
                evidence={"rule": ing, "cidrs": open_cidrs, "port": port},
            ))
        for port in _HIGH_PORTS:
            if port_in_range(frm, to, {port: _HIGH_PORTS[port]}):
                out.append(Finding(
                    module="ec2", check_id="EC2-003", severity=Severity.HIGH,
                    title=f"Security group exposes {_HIGH_PORTS[port]} ({port}) to the internet",
                    target=loc,
                    remediation=f"Restrict port {port} to private/known CIDRs.",
                    evidence={"rule": ing, "cidrs": open_cidrs, "port": port},
                ))
    return out


def port_in_range(frm, to, ports: dict) -> list[int]:
    if frm is None or to is None:
        return []
    hits = []
    for p in ports:
        if frm <= p <= to:
            hits.append(p)
    return hits


def check_unencrypted_ebs(vol: dict, account_pab=None) -> list[Finding]:
    if not vol.get("encrypted"):
        return [Finding(
            module="ec2", check_id="EC2-005", severity=Severity.MEDIUM,
            title="EBS volume is not encrypted",
            target=vol.get("volume_id", "unknown"),
            remediation="Enable EBS encryption at rest (or account-level EBS encryption by default).",
            evidence={"state": vol.get("state")},
        )]
    return []


def check_imdsv1(inst: dict, account_pab=None) -> list[Finding]:
    if not inst.get("imds_v2"):
        return [Finding(
            module="ec2", check_id="EC2-006", severity=Severity.HIGH,
            title="EC2 instance allows IMDSv1 (metadata accessible to SSRF)",
            target=inst.get("instance_id", "unknown"),
            remediation="Set metadata options HttpTokens=required to enforce IMDSv2.",
            evidence={"public_ip": inst.get("public_ip")},
        )]
    return []


# ----------------------------------------------------------------------- RDS

def check_rds_public(db: dict, account_pab=None) -> list[Finding]:
    if db.get("publicly_accessible"):
        return [Finding(
            module="ec2", check_id="RDS-001", severity=Severity.HIGH,
            title="RDS instance is publicly accessible",
            target=db.get("db_instance_identifier", "unknown"),
            remediation="Disable public accessibility; place the database in private subnets.",
            evidence={},
        )]
    return []


def check_rds_unencrypted(db: dict, account_pab=None) -> list[Finding]:
    if not db.get("storage_encrypted"):
        return [Finding(
            module="ec2", check_id="RDS-002", severity=Severity.MEDIUM,
            title="RDS storage not encrypted",
            target=db.get("db_instance_identifier", "unknown"),
            remediation="Enable storage encryption (requires snapshot/restore for existing instances).",
            evidence={},
        )]
    return []


def check_rds_backup(db: dict, account_pab=None) -> list[Finding]:
    retention = db.get("backup_retention_period", 0) or 0
    if retention < 7:
        return [Finding(
            module="ec2", check_id="RDS-003", severity=Severity.MEDIUM,
            title=f"RDS backup retention is {retention} days (< 7)",
            target=db.get("db_instance_identifier", "unknown"),
            remediation="Set backup retention period to at least 7 days.",
            evidence={"backup_retention_period": retention},
        )]
    return []


# ------------------------------------------------------------- CloudTrail

def check_cloudtrail(trails: list[dict], account_pab=None) -> list[Finding]:
    out: list[Finding] = []
    if not trails:
        return [Finding(
            module="ec2", check_id="CT-001", severity=Severity.HIGH,
            title="No CloudTrail trail configured",
            target="cloudtrail",
            remediation="Enable a multi-region CloudTrail with log-file validation and CMK encryption.",
            evidence={},
        )]
    for t in trails:
        name = t.get("name", "trail")
        if not t.get("is_multi_region"):
            out.append(Finding(
                module="ec2", check_id="CT-002", severity=Severity.MEDIUM,
                title=f"CloudTrail trail '{name}' is not multi-region",
                target=name,
                remediation="Enable multi-region trail so all regions are logged.",
                evidence={},
            ))
        if not t.get("log_file_validation_enabled"):
            out.append(Finding(
                module="ec2", check_id="CT-003", severity=Severity.MEDIUM,
                title=f"CloudTrail trail '{name}' lacks log-file validation",
                target=name,
                remediation="Enable log file integrity validation.",
                evidence={},
            ))
        if not t.get("kms_key_id"):
            out.append(Finding(
                module="ec2", check_id="CT-004", severity=Severity.LOW,
                title=f"CloudTrail trail '{name}' not encrypted with a CMK",
                target=name,
                remediation="Enable server-side encryption with a customer-managed KMS key.",
                evidence={},
            ))
    return out


SG_CHECK = _sg_findings
