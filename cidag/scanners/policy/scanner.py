"""IAM policy risk analysis (Cloudsplaining-style, fully offline).

Analyzes the policy documents themselves rather than effective identity
permissions:

- POL-001  wildcard action on wildcard resource (admin-equivalent)
- POL-002  privilege-escalation primitives granted to a policy
- POL-003  data-exfiltration capability on all resources
- POL-004  trust policy with a wildcard principal (public assume)
"""
from __future__ import annotations

import fnmatch

from ...core.finding import Finding, Severity
from ...core.registry import register

_DATA_EXFIL_ACTIONS = (
    "s3:getobject", "s3:getobjectversion", "s3:getobjectacl",
    "ssm:getparameter", "ssm:getparameters", "ssm:getparametersbypath",
    "secretsmanager:getsecretvalue",
    "dynamodb:getitem", "dynamodb:query", "dynamodb:scan",
    "kms:decrypt",
    "rds:downloaddblogfileportion",
)

_PRIVESC_ACTIONS = (
    "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy", "iam:attachrolepolicy", "iam:attachgrouppolicy",
    "iam:putuserpolicy", "iam:putrolepolicy", "iam:putgrouppolicy",
    "iam:updateassumerolepolicy",
    "iam:createloginprofile", "iam:updateloginprofile",
    "iam:createaccesskey", "iam:passrole",
)


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _actions_of(stmt: dict) -> list[str]:
    not_action = stmt.get("NotAction")
    if str(not_action).strip() == "*":
        return ["*"]
    return [str(a).strip() for a in _as_list(stmt.get("Action"))]


def _statements_of(doc: dict | None) -> list[dict]:
    if not doc:
        return []
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return [s for s in stmts if isinstance(s, dict)]


def _matches(pattern: str, action: str) -> bool:
    pattern = pattern.lower().strip()
    if pattern == action:
        return True
    return "*" in pattern and fnmatch.fnmatchcase(action, pattern)


def _resource_is_all(stmt: dict) -> bool:
    values = [str(v) for v in _as_list(stmt.get("Resource"))]
    return "*" in values


def _finding(check_id: str, severity: Severity, title: str, target: str,
             remediation: str, evidence: dict) -> Finding:
    return Finding(module="policy", check_id=check_id, severity=severity,
                   title=title, target=target, remediation=remediation,
                   evidence=evidence)


def _check_policy(policy: dict) -> list[Finding]:
    arn = str(policy.get("arn") or policy.get("name") or "unknown-policy")
    name = policy.get("name", arn)
    stmts = _statements_of({"Statement": policy.get("statements") or []})
    exfil: set[str] = set()
    privesc: set[str] = set()
    wildcard_all = False

    for stmt in stmts:
        if str(stmt.get("Effect", "Allow")).lower() != "allow":
            continue
        actions = _actions_of(stmt)
        if not actions:
            continue
        res_all = _resource_is_all(stmt)
        if "*" in actions and res_all:
            wildcard_all = True
        if stmt.get("Condition"):
            continue
        if res_all:
            for pattern in actions:
                exfil.update(a for a in _DATA_EXFIL_ACTIONS if _matches(pattern, a))
        for pattern in actions:
            privesc.update(a for a in _PRIVESC_ACTIONS if _matches(pattern, a))

    findings: list[Finding] = []
    if wildcard_all:
        findings.append(_finding(
            "POL-001", Severity.CRITICAL,
            f"Policy '{name}' grants full admin (*:* on *)",
            arn,
            "Replace the wildcard statement with the specific actions and "
            "resources the workload needs; keep privileged actions on dedicated roles",
            {"policy": name, "actions": ["*"], "resource": "*"},
        ))
        return findings
    if privesc:
        findings.append(_finding(
            "POL-002", Severity.HIGH,
            f"Policy '{name}' grants privilege-escalation actions",
            arn,
            "Remove IAM mutation permissions; scope PassRole to a single "
            "non-privileged role and require permissions boundaries",
            {"policy": name, "actions": sorted(privesc)},
        ))
    if exfil:
        findings.append(_finding(
            "POL-003", Severity.HIGH,
            f"Policy '{name}' can read sensitive data in every resource",
            arn,
            "Scope read access to named resources and add condition keys "
            "(aws:ResourceTag, aws:SourceVpc); move secrets to scoped policies",
            {"policy": name, "actions": sorted(exfil), "resource": "*"},
        ))
    return findings


def _check_trust(identity: dict) -> list[Finding]:
    name = identity.get("name", "unknown")
    arn = str(identity.get("arn") or name)
    findings: list[Finding] = []
    for stmt in _statements_of(identity.get("trust_policy")):
        if str(stmt.get("Effect", "Allow")).lower() != "allow":
            continue
        principal = stmt.get("Principal")
        wildcard = principal == "*"
        if isinstance(principal, dict):
            wildcard = wildcard or "*" in [str(p) for p in _as_list(principal.get("AWS"))]
        if wildcard:
            findings.append(_finding(
                "POL-004", Severity.CRITICAL,
                f"Role '{name}' can be assumed by anyone (wildcard principal)",
                arn,
                "Replace the wildcard principal with specific account/role ARNs "
                "and add an ExternalId condition for third-party access",
                {"identity": name, "principal": "*"},
            ))
    return findings


@register("policy")
class PolicyScanner:
    name = "policy"
    description = "IAM policy least-privilege / exposure analysis (Cloudsplaining-style)"

    def run(self, context) -> list[Finding]:
        inventory = context.inventory or {}
        findings: list[Finding] = []
        for policy in inventory.get("policies", []) or []:
            findings.extend(_check_policy(policy))
        for identity in inventory.get("identities", []) or []:
            findings.extend(_check_trust(identity))
        return findings
