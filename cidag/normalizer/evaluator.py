from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def action_matches(pattern: str, action: str) -> bool:
    if pattern == "*" or pattern == action:
        return True
    if pattern.endswith("*"):
        return action.startswith(pattern[:-1])
    return False


def resource_matches(pattern: str, resource: str) -> bool:
    if pattern == "*" or pattern == resource:
        return True
    return fnmatch.fnmatchcase(resource, pattern)


@dataclass
class Statement:
    effect: str
    actions: list[str]
    not_actions: list[str]
    resources: list[str]

    @classmethod
    def from_dict(cls, d: dict) -> "Statement":
        return cls(
            effect=d.get("Effect", "Allow"),
            actions=_as_list(d.get("Action")),
            not_actions=_as_list(d.get("NotAction")),
            resources=_as_list(d.get("Resource", "*")),
        )

    def matches_action(self, action: str) -> bool:
        if self.actions:
            return any(action_matches(p, action) for p in self.actions)
        if self.not_actions:
            return not any(action_matches(p, action) for p in self.not_actions)
        return False


@dataclass
class EffectivePermissions:
    arn: str
    label: str
    kind: str
    allow: list[Statement] = field(default_factory=list)
    deny: list[Statement] = field(default_factory=list)

    def denied(self, action: str) -> bool:
        return any(s.matches_action(action) for s in self.deny)

    def allowed(self, action: str) -> bool:
        if self.denied(action):
            return False
        return any(s.matches_action(action) for s in self.allow)

    def is_admin(self) -> bool:
        if self.denied("*"):
            return False
        return any("*" in s.actions for s in self.allow)

    def passrole_targets(self) -> list[str]:
        if self.denied("iam:PassRole"):
            return []
        targets: list[str] = []
        for s in self.allow:
            if any(action_matches(p, "iam:PassRole") for p in s.actions):
                targets.extend(s.resources)
        return targets

    def wildcard_findings(self) -> list[dict]:
        findings = []
        for s in self.allow:
            for p in s.actions:
                if self.denied(p):
                    continue
                if p == "*":
                    findings.append({
                        "severity": "CRITICAL",
                        "type": "WILDCARD_POLICY",
                        "identity": self.label,
                        "identity_arn": self.arn,
                        "reason": "Policy grants Action '*' (full admin potential)",
                        "remediation": "Replace wildcard with explicit least-privilege actions",
                    })
                elif p.endswith(":*") and "*" in s.resources:
                    findings.append({
                        "severity": "HIGH",
                        "type": "WILDCARD_POLICY",
                        "identity": self.label,
                        "identity_arn": self.arn,
                        "reason": f"Wildcard action '{p}' on Resource '*'",
                        "remediation": f"Scope '{p}' down to required actions/resources",
                    })
        return findings


def compute_effective(inventory: dict) -> dict[str, EffectivePermissions]:
    policies_by_arn = {p["arn"]: p for p in inventory.get("policies", [])}
    result: dict[str, EffectivePermissions] = {}

    for ident in inventory.get("identities", []):
        ep = EffectivePermissions(arn=ident["arn"], label=ident["name"], kind=ident["type"])
        policy_arns = ident.get("attached_policies", []) + ident.get("inline_policies", [])
        for p_arn in policy_arns:
            policy = policies_by_arn.get(p_arn)
            if not policy:
                continue
            for st in policy.get("statements", []):
                stmt = Statement.from_dict(st)
                (ep.deny if stmt.effect == "Deny" else ep.allow).append(stmt)
        result[ident["arn"]] = ep
    return result
