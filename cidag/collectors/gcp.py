"""GCP IAM collector -> CIDAG inventory (read-only).

Reads the project IAM policy (``getIamPolicy``), expands role bindings into
AWS-style statement policies, and resolves custom/predefined roles through the
IAM API. Basic roles are mapped conservatively. The existing graph, policy
analysis, and reports then work unchanged.

Read-only access required: ``resourcemanager.projects.getIamPolicy`` plus
``iam.roles.get``. Organization policy constraints -- GCP's cloud guardrails --
additionally need ``orgpolicy.policies.list`` and ``orgpolicy.constraints.list``
and degrade to a warning when missing. Install with ``pip install "cidag[gcp]"``.
"""
from __future__ import annotations

import os

from .base import BaseCollector, CloudCollectionError, CloudCredentialsError

_MEMBER_TYPES = {
    "user": "user",
    "group": "group",
    "serviceaccount": "service_account",
    "domain": "domain",
    "deleted": "deleted",
}

_BASIC_ROLES: dict[str, list[dict]] = {
    "roles/owner": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
    ],
    "roles/editor": [
        {"Effect": "Allow", "Action": [
            "compute.instances.create", "compute.instances.delete",
            "storage.objects.create", "storage.objects.delete",
            "container.clusters.create", "cloudfunctions.functions.create",
        ], "Resource": "*"},
    ],
    "roles/viewer": [
        {"Effect": "Allow", "Action": [
            "resourcemanager.projects.get", "compute.instances.list",
            "storage.objects.list",
        ], "Resource": "*"},
    ],
}


class GcpCredentialsError(CloudCredentialsError):
    """GCP credentials did not resolve for a live scan."""


class GcpCollectionError(CloudCollectionError):
    """GCP project IAM collection failed."""


def _g(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _member_kind(member: str) -> str:
    prefix = member.split(":", 1)[0].lower() if ":" in member else "unknown"
    return _MEMBER_TYPES.get(prefix, prefix)


# Standard organization policy constraints that map to concrete IAM denials.
# Boolean constraints carry no permission of their own -- GCP maps the
# constraint onto API methods internally -- so CIDAG needs an explicit table.
# Keys are constraint ids (the last path segment of the constraint name).
_CONSTRAINT_ACTIONS: dict[str, list[str]] = {
    "iam.disableServiceAccountKeyCreation": [
        "iam.serviceAccounts.keys.create",
        "iam.serviceAccounts.keys.createWithPublicKey",
        # Older CIDAG inventories spelled this without the plural "s"; deny
        # both spellings so either inventory form is gated.
        "iam.serviceAccountKeys.create",
    ],
    "iam.disableServiceAccountKeyUpload": ["iam.serviceAccounts.keys.upload"],
    "iam.disableServiceAccountCreation": ["iam.serviceAccounts.create"],
}

# A custom constraint names a resource type plus the REST method types it
# gates rather than an IAM permission; this maps the pairs that do correspond
# to one.
_CUSTOM_CONSTRAINT_ACTIONS: dict[tuple[str, str], list[str]] = {
    ("iam.googleapis.com/ServiceAccount", "CREATE"): ["iam.serviceAccounts.create"],
    ("iam.googleapis.com/ServiceAccountKey", "CREATE"): [
        "iam.serviceAccounts.keys.create",
        "iam.serviceAccounts.keys.createWithPublicKey",
    ],
    ("iam.googleapis.com/ServiceAccountKey", "DELETE"): ["iam.serviceAccounts.keys.delete"],
}


class GcpCredentialsError(CloudCredentialsError):
    """GCP credentials did not resolve for a live scan."""


class GcpCollectionError(CloudCollectionError):
    """GCP project IAM collection failed."""


def _constraint_key(constraint: str) -> str:
    """``organizations/1/customConstraints/custom.foo`` -> ``custom.foo``."""
    return str(constraint).rstrip("/").rsplit("/", 1)[-1]


def _is_deny_action(action_type) -> bool:
    if isinstance(action_type, int):
        return action_type == 2  # ActionType.DENY
    return str(action_type).upper() == "DENY"


def _constraint_actions(constraint: str, spec) -> list[str]:
    """Denied permissions for one enforced constraint, if CIDAG can name them."""
    actions = list(_CONSTRAINT_ACTIONS.get(_constraint_key(constraint), []))
    # An ALLOW custom constraint is an allow-list gated on a CEL expression
    # over the resource under review; CIDAG evaluates actions, not resources,
    # so only a plain DENY is expressible here.
    if spec and _is_deny_action(_g(spec, "action_type")):
        for resource_type in _g(spec, "resource_types") or []:
            for method_type in _g(spec, "method_types") or []:
                actions.extend(_CUSTOM_CONSTRAINT_ACTIONS.get(
                    (str(resource_type), str(method_type).upper()), []))
    return sorted(set(actions))


def normalize_org_policies(org_policies, constraints=None) -> list[dict]:
    """Map GCP organization policy rules to CIDAG deny guardrails.

    ``org_policies`` items are ``{"constraint": name, "enforce": bool}`` as
    read from ``orgpolicy_v2.Policy.rules``. ``constraints`` optionally maps a
    constraint name (full name or trailing id) to ``{"resource_types",
    "method_types", "action_type"}`` for custom constraints.

    Only enforced boolean/custom rules are expressible: list constraints
    restrict *values* (which domains, which machines), not actions, so an
    action-based evaluator cannot represent them. Constraints CIDAG cannot map
    to a permission are still recorded, with no statements, so the inventory
    shows what the project enforces.
    """
    constraints = constraints or {}
    guardrails: list[dict] = []
    for policy in org_policies or []:
        constraint = str(_g(policy, "constraint") or "")
        if not constraint or not _g(policy, "enforce", False):
            continue
        spec = constraints.get(constraint) or constraints.get(_constraint_key(constraint))
        actions = _constraint_actions(constraint, spec)
        statements = ([{"Effect": "Deny", "Action": actions,
                        "NotAction": [], "Resource": "*"}] if actions else [])
        guardrails.append({
            "id": f"gcp:orgpolicy:{constraint}",
            "name": constraint,
            "source": "gcp_org_policy",
            # Organization policies bind resources rather than principals, so
            # an enforced constraint gates every identity in the project.
            "principals": ["*"],
            "statements": statements,
        })
    return guardrails


def normalize(project: str, bindings, roles: dict[str, list[dict]],
              org_policies=None, constraints=None) -> dict:
    """Build a CIDAG inventory from GCP bindings + role-name->statements map.

    ``bindings`` items may be SDK Binding objects or ``{"role", "members"}``
    dicts. ``roles`` maps a role name to AWS-style statements. ``org_policies``
    and ``constraints`` feed :func:`normalize_org_policies`.
    """
    identities: dict[str, dict] = {}
    policy_names: set[str] = set()
    for binding in bindings:
        role = str(_g(binding, "role") or "")
        if not role:
            continue
        policy_arn = f"gcp:role:{role}"
        policy_names.add(role)
        for member in _g(binding, "members", []) or []:
            member = str(member)
            identity = identities.setdefault(member, {
                "type": _member_kind(member),
                "name": member,
                "arn": member,
                "attached_policies": [],
                "inline_policies": [],
                "groups": [],
            })
            if policy_arn not in identity["attached_policies"]:
                identity["attached_policies"].append(policy_arn)

    policies = []
    for role in sorted(policy_names):
        policies.append({
            "arn": f"gcp:role:{role}",
            "name": role,
            "statements": roles.get(role, []),
        })

    return {
        "cloud": "gcp",
        "account_id": project,
        "identities": list(identities.values()),
        "policies": policies,
        "resources": [],
        "guardrails": normalize_org_policies(org_policies, constraints),
    }


class GcpCollector(BaseCollector):
    def __init__(self, project: str | None = None, region: str = "us-central1"):
        self.project = project
        self.region = region

    def collect(self) -> dict:
        try:
            import google.auth
            from google.auth.exceptions import DefaultCredentialsError
            from google.cloud import iam_admin_v1, resourcemanager_v3
        except ImportError as e:
            raise GcpCollectionError(
                "GCP SDK not installed; run pip install 'cidag[gcp]'") from e

        try:
            credentials, detected_project = google.auth.default()
        except DefaultCredentialsError as e:
            raise GcpCredentialsError(
                f"GCP credentials not found: {e}. Run `gcloud auth "
                f"application-default login` or set GOOGLE_APPLICATION_CREDENTIALS."
            ) from e
        except Exception as e:
            raise GcpCredentialsError(f"GCP authentication failed: {e}") from e

        project = (self.project or os.environ.get("GOOGLE_CLOUD_PROJECT")
                   or detected_project)
        if not project:
            raise GcpCredentialsError(
                "no GCP project; pass --project or set GOOGLE_CLOUD_PROJECT")

        try:
            rm = resourcemanager_v3.ProjectsClient(credentials=credentials)
            policy = rm.get_iam_policy(request={"resource": f"projects/{project}"})
        except Exception as e:
            raise GcpCollectionError(
                f"GCP getIamPolicy failed for {project}: {e}") from e

        bindings = [{"role": b.role, "members": list(b.members)}
                    for b in policy.bindings]
        iam = iam_admin_v1.IAMClient(credentials=credentials)
        roles: dict[str, list[dict]] = {}
        for role in sorted({b["role"] for b in bindings}):
            roles[role] = _role_statements(role, iam)

        org_policies, constraints = self._collect_org_policies(project, credentials)
        inventory = normalize(project, bindings, roles, org_policies, constraints)
        inventory["region"] = self.region
        return inventory

    def _collect_org_policies(self, project: str, credentials) -> tuple[list[dict], dict]:
        """Read enforced organization policy constraints (best-effort).

        Needs ``orgpolicy.policies.list`` / ``orgpolicy.constraints.list``.
        Like ``_collect_scps``, a failure degrades to "no GCP guardrails" with
        a warning instead of aborting the IAM scan.
        """
        try:
            from google.cloud import orgpolicy_v2
        except ImportError as e:
            print(f"[!] org policies: unavailable ({e}); "
                  "GCP guardrail evaluation skipped")
            return [], {}

        parent = f"projects/{project}"
        org_policies: list[dict] = []
        constraints: dict[str, dict] = {}
        try:
            client = orgpolicy_v2.OrgPolicyClient(credentials=credentials)
            for policy in client.list_policies(parent=parent):
                for rule in getattr(policy, "rules", None) or []:
                    # List rules carry allow/deny values instead of `enforce`;
                    # those restrict values, not actions, and are skipped.
                    org_policies.append({
                        "constraint": str(getattr(rule, "constraint", "") or ""),
                        "enforce": bool(getattr(rule, "enforce", False)),
                    })
        except Exception as e:
            print(f"[!] org policies: unavailable ({e}); "
                  "GCP guardrail evaluation skipped")
            return [], {}

        try:
            spec_client = orgpolicy_v2.ConstraintClient(credentials=credentials)
            for spec in spec_client.list_constraints(parent=parent):
                name = str(getattr(spec, "name", "") or "")
                constraints[name] = {
                    "resource_types": list(getattr(spec, "resource_types", None) or []),
                    "method_types": list(getattr(spec, "method_types", None) or []),
                    "action_type": getattr(spec, "action_type", None),
                }
        except Exception as e:
            print(f"[!] org policy constraints: unavailable ({e}); "
                  "custom constraint evaluation skipped")

        return org_policies, constraints


def _role_statements(role: str, iam) -> list[dict]:
    if role in _BASIC_ROLES:
        return [dict(s) for s in _BASIC_ROLES[role]]
    try:
        role_obj = iam.get_role(request={"name": role})
        permissions = sorted({str(p) for p in role_obj.included_permissions if p})
    except Exception:
        permissions = []
    if not permissions:
        return []
    return [{"Effect": "Allow", "Action": permissions, "Resource": "*"}]
