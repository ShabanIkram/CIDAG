"""GCP IAM collector -> CIDAG inventory (read-only).

Reads the project IAM policy (``getIamPolicy``), expands role bindings into
AWS-style statement policies, and resolves custom/predefined roles through the
IAM API. Basic roles are mapped conservatively. The existing graph, policy
analysis, and reports then work unchanged.

Read-only access required: ``resourcemanager.projects.getIamPolicy`` plus
``iam.roles.get``. Install with ``pip install "cidag[gcp]"``.
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


def normalize(project: str, bindings, roles: dict[str, list[dict]]) -> dict:
    """Build a CIDAG inventory from GCP bindings + role-name->statements map.

    ``bindings`` items may be SDK Binding objects or ``{"role", "members"}``
    dicts. ``roles`` maps a role name to AWS-style statements.
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

        inventory = normalize(project, bindings, roles)
        inventory["region"] = self.region
        return inventory


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
