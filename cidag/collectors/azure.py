"""Azure RBAC collector -> CIDAG inventory (read-only).

Normalizes role definitions and role assignments into CIDAG's cloud-neutral
inventory: every role definition becomes an AWS-style policy document
(``Action``/``Resource`` statements), and every principal becomes an identity
with ``attached_policies`` pointing at those roles. The existing graph, policy
analysis, and reports then work unchanged.

Read-only access required: ``Reader`` at subscription scope (or
``Microsoft.Authorization/*/read``). Install with ``pip install "cidag[azure]"``.
"""
from __future__ import annotations

import os

from .base import BaseCollector, CloudCollectionError, CloudCredentialsError

_PRINCIPAL_TYPES = {
    "user": "user",
    "group": "group",
    "serviceprincipal": "service_principal",
    "foreigngroup": "group",
    "device": "device",
    "directoryrole": "directory_role",
}


class AzureCredentialsError(CloudCredentialsError):
    """Azure credentials did not resolve for a live scan."""


class AzureCollectionError(CloudCollectionError):
    """Azure subscription/RBAC collection failed."""


def _g(obj, key: str, default=None):
    """Read a field from an SDK model or a plain dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _statements_of(role_def) -> list[dict]:
    statements: list[dict] = []
    for perm in _g(role_def, "permissions", []) or []:
        actions = sorted({str(a) for a in (_g(perm, "actions", []) or [])
                          + (_g(perm, "data_actions", []) or []) if a})
        if actions:
            statements.append({"Effect": "Allow", "Action": actions, "Resource": "*"})
    return statements


def normalize(subscription_id: str, role_defs, assignments) -> dict:
    """Build a CIDAG inventory from Azure role definitions + assignments.

    Accepts azure-mgmt-authorization SDK models or equivalent dicts.
    """
    policies: dict[str, dict] = {}
    for rd in role_defs:
        role_id = str(_g(rd, "id") or _g(rd, "role_definition_id") or _g(rd, "name"))
        name = str(_g(rd, "role_name") or _g(rd, "name") or role_id)
        policies[role_id] = {
            "arn": role_id,
            "name": name,
            "statements": _statements_of(rd),
        }

    principals: dict[str, dict] = {}
    for assignment in assignments:
        principal_id = str(_g(assignment, "principal_id") or "")
        role_id = str(_g(assignment, "role_definition_id") or "")
        if not principal_id or not role_id:
            continue
        ptype = str(_g(assignment, "principal_type") or "unknown").lower()
        kind = _PRINCIPAL_TYPES.get(ptype, ptype or "unknown")
        arn = f"azure:{subscription_id}:principal:{principal_id}"
        identity = principals.setdefault(arn, {
            "type": kind,
            "name": principal_id,
            "arn": arn,
            "attached_policies": [],
            "inline_policies": [],
            "groups": [],
        })
        if role_id not in identity["attached_policies"]:
            identity["attached_policies"].append(role_id)

    return {
        "cloud": "azure",
        "account_id": subscription_id,
        "identities": list(principals.values()),
        "policies": list(policies.values()),
        "resources": [],
    }


class AzureCollector(BaseCollector):
    def __init__(self, subscription_id: str | None = None, region: str = "eastus"):
        self.subscription_id = subscription_id
        self.region = region

    def collect(self) -> dict:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.resource import SubscriptionClient
        except ImportError as e:
            raise AzureCollectionError(
                "Azure SDK not installed; run pip install 'cidag[azure]'") from e

        subscription_id = self.subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
        try:
            credential = DefaultAzureCredential()
            if not subscription_id:
                client = SubscriptionClient(credential)
                enabled = [s for s in client.subscriptions.list()
                           if str(getattr(s, "state", "Enabled")) == "Enabled"]
                if not enabled:
                    raise AzureCollectionError("no enabled Azure subscriptions found")
                subscription_id = enabled[0].subscription_id
        except AzureCollectionError:
            raise
        except Exception as e:
            raise AzureCredentialsError(f"Azure authentication failed: {e}") from e

        try:
            client = AuthorizationManagementClient(credential, subscription_id)
            scope = f"/subscriptions/{subscription_id}"
            role_defs = list(client.role_definitions.list(scope=scope))
            assignments = list(client.role_assignments.list_for_subscription())
        except Exception as e:
            raise AzureCollectionError(
                f"Azure RBAC collection failed for {subscription_id}: {e}") from e

        inventory = normalize(subscription_id, role_defs, assignments)
        inventory["region"] = self.region
        return inventory
