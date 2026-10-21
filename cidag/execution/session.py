"""Engagement session helpers for authorized exploitation.

CIDAG never stores AWS keys: credentials always come from the botocore chain or
a named profile. This module only caches clients and normalizes principal ARNs.
"""
from __future__ import annotations

import base64
import json

import boto3

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def role_name_from_arn(arn: str) -> str:
    """Extract the IAM role name from a role or assumed-role ARN."""
    if ":assumed-role/" in arn:
        tail = arn.split(":assumed-role/", 1)[1]
        return tail.rsplit("/", 1)[0]
    if ":role/" in arn:
        return arn.split(":role/", 1)[1].rsplit("/", 1)[-1]
    raise ValueError(f"not an IAM role ARN: {arn}")


def user_name_from_arn(arn: str) -> str:
    if ":user/" not in arn:
        raise ValueError(f"not an IAM user ARN: {arn}")
    return arn.split(":user/", 1)[1].rsplit("/", 1)[-1]


def canonical_iam_arn(arn: str) -> str:
    """Convert an assumed-role session ARN to the underlying IAM role ARN."""
    if ":assumed-role/" in arn:
        parts = arn.split(":")
        if len(parts) >= 5:
            return f"arn:aws:iam::{parts[4]}:role/{role_name_from_arn(arn)}"
    return arn


def principal_kind(arn: str) -> str:
    if ":assumed-role/" in arn or ":role/" in arn:
        return "role"
    if ":user/" in arn:
        return "user"
    return "unknown"


class EngagementSession:
    provider = "aws"

    def __init__(self, profile: str | None = None, region: str = "us-east-1",
                 session=None):
        self.session = session or boto3.Session(profile_name=profile,
                                                region_name=region)
        self.region = region
        self._clients: dict[tuple[str, str], object] = {}
        self._identity: dict | None = None

    def client(self, service: str, region: str | None = None):
        key = (service, region or self.region)
        if key not in self._clients:
            self._clients[key] = self.session.client(
                service, region_name=region or self.region)
        return self._clients[key]

    def caller_identity(self, refresh: bool = False) -> dict:
        if self._identity is None or refresh:
            ident = self.client("sts").get_caller_identity()
            self._identity = {
                "account": str(ident["Account"]),
                "arn": str(ident["Arn"]),
                "user_id": str(ident.get("UserId", "")),
            }
        return self._identity


def _jwt_claims(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


class AzureEngagementSession:
    """Azure RBAC execution session (lazy SDK import).

    ``client`` is injectable for tests; live mode uses DefaultAzureCredential.
    """
    provider = "azure"
    region = ""

    def __init__(self, subscription_id: str, credential=None, client=None,
                 identity: dict | None = None):
        if not subscription_id:
            raise ValueError("Azure subscription id is required")
        self.account = str(subscription_id)
        self._credential = credential
        self._client = client
        self._identity = identity

    def _get_credential(self):
        if self._credential is None:
            try:
                from azure.identity import DefaultAzureCredential
            except ImportError as e:
                raise RuntimeError(
                    "Azure SDK not installed; run pip install 'cidag[azure]'") from e
            self._credential = DefaultAzureCredential()
        return self._credential

    def client(self, service: str = "authorization"):
        if self._client is None:
            try:
                from azure.mgmt.authorization import AuthorizationManagementClient
            except ImportError as e:
                raise RuntimeError(
                    "Azure SDK not installed; run pip install 'cidag[azure]'") from e
            self._client = AuthorizationManagementClient(
                self._get_credential(), self.account)
        return self._client

    def role_assignment_parameters(self, role_id: str, principal_id: str):
        try:
            from azure.mgmt.authorization.models import (
                RoleAssignmentCreateParameters)
        except ImportError as e:
            raise RuntimeError(
                "Azure SDK not installed; run pip install 'cidag[azure]'") from e
        return RoleAssignmentCreateParameters(
            role_definition_id=role_id, principal_id=principal_id)

    def caller_identity(self) -> dict:
        if self._identity is None:
            token = self._get_credential().get_token(
                "https://management.azure.com/.default").token
            claims = _jwt_claims(token)
            oid = str(claims.get("oid") or claims.get("sub") or "")
            upn = str(claims.get("upn") or claims.get("unique_name")
                      or claims.get("appid") or "")
            self._identity = {
                "account": self.account,
                "arn": f"azure:{self.account}:principal:{oid or 'unknown'}",
                "user_id": oid,
                "upn": upn,
            }
        return self._identity


class GcpEngagementSession:
    """GCP project IAM execution session (lazy SDK import)."""
    provider = "gcp"
    region = ""

    def __init__(self, project: str, member: str | None = None,
                 credentials=None, client=None, identity: dict | None = None):
        if not project:
            raise ValueError("GCP project id is required")
        self.account = str(project)
        self.member = member or ""
        self._credentials = credentials
        self._client = client
        self._identity = identity

    def client(self, service: str = "resourcemanager"):
        if self._client is None:
            try:
                from google.cloud import resourcemanager_v3
            except ImportError as e:
                raise RuntimeError(
                    "GCP SDK not installed; run pip install 'cidag[gcp]'") from e
            if self._credentials is None:
                try:
                    import google.auth
                except ImportError as e:
                    raise RuntimeError(
                        "GCP SDK not installed; run pip install 'cidag[gcp]'") from e
                self._credentials, _ = google.auth.default()
            self._client = resourcemanager_v3.ProjectsClient(
                credentials=self._credentials)
        return self._client

    def caller_identity(self) -> dict:
        if self._identity is None:
            member = self.member or f"gcp:{self.account}"
            self._identity = {"account": self.account, "arn": member,
                              "user_id": member}
        return self._identity
