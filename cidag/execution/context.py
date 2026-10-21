"""Exploit context passed to techniques."""
from __future__ import annotations

from dataclasses import dataclass, field

from .session import canonical_iam_arn, principal_kind, role_name_from_arn, user_name_from_arn


@dataclass
class ExploitContext:
    session: object
    identity: dict
    params: dict = field(default_factory=dict)
    audit: object | None = None

    @property
    def account(self) -> str:
        return str(self.identity["account"])

    @property
    def arn(self) -> str:
        return str(self.identity["arn"])

    @property
    def canonical_arn(self) -> str:
        return canonical_iam_arn(self.arn)

    @property
    def kind(self) -> str:
        return principal_kind(self.arn)

    def iam_name(self) -> str:
        if self.kind == "role":
            return role_name_from_arn(self.arn)
        if self.kind == "user":
            return user_name_from_arn(self.arn)
        raise ValueError(f"unsupported principal type for {self.arn}")

    def client(self, service: str, region: str | None = None):
        if region:
            return self.session.client(service, region)
        return self.session.client(service)

    def param(self, name: str, default=None):
        value = self.params.get(name, default)
        return value
