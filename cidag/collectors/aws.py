import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .base import BaseCollector


def _paginate(client, method_name: str, result_key: str, **kwargs):
    paginator = client.get_paginator(method_name)
    for page in paginator.paginate(**kwargs):
        yield from page[result_key]


class AwsCollector(BaseCollector):
    def __init__(self, profile: str | None = None, region: str = "us-east-1"):
        self.profile = profile
        self.region = region

    def collect(self) -> dict:
        session = boto3.Session(profile_name=self.profile, region_name=self.region)
        iam = session.client("iam")
        identities: list[dict] = []
        policies: list[dict] = []

        identities.extend(self._collect_users(iam))
        identities.extend(self._collect_roles(iam))
        identities.extend(self._collect_groups(iam))
        policies.extend(self._collect_policies(iam, identities))

        try:
            account_id = session.client("sts").get_caller_identity().get("Account", "unknown")
        except (ClientError, BotoCoreError):
            account_id = "unknown"

        return {
            "account_id": account_id,
            "region": self.region,
            "identities": identities,
            "policies": policies,
            "resources": [],
        }

    def _collect_users(self, iam) -> list[dict]:
        out = []
        try:
            for u in _paginate(iam, "list_users", "Users"):
                attached = [p["PolicyArn"] for p in _paginate(
                    iam, "list_attached_user_policies", "AttachedPolicies", UserName=u["UserName"])]
                inline = [f"{u['Arn']}:inline/{p}" for p in
                          iam.list_user_policies(UserName=u["UserName"])["PolicyNames"]]
                groups = iam.list_groups_for_user(UserName=u["UserName"])["Groups"]
                out.append({
                    "type": "user",
                    "name": u["UserName"],
                    "arn": u["Arn"],
                    "attached_policies": attached,
                    "inline_policies": inline,
                    "groups": [g["Arn"] for g in groups],
                })
        except (ClientError, BotoCoreError) as e:
            print(f"[!] users: {e}")
        return out

    def _collect_roles(self, iam) -> list[dict]:
        out = []
        try:
            for r in _paginate(iam, "list_roles", "Roles"):
                attached = [p["PolicyArn"] for p in _paginate(
                    iam, "list_attached_role_policies", "AttachedPolicies", RoleName=r["RoleName"])]
                trust = iam.get_role(RoleName=r["RoleName"])["Role"]["AssumeRolePolicyDocument"]
                inline = [f"{r['Arn']}:inline/{p}" for p in
                          iam.list_role_policies(RoleName=r["RoleName"])["PolicyNames"]]
                out.append({
                    "type": "role",
                    "name": r["RoleName"],
                    "arn": r["Arn"],
                    "trust_policy": trust,
                    "attached_policies": attached,
                    "inline_policies": inline,
                })
        except (ClientError, BotoCoreError) as e:
            print(f"[!] roles: {e}")
        return out

    def _collect_groups(self, iam) -> list[dict]:
        out = []
        try:
            for grp in _paginate(iam, "list_groups", "Groups"):
                attached = [p["PolicyArn"] for p in _paginate(
                    iam, "list_attached_group_policies", "AttachedPolicies", GroupName=grp["GroupName"])]
                out.append({
                    "type": "group",
                    "name": grp["GroupName"],
                    "arn": grp["Arn"],
                    "attached_policies": attached,
                })
        except (ClientError, BotoCoreError) as e:
            print(f"[!] groups: {e}")
        return out

    def _collect_policies(self, iam, identities: list[dict]) -> list[dict]:
        out = []
        try:
            for p in _paginate(iam, "list_policies", "Policies", Scope="Local"):
                doc = iam.get_policy_version(
                    PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                out.append({"arn": p["Arn"], "name": p["PolicyName"], "statements": statements})
        except (ClientError, BotoCoreError) as e:
            print(f"[!] policies: {e}")

        for ident in identities:
            for inline_arn in ident.get("inline_policies", []):
                data = self._get_inline_statement(iam, ident, inline_arn)
                if data:
                    out.append(data)
        return out

    def _get_inline_statement(self, iam, ident: dict, inline_arn: str):
        name = inline_arn.split("/")[-1]
        try:
            if ident["type"] == "user":
                doc = iam.get_user_policy(UserName=ident["name"], PolicyName=name)["PolicyDocument"]
            elif ident["type"] == "role":
                doc = iam.get_role_policy(RoleName=ident["name"], PolicyName=name)["PolicyDocument"]
            else:
                doc = iam.get_group_policy(GroupName=ident["name"], PolicyName=name)["PolicyDocument"]
        except (ClientError, BotoCoreError):
            return None
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        return {"arn": inline_arn, "name": name, "statements": statements}
