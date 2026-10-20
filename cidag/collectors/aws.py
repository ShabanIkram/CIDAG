import json

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .base import BaseCollector, CloudCollectionError, CloudCredentialsError


class AwsCredentialsError(CloudCredentialsError):
    """Live collection requested but no AWS credentials resolve."""


class AwsCollectionError(CloudCollectionError):
    """A live AWS collector failed.

    Continuing with a partial/empty inventory would silently turn "we could not
    query" into findings like "No CloudTrail configured" -- fabricated positives.
    """


def verify_credentials(profile: str | None = None, region: str = "us-east-1"):
    """Resolve credentials before any live collection.

    Returns the boto3 Session or raises AwsCredentialsError. Credential
    resolution only (SSO providers may refresh a token); no AWS data API call.
    """
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        creds = session.get_credentials()
    except BotoCoreError as e:  # ProfileNotFound, PartialCredentialsError, ...
        raise AwsCredentialsError(str(e)) from e
    if creds is None:
        where = f"profile {profile!r}" if profile else "the default credential chain"
        hint = f"aws sso login --profile {profile}" if profile else "aws configure"
        raise AwsCredentialsError(
            f"no AWS credentials found via {where}. Run `{hint}` or export "
            f"AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.")
    return session


def _paginate(client, method_name: str, result_key: str, **kwargs):
    paginator = client.get_paginator(method_name)
    for page in paginator.paginate(**kwargs):
        yield from page[result_key]


class AwsCollector(BaseCollector):
    def __init__(self, profile: str | None = None, region: str = "us-east-1",
                 session=None):
        self.profile = profile
        self.region = region
        self.session = session

    def collect(self) -> dict:
        session = self.session or boto3.Session(profile_name=self.profile,
                                                region_name=self.region)
        iam = session.client("iam")
        identities: list[dict] = []
        policies: list[dict] = []

        identities.extend(self._collect_users(iam))
        identities.extend(self._collect_roles(iam))
        identities.extend(self._collect_groups(iam))
        policies.extend(self._collect_policies(iam, identities))
        self._collect_boundary_policies(iam, identities, policies)

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
            "scps": self._collect_scps(session, account_id),
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
                entry = {
                    "type": "user",
                    "name": u["UserName"],
                    "arn": u["Arn"],
                    "attached_policies": attached,
                    "inline_policies": inline,
                    "groups": [g["Arn"] for g in groups],
                }
                boundary = (u.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
                if boundary:
                    entry["boundary_policy"] = boundary
                out.append(entry)
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
                entry = {
                    "type": "role",
                    "name": r["RoleName"],
                    "arn": r["Arn"],
                    "trust_policy": trust,
                    "attached_policies": attached,
                    "inline_policies": inline,
                }
                boundary = (r.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
                if boundary:
                    entry["boundary_policy"] = boundary
                out.append(entry)
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

    def _collect_boundary_policies(self, iam, identities: list[dict],
                                   policies: list[dict]) -> None:
        """Fetch managed policies used as permissions boundaries."""
        known = {p["arn"] for p in policies}
        for ident in identities:
            arn = ident.get("boundary_policy")
            if not arn or arn in known:
                continue
            try:
                policy = iam.get_policy(PolicyArn=arn)["Policy"]
                doc = iam.get_policy_version(
                    PolicyArn=arn,
                    VersionId=policy["DefaultVersionId"])["PolicyVersion"]["Document"]
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                policies.append({"arn": arn, "name": policy["PolicyName"],
                                 "statements": statements})
                known.add(arn)
            except (ClientError, BotoCoreError) as e:
                print(f"[!] boundary policy {arn}: {e}")

    def _collect_scps(self, session, account_id: str) -> list[dict]:
        """Collect SCPs attached to the account and its OU/root ancestors."""
        if not account_id or account_id == "unknown":
            return []
        try:
            org = session.client("organizations")
            pending = [account_id]
            seen_targets: set[str] = set()
            seen_policies: set[str] = set()
            scps: list[dict] = []
            while pending:
                target = pending.pop()
                if target in seen_targets:
                    continue
                seen_targets.add(target)
                for pol in _paginate(org, "list_policies_for_target", "Policies",
                                     TargetId=target,
                                     Filter="SERVICE_CONTROL_POLICY"):
                    if pol["Id"] in seen_policies:
                        continue
                    seen_policies.add(pol["Id"])
                    content = org.describe_policy(PolicyId=pol["Id"])["Policy"]["Content"]
                    doc = json.loads(content) if isinstance(content, str) else content
                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    scps.append({"arn": pol["Arn"], "name": pol["Name"],
                                 "statements": statements})
                for parent in org.list_parents(TargetId=target).get("Parents", []):
                    pending.append(parent["Id"])
            return scps
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "AWSOrganizationsNotInUseException":
                return []
            print(f"[!] scps: unavailable ({code or e}); SCP evaluation skipped")
            return []
        except BotoCoreError as e:
            print(f"[!] scps: unavailable ({e}); SCP evaluation skipped")
            return []

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
