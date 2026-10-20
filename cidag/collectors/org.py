"""AWS Organizations helpers for multi-account scans.

The audit account calls ``organizations:ListAccounts`` and then assumes a role
in each active member account. Read-only permissions are still required inside
every member account, exactly as for a single-account ``--live`` scan.
"""
from __future__ import annotations

DEFAULT_ROLE = "OrganizationAccountAccessRole"


def list_accounts(session) -> list[dict]:
    """Return active accounts as [{"id": ..., "name": ...}], paginated."""
    org = session.client("organizations")
    accounts: list[dict] = []
    paginator = org.get_paginator("list_accounts")
    for page in paginator.paginate():
        for acct in page.get("Accounts", []):
            if acct.get("Status") != "ACTIVE":
                continue
            accounts.append({"id": acct["Id"], "name": acct.get("Name", acct["Id"])})
    return accounts


def assume_role_session(base_session, account_id: str,
                        role_name: str = DEFAULT_ROLE, region: str = "us-east-1"):
    """Assume ``role_name`` in ``account_id`` and return a boto3 Session."""
    import boto3

    sts = base_session.client("sts")
    response = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
        RoleSessionName=f"cidag-{account_id}",
    )
    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
