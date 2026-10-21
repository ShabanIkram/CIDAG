"""Apply manifest cleanup descriptors to an AWS account.

Cleanup is best-effort and allowlisted: only non-destructive removal of
CIDAG-created artifacts is supported. Apply entries in reverse order.
"""
from __future__ import annotations

import json

from .guard import ExploitError

_OPS = {
    "delete_policy_version": ("iam", "delete_policy_version"),
    "set_default_policy_version": ("iam", "set_default_policy_version"),
    "detach_role_policy": ("iam", "detach_role_policy"),
    "detach_user_policy": ("iam", "detach_user_policy"),
    "delete_role_policy": ("iam", "delete_role_policy"),
    "delete_user_policy": ("iam", "delete_user_policy"),
    "delete_access_key": ("iam", "delete_access_key"),
    "put_role_permissions_boundary": ("iam", "put_role_permissions_boundary"),
    "put_user_permissions_boundary": ("iam", "put_user_permissions_boundary"),
    "delete_role_permissions_boundary": ("iam", "delete_role_permissions_boundary"),
    "delete_user_permissions_boundary": ("iam", "delete_user_permissions_boundary"),
    "remove_user_from_group": ("iam", "remove_user_from_group"),
    "update_assume_role_policy": ("iam", "update_assume_role_policy"),
    "delete_login_profile": ("iam", "delete_login_profile"),
    "delete_function": ("lambda", "delete_function"),
}

SUPPORTED_OPS = sorted(_OPS)


def apply_cleanup(session, entry: dict) -> None:
    op = str(entry.get("op", ""))
    if op not in _OPS:
        raise ExploitError(
            f"unsupported cleanup operation {op!r}; run it manually: {entry}")
    service, method = _OPS[op]
    params = dict(entry.get("params") or {})
    if op == "update_assume_role_policy":
        doc = params.get("PolicyDocument")
        if doc is not None and not isinstance(doc, str):
            params["PolicyDocument"] = json.dumps(doc)
    try:
        getattr(session.client(service), method)(**params)
    except Exception as e:
        raise ExploitError(f"cleanup {op} failed: {e}") from e


def apply_cleanups(session, entries) -> list[dict]:
    results = []
    for entry in reversed(list(entries)):
        try:
            apply_cleanup(session, entry)
            results.append({"op": entry.get("op"), "ok": True})
        except ExploitError as e:
            results.append({"op": entry.get("op"), "ok": False, "detail": str(e)})
    return results
