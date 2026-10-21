"""Non-destructive impact proof: create, read back, and delete a canary.

The canary object contains a random marker; only its SHA-256 digest is
recorded, never the marker or any pre-existing data.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from .guard import ExploitError

SERVICES = ("secretsmanager", "s3")


def _marker() -> str:
    return f"cidag-canary-{secrets.token_urlsafe(24)}"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _secretsmanager(ctx, marker: str) -> dict:
    client = ctx.client("secretsmanager")
    name = f"cidag-canary/{ctx.account}/{secrets.token_hex(4)}"
    client.create_secret(Name=name, SecretString=marker,
                         Description="CIDAG authorized impact canary")
    result = {"service": "secretsmanager", "name": name, "read_back": False}
    try:
        got = client.get_secret_value(SecretId=name).get("SecretString")
        result["read_back"] = got == marker
    except Exception as e:
        result["read_error"] = str(e)
    finally:
        try:
            client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
            result["cleanup"] = "deleted"
        except Exception as e:
            result["cleanup"] = f"failed: {e}"
    return result


def _s3(ctx, marker: str) -> dict:
    client = ctx.client("s3", region="us-east-1")
    bucket = f"cidag-canary-{ctx.account}-{secrets.token_hex(6)}"
    key = "canary/object.txt"
    client.create_bucket(Bucket=bucket)
    result = {"service": "s3", "bucket": bucket, "key": key, "read_back": False}
    try:
        client.put_object(Bucket=bucket, Key=key, Body=marker.encode("utf-8"))
        body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        result["read_back"] = body == marker
    except Exception as e:
        result["read_error"] = str(e)
    finally:
        errors = []
        try:
            client.delete_object(Bucket=bucket, Key=key)
        except Exception as e:
            errors.append(f"object: {e}")
        try:
            client.delete_bucket(Bucket=bucket)
        except Exception as e:
            errors.append(f"bucket: {e}")
        result["cleanup"] = "deleted" if not errors else "failed: " + "; ".join(errors)
    return result


def run_canary(ctx, mode: str = "auto") -> dict:
    """Prove write access without touching customer data."""
    if mode != "auto" and mode not in SERVICES:
        raise ExploitError(f"unknown canary service {mode!r}; use auto|s3|secretsmanager")
    marker = _marker()
    attempts = []
    services = list(SERVICES) if mode == "auto" else [mode]
    for service in services:
        try:
            evidence = _secretsmanager(ctx, marker) if service == "secretsmanager" \
                else _s3(ctx, marker)
            evidence["marker_sha256"] = _digest(marker)
            evidence["at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            evidence["status"] = "verified" if evidence.get("read_back") else "unreadable"
            return evidence
        except Exception as e:
            attempts.append({"service": service, "error": str(e)})
    return {"status": "unavailable", "marker_sha256": _digest(marker),
            "attempts": attempts}
