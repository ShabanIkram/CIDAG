"""Audit trail and cleanup manifest for authorized exploitation.

Every planned and executed API action is appended to ``audit.jsonl`` with
secrets redacted. ``manifest.json`` records created/modified artifacts and the
allowlisted operations needed to undo them.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

SENSITIVE_KEYS = {
    "secretaccesskey", "sessiontoken", "password", "newpassword",
    "oldpassword", "secretstring", "secretbinary",
}

_SECRET_TEXT = re.compile(
    r"(?i)([\"']?)\b(secret[_ ]?access[_ ]?key|secret[_ ]?key|"
    r"session[_ ]?token|password)\b\1\s*[:=]\s*[\"']?[^\"'\s,}]+")


def redact(value):
    """Recursively redact secret-bearing keys."""
    if isinstance(value, dict):
        return {k: ("***REDACTED***" if str(k).lower() in SENSITIVE_KEYS
                    else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact(v) for v in value)
    return value


def redact_text(text: str) -> str:
    def _scrub(m):
        quote, key = m.group(1), m.group(2)
        return f"{quote}{key}{quote}: ***REDACTED***"
    return _SECRET_TEXT.sub(_scrub, str(text))


class AuditLog:
    def __init__(self, root: str | Path, account: str, session_arn: str,
                 technique: str | None = None):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.dir = Path(root) / f"{ts}-{account}"
        suffix = 1
        while self.dir.exists():
            suffix += 1
            self.dir = Path(root) / f"{ts}-{account}-{suffix}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.dir / "audit.jsonl"
        self.manifest_path = self.dir / "manifest.json"
        self.evidence_dir = self.dir / "evidence"
        self.evidence_dir.mkdir(exist_ok=True)
        self.secrets: dict[str, str] = {}
        self.manifest = {
            "version": 1,
            "tool": "cidag",
            "technique": technique,
            "account": str(account),
            "session_arn": str(session_arn),
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "status": "running",
            "preflight": {},
            "finding_evidence": None,
            "actions": [],
            "artifacts": [],
            "verification": {},
            "canary": None,
            "rollback": [],
            "notes": [],
            "demo": False,
        }

    def event(self, event: str, **fields) -> None:
        line = redact({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            **fields,
        })
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, default=str) + "\n")

    def plan(self, actions, preflight: dict) -> None:
        labels = [a.label for a in actions]
        self.manifest["actions"] = labels
        self.manifest["preflight"] = preflight
        self.event("plan", actions=labels, preflight=preflight)

    def artifact(self, kind: str, identifier: str, cleanup: dict | None,
                 note: str = "") -> None:
        entry = {"kind": kind, "identifier": identifier,
                 "cleanup": cleanup or {}, "note": note}
        self.manifest["artifacts"].append(entry)
        self.event("artifact", **entry)

    def secret_once(self, name: str, value: str) -> None:
        self.secrets[name] = value
        self.event("secret-issued", name=name)

    def verification(self, evidence: dict) -> None:
        self.manifest["verification"] = evidence
        self.event("verification", **evidence)

    def canary(self, evidence: dict) -> None:
        self.manifest["canary"] = evidence
        self.event("canary", **evidence)

    def rollback(self, label: str, ok: bool, detail: str = "") -> None:
        entry = {"action": label, "ok": ok, "detail": detail}
        self.manifest["rollback"].append(entry)
        self.event("rollback", **entry)

    def note(self, text: str) -> None:
        self.manifest["notes"].append(redact_text(text))
        self.event("note", text=redact_text(text))

    def action_result(self, label: str, ok: bool, detail: str = "") -> None:
        self.event("action", label=label, ok=ok, detail=detail)

    def flush(self) -> str:
        self.manifest_path.write_text(
            json.dumps(redact(self.manifest), indent=2, default=str) + "\n",
            encoding="utf-8")
        return str(self.manifest_path)

    def save(self, status: str | None = None) -> str:
        if status:
            self.manifest["status"] = status
        self.manifest["finished_at"] = datetime.now(timezone.utc).isoformat(
            timespec="seconds")
        self.manifest_path.write_text(
            json.dumps(redact(self.manifest), indent=2, default=str) + "\n",
            encoding="utf-8")
        return str(self.manifest_path)
