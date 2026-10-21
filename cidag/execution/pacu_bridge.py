"""Orchestrate an existing Pacu session without touching its credentials.

CIDAG never imports Pacu internals, never passes keys, and never invokes modules
outside an explicit read-only allowlist. The Pacu session must already be
configured by the operator; CIDAG verifies its account matches the engagement.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess

from .audit import redact_text
from .guard import ExploitError

SAFE_MODULES = frozenset({
    "iam__enum_users_roles_policies_groups",
    "iam__enum_permissions",
    "iam__privesc_scan",
    "sts__assume_role",
    "s3__enum",
    "ec2__enum",
    "lambda__enum",
})

_SESSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_ACCOUNT_RE = re.compile(r'"Account"\s*:\s*"(\d{12})"')


class PacuBridgeError(ExploitError):
    pass


def find_pacu() -> str | None:
    return shutil.which("pacu")


def parse_whoami(output: str) -> dict:
    text = str(output or "")
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        try:
            data = json.loads(text[start:end + 1])
            if isinstance(data, dict) and data.get("Account"):
                return {"account": str(data["Account"]),
                        "arn": str(data.get("Arn", "")),
                        "user_id": str(data.get("UserId", ""))}
        except json.JSONDecodeError:
            pass
    match = _ACCOUNT_RE.search(text)
    if match:
        return {"account": match.group(1), "arn": "", "user_id": ""}
    raise PacuBridgeError("could not parse Pacu --whoami output; verify the session")


class PacuBridge:
    def __init__(self, pacu_path: str | None = None, runner=None,
                 timeout: int = 900):
        self.pacu_path = pacu_path or find_pacu()
        self.runner = runner or subprocess.run
        self.timeout = timeout

    def _require(self) -> str:
        if not self.pacu_path:
            raise PacuBridgeError(
                "pacu executable not found; install Pacu and configure a session "
                "before using the bridge")
        return self.pacu_path

    @staticmethod
    def _validate_session(session: str) -> str:
        if not _SESSION_RE.match(session or ""):
            raise PacuBridgeError(
                "invalid Pacu session name; use letters, digits, dot, dash, underscore")
        return session

    def _exec(self, argv: list[str]) -> str:
        try:
            proc = self.runner(argv, capture_output=True, text=True,
                               timeout=self.timeout, shell=False)
        except subprocess.TimeoutExpired as e:
            raise PacuBridgeError(f"Pacu timed out after {self.timeout}s") from e
        output = redact_text((proc.stdout or "") + (proc.stderr or ""))
        if proc.returncode != 0:
            raise PacuBridgeError(
                f"Pacu exited {proc.returncode}: {output[-2000:]}")
        return output

    def whoami(self, session: str) -> dict:
        pacu = self._require()
        session = self._validate_session(session)
        output = self._exec([pacu, "--session", session, "--whoami"])
        identity = parse_whoami(output)
        identity["session"] = session
        return identity

    def run_module(self, session: str, module: str, module_args: str = "",
                   expected_account: str | None = None) -> dict:
        pacu = self._require()
        session = self._validate_session(session)
        if module not in SAFE_MODULES:
            raise PacuBridgeError(
                f"module {module!r} is not in the bridge allowlist "
                f"({', '.join(sorted(SAFE_MODULES))})")
        if module_args and ("\x00" in module_args or "\n" in module_args):
            raise PacuBridgeError("module arguments must be a single line")
        if len(module_args) > 2000:
            raise PacuBridgeError("module arguments exceed 2000 characters")

        identity = self.whoami(session)
        if expected_account and str(identity["account"]) != str(expected_account):
            raise PacuBridgeError(
                f"Pacu session account {identity['account']} does not match "
                f"authorized account {expected_account}")

        argv = [pacu, "--session", session, "--module-name", module, "--exec"]
        if module_args:
            argv.extend(["--module-args", module_args])
        output = self._exec(argv)
        return {
            "session": session,
            "module": module,
            "account": identity["account"],
            "arn": identity.get("arn", ""),
            "output": output[-20000:],
        }
