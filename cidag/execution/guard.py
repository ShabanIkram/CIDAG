"""Authorization and preflight checks for authorized exploitation."""
from __future__ import annotations

import sys

from botocore.exceptions import BotoCoreError, ClientError

from .session import canonical_iam_arn


class ExploitError(RuntimeError):
    """Authorized exploitation failed; nothing unsafe should have persisted."""


class GuardError(ExploitError):
    """An authorization, confirmation, or preflight check refused the action."""


class AuthorizationGuard:
    """Bind every mutating run to an explicitly authorized AWS account."""

    def __init__(self, session, authorized_accounts, assume_yes: bool = False,
                 accept_unknown: bool = False, input_fn=input,
                 tty_check=None):
        self.session = session
        self.authorized_accounts = {str(a) for a in authorized_accounts or []}
        self.assume_yes = assume_yes
        self.accept_unknown = accept_unknown
        self.input_fn = input_fn
        self.tty_check = tty_check if tty_check is not None else sys.stdin.isatty

    def authorize(self) -> dict:
        if not self.authorized_accounts:
            raise GuardError(
                "refusing to mutate resources: pass --authorize-exploitation "
                "<account-id|subscription-id|project-id> for an account you "
                "have written permission to test")
        try:
            identity = self.session.caller_identity()
        except Exception as e:
            raise GuardError(
                f"could not determine caller identity: {e}") from e
        account = str(identity["account"])
        if account not in self.authorized_accounts:
            raise GuardError(
                f"caller account {account} is not in --authorize-exploitation "
                f"{sorted(self.authorized_accounts)}; aborting before any API call")
        return identity

    def confirmation_phrase(self) -> str:
        account = self.session.caller_identity()["account"]
        return f"EXECUTE {account}"

    def confirm(self, action: str) -> None:
        if self.assume_yes:
            return
        if not self.tty_check():
            raise GuardError(
                "refusing non-interactive execution; rerun in a TTY or pass "
                "--yes-i-have-written-authorization")
        phrase = self.confirmation_phrase()
        answer = self.input_fn(f"[!] {action}\n    Type '{phrase}' to continue: ")
        if answer.strip() != phrase:
            raise GuardError("confirmation phrase did not match; nothing was changed")

    def simulate(self, actions: list[str], resources: list[str] | None = None) -> dict:
        """Preflight an action set with IAM's policy simulator (read-only)."""
        actions = [a for a in actions if a]
        if getattr(self.session, "provider", "aws") != "aws":
            return {"status": "skipped",
                    "detail": f"{getattr(self.session, 'provider')} has no "
                              f"policy simulator; verify after execution",
                    "decisions": {}}
        if not actions:
            return {"status": "skipped", "decisions": {}}
        identity = self.session.caller_identity()
        iam = self.session.client("iam")
        try:
            response = iam.simulate_principal_policy(
                PolicySourceArn=canonical_iam_arn(identity["arn"]),
                ActionNames=actions,
                ResourceArns=resources or ["*"],
            )
        except (ClientError, BotoCoreError) as e:
            if self.accept_unknown:
                return {"status": "unknown", "detail": str(e), "decisions": {}}
            raise GuardError(
                f"preflight simulation unavailable ({e}); pass --accept-unknown "
                f"to proceed without simulator evidence") from e

        results = response.get("EvaluationResults", [])
        decisions = {str(r.get("EvalActionName")): str(r.get("EvalDecision", ""))
                     for r in results}
        missing = [a for a in actions if a not in decisions]
        denied = {a: d for a, d in decisions.items() if d != "allowed"}
        if denied:
            raise GuardError(
                f"preflight simulation denied {denied}; this identity cannot "
                f"perform the technique without other permissions")
        if missing:
            if self.accept_unknown:
                return {"status": "unknown", "decisions": decisions,
                        "missing": missing}
            raise GuardError(
                f"preflight simulation returned no decision for {missing}; "
                f"pass --accept-unknown to proceed")
        return {"status": "allowed", "decisions": decisions}
