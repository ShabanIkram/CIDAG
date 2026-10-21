"""Plan, execute, verify, and roll back an authorized escalation technique."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from botocore.exceptions import BotoCoreError, ClientError

from .audit import AuditLog, redact
from .canary import run_canary
from .context import ExploitContext
from .findings import evidence_for
from .guard import ExploitError, GuardError
from .plan_only import PLAN_ONLY, plan_payload
from .techniques import TECHNIQUES, Technique, actions_for


@dataclass
class RunResult:
    technique: str
    status: str
    evidence: dict = field(default_factory=dict)
    canary: dict | None = None
    manifest_path: str = ""
    audit_dir: str = ""
    error: str | None = None


def list_techniques() -> list[dict]:
    rows = [{
        "id": t.id, "name": t.name, "description": t.description,
        "executable": True, "provider": t.provider,
        "preflight": list(t.preflight), "required": list(t.required),
    } for t in TECHNIQUES.values()]
    rows.extend({
        "id": t.id, "name": t.name, "description": t.description,
        "executable": False, "provider": "aws",
        "preflight": list(t.preflight),
        "required": list(t.required), "reason": t.reason,
    } for t in PLAN_ONLY.values())
    return sorted(rows, key=lambda row: row["id"])


class ExploitRunner:
    def __init__(self, session, guard, audit_root: str = ".cidag/engagements",
                 keep: bool = False, demo: bool = False, verify: bool = True,
                 findings: list[dict] | None = None,
                 allow_unproven: bool = False):
        self.session = session
        self.provider = getattr(session, "provider", "aws")
        self.guard = guard
        self.audit_root = audit_root
        self.keep = keep
        self.demo = demo
        self.verify = verify
        self.findings = findings
        self.allow_unproven = allow_unproven

    def _technique(self, technique_id: str) -> Technique:
        key = str(technique_id).upper()
        if key in PLAN_ONLY:
            raise ExploitError(
                f"{key} is plan-only: {PLAN_ONLY[key].reason} Run "
                f"'cidag exploit plan {key}' for the manual steps.")
        if key not in TECHNIQUES:
            raise ExploitError(
                f"unknown technique {technique_id!r}; run 'cidag exploit list'")
        tech = TECHNIQUES[key]
        if tech.provider != self.provider:
            raise ExploitError(
                f"{tech.id} targets {tech.provider}, but the current session "
                f"is {self.provider}; use --cloud {tech.provider}.")
        return tech

    @staticmethod
    def _check_required(tech: Technique, params: dict) -> None:
        missing = [p for p in tech.required if not params.get(p)]
        if missing:
            flags = ", ".join(f"--{p.replace('_', '-')}" for p in missing)
            raise ExploitError(f"{tech.id} requires {flags}")

    def plan(self, technique_id: str, params: dict | None = None) -> dict:
        key = str(technique_id).upper()
        if key in PLAN_ONLY:
            return plan_payload(PLAN_ONLY[key])
        identity = self.guard.authorize()
        tech = self._technique(technique_id)
        params = dict(params or {})
        self._check_required(tech, params)
        ctx = ExploitContext(self.session, identity, params)
        resources = tech.resources(ctx) if tech.resources else None
        preflight = self.guard.simulate(actions_for(tech, ctx), resources)
        try:
            actions = tech.plan(ctx)
        except (ClientError, BotoCoreError) as e:
            raise ExploitError(f"could not plan {tech.id}: {e}") from e
        except Exception as e:
            raise ExploitError(f"could not plan {tech.id}: {e}") from e
        evidence = (evidence_for(self.findings, tech.id, identity,
                                 self.allow_unproven)
                    if self.findings is not None or self.allow_unproven
                    else {"status": "not-checked"})
        return {
            "technique": tech.id,
            "name": tech.name,
            "account": str(identity["account"]),
            "caller_arn": identity["arn"],
            "preflight": preflight,
            "finding_evidence": evidence,
            "actions": [a.label for a in actions],
            "required": list(tech.required),
        }

    def run(self, technique_id: str, params: dict | None = None,
            canary: str | None = None) -> RunResult:
        tech = self._technique(technique_id)
        identity = self.guard.authorize()
        params = dict(params or {})
        self._check_required(tech, params)
        if canary and self.provider != "aws":
            raise ExploitError("--canary is AWS-only")
        if self.keep and self.provider != "aws":
            raise ExploitError(
                "--keep/cleanup is AWS-only; rollback is mandatory for "
                f"{self.provider} sessions")
        if self.keep and tech.id in {"ESC-07", "ESC-12"}:
            raise ExploitError(
                f"{tech.id} issues a credential whose secret is never written; "
                f"use a verified run with rollback instead of --keep")
        evidence = evidence_for(self.findings, tech.id, identity,
                                self.allow_unproven)

        audit = AuditLog(self.audit_root, identity["account"], identity["arn"],
                         tech.id)
        audit.manifest["demo"] = self.demo
        audit.manifest["provider"] = self.provider
        audit.manifest["finding_evidence"] = evidence
        ctx = ExploitContext(self.session, identity, params, audit)

        resources = tech.resources(ctx) if tech.resources else None
        try:
            preflight = self.guard.simulate(actions_for(tech, ctx), resources)
            actions = tech.plan(ctx)
            audit.plan(actions, preflight)
            audit.flush()
            self.guard.confirm(
                f"{tech.id} {tech.name} in account {ctx.account} as {ctx.arn}")
        except GuardError as e:
            audit.note(str(e))
            audit.save("aborted")
            raise
        except ExploitError as e:
            audit.note(str(e))
            audit.save("failed")
            raise
        except (ClientError, BotoCoreError) as e:
            audit.note(f"preflight read failed: {e}")
            audit.save("failed")
            raise ExploitError(f"{tech.id} preflight failed: {e}") from e
        except Exception as e:
            audit.note(f"planning failed: {e}")
            audit.save("failed")
            raise ExploitError(f"{tech.id} planning failed: {e}") from e

        executed = []
        canary_evidence = None
        evidence: dict = {}
        try:
            for action in actions:
                executed.append(action)
                result = action.run()
                audit.action_result(action.label, True,
                                    json.dumps(redact(result), default=str))
                if action.cleanup:
                    kind, identifier = action.artifact() if action.artifact \
                        else ("action", action.label)
                    audit.artifact(kind, identifier, action.cleanup())
                    audit.flush()
            evidence = tech.verify(ctx) if self.verify else {"status": "skipped"}
            audit.verification(evidence)
            if canary:
                canary_evidence = run_canary(ctx, canary)
                audit.canary(canary_evidence)
                if canary_evidence.get("status") != "verified":
                    audit.note(
                        f"canary {canary_evidence.get('status')}: "
                        f"{canary_evidence.get('attempts', '')}")
            status = "succeeded-kept" if self.keep else "succeeded"
        except Exception as e:
            audit.event("failure", error=str(e))
            self._rollback(executed, audit)
            audit.save("failed")
            raise ExploitError(f"{tech.id} failed: {e}") from e

        if not self.keep:
            clean = self._rollback(executed, audit)
            status = "rolled-back" if clean else "rollback-incomplete"
        path = audit.save(status)
        return RunResult(tech.id, status, evidence, canary_evidence, path,
                         str(audit.dir))

    @staticmethod
    def _rollback(executed, audit: AuditLog) -> bool:
        clean = True
        for action in reversed(executed):
            if not action.undo:
                continue
            try:
                action.undo()
                audit.rollback(action.label, True)
            except Exception as e:
                clean = False
                audit.rollback(action.label, False, str(e))
                audit.note(f"rollback failed for {action.label}: {e}")
        return clean
