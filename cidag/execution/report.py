"""Evidence-pack and portfolio demo reports for authorized exploitation."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .detections import detection_for, render_markdown as detections_markdown
from .techniques import TECHNIQUES

_ACCOUNT_RE = re.compile(r"\b(\d{4})\d{4}(\d{4})\b")


def mask_account(text: str) -> str:
    return _ACCOUNT_RE.sub(r"\1****\2", str(text))


def load_manifest(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _cleanup_lines(artifacts: list[dict]) -> list[str]:
    if not artifacts:
        return ["- No artifacts recorded."]
    lines = []
    for a in artifacts:
        op = (a.get("cleanup") or {}).get("op", "manual")
        lines.append(f"- `{a.get('kind')}` `{a.get('identifier')}` "
                     f"(cleanup: `{op}`)")
    return lines


def render_report(manifest: dict, audit_dir: str | Path, mask: bool = False) -> str:
    audit_dir = Path(audit_dir)
    done = lambda value: mask_account(value) if mask else str(value)
    lines = [
        "# CIDAG Authorized Exploitation Report", "",
        f"- **Technique:** `{manifest.get('technique')}` "
        f"({TECHNIQUES.get(str(manifest.get('technique')), None).name
           if str(manifest.get('technique')) in TECHNIQUES else 'unknown'})",
        f"- **Cloud:** `{manifest.get('provider', 'aws')}`",
        f"- **Account:** `{done(manifest.get('account', ''))}`",
        f"- **Caller:** `{done(manifest.get('session_arn', ''))}`",
        f"- **Status:** `{manifest.get('status')}`",
        f"- **Started:** {manifest.get('started_at')}",
        f"- **Finished:** {manifest.get('finished_at', '')}",
        f"- **Demo mode:** {bool(manifest.get('demo'))}",
        f"- **Audit directory:** `{audit_dir}`", "",
        "## Finding linkage", "",
    ]
    linkage = manifest.get("finding_evidence")
    if linkage:
        lines += [
            f"- **Status:** `{linkage.get('status')}`",
            f"- **Source:** `{linkage.get('source')}`",
        ]
        if linkage.get("finding_ids"):
            lines.append(f"- **Finding ids:** {', '.join(linkage['finding_ids'])}")
        if linkage.get("identities"):
            lines.append(f"- **Finding identities:** "
                         f"{', '.join(f'`{i}`' for i in linkage['identities'])}")
        if linkage.get("reason"):
            lines.append(f"- **Reason:** {linkage['reason']}")
    else:
        lines.append("- No finding evidence recorded.")
    lines += ["", "## Preflight", "",
        "```json", json.dumps(manifest.get("preflight", {}), indent=2), "```", "",
        "## Executed actions", "",
    ]
    actions = manifest.get("actions") or []
    lines += [f"{i}. {a}" for i, a in enumerate(actions, 1)] or ["- None"]
    lines += ["", "## Verification", "", "```json",
              json.dumps(manifest.get("verification", {}), indent=2), "```", ""]
    canary = manifest.get("canary")
    lines += ["## Impact canary", ""]
    if canary:
        lines += [
            f"- **Status:** `{canary.get('status')}`",
            f"- **Service:** `{canary.get('service', 'n/a')}`",
            f"- **Read back:** `{canary.get('read_back')}`",
            f"- **Cleanup:** `{canary.get('cleanup', 'n/a')}`",
            f"- **Marker SHA-256:** `{canary.get('marker_sha256')}`",
            "",
            "Only a digest is stored; no customer or canary content is included.",
            ""]
    else:
        lines += ["- Not requested.", ""]
    lines += ["## Artifacts and cleanup", ""]
    lines += _cleanup_lines(manifest.get("artifacts") or [])
    lines += ["", "## Rollback log", ""]
    rollback = manifest.get("rollback") or []
    lines += [f"- `{r.get('action')}` ok=`{r.get('ok')}` {r.get('detail', '')}"
              for r in rollback] or ["- Nothing executed."]
    notes = manifest.get("notes") or []
    if notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in notes]
    lines += ["", "## Detection coverage", "",
              detections_markdown([detection_for(manifest.get("technique"))])
              if manifest.get("technique") in TECHNIQUES else
              "No detection mapping.", ""]
    body = "\n".join(lines)
    return mask_account(body) if mask else body


def write_report(manifest_path: str | Path, out: str | Path | None = None,
                 mask: bool = False) -> str:
    manifest_path = Path(manifest_path)
    manifest = load_manifest(manifest_path)
    target = Path(out) if out else manifest_path.parent / "report.md"
    target.write_text(render_report(manifest, manifest_path.parent, mask=mask),
                      encoding="utf-8")
    return str(target)


def demo_report(root: str | Path = ".cidag/engagements",
                out: str | Path = "cidag-demo.md") -> str:
    root = Path(root)
    manifests = sorted(root.glob("*/manifest.json"))
    if not manifests:
        raise FileNotFoundError(
            f"no engagement manifests under {root}; run an authorized "
            f"technique in a sandbox account first")
    rolled_back = [m for m in manifests
                   if load_manifest(m).get("status") == "rolled-back"]
    candidates = [m for m in manifests
                  if load_manifest(m).get("status") in
                  {"succeeded", "succeeded-kept", "rolled-back"}]
    chosen = (rolled_back or candidates or manifests)[-1]
    manifest = load_manifest(chosen)
    body = render_report(manifest, chosen.parent, mask=True)
    body = body.replace(
        "# CIDAG Authorized Exploitation Report",
        "# CIDAG Portfolio Demo: Authorized Escalation with Rollback", 1)
    body += ("\n## Scope statement\n\n"
             "This run used dedicated sandbox credentials with written "
             "authorization. CIDAG simulated the permission, executed a single "
             "technique, proved administrator-equivalent access with a "
             "read-only simulator call, optionally verified impact with a "
             "self-deleting canary, and restored the account. No customer data "
             "was accessed and no persistence was installed.\n")
    target = Path(out)
    target.write_text(body, encoding="utf-8")
    return str(target)
