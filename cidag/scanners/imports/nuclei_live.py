"""Live nuclei bridge: run the local nuclei binary against authorized targets.

Auto-detects ``nuclei`` on PATH when the ``nuclei`` module is selected. The
binary only ever receives hosts that already passed CIDAG's scope expansion and
ScopeGuard, redirects are disabled, and Interactsh is turned off so the scan
cannot call back to out-of-scope infrastructure.

Requires ``--targets`` (same authorization model as the ``net`` module) and a
host with the nuclei binary installed; otherwise the module logs a skip.
"""
from __future__ import annotations

import shutil
import subprocess

from ...core.context import ScanContext
from ...core.finding import Finding
from ...core.registry import register
from ...core.scope import OutOfScopeError
from ..network.scanner import _expand_targets
from .files import parse_nuclei_lines

RUN_TIMEOUT = 300


@register("nuclei")
class NucleiScanner:
    name = "nuclei"
    description = "Run the nuclei binary against authorized targets (live bridge)"

    def run(self, context: ScanContext) -> list[Finding]:
        targets = list(context.opt("targets", []) or [])
        if not targets:
            context.log("    nuclei: no --targets provided; skipping")
            return []

        binary = shutil.which("nuclei")
        if not binary:
            context.log("    nuclei: binary not found on PATH; skipping "
                        "(install nuclei or use --import-path with -format nuclei)")
            return []

        max_hosts = int(context.opt("max_hosts", 1024))
        allow_private = bool(context.opt("allow_private", False))
        try:
            hosts = _expand_targets(targets, max_hosts, allow_private,
                                    context.log, label="nuclei")
        except OutOfScopeError as e:
            context.log(f"    nuclei: SCOPE DENIED: {e}")
            raise
        if not hosts:
            context.log("    nuclei: no scannable hosts "
                        "(private targets need --allow-private)")
            return []
        for ip in hosts:
            context.scope.assert_in_scope(ip)

        cmd = [binary, "-silent", "-jsonl", "-no-interactsh", "-disable-redirects",
               "-disable-update-check", "-timeout", "10", "-retries", "1"]
        templates = context.opt("nuclei_templates")
        if templates:
            cmd += ["-t", str(templates)]
        severity = context.opt("nuclei_severity")
        if severity:
            cmd += ["-severity", str(severity)]
        for host in hosts:
            cmd += ["-u", host]

        context.log(f"    nuclei: running {len(hosts)} host(s)"
                    + (f" with templates {templates}" if templates else ""))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=RUN_TIMEOUT, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            context.log(f"    nuclei: run failed ({e}); skipping")
            return []

        findings = parse_nuclei_lines(proc.stdout or "")
        context.log(f"    nuclei: {len(findings)} finding(s) from live run")
        return findings
