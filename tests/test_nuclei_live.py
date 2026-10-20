import subprocess

from cidag.core.context import ScanContext
from cidag.core.scope import ScopeGuard
from cidag.scanners.imports import nuclei_live

SAMPLE = (
    '{"template-id":"CVE-2021-41773","info":{"name":"Apache path traversal",'
    '"severity":"critical","classification":{"cve-id":["CVE-2021-41773"]}},'
    '"matched-at":"http://127.0.0.1:8080/","host":"127.0.0.1"}\n'
    '{"template-id":"tech-detect","info":{"name":"Tech detect","severity":"info"},'
    '"matched-at":"http://127.0.0.1:8080/","host":"127.0.0.1"}\n'
)


def _ctx(log=None, allow_private=True, targets=("127.0.0.1/32",)):
    return ScanContext(
        scope=ScopeGuard(networks=list(targets), allow_private=allow_private),
        options={"targets": list(targets), "allow_private": allow_private,
                 "max_hosts": 16},
        log=log or (lambda msg: None),
    )


def test_nuclei_binary_missing_skips(monkeypatch):
    monkeypatch.setattr(nuclei_live.shutil, "which", lambda name: None)
    out = nuclei_live.NucleiScanner().run(_ctx())
    assert out == []


def test_live_bridge_parses_findings(monkeypatch):
    calls = {}

    def fake_run(cmd, **kwargs):
        calls["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=SAMPLE, stderr="")

    monkeypatch.setattr(nuclei_live.shutil, "which", lambda name: "/usr/bin/nuclei")
    monkeypatch.setattr(nuclei_live.subprocess, "run", fake_run)

    findings = nuclei_live.NucleiScanner().run(_ctx())

    assert len(findings) == 2
    assert findings[0].cve == "CVE-2021-41773"
    assert findings[0].module == "import:nuclei"
    cmd = calls["cmd"]
    assert "-no-interactsh" in cmd
    assert "-disable-redirects" in cmd
    assert "-u" in cmd and "127.0.0.1" in cmd


def test_private_target_blocked_by_scope(monkeypatch):
    called = {"run": False}
    monkeypatch.setattr(nuclei_live.shutil, "which", lambda name: "/usr/bin/nuclei")
    monkeypatch.setattr(nuclei_live.subprocess, "run",
                        lambda *a, **k: called.__setitem__("run", True))

    out = nuclei_live.NucleiScanner().run(_ctx(allow_private=False))
    assert out == []
    assert called["run"] is False


def test_nuclei_requires_targets(monkeypatch):
    monkeypatch.setattr(nuclei_live.shutil, "which", lambda name: "/usr/bin/nuclei")
    ctx = ScanContext(options={}, log=lambda m: None)
    assert nuclei_live.NucleiScanner().run(ctx) == []


def test_subprocess_failure_returns_empty(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("nuclei", 1)

    monkeypatch.setattr(nuclei_live.shutil, "which", lambda name: "/usr/bin/nuclei")
    monkeypatch.setattr(nuclei_live.subprocess, "run", boom)
    assert nuclei_live.NucleiScanner().run(_ctx()) == []
