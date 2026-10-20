import asyncio

import pytest

from cidag.core.context import ScanContext
from cidag.core.scope import ScopeGuard, OutOfScopeError
from cidag.scanners.network.scanner import NetworkScanner, _expand_targets, _scan_host


def test_expand_cidr_to_hosts():
    hosts = _expand_targets(["10.0.0.0/30"], max_hosts=10, allow_private=True, log=lambda m: None)
    # /30 -> .1 and .2 (network+broadcast excluded)
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_expand_single_ip():
    assert _expand_targets(["8.8.8.8"], 10, False, lambda m: None) == ["8.8.8.8"]


def test_expand_skips_private_without_flag():
    hosts = _expand_targets(["10.0.0.0/30"], 10, allow_private=False, log=lambda m: None)
    assert hosts == []


def test_expand_refuses_oversized_range():
    with pytest.raises(OutOfScopeError):
        _expand_targets(["10.0.0.0/16"], max_hosts=1024, allow_private=True, log=lambda m: None)


def test_scanner_refuses_out_of_scope_private():
    # 10.0.0.0/24 is authorized as scope, but private without allow_private
    ctx = ScanContext(scope=ScopeGuard(networks=["10.0.0.0/24"], allow_private=False),
                      options={"targets": ["10.0.0.0/24"], "ports": [22]},
                      log=lambda m: None, offline=True)
    # expansion filters private -> no hosts -> no findings, no crash
    assert NetworkScanner().run(ctx) == []


def test_scanner_skips_without_targets():
    ctx = ScanContext(scope=ScopeGuard(), options={}, log=lambda m: None, offline=True)
    assert NetworkScanner().run(ctx) == []


def test_scanner_enforces_scope_before_scan(monkeypatch):
    # A target outside the allowlist must raise OutOfScopeError before probing.
    # We monkeypatch _run_async to detect if a scan was attempted.
    attempted = {"ran": False}

    async def fake_run(self, hosts, ports, sem, log=None):
        attempted["ran"] = True
        return []

    monkeypatch.setattr(NetworkScanner, "_run_async", fake_run)
    # Public target not in allowlist -> expansion produces the host, but
    # assert_in_scope must raise before _run_async is reached.
    ctx = ScanContext(scope=ScopeGuard(networks=["203.0.113.0/24"], allow_private=False),
                      options={"targets": ["8.8.8.8/32"], "ports": [22]},
                      log=lambda m: None, offline=True)
    with pytest.raises(OutOfScopeError):
        NetworkScanner().run(ctx)
    assert attempted["ran"] is False


def test_scan_host_bounds_concurrency_per_probe():
    # Regression: the semaphore used to be held once per host, so a large
    # --ports range fired every connect simultaneously and collapsed to 0
    # results. Probes must be bounded per connection instead.
    peak = {"now": 0, "max": 0}

    async def main():
        async def handler(reader, writer):
            peak["now"] += 1
            peak["max"] = max(peak["max"], peak["now"])
            await asyncio.sleep(0.15)
            peak["now"] -= 1
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        sem = asyncio.Semaphore(2)
        # same port probed repeatedly: with per-probe bounding, at most
        # 2 probes x (probe + banner connection overlap) are ever open
        res = await asyncio.wait_for(_scan_host("127.0.0.1", [port] * 10, sem),
                                     timeout=20)
        server.close()
        await server.wait_closed()
        return res

    res = asyncio.run(main())
    assert len(res) == 10
    assert peak["max"] <= 5
