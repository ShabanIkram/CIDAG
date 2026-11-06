"""Network scanner module.

Performs an asyncio TCP connect scan of authorized targets and, depending on
``--scan-mode``, active service-detection probes and UDP probes. Banners and
probe responses are fingerprinted into product/version and correlated against
the NVD mirror via :class:`cidag.cve.engine.CVEEngine`.

Authorization is non-negotiable: every target IP must be inside the
``ScopeGuard`` allowlist, checked *before* any socket is opened.
"""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Iterable

from ...core.context import ScanContext
from ...core.finding import Finding, Severity
from ...core.registry import register
from ...core.scope import OutOfScopeError
from ...cve import CVEEngine, DetectedService, NVDClient
from .probes import DEFAULT_UDP_PORTS, parse_banner, probe_tcp, udp_scan

# A compact default of the most common/impactful ports (full range via --ports).
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5984,
    6379, 8080, 8443, 9200, 11211, 27017,
]

SCAN_MODES = ("connect", "service", "udp", "all")

_BANNER_TIMEOUT = 4.0
_CONNECT_TIMEOUT = 1.2

_TCP_HIGH_PORTS = {21, 22, 23, 445, 3389}
_TCP_INFO_PORTS = {80, 443, 8080, 8443}
_UDP_HIGH_PORTS = {69, 161, 162}
_UDP_MEDIUM_PORTS = {137, 138}


async def _grab_banner(host: str, port: int) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_CONNECT_TIMEOUT)
    except Exception:
        return ""
    data = b""
    try:
        # some services (HTTP) wait for a request
        if port in (80, 8080, 8000, 443, 8443):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=_BANNER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
    except Exception:
        data = b""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return data.decode("utf-8", errors="replace").strip()


async def _scan_host(host: str, ports: Iterable[int], sem: asyncio.Semaphore) -> list[dict]:
    open_ports: list[dict] = []

    async def probe(port: int):
        async with sem:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=_CONNECT_TIMEOUT)
            except Exception:
                return
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            banner = await _grab_banner(host, port)
            open_ports.append({"host": host, "port": port, "proto": "tcp",
                               "banner": banner})

    await asyncio.gather(*(probe(p) for p in ports))
    return open_ports


def _expand_targets(cidrs: Iterable[str], max_hosts: int, allow_private: bool,
                    log, label: str = "net") -> list[str]:
    """Expand CIDR/IP allowlist entries into individual host IPs to scan.

    Private addresses are skipped unless ``allow_private`` is set (the
    ScopeGuard is the hard gate; this just avoids noisy denials). Refuses to
    build a target list larger than ``max_hosts`` so a fat-fingered /8 doesn't
    kick off a mass scan.
    """
    hosts: list[str] = []
    for entry in cidrs:
        net = ipaddress.ip_network(entry, strict=False)
        if net.num_addresses > max_hosts:
            raise OutOfScopeError(
                f"target {entry} expands to {net.num_addresses} hosts "
                f"(max-hosts={max_hosts}); narrow the range or raise --max-hosts")
        for ip in net.hosts() if net.num_addresses > 1 else [net.network_address]:
            addr = ipaddress.ip_address(str(ip))
            if addr.is_private and not allow_private:
                continue
            hosts.append(str(ip))
    hosts = sorted(set(hosts), key=lambda h: ipaddress.ip_address(h))
    if len(hosts) > max_hosts:
        raise OutOfScopeError(
            f"{len(hosts)} hosts exceed max-hosts={max_hosts}; narrow --targets or raise the cap")
    log(f"    {label}: {len(hosts)} in-scope host(s) after expansion")
    return hosts


@register("net")
class NetworkScanner:
    name = "net"
    description = ("Authorized network scan: TCP/UDP ports, active service "
                   "detection, CVE correlation")

    def run(self, context: ScanContext) -> list[Finding]:
        targets: list[str] = list(context.opt("targets", []) or [])
        if not targets:
            context.log("    net: no --targets provided; skipping")
            return []
        mode = str(context.opt("scan_mode", "connect") or "connect").lower()
        if mode not in SCAN_MODES:
            context.log(f"    net: unknown scan mode {mode!r}; using connect")
            mode = "connect"
        allow_private = bool(context.scope.allow_private)
        max_hosts = int(context.opt("max_hosts", 1024))
        # Expand the authorized CIDR allowlist into concrete hosts, then
        # re-verify every host against the guard before any socket opens.
        try:
            hosts = _expand_targets(targets, max_hosts, allow_private, context.log)
        except OutOfScopeError as e:
            context.log(f"    net: SCOPE DENIED: {e}")
            raise
        if not hosts:
            context.log("    net: no scannable hosts (private targets need --allow-private)")
            return []
        for ip in hosts:
            context.scope.assert_in_scope(ip)

        concurrency = int(context.opt("concurrency", 256))
        findings: list[Finding] = []
        services: list[DetectedService] = []

        if mode in ("connect", "service", "all"):
            ports = list(context.opt("ports", DEFAULT_PORTS) or DEFAULT_PORTS)
            context.log(f"    net: tcp {len(hosts)} host(s) x {len(ports)} ports "
                        f"[mode={mode}]")
            results = asyncio.run(self._run_async(hosts, ports,
                                                  asyncio.Semaphore(concurrency),
                                                  log=context.log))
            for r, svc in self._identify(results, concurrency, mode, context.log):
                findings.extend(self._open_port_finding(r))
                if svc and svc.product != "unknown":
                    services.append(svc)
                    if mode in ("service", "all"):
                        findings.append(self._service_finding(r, svc))
            if not results:
                context.log("    net: no open tcp ports found - if unexpected, check the "
                            "target is up (ping) and reachable from this host")

        if mode in ("udp", "all"):
            udp_ports = list(context.opt("udp_ports", DEFAULT_UDP_PORTS)
                             or DEFAULT_UDP_PORTS)
            context.log(f"    net: udp {len(hosts)} host(s) x {len(udp_ports)} ports")
            udp_results = asyncio.run(udp_scan(hosts, udp_ports,
                                               asyncio.Semaphore(concurrency)))
            for r in udp_results:
                findings.extend(self._open_port_finding(r))
                svc = r.get("service")
                if svc and svc.product != "unknown":
                    services.append(svc)
                    findings.append(self._service_finding(r, svc))
            if not udp_results:
                context.log("    net: no udp responses (silent = open|filtered, not reported)")

        # Correlate detected services against NVD mirror. Offline seeds always
        # run; live NVD queries are gated by --no-nvd / offline mode.
        if services:
            try:
                engine = CVEEngine(
                    nvd=NVDClient(verbose=False),
                    use_network=bool(context.opt("nvd_network", True)) and not context.offline,
                    log=context.log,
                )
                cve_findings = engine.correlate(services)
                findings.extend(cve_findings)
                context.log(f"    net: correlated {len(services)} service(s) -> "
                            f"{len(cve_findings)} CVE findings")
            except Exception as e:
                context.log(f"    net: CVE correlation skipped ({e})")

        context.log(f"    net: {len(findings)} findings")
        return findings

    def _identify(self, results: list[dict], concurrency: int, mode: str,
                  log) -> list[tuple[dict, DetectedService | None]]:
        """Pair open ports with a detected service (active probes in service mode)."""
        if mode not in ("service", "all"):
            return [(r, parse_banner(r["banner"], r["port"], r.get("proto", "tcp")))
                    for r in results]
        return asyncio.run(self._identify_async(results, concurrency, log))

    async def _identify_async(self, results: list[dict], concurrency: int,
                              log) -> list[tuple[dict, DetectedService | None]]:
        sem = asyncio.Semaphore(concurrency)

        async def one(r: dict):
            banner_svc = parse_banner(r["banner"], r["port"], r.get("proto", "tcp"))
            if banner_svc and banner_svc.version:
                return r, banner_svc
            try:
                async with sem:
                    detected = await probe_tcp(r["host"], r["port"])
            except Exception as e:
                if log is not None:
                    log(f"    net: probe {r['host']}:{r['port']} failed: {e!r}")
                detected = None
            return r, detected or banner_svc

        pairs = await asyncio.gather(*(one(r) for r in results))
        return list(pairs)

    async def _run_async(self, targets, ports, sem, log=None) -> list[dict]:
        tasks = [_scan_host(t, ports, sem) for t in targets]
        nested = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[dict] = []
        for item in nested:
            if isinstance(item, list):
                out.extend(item)
            elif log is not None and isinstance(item, BaseException):
                log(f"    net: host scan failed: {item!r}")
        return out

    def _port_severity(self, proto: str, port: int) -> Severity:
        if proto == "udp":
            if port in _UDP_HIGH_PORTS:
                return Severity.HIGH
            if port in _UDP_MEDIUM_PORTS:
                return Severity.MEDIUM
            return Severity.LOW
        if port in _TCP_HIGH_PORTS:
            return Severity.HIGH
        if port in _TCP_INFO_PORTS:
            return Severity.INFO
        return Severity.LOW

    def _open_port_finding(self, r: dict) -> list[Finding]:
        port = int(r["port"])
        proto = r.get("proto", "tcp")
        sev = self._port_severity(proto, port)
        banner = r.get("banner", "")
        if sev == Severity.INFO and not banner:
            return []
        target = f"{r['host']}:{port}" + ("/udp" if proto == "udp" else "")
        return [Finding(
            module="net", check_id="NET-OPEN", severity=sev,
            title=f"Open port {port}/{proto} on {r['host']}",
            target=target,
            remediation="Confirm the service is required; restrict exposure via security group/firewall.",
            evidence={"port": port, "proto": proto, "banner": banner[:300]},
        )]

    def _service_finding(self, r: dict, svc: DetectedService) -> Finding:
        proto = r.get("proto", "tcp")
        label = f"{svc.product} {svc.version}".strip()
        target = f"{r['host']}:{r['port']}" + ("/udp" if proto == "udp" else "")
        return Finding(
            module="net", check_id="NET-SERVICE", severity=Severity.INFO,
            title=f"Service identified: {label} on {r['host']}:{r['port']}/{proto}",
            target=target,
            remediation="Confirm the service/version is required and patch to the latest release.",
            evidence={"product": svc.product, "vendor": svc.vendor,
                      "version": svc.version, "port": svc.port, "proto": proto,
                      "banner": svc.banner[:300]},
        )
