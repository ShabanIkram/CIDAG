"""Network scanner module.

Performs an asyncio TCP connect scan of authorized targets, grabs service
banners, fingerprints product/version, and correlates them against the NVD
mirror via :class:`cidag.cve.engine.CVEEngine`.

Authorization is non-negotiable: every target IP must be inside the
``ScopeGuard`` allowlist, checked *before* any socket is opened.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
from typing import Iterable

from ...core.context import ScanContext
from ...core.finding import Finding, Severity
from ...core.registry import register
from ...core.scope import OutOfScopeError
from ...cve import CVEEngine, DetectedService, NVDClient

# A compact default of the most common/impactful ports (full range via --ports).
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5984,
    6379, 8080, 8443, 9200, 11211, 27017,
]

_BANNER_TIMEOUT = 4.0
_CONNECT_TIMEOUT = 1.2

# product fingerprinting from banners
_BANNER_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"OpenSSH[_/](?P<v>[\d.p]+)", re.I), "openssh", "openbsd"),
    (re.compile(r"ProFTPD (?P<v>[\d.a-z]+)", re.I), "proftpd", "proftpd"),
    (re.compile(r"vsftpd (?P<v>[\d.]+)", re.I), "vsftpd", "vsftpd"),
    (re.compile(r"Apache/(?P<v>[\d.]+)", re.I), "apache http server", "apache"),
    (re.compile(r"nginx/?(?P<v>[\d.]+)", re.I), "nginx", "nginx"),
    (re.compile(r"Microsoft-IIS/(?P<v>[\d.]+)", re.I), "microsoft iis", "microsoft"),
    (re.compile(r"Redis server v=(?P<v>[\d.]+)", re.I), "redis", "redis"),
    (re.compile(r"220 (?P<v>[\d.]+)\s*FileZilla", re.I), "filezilla server", "filezilla"),
    (re.compile(r"220.*ProFTPD", re.I), "proftpd", "proftpd"),
    (re.compile(r"SIP/2.0", re.I), "asterisk", "asterisk"),
    (re.compile(r"MySQL", re.I), "mysql", "oracle"),
    (re.compile(r"PostgreSQL", re.I), "postgresql", "postgresql"),
]


def _parse_banner(banner: str, port: int) -> DetectedService | None:
    for pattern, product, vendor in _BANNER_PATTERNS:
        m = pattern.search(banner)
        if m:
            version = ""
            try:
                version = m.groupdict().get("v", "") or ""
            except (IndexError, AttributeError):
                version = ""
            return DetectedService(product=product, vendor=vendor, version=version,
                                   port=port, banner=banner)
    # HTTP header fallback
    if banner.lower().startswith("http/") or re.search(r"server:", banner, re.I):
        server = ""
        m = re.search(r"server:\s*([^\r\n]+)", banner, re.I)
        if m:
            server = m.group(1).strip()
            vm = re.search(r"([\d][\d.]+)", server)
            product = re.split(r"[/\s]", server)[0].lower() or "http"
            return DetectedService(product=product, vendor="", version=vm.group(1) if vm else "",
                                   port=port, banner=banner)
    if banner:
        return DetectedService(product="unknown", version="", port=port, banner=banner)
    return None


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
    async with sem:
        async def probe(port: int):
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
            open_ports.append({"host": host, "port": port, "banner": banner})

        await asyncio.gather(*(probe(p) for p in ports))
    return open_ports


def _expand_targets(cidrs: Iterable[str], max_hosts: int, allow_private: bool,
                    log) -> list[str]:
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
    log(f"    net: {len(hosts)} in-scope host(s) after expansion")
    return hosts


@register("net")
class NetworkScanner:
    name = "net"
    description = "Authorized network port scan + banner grab + CVE correlation"

    def run(self, context: ScanContext) -> list[Finding]:
        targets: list[str] = list(context.opt("targets", []) or [])
        if not targets:
            context.log("    net: no --targets provided; skipping")
            return []
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

        ports = list(context.opt("ports", DEFAULT_PORTS) or DEFAULT_PORTS)
        concurrency = int(context.opt("concurrency", 256))

        context.log(f"    net: scanning {len(hosts)} host(s) x {len(ports)} ports")

        sem = asyncio.Semaphore(concurrency)
        results = asyncio.run(self._run_async(hosts, ports, sem))

        findings: list[Finding] = []
        services: list[DetectedService] = []
        for r in results:
            findings.extend(self._open_port_finding(r))
            svc = _parse_banner(r["banner"], r["port"])
            if svc:
                services.append(svc)

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

        context.log(f"    net: {len(results)} open ports -> {len(findings)} findings")
        return findings

    async def _run_async(self, targets, ports, sem) -> list[dict]:
        tasks = [_scan_host(t, ports, sem) for t in targets]
        nested = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[dict] = []
        for item in nested:
            if isinstance(item, list):
                out.extend(item)
        return out

    def _open_port_finding(self, r: dict) -> list[Finding]:
        port = r["port"]
        if port in (22, 3389, 21, 23, 445):
            sev = Severity.HIGH
        elif port in (80, 443, 8080, 8443):
            sev = Severity.INFO
        else:
            sev = Severity.LOW
        if sev == Severity.INFO and not r["banner"]:
            return []
        return [Finding(
            module="net", check_id="NET-OPEN", severity=sev,
            title=f"Open port {port}/tcp on {r['host']}",
            target=f"{r['host']}:{port}",
            remediation="Confirm the service is required; restrict exposure via security group/firewall.",
            evidence={"port": port, "banner": r["banner"][:300]},
        )]
