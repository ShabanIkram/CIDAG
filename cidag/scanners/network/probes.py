"""Active TCP service-detection probes and UDP probes.

Everything here is read-only: each probe sends at most one request (some
services speak first), never authenticates, and is bounded by a short timeout.
Results are normalized into :class:`cidag.cve.cpe.DetectedService` so a scan
feeds the CVE engine instead of only listing open ports.
"""
from __future__ import annotations

import asyncio
import json
import re
import ssl

from ...cve.cpe import DetectedService

PROBE_TIMEOUT = 3.0
MAX_READ = 4096

# Common UDP services worth probing. UDP has no handshake, so a port only
# counts as open when the service answers a protocol-specific datagram.
DEFAULT_UDP_PORTS = [53, 123, 161, 1900, 5353]

_USER_AGENT = "cidag-probe"

# product fingerprinting from banners (HTTP headers, SSH/FTP/SMTP greetings…)
_BANNER_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"OpenSSH[_/](?P<v>[\d.p]+)", re.I), "openssh", "openbsd"),
    (re.compile(r"ProFTPD (?P<v>[\d.a-z]+)", re.I), "proftpd", "proftpd"),
    (re.compile(r"vsftpd (?P<v>[\d.]+)", re.I), "vsftpd", "vsftpd"),
    (re.compile(r"lighttpd/(?P<v>[\d.]+)", re.I), "lighttpd", "lighttpd"),
    (re.compile(r"Apache/(?P<v>[\d.]+)", re.I), "apache http server", "apache"),
    (re.compile(r"nginx/?(?P<v>[\d.]+)", re.I), "nginx", "nginx"),
    (re.compile(r"Microsoft-IIS/(?P<v>[\d.]+)", re.I), "microsoft iis", "microsoft"),
    (re.compile(r"Jetty\((?P<v>[\d.]+)", re.I), "jetty", "eclipse"),
    (re.compile(r"Redis server v=(?P<v>[\d.]+)", re.I), "redis", "redis"),
    (re.compile(r"220 (?P<v>[\d.]+)\s*FileZilla", re.I), "filezilla server", "filezilla"),
    (re.compile(r"220.*ProFTPD", re.I), "proftpd", "proftpd"),
    (re.compile(r"SIP/2.0", re.I), "asterisk", "asterisk"),
    (re.compile(r"Exim (?P<v>[\d._]+)", re.I), "exim", "exim"),
    (re.compile(r"MySQL", re.I), "mysql", "oracle"),
    (re.compile(r"PostgreSQL", re.I), "postgresql", "postgresql"),
]


def parse_banner(banner: str, port: int, proto: str = "tcp") -> DetectedService | None:
    """Turn a raw banner/response into a detected service."""
    if not banner:
        return None
    # JSON APIs (Elasticsearch, Docker) before the generic header fallback.
    if "You Know, for Search" in banner or '"cluster_name"' in banner:
        return _json_service(banner, "elasticsearch", "elastic", port, proto)
    if '"ApiVersion"' in banner and '"Version"' in banner:
        return _json_service(banner, "docker", "docker", port, proto)
    m = re.match(r"VERSION\s+(\S+)", banner.strip(), re.I)
    if m:
        return DetectedService(product="memcached", vendor="memcached",
                               version=m.group(1), port=port, proto=proto,
                               banner=banner[:300])
    if "mysql_native_password" in banner:
        return DetectedService(product="mysql", vendor="oracle", port=port,
                               proto=proto, banner=banner[:300])
    for pattern, product, vendor in _BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            version = ""
            try:
                version = match.groupdict().get("v", "") or ""
            except (IndexError, AttributeError):
                version = ""
            return DetectedService(product=product, vendor=vendor, version=version,
                                   port=port, proto=proto, banner=banner[:300])
    # HTTP header fallback
    if banner.lower().startswith("http/") or re.search(r"server:", banner, re.I):
        server = ""
        match = re.search(r"server:\s*([^\r\n]+)", banner, re.I)
        if match:
            server = match.group(1).strip()
            vm = re.search(r"([\d][\d.]+)", server)
            product = re.split(r"[/\s]", server)[0].lower() or "http"
            return DetectedService(product=product, vendor="",
                                   version=vm.group(1) if vm else "",
                                   port=port, proto=proto, banner=banner[:300])
    return DetectedService(product="unknown", version="", port=port,
                           proto=proto, banner=banner[:300])


def _json_service(text: str, product: str, vendor: str, port: int,
                  proto: str = "tcp") -> DetectedService:
    body = text.split("\r\n\r\n", 1)[-1]
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    version = ""
    if isinstance(data, dict):
        nested = data.get("version")
        if isinstance(nested, dict):
            version = str(nested.get("number") or "")
        elif isinstance(data.get("Version"), str):
            version = data["Version"]
    return DetectedService(product=product, vendor=vendor, version=version,
                           port=port, proto=proto, banner=text[:300])


# ---------------------------------------------------------------------------
# TCP probes
# ---------------------------------------------------------------------------

async def _open(host: str, port: int, tls: bool):
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return await asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)
    return await asyncio.open_connection(host, port)


async def exchange(host: str, port: int, payload: bytes = b"", *,
                   tls: bool = False, read: int = MAX_READ,
                   timeout: float = PROBE_TIMEOUT) -> bytes:
    """Send one payload and read one response, or ``b""`` on any failure."""
    try:
        reader, writer = await asyncio.wait_for(_open(host, port, tls), timeout=timeout)
    except Exception:
        return b""
    try:
        if payload:
            writer.write(payload)
            await writer.drain()
        try:
            return await asyncio.wait_for(reader.read(read), timeout=timeout)
        except Exception:
            return b""
    except Exception:
        return b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _request(path: str, host: str) -> bytes:
    return (f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
            f"User-Agent: {_USER_AGENT}\r\nAccept: */*\r\n\r\n").encode()


async def probe_http(host: str, port: int, tls: bool = False) -> DetectedService | None:
    raw = await exchange(host, port, _request("/", host), tls=tls)
    return parse_banner(raw.decode("utf-8", "replace"), port)


async def probe_elastic(host: str, port: int, tls: bool = False) -> DetectedService | None:
    raw = await exchange(host, port, _request("/", host), tls=tls)
    text = raw.decode("utf-8", "replace")
    if "You Know, for Search" not in text and '"cluster_name"' not in text:
        return None
    return _json_service(text, "elasticsearch", "elastic", port)


async def probe_docker(host: str, port: int, tls: bool = False) -> DetectedService | None:
    raw = await exchange(host, port, _request("/version", host), tls=tls)
    text = raw.decode("utf-8", "replace")
    if '"ApiVersion"' not in text and '"Version"' not in text:
        return None
    return _json_service(text, "docker", "docker", port)


async def probe_redis(host: str, port: int) -> DetectedService | None:
    raw = await exchange(host, port, b"INFO server\r\n")
    match = re.search(rb"redis_version:([^\r\n]+)", raw)
    if not match:
        return None
    return DetectedService(product="redis", vendor="redis",
                           version=match.group(1).decode("latin-1").strip(),
                           port=port, banner=raw[:300].decode("latin-1", "replace"))


async def probe_memcached(host: str, port: int) -> DetectedService | None:
    raw = await exchange(host, port, b"version\r\n")
    match = re.match(rb"VERSION\s+(\S+)", raw)
    if not match:
        return None
    return DetectedService(product="memcached", vendor="memcached",
                           version=match.group(1).decode("latin-1"),
                           port=port, banner=raw[:300].decode("latin-1", "replace"))


async def probe_mysql(host: str, port: int) -> DetectedService | None:
    """MySQL greets first: 3-byte length, 1-byte seq, protocol 10, version\\0."""
    raw = await exchange(host, port)
    if len(raw) < 6 or raw[4] != 10:
        return None
    end = raw.find(b"\x00", 5)
    version = raw[5:end if end != -1 else 36].decode("latin-1", "replace")
    return DetectedService(product="mysql", vendor="oracle", version=version,
                           port=port, banner=raw[:200].decode("latin-1", "replace"))


async def probe_postgres(host: str, port: int) -> DetectedService | None:
    """A PostgreSQL SSLRequest is answered with a single ``S`` or ``N`` byte."""
    raw = await exchange(host, port, b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
    if raw[:1] not in (b"S", b"N"):
        return None
    return DetectedService(product="postgresql", vendor="postgresql", port=port,
                           banner=f"SSLRequest answered {raw[:1].decode()}")


_HTTP_PORTS = {80, 8000, 8080, 8888, 9000}
_TLS_HTTP_PORTS = {443, 8443}
_PORT_PROBES = {
    2375: probe_docker,
    2376: lambda host, port: probe_docker(host, port, tls=True),
    3306: probe_mysql,
    5432: probe_postgres,
    6379: probe_redis,
    9200: probe_elastic,
    11211: probe_memcached,
}


async def probe_tcp(host: str, port: int) -> DetectedService | None:
    """Pick the right active probe for ``port`` (``None`` = banner-only port)."""
    probe = _PORT_PROBES.get(port)
    if probe is not None:
        return await probe(host, port)
    if port in _HTTP_PORTS:
        return await probe_http(host, port)
    if port in _TLS_HTTP_PORTS:
        return await probe_http(host, port, tls=True)
    return None


# ---------------------------------------------------------------------------
# UDP probes
# ---------------------------------------------------------------------------

def _dns_query(name: str, qtype: int, qclass: int) -> bytes:
    header = b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(bytes([len(label)]) + label.encode()
                     for label in name.split(".")) + b"\x00"
    return header + qname + qtype.to_bytes(2, "big") + qclass.to_bytes(2, "big")


# SNMPv1 GetRequest for 1.3.6.1.2.1.1.1.0 (sysDescr.0), community "public".
_SNMP_GET = bytes.fromhex(
    "302902010004067075626c6963a01c020413371337020100020100300e300c"
    "06082b060102010101000500"
)

_NTP_CLIENT = b"\x1b" + b"\x00" * 47  # LI=0 VN=3 Mode=3 (client)

_SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


def udp_payload(port: int) -> bytes:
    if port == 53:
        return _dns_query("version.bind", 16, 3)          # TXT CHAOS
    if port == 123:
        return _NTP_CLIENT
    if port == 161:
        return _SNMP_GET
    if port == 1900:
        return _SSDP_SEARCH
    if port == 5353:
        return _dns_query("_services._dns-sd._udp.local", 12, 1)  # PTR IN
    return b"\x00"  # generic reachability probe


def _skip_dns_name(raw: bytes, pos: int) -> int:
    while pos < len(raw):
        length = raw[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            return pos + 2
        pos += length + 1
    return pos


def _dns_txt(raw: bytes) -> str:
    """First TXT record from a DNS response (name compression tolerated)."""
    if len(raw) < 12:
        return ""
    questions = int.from_bytes(raw[4:6], "big")
    answers = int.from_bytes(raw[6:8], "big")
    pos = 12
    try:
        for _ in range(questions):
            pos = _skip_dns_name(raw, pos) + 4
        for _ in range(answers):
            pos = _skip_dns_name(raw, pos)
            rtype = int.from_bytes(raw[pos:pos + 2], "big")
            rdlength = int.from_bytes(raw[pos + 8:pos + 10], "big")
            rdata = raw[pos + 10:pos + 10 + rdlength]
            if rtype == 16 and rdata:
                return rdata[1:1 + rdata[0]].decode("utf-8", "replace")
            pos += 10 + rdlength
    except (IndexError, ValueError):
        return ""
    return ""


def _printable(raw: bytes, minimum: int = 6) -> str:
    runs = re.findall(rb"[\x20-\x7e]{6,}", raw)
    if not runs:
        return ""
    return max(runs, key=len).decode("latin-1", "replace")


def parse_udp_response(port: int, raw: bytes) -> DetectedService | None:
    if not raw:
        return None
    if port == 53:
        version = _dns_txt(raw)
        if version:
            match = re.search(r"\d[\w.\-]*", version)
            return DetectedService(product="bind", vendor="isc",
                                   version=match.group(0) if match else "",
                                   port=port, proto="udp", banner=version[:200])
        return DetectedService(product="dns", port=port, proto="udp",
                               banner=raw[:200].decode("latin-1", "replace"))
    if port == 123 and len(raw) >= 48:
        return DetectedService(product="ntp", vendor="ntp",
                               version=str((raw[0] >> 3) & 0x7),
                               port=port, proto="udp", banner=str(raw[:1]))
    if port == 161:
        return DetectedService(product="snmp", vendor="snmp", port=port,
                               proto="udp", banner=_printable(raw)[:200])
    if port == 1900:
        return parse_banner(raw.decode("latin-1", "replace"), port, proto="udp")
    if port == 5353:
        return DetectedService(product="mdns", port=port, proto="udp",
                               banner=_printable(raw)[:200])
    return DetectedService(product="unknown", port=port, proto="udp",
                           banner=raw[:200].decode("latin-1", "replace"))


class _DatagramWaiter(asyncio.DatagramProtocol):
    def __init__(self):
        self.future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(bytes(data))

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_exception(exc)


async def udp_exchange(host: str, port: int,
                       timeout: float = PROBE_TIMEOUT) -> bytes | None:
    """Send one UDP datagram; return the reply, or ``None`` if silent."""
    loop = asyncio.get_running_loop()
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            _DatagramWaiter, remote_addr=(host, port))
    except Exception:
        return None
    try:
        transport.sendto(udp_payload(port))
        try:
            return await asyncio.wait_for(protocol.future, timeout=timeout)
        except (asyncio.TimeoutError, OSError):
            return None
    except Exception:
        return None
    finally:
        transport.close()


async def udp_scan(hosts, ports, sem: asyncio.Semaphore,
                   timeout: float = PROBE_TIMEOUT) -> list[dict]:
    """Probe every host/port pair, returning only ports that answered."""

    async def one(host: str, port: int):
        async with sem:
            raw = await udp_exchange(host, port, timeout)
        if raw is None:
            return None
        service = parse_udp_response(port, raw)
        return {
            "host": host,
            "port": port,
            "proto": "udp",
            "banner": raw[:300].decode("latin-1", "replace").strip(),
            "service": service,
        }

    results = await asyncio.gather(*(one(h, p) for h in hosts for p in ports))
    return [r for r in results if r is not None]
