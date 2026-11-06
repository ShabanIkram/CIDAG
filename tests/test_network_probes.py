"""Active service-detection and UDP probe tests (all against localhost)."""
import asyncio
import socket
import socketserver
import threading

from cidag.core.context import ScanContext
from cidag.core.scope import ScopeGuard
from cidag.scanners.network import probes
from cidag.scanners.network.probes import (
    parse_banner, parse_udp_response, probe_docker, probe_elastic, probe_http,
    probe_memcached, probe_mysql, probe_postgres, probe_redis, udp_payload,
    udp_scan,
)
from cidag.scanners.network.scanner import NetworkScanner


class _Handler(socketserver.BaseRequestHandler):
    response = b""
    speak_first = False

    def handle(self):
        try:
            if not self.speak_first:
                self.request.recv(1024)
            self.request.sendall(self.response)
        except OSError:
            pass


def _serve_tcp(response: bytes, speak_first: bool = False):
    """Threaded TCP server; serves any number of connections on localhost."""
    class Handler(_Handler):
        pass

    Handler.response = response
    Handler.speak_first = speak_first
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _stop(server):
    server.shutdown()
    server.server_close()


def _probe_tcp_banner(probe, response, speak_first: bool = False, **kwargs):
    server = _serve_tcp(response, speak_first)
    try:
        return asyncio.run(probe("127.0.0.1", server.server_address[1], **kwargs))
    finally:
        _stop(server)


# ---------------------------------------------------------------------------
# TCP probes
# ---------------------------------------------------------------------------

def test_http_probe_fingerprints_server_header():
    svc = _probe_tcp_banner(
        probe_http, b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\nhi")
    assert (svc.product, svc.version) == ("nginx", "1.18.0")


def test_elasticsearch_probe_parses_version_json():
    body = (b'{"name":"n1","cluster_name":"c","tagline":"You Know, for Search",'
            b'"version":{"number":"1.4.2"}}')
    svc = _probe_tcp_banner(
        probe_elastic, b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body)
    assert (svc.product, svc.version) == ("elasticsearch", "1.4.2")


def test_docker_probe_parses_engine_version():
    body = b'{"Version":"18.09.1","ApiVersion":"1.39","Os":"linux"}'
    svc = _probe_tcp_banner(
        probe_docker, b"HTTP/1.1 200 OK\r\n\r\n" + body)
    assert (svc.product, svc.version) == ("docker", "18.09.1")


def test_redis_probe_reads_info_version():
    svc = _probe_tcp_banner(
        probe_redis, b"$40\r\n# Server\r\nredis_version:6.0.9\r\ntcp_port:6379\r\n")
    assert (svc.product, svc.version) == ("redis", "6.0.9")


def test_memcached_probe_reads_version():
    svc = _probe_tcp_banner(probe_memcached, b"VERSION 1.6.9\r\n")
    assert (svc.product, svc.version) == ("memcached", "1.6.9")


def _mysql_greeting(version: bytes) -> bytes:
    payload = b"\x0a" + version + b"\x00" + b"\x00" * 30 + b"mysql_native_password\x00"
    return len(payload).to_bytes(3, "big") + b"\x00" + payload


def test_mysql_probe_parses_handshake():
    svc = _probe_tcp_banner(probe_mysql, _mysql_greeting(b"5.7.14"), speak_first=True)
    assert (svc.product, svc.version) == ("mysql", "5.7.14")


def test_postgres_probe_accepts_sslrequest():
    svc = _probe_tcp_banner(probe_postgres, b"S")
    assert svc.product == "postgresql"


def test_parse_banner_covers_lighttpd_and_exim():
    assert parse_banner("lighttpd/1.4.45", 80).product == "lighttpd"
    exim = parse_banner("220 mail.example.com ESMTP Exim 4.90_1", 25)
    assert (exim.product, exim.version) == ("exim", "4.90_1")


def test_parse_banner_returns_none_for_empty():
    assert parse_banner("", 80) is None


# ---------------------------------------------------------------------------
# UDP probes
# ---------------------------------------------------------------------------

def _dns_txt_response(txt: bytes) -> bytes:
    query = udp_payload(53)
    header = query[:2] + b"\x85\x80" + b"\x00\x01\x00\x01" + query[8:12]
    question = query[12:]
    rdata = bytes([len(txt)]) + txt
    answer = (b"\xc0\x0c" + b"\x00\x10" + b"\x00\x03" + b"\x00\x00\x00\x00"
              + len(rdata).to_bytes(2, "big") + rdata)
    return header + question + answer


def test_parse_udp_dns_txt_extracts_bind_version():
    svc = parse_udp_response(53, _dns_txt_response(b"9.11.3-1ubuntu1.2"))
    assert (svc.product, svc.version, svc.proto) == ("bind", "9.11.3-1ubuntu1.2", "udp")


def test_parse_udp_ntp_version():
    svc = parse_udp_response(123, b"\x24" + b"\x00" * 47)
    assert (svc.product, svc.version) == ("ntp", "4")


def test_parse_udp_ssdp_server_header():
    svc = parse_udp_response(
        1900, b"HTTP/1.1 200 OK\r\nSERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/1.9\r\n\r\n")
    assert svc.proto == "udp" and svc.product


def test_udp_scan_reports_responders_only():
    async def main():
        received = asyncio.Event()

        class Responder(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                received.set()
                self.transport.sendto(b"\x00" * 48, addr)

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            Responder, local_addr=("127.0.0.1", 0))
        port = transport.get_extra_info("sockname")[1]
        silent = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        silent_port = silent.sockets[0].getsockname()[1]
        silent.close()
        await silent.wait_closed()
        try:
            results = await udp_scan(["127.0.0.1"], [port, silent_port],
                                     asyncio.Semaphore(4), timeout=0.3)
        finally:
            transport.close()
        return port, results

    port, results = asyncio.run(main())
    assert [r["port"] for r in results] == [port]
    assert results[0]["proto"] == "udp"


# ---------------------------------------------------------------------------
# scanner modes
# ---------------------------------------------------------------------------

def _ctx(targets, options, allow_private=True):
    return ScanContext(
        scope=ScopeGuard(networks=targets, allow_private=allow_private),
        options={"targets": targets, **options},
        log=lambda m: None, offline=True,
    )


def test_scanner_udp_mode_emits_net_open_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        sock.settimeout(0.1)
        while not stop.is_set():
            try:
                _, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                return
            sock.sendto(b"\x00" * 48, addr)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        findings = NetworkScanner().run(
            _ctx(["127.0.0.1/32"], {"scan_mode": "udp", "udp_ports": [port]}))
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()
    open_udp = [f for f in findings if f.check_id == "NET-OPEN"]
    assert open_udp and open_udp[0].target.endswith("/udp")


def test_scanner_connect_mode_does_not_probe_udp(monkeypatch):
    called = {"udp": False}

    async def fake_udp(*args, **kwargs):
        called["udp"] = True
        return []

    monkeypatch.setattr("cidag.scanners.network.scanner.udp_scan", fake_udp)
    NetworkScanner().run(_ctx(["127.0.0.1/32"], {"scan_mode": "connect",
                                                 "ports": [1]}))
    assert called["udp"] is False


def test_scanner_service_mode_identifies_service_and_correlates(monkeypatch):
    server = _serve_tcp(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n")
    port = server.server_address[1]
    # Teach the dispatcher to use the HTTP probe on this ephemeral port.
    monkeypatch.setitem(probes._PORT_PROBES, port, probes.probe_http)
    # The port is not in the HTTP set, so banner grab waits for the timeout.
    monkeypatch.setattr("cidag.scanners.network.scanner._BANNER_TIMEOUT", 0.2)
    try:
        findings = NetworkScanner().run(
            _ctx(["127.0.0.1/32"], {"scan_mode": "service", "ports": [port]}))
    finally:
        _stop(server)

    checks = {f.check_id for f in findings}
    assert "NET-SERVICE" in checks
    # service detection feeds the offline seed engine end to end
    assert "CVE-2021-23017" in checks


def test_scanner_rejects_unknown_mode_gracefully():
    findings = NetworkScanner().run(
        _ctx(["127.0.0.1/32"], {"scan_mode": "bogus", "ports": [1]}))
    assert findings == []
