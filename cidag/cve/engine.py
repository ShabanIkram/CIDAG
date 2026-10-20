"""CVE correlation engine.

Turns detected services (product + version, from the network scanner, package
inventory, or cloud imports) into ``Finding`` objects carrying real CVE ids by
matching against the local NVD mirror (see :mod:`cidag.cve.nvd`).

Pipeline::

    DetectedService  --to_cpe()-->  CPE  --NVD search-->  CVEs  --> Findings

The NVD mirror is the source of truth for "every CVE" -- it is queried live or
served from the offline SQLite cache. A tiny curated seed list of legendary
vulnerabilities is also included so the engine still demonstrates value with a
cold cache and no network.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.finding import Finding, Severity
from .cpe import DetectedService, match_cpe, version_gte, version_lt, version_lte
from .nvd import CVE, NVDClient

# NVD severity string -> our Severity
_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.INFO,
    "UNKNOWN": Severity.MEDIUM,
}


@dataclass(frozen=True)
class SeedRule:
    """Curated offline fallback for a handful of famous vulnerabilities."""

    product: str
    affected_below: str            # vulnerable if version < affected_below
    cve_id: str
    severity: Severity
    title: str
    remediation: str
    affected_from: str = ""        # inclusive lower bound ("" = no bound)


# Small, famous, offline-demo seed set. The NVD mirror is the real database;
# this only guarantees the engine is useful on a cold cache.
#
# Both bounds matter: without affected_from an old release reports a CVE that
# never applied to it (Apache 2.2.8 "CVE-2021-41773", OpenSSH 4.7p1
# "CVE-2016-0777") -- a false positive on every legacy box you scan.
SEED_RULES: list[SeedRule] = [
    SeedRule("apache http server", "2.4.51", "CVE-2021-41773", Severity.CRITICAL,
             "Apache path traversal / RCE (2.4.49-2.4.50)",
             "Upgrade Apache httpd to 2.4.51 or later", affected_from="2.4.49"),
    SeedRule("apache http server", "2.4.51", "CVE-2021-42013", Severity.CRITICAL,
             "Apache path traversal / RCE follow-up",
             "Upgrade Apache httpd to 2.4.51 or later", affected_from="2.4.49"),
    SeedRule("openssh", "7.4", "CVE-2016-0777", Severity.HIGH,
             "OpenSSH client info leak / command injection (roaming)",
             "Upgrade OpenSSH; disable roaming client", affected_from="5.4"),
    SeedRule("proftpd", "1.3.6", "CVE-2019-12815", Severity.CRITICAL,
             "ProFTPD mod_copy arbitrary command execution",
             "Upgrade ProFTPD to 1.3.6 or later / remove mod_copy",
             affected_from="1.3.5"),
    SeedRule("vsftpd", "2.3.5", "CVE-2011-2523", Severity.CRITICAL,
             "vsftpd 2.3.4 backdoor (smiley face)",
             "Reinstall genuine vsftpd; the backdoored build is not upstream",
             affected_from="2.3.4"),
    SeedRule("redis", "6.2.7", "CVE-2022-0543", Severity.CRITICAL,
             "Redis Lua sandbox escape / RCE (Debian/Ubuntu)",
             "Upgrade Redis; restrict network exposure", affected_from="4.0"),
    SeedRule("openssl", "1.0.2k", "CVE-2016-2107", Severity.HIGH,
             "OpenSSL padding oracle (CVE-2016-2107)",
             "Upgrade OpenSSL to a patched release", affected_from="1.0.1"),
]


def _seed_matches(detected: DetectedService) -> list[Finding]:
    out: list[Finding] = []
    if not detected.version:
        return out
    for rule in SEED_RULES:
        if not _similar(rule.product, detected.product):
            continue
        if not version_lt(detected.version, rule.affected_below):
            continue
        if rule.affected_from and not version_gte(detected.version, rule.affected_from):
            continue
        loc = f"{detected.product}:{detected.version}"
        if detected.port:
            loc = f"{detected.product}:{detected.version} (:{detected.port})"
        out.append(Finding(
            module="cve",
            check_id=rule.cve_id,
            severity=rule.severity,
            title=f"{rule.title} — {loc}",
            target=loc,
            remediation=rule.remediation,
            cve=rule.cve_id,
            evidence={
                "product": detected.product,
                "version": detected.version,
                "port": detected.port,
                "banner": detected.banner[:200],
                "source": "seed-rules",
            },
        ))
    return out


def _similar(a: str, b: str) -> bool:
    a, b = a.lower(), b.lower()
    return a == b or a in b or b in a


def _cve_to_finding(cve: CVE, detected: DetectedService) -> Finding:
    loc = f"{detected.product}:{detected.version or '?'}"
    if detected.port:
        loc += f" (:{detected.port})"
    return Finding(
        module="cve",
        check_id=cve.cve_id,
        severity=_SEV.get(cve.severity, Severity.MEDIUM),
        title=f"{cve.cve_id}: {detected.product} {detected.version or ''}".strip(),
        target=loc,
        remediation=f"Patch or upgrade {detected.product}; see {cve.url}",
        cve=cve.cve_id,
        evidence={
            "product": detected.product,
            "version": detected.version,
            "port": detected.port,
            "banner": detected.banner[:200],
            "cvss3_score": cve.cvss3_score,
            "cvss3_vector": cve.cvss3_vector,
            "nvd_url": cve.url,
            "description": cve.description[:500],
            "source": "nvd",
        },
    )


class CVEEngine:
    """Correlate detected services against the NVD mirror."""

    def __init__(self, nvd: NVDClient | None = None, use_network: bool = True,
                 min_severity: Severity = Severity.LOW, log=print):
        self.nvd = nvd or NVDClient()
        self.use_network = use_network
        self.min_severity = min_severity
        self.log = log

    def correlate(self, services: list[DetectedService]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for svc in services:
            # 1) curated offline seeds (instant, no cache needed)
            for f in _seed_matches(svc):
                if (f.check_id, f.target) not in seen and f.severity >= self.min_severity:
                    seen.add((f.check_id, f.target))
                    findings.append(f)
            # 2) NVD mirror (offline cache or live query)
            if self.use_network or self.nvd.count() > 0:
                cves = self._query_nvd(svc)
                for cve in cves:
                    if not match_cpe_any(cve.cpes, svc):
                        continue
                    if _SEV.get(cve.severity, Severity.MEDIUM) < self.min_severity:
                        continue
                    key = (cve.cve_id, svc.key)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(_cve_to_finding(cve, svc))
        return findings

    def _query_nvd(self, svc: DetectedService) -> list[CVE]:
        try:
            cpe = svc.to_cpe()
            # use_network=False (--no-nvd): read the local mirror only, never the API
            net = self.use_network
            cves = self.nvd.search_cpe(cpe, use_cache=True, allow_network=net)
            if cves:
                return cves
            # versioned CPE returned nothing -> try product keyword (wider net)
            return self.nvd.search_keyword(svc.product, use_cache=True, allow_network=net)
        except Exception as e:  # network/API issues must never crash a scan
            self.log(f"[!] NVD query failed for {svc.product}: {e}")
            return []


def match_cpe_any(cpes: list[str], svc: DetectedService) -> bool:
    if not cpes:
        # no CPE criteria in the CVE -> accept keyword matches as relevant
        return _similar(svc.product, svc.product)
    return any(match_cpe(c, svc) for c in cpes)
