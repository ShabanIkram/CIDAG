"""Curated offline CVE seeds.

The NVD mirror is the source of truth for "every CVE"; these rules only
guarantee the engine is useful on a cold cache with no network. Where a lower
bound is known they are version-bounded on *both* sides: without
``affected_from`` an old release reports a CVE that never applied to it (Apache
2.2.8 matching CVE-2021-41773, OpenSSH 4.7p1 matching CVE-2016-0777) -- a false
positive on every legacy box you scan.

Where an advisory spans several unsynchronised release branches (5.5/5.6/5.7,
9.0/8.5/7.0) a rule covers one branch and names it in the title, rather than
using a range that would also match patched builds from another branch.
"""
from __future__ import annotations

from ..core.finding import Severity


class SeedRule:
    """Curated offline fallback for a famous vulnerability."""

    __slots__ = ("product", "affected_below", "cve_id", "severity", "title",
                 "remediation", "affected_from")

    def __init__(self, product: str, affected_below: str, cve_id: str,
                 severity: Severity, title: str, remediation: str,
                 affected_from: str = ""):
        self.product = product
        self.affected_below = affected_below
        self.cve_id = cve_id
        self.severity = severity
        self.title = title
        self.remediation = remediation
        self.affected_from = affected_from

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"SeedRule({self.product!r}, {self.cve_id!r})"


SEED_RULES: list[SeedRule] = [
    # ---- web servers -----------------------------------------------------
    SeedRule("apache http server", "2.4.51", "CVE-2021-41773", Severity.CRITICAL,
             "Apache path traversal / RCE (2.4.49-2.4.50)",
             "Upgrade Apache httpd to 2.4.51 or later", affected_from="2.4.49"),
    SeedRule("apache http server", "2.4.51", "CVE-2021-42013", Severity.CRITICAL,
             "Apache path traversal / RCE follow-up (2.4.49-2.4.50)",
             "Upgrade Apache httpd to 2.4.51 or later", affected_from="2.4.49"),
    SeedRule("apache http server", "2.4.52", "CVE-2021-44790", Severity.CRITICAL,
             "Apache mod_lua buffer overflow (2.4.0-2.4.51)",
             "Upgrade Apache httpd to 2.4.52 or later", affected_from="2.4.0"),
    SeedRule("apache http server", "2.4.53", "CVE-2022-22720", Severity.HIGH,
             "Apache HTTP request smuggling (2.4.0-2.4.52)",
             "Upgrade Apache httpd to 2.4.53 or later", affected_from="2.4.0"),
    SeedRule("apache http server", "2.4.56", "CVE-2023-25690", Severity.HIGH,
             "Apache mod_proxy HTTP request splitting (2.4.0-2.4.55)",
             "Upgrade Apache httpd to 2.4.56 or later", affected_from="2.4.0"),
    SeedRule("apache http server", "2.4.60", "CVE-2024-38475", Severity.CRITICAL,
             "Apache mod_rewrite escaping / code execution (2.4.0-2.4.59)",
             "Upgrade Apache httpd to 2.4.60 or later", affected_from="2.4.0"),
    SeedRule("nginx", "1.20.1", "CVE-2021-23017", Severity.HIGH,
             "nginx resolver off-by-one (0.6.18-1.20.0)",
             "Upgrade nginx to 1.20.1 or later", affected_from="0.6.18"),
    SeedRule("nginx", "1.17.7", "CVE-2019-20372", Severity.MEDIUM,
             "nginx error_page request smuggling (1.9.0-1.17.6)",
             "Upgrade nginx to 1.17.7 or later", affected_from="1.9.0"),
    SeedRule("nginx", "1.13.3", "CVE-2017-7529", Severity.HIGH,
             "nginx range-filter integer overflow / memory leak (0.5.6-1.13.2)",
             "Upgrade nginx to 1.13.3 or later", affected_from="0.5.6"),
    SeedRule("lighttpd", "1.4.51", "CVE-2018-19052", Severity.HIGH,
             "lighttpd mod_alias path traversal (1.4.0-1.4.50)",
             "Upgrade lighttpd to 1.4.51 or later", affected_from="1.4.0"),
    SeedRule("microsoft iis", "9.0", "CVE-2015-1635", Severity.CRITICAL,
             "IIS HTTP.sys range header RCE / DoS (7.5-8.5)",
             "Apply MS15-034; upgrade IIS to 10.0", affected_from="7.5"),
    SeedRule("microsoft iis", "6.1", "CVE-2017-7269", Severity.CRITICAL,
             "IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow",
             "Retire IIS 6.0 or apply the vendor fix", affected_from="6.0"),

    # ---- remote access ---------------------------------------------------
    SeedRule("openssh", "7.4", "CVE-2016-0777", Severity.HIGH,
             "OpenSSH client info leak / command injection (roaming)",
             "Upgrade OpenSSH; disable roaming client", affected_from="5.4"),
    SeedRule("openssh", "7.7", "CVE-2018-15473", Severity.MEDIUM,
             "OpenSSH username enumeration (2.3-7.6)",
             "Upgrade OpenSSH to 7.7 or later", affected_from="2.3"),
    SeedRule("openssh", "9.3p2", "CVE-2023-38408", Severity.CRITICAL,
             "OpenSSH PKCS#11 remote code execution (5.5-9.3p1)",
             "Upgrade OpenSSH to 9.3p2 or later", affected_from="5.5"),
    SeedRule("openssh", "9.8p1", "CVE-2024-6387", Severity.CRITICAL,
             "OpenSSH regreSSHion signal-handler RCE (8.5p1-9.7p1)",
             "Upgrade OpenSSH to 9.8p1 or later; set LoginGraceTime 0",
             affected_from="8.5p1"),

    # ---- TLS -------------------------------------------------------------
    SeedRule("openssl", "1.0.2k", "CVE-2016-2107", Severity.HIGH,
             "OpenSSL padding oracle (CVE-2016-2107)",
             "Upgrade OpenSSL to a patched release", affected_from="1.0.1"),
    SeedRule("openssl", "1.0.1g", "CVE-2014-0160", Severity.CRITICAL,
             "OpenSSL Heartbleed memory disclosure (1.0.1-1.0.1f)",
             "Upgrade OpenSSL to 1.0.1g or later and reissue certificates",
             affected_from="1.0.1"),

    # ---- file transfer ---------------------------------------------------
    SeedRule("proftpd", "1.3.6", "CVE-2019-12815", Severity.CRITICAL,
             "ProFTPD mod_copy arbitrary command execution",
             "Upgrade ProFTPD to 1.3.6 or later / remove mod_copy",
             affected_from="1.3.5"),
    SeedRule("proftpd", "1.3.7a", "CVE-2020-9273", Severity.HIGH,
             "ProFTPD pool use-after-free (1.3.6-1.3.7)",
             "Upgrade ProFTPD to 1.3.7a or later", affected_from="1.3.6"),
    SeedRule("vsftpd", "2.3.5", "CVE-2011-2523", Severity.CRITICAL,
             "vsftpd 2.3.4 backdoor (smiley face)",
             "Reinstall genuine vsftpd; the backdoored build is not upstream",
             affected_from="2.3.4"),

    # ---- mail ------------------------------------------------------------
    SeedRule("exim", "4.92", "CVE-2019-10149", Severity.CRITICAL,
             "Exim RCPT TO remote command execution (4.87-4.91)",
             "Upgrade Exim to 4.92 or later", affected_from="4.87"),
    SeedRule("opensmtpd", "6.6.2", "CVE-2020-7247", Severity.CRITICAL,
             "OpenSMTPD MAIL FROM command injection (6.0-6.6.1)",
             "Upgrade OpenSMTPD to 6.6.2 or later", affected_from="6.0"),

    # ---- databases / caches ---------------------------------------------
    SeedRule("redis", "6.2.7", "CVE-2022-0543", Severity.CRITICAL,
             "Redis Lua sandbox escape / RCE (Debian/Ubuntu)",
             "Upgrade Redis; restrict network exposure", affected_from="4.0"),
    SeedRule("mysql", "5.7.15", "CVE-2016-6662", Severity.CRITICAL,
             "MySQL 5.7 configuration injection / RCE (5.7.0-5.7.14)",
             "Upgrade MySQL 5.7 to 5.7.15 or later", affected_from="5.7"),
    SeedRule("postgresql", "11.3", "CVE-2019-9193", Severity.HIGH,
             "PostgreSQL COPY TO PROGRAM command execution (9.3-11.2)",
             "Upgrade PostgreSQL to 11.3 or later; restrict superuser access",
             affected_from="9.3"),
    SeedRule("elasticsearch", "1.1.2", "CVE-2014-3120", Severity.CRITICAL,
             "Elasticsearch MVEL dynamic scripting RCE (<1.1.2)",
             "Upgrade Elasticsearch; disable dynamic scripting"),
    SeedRule("elasticsearch", "1.4.3", "CVE-2015-1427", Severity.CRITICAL,
             "Elasticsearch Groovy sandbox bypass RCE (1.3.0-1.4.2)",
             "Upgrade Elasticsearch to 1.4.3 or later", affected_from="1.3"),
    SeedRule("memcached", "1.5.6", "CVE-2018-1000115", Severity.HIGH,
             "memcached UDP amplification (1.5.5 and earlier)",
             "Upgrade memcached to 1.5.6+; disable UDP; bind to localhost"),

    # ---- application servers / platforms --------------------------------
    SeedRule("apache tomcat", "7.0.80", "CVE-2017-12615", Severity.CRITICAL,
             "Tomcat 7 PUT JSP upload RCE (7.0.0-7.0.79)",
             "Upgrade Tomcat 7.0 to 7.0.80+; disable readonly=false",
             affected_from="7.0.0"),
    SeedRule("apache tomcat", "9.0.31", "CVE-2020-1938", Severity.CRITICAL,
             "Tomcat Ghostcat AJP file read / inclusion (9.0.0-9.0.30)",
             "Upgrade Tomcat 9.0 to 9.0.31+; disable the AJP connector",
             affected_from="9.0"),
    SeedRule("gitlab", "13.10.3", "CVE-2021-22205", Severity.CRITICAL,
             "GitLab ExifTool unauthenticated RCE (13.10.0-13.10.2)",
             "Upgrade GitLab 13.10 to 13.10.3 or later", affected_from="13.10"),

    # ---- file sharing / containers --------------------------------------
    # CVE-2017-7494 shipped fixes on three branches; one merged range would
    # flag patched 4.4.14+/4.5.10+ builds as vulnerable.
    SeedRule("samba", "4.4.14", "CVE-2017-7494", Severity.CRITICAL,
             "SambaCry remote code execution (3.5.0-4.4.13)",
             "Upgrade Samba to 4.4.14 or later",
             affected_from="3.5.0"),
    SeedRule("samba", "4.5.10", "CVE-2017-7494", Severity.CRITICAL,
             "SambaCry remote code execution (4.5.0-4.5.9)",
             "Upgrade Samba to 4.5.10 or later",
             affected_from="4.5.0"),
    SeedRule("samba", "4.6.5", "CVE-2017-7494", Severity.CRITICAL,
             "SambaCry remote code execution (4.6.0-4.6.4)",
             "Upgrade Samba to 4.6.5 or later",
             affected_from="4.6.0"),
    SeedRule("docker", "18.09.2", "CVE-2019-5736", Severity.CRITICAL,
             "runc host escape via /proc/self/exe overwrite (Docker <18.09.2)",
             "Upgrade Docker Engine to 18.09.2+ / runc 1.0-rc7",
             affected_from="17.06"),
]
