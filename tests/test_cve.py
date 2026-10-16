from cidag.core.finding import Severity
from cidag.cve.cpe import DetectedService, match_cpe, parse_version, version_lt, version_lte
from cidag.cve.engine import _seed_matches, CVEEngine
from cidag.cve.nvd import CVE


def test_parse_version():
    assert parse_version("2.4.49") == [2, 4, 49]
    assert parse_version("") == []
    assert parse_version("8.4p1") == [8, 4, "p", 1]


def test_version_lt():
    assert version_lt("1.3.5", "1.3.6")
    assert not version_lt("1.3.6", "1.3.5")
    assert version_lt("2.4.49", "2.4.51")
    assert not version_lt("8.4", "8.4")


def test_version_lte():
    assert version_lte("1.3.6", "1.3.6")
    assert version_lte("1.3.5", "1.3.6")


def test_cpe_string_escaping():
    svc = DetectedService(product="apache http server", vendor="apache", version="2.4.49")
    cpe = svc.to_cpe()
    assert cpe.startswith("cpe:2.3:a:apache:apache http server:2.4.49:")


def test_match_cpe_wildcards():
    svc = DetectedService(product="openssh", vendor="openbsd", version="7.1")
    assert match_cpe("cpe:2.3:a:openbsd:openssh:7.1:*:*:*:*:*:*:*", svc)
    assert match_cpe("cpe:2.3:a:*:openssh:*:*:*:*:*:*:*:*", svc)  # wildcard version
    assert not match_cpe("cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*", svc)


def test_seed_rules_fire_on_vulnerable_version():
    svc = DetectedService(product="proftpd", vendor="proftpd", version="1.3.5", port=21)
    findings = _seed_matches(svc)
    assert any(f.cve == "CVE-2019-12815" for f in findings)


def test_seed_rules_ignore_patched_version():
    svc = DetectedService(product="proftpd", version="1.3.6")
    assert not any(f.cve == "CVE-2019-12815" for f in _seed_matches(svc))


def test_seed_ignores_versionless_service():
    assert _seed_matches(DetectedService(product="proftpd", version="")) == []


def test_engine_correlate_seeds_offline():
    svc = DetectedService(product="apache http server", vendor="apache",
                          version="2.4.49", port=80, banner="Apache/2.4.49")
    engine = CVEEngine(use_network=False, log=lambda m: None)
    findings = engine.correlate([svc])
    cves = {f.cve for f in findings}
    assert {"CVE-2021-41773", "CVE-2021-42013"} <= cves
    # every CVE finding carries severity + remediation
    for f in findings:
        assert f.cve and f.remediation


def test_cve_severity_mapping():
    cve = CVE(cve_id="CVE-2021-44228", severity="CRITICAL", cvss3_score=10.0,
              cvss3_vector="CVSS:3.1/AV:N", description="log4shell", published=None,
              last_modified=None, cpes=[], url="")
    assert cve.severity == "CRITICAL"
