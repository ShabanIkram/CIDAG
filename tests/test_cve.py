from cidag.core.finding import Severity
from cidag.cve import SEED_RULES
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


def test_no_nvd_never_touches_network(tmp_path, monkeypatch):
    """--no-nvd must never hit the API, even when the local mirror is warm.

    Regression: engine.correlate() gated on `use_network or count() > 0`, so a
    populated mirror re-entered _query_nvd() with use_network=False, and a cold
    query_cache fell through to a live NVD request.
    """
    from cidag.cve.nvd import NVDClient

    client = NVDClient(cache_path=tmp_path / "mirror.db")
    client._upsert([CVE(cve_id="CVE-2020-0000", severity="HIGH", cvss3_score=8.0,
                        cvss3_vector="", description="warm mirror", published=None,
                        last_modified=None, cpes=[], url="")])
    assert client.count() > 0  # the exact condition that reopened the gate

    calls = {"http": 0}

    def boom(*args, **kwargs):
        calls["http"] += 1
        raise AssertionError("offline mode hit the live NVD API")

    monkeypatch.setattr(NVDClient, "_get", boom)

    engine = CVEEngine(nvd=client, use_network=False, log=lambda m: None)
    svc = DetectedService(product="unknown", vendor="unknown", version="1.0",
                          port=1, banner="mystery service")
    engine.correlate([svc])
    assert calls["http"] == 0


def test_seed_rules_respect_affected_from():
    """Legacy versions must not report CVEs that never applied to them."""
    def cves(product, version):
        return {f.cve for f in _seed_matches(
            DetectedService(product=product, vendor=product, version=version))}

    assert "CVE-2021-41773" not in cves("apache http server", "2.2.8")
    assert "CVE-2021-41773" in cves("apache http server", "2.4.49")
    assert "CVE-2021-41773" not in cves("apache http server", "2.4.51")
    assert "CVE-2016-0777" not in cves("openssh", "4.7p1")
    assert "CVE-2016-0777" in cves("openssh", "5.9p1")
    assert "CVE-2016-0777" not in cves("openssh", "8.2p1")


def test_vsftpd_seed_only_exact_backdoored_version():
    def cves(version):
        return {f.cve for f in _seed_matches(
            DetectedService(product="vsftpd", vendor="vsftpd", version=version))}

    assert cves("2.3.4") == {"CVE-2011-2523"}
    assert cves("2.3.3") == set()
    # old rule used affected_below=3.0.3, reporting every version under 3.0.3
    assert cves("3.0.0") == set()


def test_seed_rule_bounds_are_well_formed():
    """Every seed is a real, actionable rule with a sane version window."""
    for rule in SEED_RULES:
        assert rule.title.strip(), rule.cve_id
        assert rule.remediation.strip(), rule.cve_id
        assert rule.affected_below, rule.cve_id
        if rule.affected_from:
            assert version_lt(rule.affected_from, rule.affected_below), rule.cve_id


def test_seed_rule_matches_inside_and_not_at_upper_bound():
    """A rule fires within its window and never on the fixed release."""
    def cves(rule, version):
        return {f.cve for f in _seed_matches(
            DetectedService(product=rule.product, vendor=rule.product, version=version))}

    for rule in SEED_RULES:
        assert rule.cve_id in cves(rule, rule.affected_from or "0.0.1"), rule.cve_id
        assert rule.cve_id not in cves(rule, rule.affected_below), rule.cve_id


def test_seed_rule_ids_are_unique_per_product():
    # Branch-scoped advisories may repeat one CVE, but never with the same window.
    windows = [(r.product, r.cve_id, r.affected_from, r.affected_below)
               for r in SEED_RULES]
    assert len(windows) == len(set(windows))
    assert len(SEED_RULES) >= 30


def test_expanded_seed_coverage_spot_checks():
    def cves(product, version):
        return {f.cve for f in _seed_matches(
            DetectedService(product=product, version=version))}

    assert "CVE-2024-6387" in cves("openssh", "9.7p1")      # regreSSHion
    assert "CVE-2024-6387" not in cves("openssh", "9.8p1")
    assert "CVE-2019-5736" in cves("docker", "18.09.1")     # runc escape
    assert "CVE-2017-7494" in cves("samba", "4.6.4")        # SambaCry
    # branch-scoped fixes must not be flagged
    assert "CVE-2017-7494" not in cves("samba", "4.4.14")
    assert "CVE-2017-7494" not in cves("samba", "4.5.10")
    assert "CVE-2015-1635" in cves("microsoft iis", "8.5")  # HTTP.sys
    assert "CVE-2021-44228" not in cves("apache http server", "2.4.48")
