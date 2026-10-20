import json

from cidag.cli.main import main


def test_scan_json(capsys):
    main(["scan", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings"] >= 1
    assert isinstance(data["findings"], list)


def test_paths_runs(capsys):
    main(["paths"])
    out = capsys.readouterr().out
    assert "admin-role" in out


def test_blast_runs(capsys):
    main(["blast", "--identity", "lambda-exec-role"])
    out = capsys.readouterr().out
    assert "admin-role" in out


def test_report_md(capsys):
    main(["report", "--format", "md"])
    out = capsys.readouterr().out
    assert "# CIDAG" in out

class _NoCredsSession:
    def get_credentials(self):
        return None


def test_live_without_credentials_aborts(monkeypatch, capsys):
    """Dead credentials must abort (rc=2), never emit fabricated findings.

    Before this guard, `scan --live` with no credentials collected an empty
    inventory and then reported CT-001 / S3-009 as if those resources were
    genuinely absent -- false positives with rc=0.
    """
    import cidag.collectors.aws as aws_mod

    fake_boto3 = type("FakeBoto3", (), {"Session": staticmethod(lambda **kw: _NoCredsSession())})
    monkeypatch.setattr(aws_mod, "boto3", fake_boto3)

    rc = main(["scan", "--live", "--modules", "iam,s3,ec2"])
    err = capsys.readouterr().err

    assert rc == 2
    assert "LIVE SCAN ABORTED" in err
    assert "no AWS credentials" in err


def test_live_bad_profile_aborts(monkeypatch, capsys):
    from botocore.exceptions import ProfileNotFound

    import cidag.collectors.aws as aws_mod

    def bad_profile(**kw):
        raise ProfileNotFound(profile=kw.get("profile_name") or "default")

    fake_boto3 = type("FakeBoto3", (), {"Session": staticmethod(bad_profile)})
    monkeypatch.setattr(aws_mod, "boto3", fake_boto3)

    rc = main(["scan", "--live", "--profile", "ghost"])
    err = capsys.readouterr().err

    assert rc == 2
    assert "ghost" in err


def test_live_collector_failure_aborts(monkeypatch, capsys):
    """A failed live collector is fatal: partial inventory = fabricated findings."""
    class FakeCollector:
        def __init__(self, profile=None, region="us-east-1"):
            pass

        def collect(self):
            return {"account_id": "123456789012", "region": "us-east-1",
                    "identities": [], "policies": [], "resources": []}

    def denied(session):
        raise RuntimeError("AccessDenied: s3:ListAllMyBuckets")

    monkeypatch.setattr("cidag.cli.main.verify_credentials", lambda *a, **k: object())
    monkeypatch.setattr("cidag.cli.main.AwsCollector", FakeCollector)
    monkeypatch.setattr("cidag.scanners.s3.collector.collect_s3", denied)

    rc = main(["scan", "--live", "--modules", "s3"])
    err = capsys.readouterr().err

    assert rc == 2
    assert "s3 collection failed" in err
    assert "AccessDenied" in err
