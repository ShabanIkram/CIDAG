import json
from pathlib import Path

import pytest

import cidag.collectors.org as org_mod
from cidag.cli.main import main

MOCK = Path(__file__).resolve().parents[1] / "cidag" / "data" / "mock_aws.json"


class _FakeCollector:
    def __init__(self, profile=None, region="us-east-1", session=None):
        self.session = session

    def collect(self):
        return json.loads(MOCK.read_text(encoding="utf-8"))


@pytest.fixture
def fake_org(monkeypatch):
    monkeypatch.setattr("cidag.cli.main.AwsCollector", _FakeCollector)
    monkeypatch.setattr("cidag.cli.main._collect_live_scanners",
                        lambda *a, **k: None)
    monkeypatch.setattr(org_mod, "list_accounts", lambda session: [
        {"id": "111111111111", "name": "prod"},
        {"id": "222222222222", "name": "dev"},
    ])
    monkeypatch.setattr(org_mod, "assume_role_session",
                        lambda base, acct, role, region: object())


def test_all_accounts_tags_every_finding(fake_org, capsys):
    rc = main(["scan", "--live", "--all-accounts", "--modules", "iam", "--json"])
    data = json.loads(capsys.readouterr().out)

    assert rc is None or rc == 0
    assert data["account_id"] == "org:2"
    assert data["findings"]
    assert {f["account"] for f in data["findings"]} == {
        "111111111111", "222222222222"}
    assert len({f["id"] for f in data["findings"]}) == len(data["findings"])


def test_account_id_filter(fake_org, capsys):
    main(["scan", "--live", "--all-accounts", "--modules", "iam", "--json",
          "--account-id", "111111111111"])
    data = json.loads(capsys.readouterr().out)
    assert {f["account"] for f in data["findings"]} == {"111111111111"}


def test_all_accounts_requires_live(capsys):
    rc = main(["scan", "--all-accounts", "--modules", "iam"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "LIVE SCAN ABORTED" in err
    assert "--live" in err


def test_assume_role_failure_aborts(fake_org, monkeypatch, capsys):
    def denied(*a, **k):
        raise RuntimeError("AccessDenied")

    monkeypatch.setattr(org_mod, "assume_role_session", denied)
    rc = main(["scan", "--live", "--all-accounts", "--modules", "iam"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "cannot assume" in err


def test_list_accounts_failure_aborts(fake_org, monkeypatch, capsys):
    def boom(session):
        raise RuntimeError("not in an organization")

    monkeypatch.setattr(org_mod, "list_accounts", boom)
    rc = main(["scan", "--live", "--all-accounts", "--modules", "iam"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "ListAccounts failed" in err
