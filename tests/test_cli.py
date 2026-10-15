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