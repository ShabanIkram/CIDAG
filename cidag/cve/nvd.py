"""NVD (National Vulnerability Database) API 2.0 client with an offline SQLite cache.

Design notes
------------
* The full CVE corpus (~290k+ CVEs) is never hardcoded -- it lives in NVD and is
  pulled on demand and kept fresh via incremental ``lastModStartDate`` syncs.
* ``nvd sync`` builds a local mirror so scans work fully offline afterward.
* Results for every query are cached in SQLite keyed by CVE id, so a re-scan of
  the same product/version never hits the network twice.
* Uses only the stdlib (``urllib``) -- no extra runtime dependency.
* Rate limits: 5 req/30s anonymous, 50 req/30s with a free NVD API key
  (``NVD_API_KEY`` env var). We self-throttle accordingly.
"""
from __future__ import annotations

import gzip
import json
import os
import sqlite3
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE = Path.home() / ".cache" / "cidag" / "nvd.sqlite3"


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


@dataclass
class CVE:
    cve_id: str
    severity: str                 # CRITICAL | HIGH | MEDIUM | LOW | NONE | UNKNOWN
    cvss3_score: float | None
    cvss3_vector: str | None
    description: str
    published: str | None
    last_modified: str | None
    cpes: list[str] = field(default_factory=list)
    url: str = ""

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss3_score": self.cvss3_score,
            "cvss3_vector": self.cvss3_vector,
            "description": self.description,
            "published": self.published,
            "last_modified": self.last_modified,
            "cpes": self.cpes,
            "url": self.url,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "CVE":
        return cls(
            cve_id=row["cve_id"],
            severity=row["severity"],
            cvss3_score=row["cvss3_score"],
            cvss3_vector=row["cvss3_vector"],
            description=row["description"],
            published=row["published"],
            last_modified=row["last_modified"],
            cpes=json.loads(row["cpes"] or "[]"),
            url=row["url"] or f"https://nvd.nist.gov/vuln/detail/{row['cve_id']}",
        )


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id        TEXT PRIMARY KEY,
    severity      TEXT,
    cvss3_score   REAL,
    cvss3_vector  TEXT,
    description   TEXT,
    published     TEXT,
    last_modified TEXT,
    cpes          TEXT,
    url           TEXT
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS query_cache (
    query TEXT PRIMARY KEY,
    cve_ids TEXT,
    fetched_at TEXT
);
"""


class NVDClient:
    """NVD API 2.0 client backed by a local SQLite mirror."""

    def __init__(self, cache_path: str | Path | None = None, api_key: str | None = None,
                 timeout: float = 30.0, verbose: bool = False):
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.timeout = timeout
        self.verbose = verbose
        self._conn = sqlite3.connect(str(self.cache_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        # anonymous = 5 req / 30s  -> min interval 6s; keyed = 50/30s -> 0.6s
        self._min_interval = 0.65 if self.api_key else 6.1
        self._last_request = 0.0

    # ------------------------------------------------------------------ HTTP
    def _throttle(self) -> None:
        delta = time.monotonic() - self._last_request
        if delta < self._min_interval:
            time.sleep(self._min_interval - delta)
        self._last_request = time.monotonic()

    def _get(self, params: dict) -> dict:
        self._throttle()
        url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"User-Agent": "cidag/2.0"})
        if self.api_key:
            req.add_header("apiKey", self.api_key)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    # ------------------------------------------------------------ transforms
    @staticmethod
    def _to_cve(item: dict) -> CVE:
        c = item.get("cve", {})
        metrics = c.get("metrics", {})
        score = vector = severity = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3"):
            if metrics.get(key):
                m = metrics[key][0].get("cvssData", {})
                score = m.get("baseScore")
                vector = m.get("vectorString")
                severity = metrics[key][0].get("baseSeverity") or m.get("baseSeverity")
                break
        if severity is None:
            # fall back to v2
            if metrics.get("cvssMetricV2"):
                m = metrics["cvssMetricV2"][0]
                score = m.get("cvssData", {}).get("baseScore")
                severity = m.get("baseSeverity")
        severity = (severity or "UNKNOWN").upper()
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        cpes: list[str] = []
        for node in c.get("configurations", []):
            for cfg in node.get("nodes", []):
                for match in cfg.get("cpeMatch", []):
                    if match.get("criteria"):
                        cpes.append(match["criteria"])
        cve_id = c.get("id", "")
        return CVE(
            cve_id=cve_id,
            severity=severity,
            cvss3_score=score,
            cvss3_vector=vector,
            description=desc,
            published=c.get("published"),
            last_modified=c.get("lastModified"),
            cpes=sorted(set(cpes)),
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        )

    # ----------------------------------------------------------------- cache
    def _upsert(self, cves: list[CVE]) -> None:
        self._conn.executemany(
            """INSERT INTO cves (cve_id,severity,cvss3_score,cvss3_vector,description,
                                 published,last_modified,cpes,url)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(cve_id) DO UPDATE SET
                 severity=excluded.severity, cvss3_score=excluded.cvss3_score,
                 cvss3_vector=excluded.cvss3_vector, description=excluded.description,
                 published=excluded.published, last_modified=excluded.last_modified,
                 cpes=excluded.cpes, url=excluded.url""",
            [
                (c.cve_id, c.severity, c.cvss3_score, c.cvss3_vector, c.description,
                 c.published, c.last_modified, json.dumps(c.cpes), c.url)
                for c in cves
            ],
        )
        self._conn.commit()

    def get(self, cve_id: str) -> CVE | None:
        row = self._conn.execute(
            "SELECT * FROM cves WHERE cve_id = ?", (cve_id.upper(),)
        ).fetchone()
        return CVE.from_row(row) if row else None

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]

    def last_sync(self) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='last_sync'"
        ).fetchone()
        return row["value"] if row else None

    # -------------------------------------------------------------- queries
    def _cache_get(self, query: str) -> list[str] | None:
        row = self._conn.execute(
            "SELECT cve_ids FROM query_cache WHERE query=?", (query,)
        ).fetchone()
        return json.loads(row["cve_ids"]) if row else None

    def _cache_put(self, query: str, ids: list[str]) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO query_cache (query, cve_ids, fetched_at) VALUES (?,?,?)",
            (query, json.dumps(ids), datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def _query(self, params: dict, use_cache: bool = True, allow_network: bool = True) -> list[CVE]:
        cache_key = json.dumps(params, sort_keys=True)
        if use_cache:
            cached = self._cache_get(cache_key)
            if cached is not None:
                out = []
                for cid in cached:
                    cve = self.get(cid)
                    if cve:
                        out.append(cve)
                return out
        if not allow_network:
            # offline mode: a cold cache must not fall through to the live API
            return []
        results: list[CVE] = []
        start = 0
        while True:
            page = self._get({**params, "resultsPerPage": "200", "startIndex": str(start)})
            vulns = page.get("vulnerabilities", [])
            for item in vulns:
                results.append(self._to_cve(item))
            total = page.get("totalResults", 0)
            start += len(vulns)
            if start >= total or not vulns:
                break
        self._upsert(results)
        self._cache_put(cache_key, [c.cve_id for c in results])
        return results

    def search_keyword(self, keyword: str, use_cache: bool = True,
                       allow_network: bool = True) -> list[CVE]:
        return self._query({"keywordSearch": keyword}, use_cache=use_cache,
                           allow_network=allow_network)

    def search_cpe(self, cpe: str, use_cache: bool = True,
                   allow_network: bool = True) -> list[CVE]:
        """cpe:2.3:part:vendor:product:version:..."""
        return self._query({"cpeName": cpe}, use_cache=use_cache,
                           allow_network=allow_network)

    def search_severity(self, severity: str, days: int = 30, use_cache: bool = True) -> list[CVE]:
        start = datetime.now(timezone.utc) - timedelta(days=days)
        return self._query(
            {"cvssV3Severity": severity.upper(),
             "pubStartDate": _utc(start),
             "pubEndDate": _utc(datetime.now(timezone.utc))},
            use_cache=use_cache,
        )

    # ----------------------------------------------------------------- sync
    def sync(self, days: int = 120, log=print) -> int:
        """Incrementally pull CVEs modified in the last ``days`` days.

        Returns the number of CVEs fetched. First run pulls ~``days`` of history;
        subsequent runs only fetch what changed since the stored ``last_sync``.
        """
        last = self.last_sync()
        if last:
            start = datetime.fromisoformat(last.replace("Z", "+00:00"))
        else:
            start = datetime.now(timezone.utc) - timedelta(days=days)
        end = datetime.now(timezone.utc)
        total = 0
        start_index = 0
        log(f"[*] NVD sync {_utc(start)} -> {_utc(end)}")
        while True:
            page = self._get({
                "lastModStartDate": _utc(start),
                "lastModEndDate": _utc(end),
                "resultsPerPage": "2000",
                "startIndex": str(start_index),
            })
            vulns = page.get("vulnerabilities", [])
            cves = [self._to_cve(v) for v in vulns]
            self._upsert(cves)
            total += len(cves)
            log(f"    fetched {total} / {page.get('totalResults', total)}")
            start_index += len(vulns)
            if start_index >= page.get("totalResults", 0) or not vulns:
                break
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key,value) VALUES ('last_sync',?)",
            (end.isoformat(),),
        )
        self._conn.commit()
        log(f"[+] NVD sync complete: {total} CVEs upserted; mirror now holds {self.count()}")
        return total

    def close(self) -> None:
        self._conn.close()
