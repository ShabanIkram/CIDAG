"""CPE (Common Platform Enumeration) construction and version utilities.

Network banners give us ``product`` + ``version``; CPE gives NVD a precise key
to match against. This module turns detected services into CPE 2.3 URIs and
provides the version ordering needed for "affected below X" checks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_CPE_SPECIAL = re.compile(r"([:\\])")


def escape_cpe(value: str) -> str:
    return _CPE_SPECIAL.sub(r"\\\1", value)


@dataclass(frozen=True)
class DetectedService:
    """A service identified during collection (network banner, package list…)."""

    product: str                 # "openssh", "apache http server", "proftpd"
    vendor: str = ""             # "openbsd", "apache", "proftpd" (best-effort)
    version: str = ""            # "8.4p1", "2.4.49" ("" = unknown)
    port: int | None = None
    proto: str = "tcp"
    banner: str = ""
    source: str = "net"          # "net" | "package" | "inspector"

    def to_cpe(self) -> str:
        part = "a"  # applications are what we detect from banners
        return (
            "cpe:2.3:"
            f"{part}:"
            f"{escape_cpe(self.vendor or '*')}:"
            f"{escape_cpe(self.product)}:"
            f"{escape_cpe(self.version or '*')}:"
            "*:*:*:*:*:*:*"
        )

    @property
    def key(self) -> str:
        return f"{self.product}:{self.version}"


_VERSION_RE = re.compile(r"(\d+|[a-z]+)")


def parse_version(version: str) -> list:
    """Split a version string into comparable tokens.

    ``"2.4.49" -> [2, 4, 49]``; ``"8.4p1" -> [8, 4, 'p', 1]``; empty -> [].
    Numeric tokens compare as ints, alpha tokens as lowercase strings, so
    ``2.4.49 < 2.4.50`` and ``8.4p1 > 8.4``.
    """
    if not version:
        return []
    tokens: list = []
    for tok in _VERSION_RE.findall(version):
        tokens.append(int(tok) if tok.isdigit() else tok.lower())
    return tokens


def version_lt(a: str, b: str) -> bool:
    """True if version ``a`` is strictly older than ``b`` (best-effort)."""
    return _cmp(a, b) < 0


def version_lte(a: str, b: str) -> bool:
    return _cmp(a, b) <= 0


def version_gte(a: str, b: str) -> bool:
    return _cmp(a, b) >= 0


def _cmp(a: str, b: str) -> int:
    ta, tb = parse_version(a), parse_version(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        # numeric vs alpha: treat numeric as lower so "8.4p1" > "8.4"
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int):
            return -1
        if isinstance(y, int):
            return 1
        return -1 if str(x) < str(y) else 1
    return (len(ta) > len(tb)) - (len(ta) < len(tb))


def match_cpe(cve_cpe: str, detected: DetectedService) -> bool:
    """Best-effort check whether a CVE's CPE criteria matches a detected service.

    NVD CPE criteria are full 2.3 URIs; we compare vendor/product/version with
    ``*``/``-`` wildcards honored. Not a full CPE 2.3 engine, but covers the
    vendor/product/version matching that dominates real NVD entries.
    """
    if not cve_cpe.startswith("cpe:2.3:"):
        return False
    parts = cve_cpe.split(":")
    # cpe:2.3:part:vendor:product:version:...
    if len(parts) < 6:
        return False
    _, _, part, vendor, product, version = parts[:6]
    if part not in ("a", "h", "*"):
        return False
    if product not in ("*", detected.product.lower()) and \
            not _similar(product, detected.product):
        return False
    if vendor not in ("*", "-") and detected.vendor and \
            not _similar(vendor, detected.vendor):
        return False
    if version in ("*", "-") or not detected.version:
        return True
    return version == detected.version.lower()


def _similar(a: str, b: str) -> bool:
    a, b = a.lower(), b.lower()
    return a == b or a in b or b in a
