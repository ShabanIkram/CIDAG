"""Unified Finding schema (v1).

Every scanner module -- IAM, S3, EC2, network, CVE imports -- emits ``Finding``
objects. One schema keeps the CLI, exporters, GUI, and diffing consistent no
matter how many modules exist.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import IntEnum


class Severity(IntEnum):
    """Ordered severity so findings sort worst-first.

    Backward-compatible with the existing IAM engine's string severities
    (``"CRITICAL"`` / ``"HIGH"``).
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name

    @classmethod
    def parse(cls, value) -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        if isinstance(value, str):
            try:
                return cls[value.strip().upper()]
            except KeyError:
                raise ValueError(f"unknown severity: {value!r}") from None
        raise ValueError(f"cannot parse severity from {value!r}")


def _stable_id(module: str, check_id: str, target: str) -> str:
    raw = f"{module}|{check_id}|{target}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:12]


@dataclass
class Finding:
    """A single security finding, independent of which module produced it."""

    module: str                    # "iam" | "s3" | "ec2" | "net" | "import:inspector" ...
    check_id: str                  # "ESC-01", "S3-001", "NET-002", "CVE-2021-44228" ...
    severity: Severity
    title: str                     # short human label
    target: str                    # ARN / bucket name / "ip:port" / resource id
    remediation: str = ""
    evidence: dict = field(default_factory=dict)
    cve: str | None = None         # CVE id when this finding maps to one
    cwe: str | None = None
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    # IAM-specific extras (optional; kept so existing outputs stay compatible).
    identity: str | None = None
    identity_arn: str | None = None
    chain: list[str] | None = None
    reason: str | None = None      # legacy IAM "reason" text == title for IAM findings
    # Stable identity across rescans of the same target (diff-friendly).
    id: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if not self.id:
            self.id = _stable_id(self.module, self.check_id, self.target)
        if self.reason is None:
            self.reason = self.title

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        # Drop empty optional noise so exporters/GUI stay clean.
        return {k: v for k, v in d.items() if v not in (None, [], {})}

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d["severity"] = Severity.parse(d.get("severity", "INFO"))
        known = {f for f in cls.__dataclass_fields__ if f != "id"}
        return cls(**{k: v for k, v in d.items() if k in known})
