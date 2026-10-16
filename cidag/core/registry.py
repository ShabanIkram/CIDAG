"""Scanner plugin registry.

Any module can register a ``Scanner``; the CLI/GUI discover them here so adding
a new check pack never requires touching the core.

Usage::

    @register("s3")
    class S3Scanner(Scanner):
        name = "s3"
        description = "S3 bucket configuration checks"

        def run(self, context): ...
"""
from __future__ import annotations

from typing import Iterable, Protocol, runtime_checkable

from .finding import Finding


@runtime_checkable
class Scanner(Protocol):
    """Contract every scanner module implements."""

    name: str
    description: str

    def run(self, context: "ScanContext") -> list[Finding]:  # noqa: F821
        ...


_REGISTRY: dict[str, Scanner] = {}


def register(name: str):
    """Class decorator: instantiate and store a scanner under ``name``."""

    def wrap(cls):
        instance = cls()
        # Allow class attribute to win if set; otherwise use the register arg.
        instance.name = getattr(cls, "name", name) or name
        if not getattr(cls, "description", ""):
            cls.description = instance.name
        _REGISTRY[instance.name] = instance
        return cls

    return wrap


def get_scanner(name: str) -> Scanner:
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "(none loaded)"
        raise KeyError(f"unknown scanner {name!r}; registered: {known}") from None


def all_scanners() -> dict[str, Scanner]:
    return dict(_REGISTRY)


def run_scanners(names: Iterable[str], context: "ScanContext") -> list[Finding]:  # noqa: F821
    """Run the named scanners in order and concatenate findings."""
    findings: list[Finding] = []
    for name in names:
        scanner = get_scanner(name)
        context.log(f"[*] running scanner: {name}")
        findings.extend(scanner.run(context))
    return findings
