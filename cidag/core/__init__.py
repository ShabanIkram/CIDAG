"""CIDAG core framework: unified findings, scanner registry, authorization scope."""
from .finding import Finding, Severity
from .registry import Scanner, register, get_scanner, all_scanners, run_scanners
from .scope import ScopeGuard, OutOfScopeError
from .context import ScanContext

__all__ = [
    "Finding",
    "Severity",
    "Scanner",
    "register",
    "get_scanner",
    "all_scanners",
    "run_scanners",
    "ScopeGuard",
    "OutOfScopeError",
    "ScanContext",
]
