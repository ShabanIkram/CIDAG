"""ScanContext passed to every scanner's ``run`` method."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .scope import ScopeGuard


@dataclass
class ScanContext:
    """Everything a scanner needs to run."""

    inventory: dict = field(default_factory=dict)
    scope: ScopeGuard = field(default_factory=ScopeGuard)
    options: dict[str, Any] = field(default_factory=dict)
    log: Callable[[str], None] = field(default=lambda msg: None)
    offline: bool = False          # True -> never touch the network

    def opt(self, key: str, default=None):
        return self.options.get(key, default)
