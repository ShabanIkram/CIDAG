"""Ordered multi-step execution chains (AWS).

A chain is an explicit, operator-supplied list of executable technique ids.
Every step is planned and authorized before the first mutation, then executed
in order. The first failure stops the chain and rolls back every executed
action across all steps in reverse order.
"""
from __future__ import annotations

from .guard import ExploitError


def is_chain(value) -> bool:
    text = str(value or "")
    return "," in text or "+" in text


def parse_chain(value) -> list[str]:
    """Split a chain expression into normalized technique ids."""
    if isinstance(value, (list, tuple)):
        parts = [str(p) for p in value]
    else:
        parts = str(value or "").replace("+", ",").split(",")
    steps: list[str] = []
    for part in parts:
        step = part.strip().upper()
        if step:
            steps.append(step)
    if len(steps) < 2:
        raise ExploitError(
            "a chain needs at least two techniques, e.g. "
            "'cidag exploit chain ESC-04,ESC-08'")
    duplicates = sorted({s for s in steps if steps.count(s) > 1})
    if duplicates:
        raise ExploitError(
            f"duplicate techniques in chain: {', '.join(duplicates)}")
    return steps
