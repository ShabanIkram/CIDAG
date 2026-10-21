"""Authorized exploitation engine (opt-in).

Default CIDAG stays read-only. This package executes escalation techniques only
when the operator passes an explicit ``--authorize-exploitation`` account id,
proves the caller identity matches, and confirms in a TTY.
"""
from .guard import AuthorizationGuard, ExploitError, GuardError
from .session import (AzureEngagementSession, EngagementSession,
                      GcpEngagementSession)

__all__ = [
    "AuthorizationGuard", "ExploitError", "GuardError", "EngagementSession",
    "AzureEngagementSession", "GcpEngagementSession",
]
