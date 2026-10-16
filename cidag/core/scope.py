"""Authorization scope guard.

Network scanning is dual-use by design; this makes authorization explicit and
enforced. The network scanner refuses to probe any address outside the declared
allowlist -- there is no wildcard "scan everything" path.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable


class OutOfScopeError(PermissionError):
    """Raised when a probe target is not covered by the declared allowlist."""


class ScopeGuard:
    """Allowlist of CIDR networks and account ids a scan is authorized for."""

    def __init__(
        self,
        networks: Iterable[str] | None = None,
        accounts: Iterable[str] | None = None,
        allow_private: bool = False,
    ):
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for n in networks or []:
            self.add_network(n)
        self._accounts = {a for a in (accounts or [])}
        self.allow_private = allow_private

    def add_network(self, cidr: str) -> None:
        net = ipaddress.ip_network(cidr, strict=False)
        self._networks.append(net)

    def add_account(self, account_id: str) -> None:
        self._accounts.add(account_id)

    @property
    def networks(self) -> list[str]:
        return [str(n) for n in self._networks]

    def is_empty(self) -> bool:
        return not self._networks

    def in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        # Private/loopback addresses always require the explicit allow_private
        # opt-in, even if listed in the allowlist -- an extra safety interlock.
        if addr.is_private and not self.allow_private:
            return False
        return self._covers(addr)

    def _covers(self, addr) -> bool:
        return any(addr in net for net in self._networks)

    def assert_in_scope(self, ip: str) -> None:
        if not self.in_scope(ip):
            raise OutOfScopeError(
                f"target {ip} is outside the authorized scope "
                f"(allowlist: {', '.join(self.networks) or 'empty'})"
            )

    def assert_account(self, account_id: str) -> None:
        if self._accounts and account_id not in self._accounts:
            raise OutOfScopeError(
                f"account {account_id} is not in the authorized account allowlist"
            )
