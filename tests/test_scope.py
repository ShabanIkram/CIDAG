import pytest

from cidag.core.scope import OutOfScopeError, ScopeGuard


def test_public_ip_in_public_cidr_in_scope():
    g = ScopeGuard(networks=["8.8.8.0/24"])
    assert g.in_scope("8.8.8.5")
    assert not g.in_scope("8.8.4.4")  # outside the cidr


def test_out_of_scope_raises():
    g = ScopeGuard(networks=["8.8.8.0/24"])
    with pytest.raises(OutOfScopeError):
        g.assert_in_scope("9.9.9.9")


def test_empty_scope_denies_everything():
    g = ScopeGuard()
    assert g.is_empty()
    assert not g.in_scope("8.8.8.8")


def test_private_denied_without_allow_private_even_if_listed():
    # Listing a private range is NOT enough -- allow_private is a hard interlock.
    g = ScopeGuard(networks=["127.0.0.1/32"])
    assert not g.in_scope("127.0.0.1")


def test_private_allowed_with_allow_private():
    g = ScopeGuard(networks=["127.0.0.1/32"], allow_private=True)
    assert g.in_scope("127.0.0.1")
    g2 = ScopeGuard(networks=["10.0.0.0/24"], allow_private=True)
    assert g2.in_scope("10.0.0.5")
    assert not g2.in_scope("10.0.1.5")  # still bounded by the cidr


def test_invalid_ip_not_in_scope():
    g = ScopeGuard(networks=["8.8.8.0/24"])
    assert not g.in_scope("not-an-ip")


def test_account_allowlist():
    g = ScopeGuard(accounts=["111111111111"])
    g.assert_account("111111111111")
    with pytest.raises(OutOfScopeError):
        g.assert_account("222222222222")


def test_multiple_networks():
    g = ScopeGuard(networks=["8.8.8.0/24", "1.1.1.0/24"])
    assert g.in_scope("8.8.8.8") and g.in_scope("1.1.1.1")
    assert not g.in_scope("2.2.2.2")
