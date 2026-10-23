from __future__ import annotations

from datetime import date, timedelta

import pytest

from vulnscan.scope import ScopeError, build_scope

from .fixture_server import fixture_server
from .helpers import make_config


def test_private_target_requires_flag():
    with fixture_server() as base:
        config = make_config(base, allow_private=False)
        with pytest.raises(ScopeError, match="私有 IP"):
            build_scope(config)


def test_private_target_allowed_and_normalized():
    with fixture_server() as base:
        scope = build_scope(make_config(base))
        assert scope.seeds == [base + "/"]
        assert scope.is_allowed(base + "/page?x=1")
        assert not scope.is_allowed("https://example.org/")


def test_expired_authorization_rejected():
    with fixture_server() as base:
        config = make_config(base, expires=date.today() - timedelta(days=1))
        with pytest.raises(ScopeError, match="到期日已過"):
            build_scope(config)


def test_cidr_expansion_is_bounded():
    config = make_config(
        "10.20.30.0/30",
        targets=["10.20.30.0/30"],
        allow_private=True,
    )
    scope = build_scope(config)
    assert len(scope.seeds) == 4
    assert "10.20.30.1" in scope.allowed_ips
    assert "10.20.30.2" in scope.allowed_ips


def test_exclusions_and_default_ignored_paths():
    with fixture_server() as base:
        scope = build_scope(make_config(base, exclude=["/private/*"]))
        assert scope.is_excluded(base + "/logout")
        assert scope.is_excluded(base + "/private/report")
        assert not scope.is_excluded(base + "/page?x=1")
