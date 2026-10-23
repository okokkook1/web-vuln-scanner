from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulnscan.models import AdvancedCheck, AuthConfig, AuthType, Profile

from .helpers import make_config


def test_full_profile_requires_advanced_checks_and_ack():
    with pytest.raises(ValidationError, match="至少需要選擇"):
        make_config("https://example.com", profile=Profile.FULL, advanced_ack=True)

    with pytest.raises(ValidationError, match="明確確認"):
        make_config(
            "https://example.com",
            profile=Profile.FULL,
            advanced_checks=[AdvancedCheck.SQLI_BOOLEAN],
            advanced_ack=False,
        )

    config = make_config(
        "https://example.com",
        profile=Profile.FULL,
        advanced_checks=[AdvancedCheck.SQLI_BOOLEAN, AdvancedCheck.TRAVERSAL],
        advanced_ack=True,
    )
    assert [item.value for item in config.advanced_checks] == ["sqli_boolean", "traversal"]


def test_advanced_checks_only_allowed_in_full_mode():
    with pytest.raises(ValidationError, match="僅適用"):
        make_config(
            "https://example.com",
            profile=Profile.SAFE,
            advanced_checks=[AdvancedCheck.TRAVERSAL],
        )


def test_api_post_requires_allowlist_or_explicit_all_ack():
    with pytest.raises(ValidationError, match="白名單為空"):
        make_config(
            "https://example.com",
            openapi_spec={"openapi": "3.0.0", "paths": {}},
            allow_api_post=True,
            api_post_all_ack=False,
        )

    config = make_config(
        "https://example.com",
        openapi_spec={"openapi": "3.0.0", "paths": {}},
        allow_api_post=True,
        api_post_all_ack=True,
    )
    assert config.api_post_all_ack is True


def test_api_post_allowlist_is_trimmed_and_deduplicated():
    config = make_config(
        "https://example.com",
        api_post_allowlist=[" POST /api/items/* ", "", "POST /api/items/*"],
        bola_allowlist=[" GET https://example.com/orders/* ", ""],
    )
    assert config.api_post_allowlist == ["POST /api/items/*"]
    assert config.bola_allowlist == ["GET https://example.com/orders/*"]


def test_bola_requires_two_accounts_and_explicit_ack():
    with pytest.raises(ValidationError, match="主要帳號"):
        make_config(
            "https://example.com",
            enable_bola=True,
            bola_ack=True,
            bola_auth=AuthConfig(type=AuthType.COOKIE, cookie="second=1"),
        )

    with pytest.raises(ValidationError, match="明確確認"):
        make_config(
            "https://example.com",
            enable_bola=True,
            bola_ack=False,
            auth=AuthConfig(type=AuthType.COOKIE, cookie="first=1"),
            bola_auth=AuthConfig(type=AuthType.COOKIE, cookie="second=1"),
        )

    with pytest.raises(ValidationError, match="第二個帳號"):
        make_config(
            "https://example.com",
            enable_bola=True,
            bola_ack=True,
            auth=AuthConfig(type=AuthType.COOKIE, cookie="first=1"),
        )

    with pytest.raises(ValidationError, match="BOLA GET 白名單"):
        make_config(
            "https://example.com",
            enable_bola=True,
            bola_ack=True,
            auth=AuthConfig(type=AuthType.COOKIE, cookie="first=1"),
            bola_auth=AuthConfig(type=AuthType.COOKIE, cookie="second=1"),
        )

    config = make_config(
        "https://example.com",
        enable_bola=True,
        bola_ack=True,
        auth=AuthConfig(type=AuthType.COOKIE, cookie="first=1"),
        bola_auth=AuthConfig(type=AuthType.COOKIE, cookie="second=1"),
        bola_allow_all_ack=True,
        max_api_tests=30,
        max_bola_tests=3,
    )
    assert config.max_api_tests == 30
    assert config.max_bola_tests == 3
    assert config.bola_allow_all_ack is True


def test_ssrf_callback_must_be_http_and_reachable_host():
    config = make_config(
        "https://example.com",
        profile=Profile.FULL,
        advanced_checks=[AdvancedCheck.SSRF],
        advanced_ack=True,
        ssrf_callback="http://127.0.0.1:9000/callback/",
    )
    assert config.ssrf_callback == "http://127.0.0.1:9000/callback"

    with pytest.raises(ValidationError, match="僅支援 http"):
        make_config(
            "https://example.com",
            profile=Profile.FULL,
            advanced_checks=[AdvancedCheck.SSRF],
            advanced_ack=True,
            ssrf_callback="https://callback.example/",
        )
    with pytest.raises(ValidationError, match=r"0\.0\.0\.0"):
        make_config(
            "https://example.com",
            profile=Profile.FULL,
            advanced_checks=[AdvancedCheck.SSRF],
            advanced_ack=True,
            ssrf_callback="http://0.0.0.0:9000/",
        )
