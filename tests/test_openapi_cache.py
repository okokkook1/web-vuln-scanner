from __future__ import annotations

from pathlib import Path

from vulnscan.models import AuthConfig, AuthType
from vulnscan.openapi_cache import OpenAPIRefCache, auth_cache_key


def test_openapi_ref_cache_roundtrip_and_expiry(
    tmp_path: Path,
    monkeypatch,
):
    cache = OpenAPIRefCache(tmp_path / "cache", ttl_seconds=10)
    document = {"openapi": "3.0.0", "paths": {"/x": {}}}
    cache.set("https://example.com/ref.json", "https://cdn.example/ref.json", document)
    loaded = cache.get("https://example.com/ref.json")
    assert loaded is not None
    assert loaded[0] == document
    assert loaded[1] == "https://cdn.example/ref.json"

    monkeypatch.setattr("vulnscan.openapi_cache.time.time", lambda: 9999999999.0)
    assert cache.get("https://example.com/ref.json") is None


def test_openapi_cache_key_distinguishes_auth_modes():
    anonymous = auth_cache_key(None)
    cookie = auth_cache_key(AuthConfig(type=AuthType.COOKIE, cookie="a=1"))
    header = auth_cache_key(
        AuthConfig(type=AuthType.HEADER, header_name="Authorization", header_value="x")
    )
    assert len({anonymous, cookie, header}) == 3


def test_openapi_ref_cache_ignores_corrupt_entries(tmp_path: Path):
    cache = OpenAPIRefCache(tmp_path / "cache")
    cache.directory.mkdir(parents=True)
    path = cache._path("https://example.com/ref.json", "anonymous")
    path.write_text("{not json", encoding="utf-8")
    assert cache.get("https://example.com/ref.json") is None
    assert not path.exists()
