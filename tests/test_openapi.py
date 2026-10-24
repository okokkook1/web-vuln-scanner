from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnscan.checks import api_active
from vulnscan.checks.bola import _similarity_for_pages
from vulnscan.db import Database
from vulnscan.engine import ScanEngine, ScanError
from vulnscan.models import (
    AdvancedCheck,
    AuthConfig,
    AuthType,
    Endpoint,
    Parameter,
    Profile,
    Scan,
    new_scan_id,
)
from vulnscan.openapi_import import (
    filter_get_endpoints,
    filter_post_endpoints,
    parse_openapi,
    parse_openapi_report,
    preview_post_endpoints,
)
from vulnscan.openapi_refs import fingerprint_spec
from vulnscan.scope import build_scope

from .fixture_server import fixture_server
from .helpers import make_config


def _spec(base: str) -> dict:
    return {
        "openapi": "3.0.0",
        "servers": [{"url": base}],
        "paths": {
            "/api/echo": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "q": {"type": "string"},
                                        "url": {"type": "string"},
                                        "user": {
                                            "type": "object",
                                            "properties": {
                                                "name": {"type": "string"}
                                            },
                                        },
                                    },
                                }
                            }
                        }
                    }
                }
            },
            "/api/boolean": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"q": {"type": "string"}},
                                }
                            }
                        }
                    }
                }
            },
            "/items": {
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}}
                    ]
                },
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "q": {"type": "string"},
                                        "url": {"type": "string"},
                                    },
                                }
                            }
                        },
                    }
                },
            },
        },
    }


def test_openapi_server_variables_and_path_operation_servers():
    with fixture_server() as base:
        spec = {
            "openapi": "3.0.0",
            "servers": [
                {
                    "url": base + "/{version}",
                    "variables": {
                        "version": {
                            "default": "v1",
                            "enum": ["v1", "v2"],
                        }
                    },
                }
            ],
            "paths": {
                "/root": {"get": {}},
                "/path": {
                    "servers": [{"url": base + "/path-base"}],
                    "get": {},
                },
                "/op": {
                    "servers": [{"url": base + "/path-base"}],
                    "get": {},
                    "post": {
                        "servers": [{"url": base + "/op-base"}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"q": {"type": "string"}},
                                    }
                                }
                            }
                        },
                    },
                },
            },
        }
        config = make_config(base, openapi_spec=spec, allow_api_post=True)
        report = parse_openapi_report(spec, build_scope(config), allow_post=True)
        urls = {(endpoint.method, endpoint.url) for endpoint in report.endpoints}
        assert ("GET", f"{base}/v1/root") in urls
        assert ("GET", f"{base}/path-base/path") in urls
        assert ("GET", f"{base}/path-base/op") in urls
        assert ("POST", f"{base}/op-base/op") in urls


def test_openapi_parser_builds_get_and_json_post_endpoints():
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_spec=_spec(base),
            allow_api_post=True,
        )
        scope = build_scope(config)
        endpoints = parse_openapi(config.openapi_spec or {}, scope, allow_post=True)
        assert any(item.method == "GET" and "q=test" in item.url for item in endpoints)
        post = next(item for item in endpoints if item.method == "POST" and item.url.endswith("/items"))
        assert post.body == {"q": "test", "url": "test"}
        assert {param.location for param in post.params} == {"body"}

        echo = next(item for item in endpoints if item.method == "POST" and item.url.endswith("/api/echo"))
        assert echo.body == {
            "q": "test",
            "url": "test",
            "user": {"name": "test"},
        }
        echo_params = {param.name for param in echo.params}
        assert {"q", "url", "user.name"} <= echo_params

        get_only = parse_openapi(config.openapi_spec or {}, scope, allow_post=False)
        assert all(item.method == "GET" for item in get_only)


def test_openapi_31_allof_pathitem_ref_and_type_union():
    with fixture_server() as base:
        spec = {
            "openapi": "3.1.0",
            "servers": [{"url": base}],
            "paths": {
                "/api/echo": {"$ref": "#/components/pathItems/echo"},
            },
            "components": {
                "pathItems": {
                    "echo": {
                        "post": {
                            "requestBody": {
                                "$ref": "#/components/requestBodies/echo"
                            }
                        }
                    }
                },
                "requestBodies": {
                    "echo": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": ["object", "null"],
                                    "allOf": [
                                        {
                                            "type": "object",
                                            "properties": {
                                                "q": {
                                                    "type": "string",
                                                    "examples": ["hello"],
                                                }
                                            },
                                        },
                                        {
                                            "type": "object",
                                            "properties": {
                                                "user": {
                                                    "type": ["object", "null"],
                                                    "properties": {
                                                        "name": {"const": "alice"}
                                                    },
                                                }
                                            },
                                        },
                                    ],
                                }
                            }
                        }
                    }
                },
            },
        }
        config = make_config(base, openapi_spec=spec, allow_api_post=True)
        scope = build_scope(config)
        endpoints = parse_openapi(spec, scope, allow_post=True)
        echo = next(
            item
            for item in endpoints
            if item.method == "POST" and item.url.endswith("/api/echo")
        )
        assert echo.body == {"q": "hello", "user": {"name": "alice"}}
        assert {param.name for param in echo.params} == {"q", "user.name"}


def test_bola_compares_json_shape_not_values():
    similarity, mode = _similarity_for_pages(
        '{"id":1,"owner":"alice","items":[{"id":1}]}',
        '{"id":2,"owner":"bob","items":[{"id":9}]}',
    )
    assert mode == "json_shape"
    assert similarity > 0.95


def test_allowlist_supports_host_aware_patterns():
    endpoints = [
        Endpoint(url="https://a.example/api/items", method="POST"),
        Endpoint(url="https://b.example/api/items", method="POST"),
    ]
    host_aware = filter_post_endpoints(
        endpoints,
        ["POST https://a.example/api/*"],
    )
    assert [item.url for item in host_aware] == ["https://a.example/api/items"]

    path_only = filter_post_endpoints(endpoints, ["POST /api/*"])
    assert len(path_only) == 2

    preview = preview_post_endpoints(endpoints, [])
    assert preview[0]["allowlist_pattern"] == "POST https://a.example/api/items"


def test_bola_get_allowlist_supports_host_aware_patterns():
    endpoints = [
        Endpoint(url="https://a.example/api/items/1", method="GET"),
        Endpoint(url="https://b.example/api/items/1", method="GET"),
    ]
    filtered = filter_get_endpoints(
        endpoints,
        ["GET https://a.example/api/*"],
    )
    assert [item.url for item in filtered] == [
        "https://a.example/api/items/1"
    ]


def test_openapi_report_warns_about_external_refs_methods_and_scope():
    with fixture_server() as base:
        spec = {
            "openapi": "3.1.0",
            "servers": [{"url": base}],
            "paths": {
                "/ok": {"get": {}},
                "/put": {"put": {}},
                "/external": {"$ref": "https://example.com/not-fetched.json"},
            },
        }
        scope = build_scope(make_config(base, openapi_spec=spec))
        report = parse_openapi_report(spec, scope, allow_post=True)
        assert len(report.endpoints) == 1
        assert report.stats["get"] == 1
        assert report.stats["skipped_methods"] == 1
        assert report.stats["external_refs"] == 1
        assert any("外部 $ref" in warning for warning in report.warnings)
        assert any("其他 HTTP method" in warning for warning in report.warnings)

        outside = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://outside.example"}],
            "paths": {"/outside": {"get": {}}},
        }
        outside_scope = build_scope(make_config(base, openapi_spec=outside))
        outside_report = parse_openapi_report(outside, outside_scope, allow_post=True)
        assert outside_report.endpoints == []
        assert outside_report.stats["skipped_scope"] == 1
        assert any("scope" in warning for warning in outside_report.warnings)


def test_openapi_reports_unresolved_parameter_and_body_refs():
    with fixture_server() as base:
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": base}],
            "paths": {
                "/parameters": {
                    "get": {
                        "parameters": [
                            {"$ref": "https://refs.example/params.json#/id"}
                        ]
                    }
                },
                "/body": {
                    "post": {
                        "requestBody": {
                            "$ref": "https://refs.example/body.json#/Body"
                        }
                    }
                },
            },
        }
        scope = build_scope(make_config(base, openapi_spec=spec))
        report = parse_openapi_report(spec, scope, allow_post=True)
        assert any(
            "parameters" in warning and "參數 $ref" in warning
            for warning in report.warnings
        )
        assert any(
            "requestBody" in warning and "body.json" in warning
            for warning in report.warnings
        )


def test_post_allowlist_filters_and_preview_marks_allowed():
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_spec=_spec(base),
            allow_api_post=True,
            api_post_allowlist=["POST /api/boolean"],
        )
        scope = build_scope(config)
        assert scope.snapshot()["api"]["post_allowlist"] == ["POST /api/boolean"]
        endpoints = parse_openapi(config.openapi_spec or {}, scope, allow_post=True)
        filtered = filter_post_endpoints(endpoints, config.api_post_allowlist)
        post_paths = {
            item.url.rsplit("/", 1)[-1]
            for item in filtered
            if item.method == "POST"
        }
        assert post_paths == {"boolean"}
        assert any(item.method == "GET" for item in filtered)

        preview = preview_post_endpoints(endpoints, config.api_post_allowlist)
        by_path = {item["path"]: item for item in preview}
        assert by_path["/api/boolean"]["allowed"] is True
        assert by_path["/api/echo"]["allowed"] is False

        wildcard = filter_post_endpoints(endpoints, ["/api/*"])
        wildcard_posts = [item for item in wildcard if item.method == "POST"]
        assert len(wildcard_posts) == 2
        assert all(
            item.url.endswith(("/api/echo", "/api/boolean"))
            for item in wildcard_posts
        )


async def _run(
    base: str,
    config,
    tmp_path: Path,
    *,
    return_scan: bool = False,
):
    scope = build_scope(config)
    db = Database(tmp_path / "vulnscan.db")
    db.init()
    scan_id = new_scan_id()
    db.create_scan(
        Scan(
            id=scan_id,
            status="running",
            profile=config.profile.value,
            targets_json=json.dumps(config.targets),
            scope_json=json.dumps(scope.snapshot(), ensure_ascii=False),
        )
    )
    engine = ScanEngine(
        scan_id=scan_id,
        config=config,
        db=db,
        data_dir=tmp_path,
        cancel_event=asyncio.Event(),
        on_update=lambda *args: None,
    )
    result = await engine.run()
    if return_scan:
        return result, db.get_scan(scan_id)
    return result


async def test_api_post_json_checks_and_openapi_import(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_spec=_spec(base),
            openapi_name="spec.json",
            allow_api_post=True,
        )
        result = await _run(base, config, tmp_path)

    rules = {finding.rule_id for finding in result.findings}
    assert "api-xss-reflected" in rules
    assert "api-sqli-error" in rules
    assert "api-sqli-boolean" in rules
    assert any(
        finding.rule_id == "api-xss-reflected" and finding.parameter == "user.name"
        for finding in result.findings
    )
    assert result.stats.endpoints >= 3


async def test_openapi_url_import_and_nested_json_boolean(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_url=f"{base}/api/openapi.json",
            openapi_name="fixture-openapi",
            allow_api_post=True,
        )
        result = await _run(base, config, tmp_path)

    rules = {finding.rule_id for finding in result.findings}
    assert "api-xss-reflected" in rules
    assert "api-sqli-boolean" in rules
    assert any(
        finding.rule_id == "api-xss-reflected" and finding.parameter == "user.name"
        for finding in result.findings
    )
    assert result.stats.endpoints >= 3


async def test_openapi_url_follows_in_scope_redirect(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_url=f"{base}/api/openapi-redirect",
            allow_api_post=True,
        )
        result = await _run(base, config, tmp_path)

    rules = {finding.rule_id for finding in result.findings}
    assert "api-sqli-boolean" in rules


async def test_openapi_url_rejects_out_of_scope_redirect(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_url=f"{base}/api/openapi-outside",
            allow_api_post=True,
        )
        with pytest.raises(ScanError, match="授權範圍"):
            await _run(base, config, tmp_path)


async def test_openapi_url_rejects_redirect_loop(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_url=f"{base}/api/openapi-loop",
            allow_api_post=True,
        )
        with pytest.raises(ScanError, match="次數過多"):
            await _run(base, config, tmp_path)


async def test_boolean_sqli_requires_consistent_confirmation_rounds(monkeypatch):
    endpoint = Endpoint(
        url="https://example.com/api",
        method="POST",
        params=[Parameter(name="q", location="body")],
        body={"q": "test"},
    )
    context = SimpleNamespace(
        take_api_test=lambda: True,
        record_api_test=lambda *args, **kwargs: None,
    )
    round_result = {
        "baseline_status": 200,
        "true_status": 200,
        "false_status": 200,
        "similarity_baseline_true": 1.0,
        "similarity_true_false": 0.5,
        "status_signal": False,
        "content_signal": True,
        "signal": True,
    }
    calls = 0

    async def flaky_round(*args, **kwargs):
        nonlocal calls
        calls += 1
        return round_result if calls == 1 else {**round_result, "signal": False}

    monkeypatch.setattr(api_active, "_boolean_round", flaky_round)
    assert await api_active._boolean_sqli([endpoint], context) == []

    async def stable_round(*args, **kwargs):
        return round_result

    monkeypatch.setattr(api_active, "_boolean_round", stable_round)
    findings = await api_active._boolean_sqli([endpoint], context)
    assert [item.rule_id for item in findings] == ["api-sqli-boolean"]
    assert findings[0].evidence["confirmation_rounds"] == 2


async def test_engine_persists_api_selection_and_import_stats(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_spec=_spec(base),
            openapi_name="spec.json",
            allow_api_post=True,
            api_post_allowlist=["POST /api/boolean"],
            max_api_tests=7,
        )
        _result, scan = await _run(base, config, tmp_path, return_scan=True)

    assert scan is not None
    scope = json.loads(scan.scope_json)
    api = scope["api"]
    assert api["selection"]["allowlist"] == ["POST /api/boolean"]
    assert api["selection"]["selected_count"] == 1
    assert api["selection"]["skipped_count"] >= 1
    assert api["selection"]["selected_endpoints"][0]["path"] == "/api/boolean"
    assert api["import_stats"]["post"] >= 1
    assert api["post_allow_all"] is False
    tests = api["test_results"]
    assert tests["selected"] == 1
    assert tests["tested"] == 1
    assert tests["api_tests"] >= 1
    assert tests["max_api_tests"] == 7
    assert tests["endpoints"][0]["path"] == "/api/boolean"
    assert tests["endpoints"][0]["checks"]


async def test_api_post_allowlist_limits_engine_tests(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_spec=_spec(base),
            openapi_name="spec.json",
            allow_api_post=True,
            api_post_allowlist=["POST /api/boolean"],
        )
        result = await _run(base, config, tmp_path)

    rules = {finding.rule_id for finding in result.findings}
    assert "api-sqli-boolean" in rules
    assert "api-xss-reflected" not in rules
    assert "api-sqli-error" not in rules


async def test_openapi_external_refs_are_bundled(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_url=f"{base}/api/openapi-external.json",
            allow_api_post=True,
        )
        result, scan = await _run(base, config, tmp_path, return_scan=True)

    rules = {finding.rule_id for finding in result.findings}
    assert "api-xss-reflected" in rules
    assert any(
        finding.parameter == "user.name" for finding in result.findings
    )
    assert scan is not None
    scope = json.loads(scan.scope_json)
    assert scope["api"]["import_stats"]["external_documents"] >= 1
    assert scope["api"]["import_stats"]["resolved_refs"] >= 1
    assert list((tmp_path / "openapi-cache").glob("*.json"))


async def test_bfla_readonly_detects_second_account_admin_access(tmp_path: Path):
    with fixture_server() as base:
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": base}],
            "paths": {"/api/admin/settings": {"get": {}}},
        }
        config = make_config(
            base,
            profile=Profile.SAFE,
            openapi_spec=spec,
            enable_bola=True,
            bola_ack=True,
            bola_auth=AuthConfig(
                type=AuthType.COOKIE,
                cookie="auth=bob",
            ),
            bola_allowlist=["GET /api/admin/*"],
            auth=AuthConfig(
                type=AuthType.COOKIE,
                cookie="auth=alice",
            ),
            max_bola_tests=4,
        )
        result, scan = await _run(base, config, tmp_path, return_scan=True)

    bfla = [
        finding for finding in result.findings if finding.rule_id == "api-bfla-readonly"
    ]
    assert [finding.url for finding in bfla] == [f"{base}/api/admin/settings"]
    assert scan is not None
    scope = json.loads(scan.scope_json)
    assert scope["api"]["bola"]["findings"] == 1
    item = scope["api"]["bola"]["results"][0]
    assert item["kind"] == "bfla"
    assert item["result"] == "vulnerable"


async def test_engine_skips_api_on_spec_fingerprint_mismatch(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_spec=_spec(base),
            allow_api_post=True,
            api_post_allowlist=["POST /api/echo"],
            openapi_fingerprint="not-the-previewed-spec",
        )
        result, scan = await _run(base, config, tmp_path, return_scan=True)

    rules = {finding.rule_id for finding in result.findings}
    assert "api-xss-reflected" not in rules
    assert scan is not None
    scope = json.loads(scan.scope_json)
    assert scope["api"]["fingerprint_match"] is False
    assert scope["api"]["selection"]["skipped_reason"] == "spec_drift"


async def test_engine_accepts_matching_spec_fingerprint(tmp_path: Path):
    with fixture_server() as base:
        spec = _spec(base)
        config = make_config(
            base,
            openapi_spec=spec,
            allow_api_post=True,
            api_post_allowlist=["POST /api/echo"],
            openapi_fingerprint=fingerprint_spec(spec),
        )
        result, scan = await _run(base, config, tmp_path, return_scan=True)

    rules = {finding.rule_id for finding in result.findings}
    assert "api-xss-reflected" in rules
    assert scan is not None
    scope = json.loads(scan.scope_json)
    assert scope["api"]["fingerprint_match"] is True


async def test_engine_runs_api_when_session_is_valid(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_spec=_spec(base),
            allow_api_post=True,
            api_post_allowlist=["POST /api/echo"],
            auth=AuthConfig(
                type=AuthType.COOKIE,
                cookie="auth=ok",
                verify_url=f"{base}/private",
            ),
        )
        result, scan = await _run(base, config, tmp_path, return_scan=True)

    rules = {finding.rule_id for finding in result.findings}
    assert "api-xss-reflected" in rules
    assert scan is not None
    scope = json.loads(scan.scope_json)
    assert scope["api"]["auth_session"]["valid"] is True
    assert scope["api"]["selection"]["skipped_reason"] is None


async def test_engine_skips_api_when_session_is_invalid(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            openapi_spec=_spec(base),
            allow_api_post=True,
            api_post_allowlist=["POST /api/echo"],
            auth=AuthConfig(
                type=AuthType.COOKIE,
                cookie="auth=bad",
                verify_url=f"{base}/private",
            ),
        )
        result, scan = await _run(base, config, tmp_path, return_scan=True)

    rules = {finding.rule_id for finding in result.findings}
    assert "api-xss-reflected" not in rules
    assert scan is not None
    scope = json.loads(scan.scope_json)
    assert scope["api"]["auth_session"]["valid"] is False
    assert scope["api"]["selection"]["skipped_reason"] == "session_invalid"


async def test_bola_readonly_detects_second_account_access(tmp_path: Path):
    with fixture_server() as base:
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": base}],
            "paths": {
                "/api/object/1": {"get": {}},
                "/api/object/2": {"get": {}},
            },
        }
        config = make_config(
            base,
            profile=Profile.SAFE,
            openapi_spec=spec,
            enable_bola=True,
            bola_ack=True,
            bola_auth=AuthConfig(
                type=AuthType.COOKIE,
                cookie="auth=bob",
            ),
            bola_allowlist=["GET /api/object/*"],
            auth=AuthConfig(
                type=AuthType.COOKIE,
                cookie="auth=alice",
            ),
            max_bola_tests=4,
        )
        result, scan = await _run(base, config, tmp_path, return_scan=True)

    bola = [
        finding for finding in result.findings if finding.rule_id == "api-bola-readonly"
    ]
    assert [finding.url for finding in bola] == [f"{base}/api/object/1"]
    assert scan is not None
    scope = json.loads(scan.scope_json)
    bola_meta = scope["api"]["bola"]
    assert bola_meta["enabled"] is True
    assert bola_meta["tested"] >= 2
    assert bola_meta["findings"] == 1
    by_url = {item["url"]: item["result"] for item in bola_meta["results"]}
    assert by_url[f"{base}/api/object/1"] == "vulnerable"
    assert by_url[f"{base}/api/object/2"] == "protected"
    assert bola_meta["result_counts"]["vulnerable"] == 1


async def test_api_json_ssrf_uses_callback(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(
            base,
            profile=Profile.FULL,
            advanced_checks=[AdvancedCheck.SSRF],
            advanced_ack=True,
            openapi_spec=_spec(base),
            openapi_name="spec.json",
            allow_api_post=True,
        )
        result = await _run(base, config, tmp_path)

    rules = {finding.rule_id for finding in result.findings}
    assert "api-ssrf-callback" in rules
