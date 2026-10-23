from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from .models import Endpoint, Parameter
from .scope import Scope

MAX_ENDPOINTS = 500
ALLOW_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
OTHER_METHODS = ("put", "patch", "delete", "head", "options", "trace")


@dataclass
class OpenAPIImportReport:
    endpoints: list[Endpoint] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


def filter_post_endpoints(
    endpoints: list[Endpoint],
    allowlist: list[str],
) -> list[Endpoint]:
    """Keep GET endpoints, but restrict POST endpoints to matching allowlist patterns."""
    patterns = _parse_allowlist(allowlist)
    if not patterns:
        return list(endpoints)
    return [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() != "POST" or _matches_allowlist(endpoint, patterns)
    ]


def filter_get_endpoints(
    endpoints: list[Endpoint],
    allowlist: list[str],
) -> list[Endpoint]:
    patterns = _parse_allowlist(allowlist)
    if not patterns:
        return list(endpoints)
    return [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() != "GET"
        or _matches_allowlist(endpoint, patterns)
    ]


def preview_post_endpoints(
    endpoints: list[Endpoint],
    allowlist: list[str],
) -> list[dict[str, Any]]:
    """Describe POST requests that would be tested, without making any request."""
    patterns = _parse_allowlist(allowlist)
    items: list[dict[str, Any]] = []
    for endpoint in endpoints:
        if endpoint.method.upper() != "POST":
            continue
        fields = [
            param.name for param in endpoint.params if param.location == "body"
        ]
        items.append(
            {
                "method": "POST",
                "path": urlsplit(endpoint.url).path or "/",
                "url": endpoint.url,
                "fields": fields[:100],
                "allowed": not patterns or _matches_allowlist(endpoint, patterns),
                "allowlist_pattern": _endpoint_allowlist_pattern(endpoint),
                "request": {
                    "method": "POST",
                    "url": endpoint.url,
                    "headers": {
                        "Content-Type": endpoint.content_type or "application/json"
                    },
                    "body": endpoint.body,
                    "canary_fields": fields[:100],
                },
            }
        )
    return items


def _parse_allowlist(
    allowlist: list[str],
) -> list[tuple[str | None, str | None, str | None, str]]:
    """Parse METHOD [absolute-URL|path] patterns.

    A path-only pattern keeps matching any host for backward compatibility.
    An absolute URL pattern is host-aware and also matches the scheme.
    """
    patterns: list[tuple[str | None, str | None, str | None, str]] = []
    for raw in allowlist:
        text = str(raw).strip()
        if not text:
            continue
        method: str | None = None
        parts = text.split(None, 1)
        if len(parts) == 2 and parts[0].upper() in ALLOW_METHODS:
            method = parts[0].upper()
            text = parts[1].strip()
        lowered = text.lower()
        if lowered.startswith(("http://", "https://")):
            parsed = urlsplit(text)
            if not parsed.netloc or parsed.username or parsed.password:
                continue
            patterns.append(
                (
                    method,
                    parsed.scheme.lower(),
                    parsed.netloc.lower(),
                    parsed.path or "/",
                )
            )
            continue
        if text.startswith("//"):
            parsed = urlsplit(f"http:{text}")
            if not parsed.netloc:
                continue
            patterns.append(
                (method, None, parsed.netloc.lower(), parsed.path or "/")
            )
            continue
        if not text.startswith("/"):
            text = f"/{text}"
        if text:
            patterns.append((method, None, None, text))
    return patterns


def _matches_allowlist(
    endpoint: Endpoint,
    patterns: list[tuple[str | None, str | None, str | None, str]],
) -> bool:
    parsed = urlsplit(endpoint.url)
    path = parsed.path or "/"
    method = endpoint.method.upper()
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    return any(
        (pattern_method is None or pattern_method == method)
        and (pattern_scheme is None or pattern_scheme == scheme)
        and (pattern_netloc is None or fnmatchcase(netloc, pattern_netloc))
        and fnmatchcase(path, pattern_path)
        for pattern_method, pattern_scheme, pattern_netloc, pattern_path in patterns
    )


def _endpoint_allowlist_pattern(endpoint: Endpoint) -> str:
    parsed = urlsplit(endpoint.url)
    if parsed.scheme and parsed.netloc:
        target = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    else:
        target = parsed.path or "/"
    return f"{endpoint.method.upper()} {target}"


def parse_openapi(
    spec: dict[str, Any],
    scope: Scope,
    *,
    allow_post: bool = False,
) -> list[Endpoint]:
    return parse_openapi_report(spec, scope, allow_post=allow_post).endpoints


def parse_openapi_report(
    spec: dict[str, Any],
    scope: Scope,
    *,
    allow_post: bool = False,
) -> OpenAPIImportReport:
    warnings: list[str] = []
    stats: dict[str, int] = {
        "paths": 0,
        "endpoints": 0,
        "get": 0,
        "post": 0,
        "skipped_scope": 0,
        "skipped_methods": 0,
        "post_disabled": 0,
        "unparsed_bodies": 0,
        "invalid_paths": 0,
        "external_refs": 0,
        "cap_reached": 0,
        "warnings": 0,
    }

    def warn(message: str) -> None:
        if len(warnings) < 30:
            warnings.append(message)

    version = str(spec.get("openapi") or spec.get("swagger") or "").strip()
    if version and not (
        version.startswith("3.0")
        or version.startswith("3.1")
        or version == "2.0"
    ):
        warn(f"未識別的 OpenAPI 版本：{version}，仍會嘗試解析")

    external_refs = _count_external_refs(spec)
    stats["external_refs"] = external_refs
    if external_refs:
        warn(
            f"規格含 {external_refs} 個外部 $ref；目前只解析文件內 #/ 參照，"
            "相關欄位或端點可能被略過"
        )

    paths = spec.get("paths")
    if not isinstance(paths, dict):
        warn("規格沒有 paths 物件，沒有可匯入的端點")
        stats["warnings"] = len(warnings)
        return OpenAPIImportReport(warnings=warnings, stats=stats)

    stats["paths"] = len(paths)
    endpoints: dict[str, Endpoint] = {}
    other_methods = 0
    skipped_scope = 0
    post_disabled = 0
    unparsed_bodies = 0
    cap_reached = False

    for path, path_item in paths.items():
        if cap_reached:
            break
        if not isinstance(path_item, dict):
            stats["invalid_paths"] += 1
            warn(f"路徑 {path} 不是物件，已跳過")
            continue
        path_item = _resolve_schema(path_item, spec)
        if not isinstance(path_item, dict):
            stats["invalid_paths"] += 1
            warn(f"路徑 {path} 的 $ref 無法解析，已跳過")
            continue
        other_methods += sum(
            1
            for method in OTHER_METHODS
            if isinstance(path_item.get(method), dict)
        )
        path_parameters = path_item.get("parameters") or []
        for method in ("get", "post"):
            if method == "post" and not allow_post:
                if isinstance(path_item.get("post"), dict):
                    post_disabled += 1
                continue
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            operation_servers = operation.get("servers")
            path_servers = path_item.get("servers")
            base = _base_url(
                spec,
                scope,
                servers=(
                    operation_servers
                    if isinstance(operation_servers, list) and operation_servers
                    else path_servers
                ),
            )
            raw_parameters = [
                *path_parameters,
                *(operation.get("parameters") or []),
            ]
            unresolved_parameters = [
                str(item.get("$ref"))
                for item in raw_parameters
                if isinstance(item, dict)
                and isinstance(item.get("$ref"), str)
                and not item["$ref"].startswith("#/")
            ]
            if unresolved_parameters:
                warn(
                    f"{method.upper()} {path} 有未解析的參數 $ref："
                    + ", ".join(unresolved_parameters[:3])
                )
            parameters = _merge_parameters(
                path_parameters,
                operation.get("parameters") or [],
                spec,
            )
            url, query_params = _build_url(base, str(path), parameters, spec)
            if not scope.is_allowed(url):
                skipped_scope += 1
                continue
            has_body = isinstance(operation.get("requestBody"), dict) or any(
                isinstance(param, dict)
                and str(param.get("in") or "").lower() == "body"
                for param in parameters
            )
            body, body_params = _build_body(operation, parameters, spec)
            if has_body and body is None:
                unparsed_bodies += 1
                body_ref = _unresolved_body_ref(operation)
                detail = f"（$ref: {body_ref}）" if body_ref else ""
                warn(
                    f"{method.upper()} {path} 的 requestBody 沒有可解析的 JSON schema"
                    f"{detail}，body 參數已略過"
                )
            key = f"{method.upper()} {url}"
            endpoints[key] = Endpoint(
                url=url,
                method=method.upper(),
                params=query_params + body_params,
                source="openapi",
                depth=0,
                body=body,
            )
            stats[method] += 1
            stats["endpoints"] = len(endpoints)
            if len(endpoints) >= MAX_ENDPOINTS:
                cap_reached = True
                stats["cap_reached"] = 1
                warn(f"端點數量達到上限 {MAX_ENDPOINTS}，其餘端點已略過")
                break

    stats["skipped_scope"] = skipped_scope
    stats["skipped_methods"] = other_methods
    stats["post_disabled"] = post_disabled
    stats["unparsed_bodies"] = unparsed_bodies
    if skipped_scope:
        warn(f"有 {skipped_scope} 個端點不在授權 scope，已跳過")
    if other_methods:
        warn(f"只匯入 GET/POST；已跳過 {other_methods} 個其他 HTTP method")
    if post_disabled:
        warn(f"未啟用 API POST；已跳過 {post_disabled} 個 POST 操作")
    if not endpoints:
        warn("匯入後沒有可測試的端點")
    stats["warnings"] = len(warnings)
    return OpenAPIImportReport(
        endpoints=list(endpoints.values()),
        warnings=warnings,
        stats=stats,
    )


def _unresolved_body_ref(operation: dict[str, Any]) -> str:
    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return ""
    ref = request_body.get("$ref")
    if isinstance(ref, str) and not ref.startswith("#/"):
        return ref
    content = request_body.get("content")
    if not isinstance(content, dict):
        return ""
    for media in content.values():
        if not isinstance(media, dict):
            continue
        schema = media.get("schema")
        if isinstance(schema, dict):
            schema_ref = schema.get("$ref")
            if isinstance(schema_ref, str) and not schema_ref.startswith("#/"):
                return schema_ref
    return ""


def _count_external_refs(value: Any, depth: int = 0) -> int:
    if depth > 8:
        return 0
    if isinstance(value, dict):
        count = 0
        for key, item in value.items():
            if key == "$ref" and isinstance(item, str) and not item.startswith("#"):
                count += 1
            else:
                count += _count_external_refs(item, depth + 1)
        return count
    if isinstance(value, list):
        return sum(_count_external_refs(item, depth + 1) for item in value)
    return 0


def _base_url(
    spec: dict[str, Any],
    scope: Scope,
    *,
    servers: Any = None,
) -> str:
    candidates = servers if isinstance(servers, list) and servers else spec.get("servers")
    if isinstance(candidates, list) and candidates:
        for server in candidates:
            if not isinstance(server, dict):
                continue
            raw = _server_url(server)
            if raw:
                return _strip_trailing(urljoin(scope.base_urls()[0], raw))
    if spec.get("host"):
        scheme = (spec.get("schemes") or ["https"])[0]
        return _strip_trailing(
            f"{scheme}://{spec.get('host')}{spec.get('basePath') or ''}"
        )
    return _strip_trailing(scope.base_urls()[0])


def _server_url(server: dict[str, Any]) -> str:
    raw = str(server.get("url") or "").strip()
    if not raw:
        return ""
    variables = server.get("variables")
    if not isinstance(variables, dict):
        return raw
    for name, definition in variables.items():
        if not isinstance(definition, dict):
            continue
        value = definition.get("default")
        if value is None:
            choices = definition.get("enum")
            if isinstance(choices, list) and choices:
                value = choices[0]
        if value is None:
            continue
        raw = raw.replace(f"{{{name}}}", str(value))
    return raw


def _strip_trailing(value: str) -> str:
    return value.rstrip("/")


def _merge_parameters(
    path_params: list,
    op_params: list,
    spec: dict[str, Any],
) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for item in [*path_params, *op_params]:
        if not isinstance(item, dict):
            continue
        item = _resolve_schema(item, spec)
        key = (str(item.get("name") or ""), str(item.get("in") or ""))
        if key[0]:
            merged[key] = item
    return list(merged.values())


def _build_url(
    base: str,
    path: str,
    parameters: list[dict[str, Any]],
    spec: dict[str, Any],
) -> tuple[str, list[Parameter]]:
    rendered_path = path
    query: list[tuple[str, str]] = []
    endpoint_params: list[Parameter] = []
    for param in parameters:
        placement = str(param.get("in") or "").lower()
        name = str(param.get("name") or "")
        if not name:
            continue
        schema = param.get("schema") if isinstance(param.get("schema"), dict) else param
        value = _sample(schema, spec)
        text = _as_text(value)
        if placement == "path":
            rendered_path = rendered_path.replace(f"{{{name}}}", text)
        elif placement == "query":
            query.append((name, text))
            endpoint_params.append(Parameter(name=name, location="query", value=text))
    path_part = rendered_path if rendered_path.startswith("/") else f"/{rendered_path}"
    url = f"{base}{path_part}"
    if query:
        parsed = urlsplit(url)
        merged_query = urlencode(query, doseq=True)
        if parsed.query:
            merged_query = f"{parsed.query}&{merged_query}"
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, merged_query, ""))
    return url, endpoint_params


def _build_body(
    operation: dict[str, Any],
    parameters: list[dict[str, Any]],
    spec: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[Parameter]]:
    schema: dict[str, Any] | None = None
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        request_body = _resolve_schema(request_body, spec)
        content = request_body.get("content") or {}
        if isinstance(content, dict):
            media = content.get("application/json") or next(
                (value for value in content.values() if isinstance(value, dict)), None
            )
            if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                schema = media["schema"]
    if schema is None:
        for param in parameters:
            if str(param.get("in") or "").lower() == "body" and isinstance(
                param.get("schema"), dict
            ):
                schema = param["schema"]
                break
    if schema is None:
        return None, []
    resolved = _resolve_schema(schema, spec)
    if not isinstance(resolved, dict):
        return None, []
    body = _sample(resolved, spec)
    if not isinstance(body, dict):
        body = {"input": body}
    body_params = _flatten_body(body)
    return body, body_params


def _flatten_body(body: dict[str, Any], prefix: str = "", depth: int = 0) -> list[Parameter]:
    if depth > 5:
        return []
    params: list[Parameter] = []
    for key, value in list(body.items())[:30]:
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            params.extend(_flatten_body(value, path, depth + 1))
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                params.extend(_flatten_body(value[0], f"{path}[0]", depth + 1))
            elif value:
                params.append(Parameter(name=f"{path}[0]", location="body", value=None))
            else:
                params.append(Parameter(name=path, location="body", value=None))
        else:
            params.append(Parameter(name=path, location="body", value=None))
        if len(params) >= 30:
            break
    return params[:30]


def _resolve_schema(schema: dict[str, Any], spec: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    if depth > 5:
        return schema
    ref = schema.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return schema
    node: Any = spec
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return schema
        node = node.get(part.replace("~1", "/").replace("~0", "~"))
    if isinstance(node, dict):
        return _resolve_schema(node, spec, depth + 1)
    return schema


def _schema_type(schema: dict[str, Any]) -> str | None:
    """OpenAPI 3.1 permits type to be a list, including ["string", "null"]."""
    raw = schema.get("type")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and item != "null":
                return item
        return "null" if raw else None
    return str(raw) if isinstance(raw, str) else None


def _all_of_properties(
    parts: list,
    spec: dict[str, Any],
    depth: int = 0,
) -> dict[str, Any]:
    if depth > 4:
        return {}
    properties: dict[str, Any] = {}
    for part in parts:
        if not isinstance(part, dict):
            continue
        resolved = _resolve_schema(part, spec)
        if not isinstance(resolved, dict):
            continue
        nested = resolved.get("allOf")
        if isinstance(nested, list):
            properties.update(_all_of_properties(nested, spec, depth + 1))
        child_properties = resolved.get("properties")
        if isinstance(child_properties, dict):
            properties.update(child_properties)
    return properties


def _sample(schema: dict[str, Any] | None, spec: dict[str, Any], depth: int = 0) -> Any:
    if not isinstance(schema, dict) or depth > 4:
        return "test"
    if "$ref" in schema:
        schema = _resolve_schema(schema, spec)
    if "const" in schema:
        return schema["const"]
    if "example" in schema:
        return schema["example"]
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[0]
    if "default" in schema:
        return schema["default"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]

    all_of = schema.get("allOf")
    if isinstance(all_of, list) and all_of:
        properties = _all_of_properties(all_of, spec, depth)
        own_properties = schema.get("properties")
        if isinstance(own_properties, dict):
            properties.update(own_properties)
        if properties:
            return {
                str(key): _sample(value, spec, depth + 1)
                for key, value in list(properties.items())[:20]
            }
        return _sample(all_of[0], spec, depth + 1)

    for keyword in ("oneOf", "anyOf"):
        options = schema.get(keyword)
        if not isinstance(options, list) or not options:
            continue
        chosen = next(
            (
                option
                for option in options
                if not isinstance(option, dict)
                or _schema_type(_resolve_schema(option, spec)) != "null"
            ),
            options[0],
        )
        return _sample(chosen, spec, depth + 1)

    schema_type = _schema_type(schema)
    if schema_type == "object" or "properties" in schema:
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return {}
        return {
            str(key): _sample(value, spec, depth + 1)
            for key, value in list(properties.items())[:20]
        }
    if schema_type == "array":
        item = schema.get("items")
        return [_sample(item, spec, depth + 1)] if isinstance(item, dict) else []
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1.0
    if schema_type == "boolean":
        return True
    if schema_type == "string":
        fmt = schema.get("format")
        if fmt == "date":
            return "2026-01-01"
        if fmt == "date-time":
            return "2026-01-01T00:00:00Z"
        return "test"
    if schema_type == "null":
        return None
    return "test"


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
