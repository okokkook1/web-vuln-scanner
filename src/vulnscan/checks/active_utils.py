from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..models import Endpoint, Parameter

SKIP_PARAMS = {
    "password",
    "passwd",
    "pwd",
    "csrf",
    "csrf_token",
    "xsrf",
    "_token",
    "authenticity_token",
    "token",
    "session",
    "sessionid",
    "auth",
    "captcha",
    "submit",
    "email",
}


def replace_param(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    new_pairs: list[tuple[str, str]] = []
    for key, current in pairs:
        if key == name and not replaced:
            new_pairs.append((key, value))
            replaced = True
        else:
            new_pairs.append((key, current))
    if not replaced:
        new_pairs.append((name, value))
    query = urlencode(new_pairs, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def with_param_values(url: str, params: list[Parameter]) -> str:
    parsed = urlsplit(url)
    current = dict(parse_qsl(parsed.query, keep_blank_values=True))
    pairs: list[tuple[str, str]] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        pairs.append((key, current.get(key, value) or "1"))
    for param in params:
        if param.location == "query" and param.name not in {p[0] for p in pairs}:
            pairs.append((param.name, param.value or "1"))
    query = urlencode(pairs, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def testable_params(endpoints: list[Endpoint], limit: int = 20) -> list[tuple[Endpoint, Parameter]]:
    result: list[tuple[Endpoint, Parameter]] = []
    for endpoint in endpoints:
        if endpoint.method.upper() != "GET":
            continue
        for param in endpoint.params:
            if param.location != "query" or not param.name:
                continue
            if param.name.lower() in SKIP_PARAMS:
                continue
            result.append((endpoint, param))
            if len(result) >= limit:
                return result
    return result
