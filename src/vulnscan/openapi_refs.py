from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

from .http import ScanCancelled
from .scope import Scope

FetchDocument = Callable[[str], Awaitable[tuple[dict[str, Any], str]]]
MISSING = object()
MAX_DEPTH = 12


@dataclass
class RefBundleResult:
    spec: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


def fingerprint_spec(spec: dict[str, Any]) -> str:
    """Stable fingerprint of an OpenAPI document, independent of key order."""
    canonical = json.dumps(
        spec,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def bundle_external_refs(
    spec: dict[str, Any],
    *,
    base_url: str | None,
    scope: Scope,
    fetch: FetchDocument,
    max_documents: int = 8,
    max_refs: int = 100,
) -> RefBundleResult:
    """Resolve HTTP(S) external ``$ref`` documents within the authorized scope.

    This is intentionally a small JSON Reference bundler, not a general schema
    validator. It only follows HTTP(S) refs; local-file refs are left unresolved
    and reported as warnings.
    """
    warnings: list[str] = []
    stats: dict[str, int] = {
        "refs": 0,
        "external_refs": 0,
        "resolved_refs": 0,
        "external_documents": 0,
        "skipped_scope": 0,
        "failed_refs": 0,
        "cycle_refs": 0,
        "warnings": 0,
    }

    def warn(message: str) -> None:
        if len(warnings) < 30:
            warnings.append(message)

    documents: dict[str, dict[str, Any]] = {}
    document_bases: dict[str, str] = {}
    main_key = base_url or ""
    documents[main_key] = spec
    document_bases[main_key] = base_url or ""
    stack: set[tuple[str, str]] = set()
    ref_count = 0

    async def get_document(
        target_url: str,
        current_base: str,
    ) -> tuple[dict[str, Any], str] | None:
        target_url = urljoin(current_base, target_url)
        parsed = urlsplit(target_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            warn(f"外部 $ref 不是 HTTP(S) URL，已跳過：{target_url}")
            stats["failed_refs"] += 1
            return None
        if not scope.is_allowed(target_url):
            warn(f"外部 $ref 不在授權 scope，已跳過：{target_url}")
            stats["skipped_scope"] += 1
            return None
        if target_url in documents:
            return documents[target_url], document_bases[target_url]
        if stats["external_documents"] >= max_documents:
            warn(f"外部文件數量達到上限 {max_documents}，已停止載入")
            stats["failed_refs"] += 1
            return None
        try:
            loaded, final_url = await fetch(target_url)
        except ScanCancelled:
            raise
        except Exception as exc:
            warn(f"外部 $ref 取得失敗：{target_url}（{exc}）")
            stats["failed_refs"] += 1
            return None
        if not isinstance(loaded, dict):
            warn(f"外部 $ref 文件不是 JSON/YAML 物件：{target_url}")
            stats["failed_refs"] += 1
            return None
        stats["external_documents"] += 1
        documents[target_url] = loaded
        documents[final_url] = loaded
        document_bases[target_url] = final_url
        document_bases[final_url] = final_url
        return loaded, final_url

    async def resolve_ref(
        node: dict[str, Any],
        doc_url: str,
        document: dict[str, Any],
        depth: int,
    ) -> Any:
        nonlocal ref_count
        ref = node.get("$ref")
        if not isinstance(ref, str):
            return node
        ref_count += 1
        stats["refs"] += 1
        if ref_count > max_refs:
            warn(f"$ref 數量達到上限 {max_refs}，其餘參照保留未解析")
            stats["failed_refs"] += 1
            return node

        doc_part, _separator, fragment = ref.partition("#")
        if doc_part:
            stats["external_refs"] += 1
            target_url = urljoin(doc_url, doc_part)
        else:
            target_url = doc_url
        target_url = target_url.rstrip("#")

        if not doc_part and doc_url == main_key:
            # Main-spec internal refs are handled by the synchronous parser.
            # Their component targets are still traversed separately.
            return {
                key: await walk(value, doc_url, document, False, depth + 1)
                if key != "$ref"
                else value
                for key, value in node.items()
            }

        if doc_part:
            fetched = await get_document(doc_part, doc_url)
            if fetched is None:
                return node
            target_document, target_base = fetched
        else:
            target_document = document
            target_base = doc_url

        cycle_key = (target_base or target_url, fragment)
        if cycle_key in stack:
            warn(f"偵測到循環 $ref，已停止展開：{ref}")
            stats["cycle_refs"] += 1
            return {"type": "object"}
        target = _resolve_pointer(target_document, fragment)
        if target is MISSING:
            warn(f"$ref 片段找不到：{ref}")
            stats["failed_refs"] += 1
            return node

        siblings = {
            key: value for key, value in node.items() if key != "$ref"
        }
        stack.add(cycle_key)
        try:
            resolved = await walk(
                copy.deepcopy(target),
                target_base,
                target_document,
                True,
                depth + 1,
            )
            if siblings:
                walked_siblings = {
                    key: await walk(value, target_base, target_document, True, depth + 1)
                    for key, value in siblings.items()
                }
                resolved = (
                    {**resolved, **walked_siblings}
                    if isinstance(resolved, dict)
                    else walked_siblings
                )
        finally:
            stack.remove(cycle_key)
        stats["resolved_refs"] += 1
        return resolved

    async def walk(
        value: Any,
        doc_url: str,
        document: dict[str, Any],
        expand_internal: bool,
        depth: int = 0,
    ) -> Any:
        if depth > MAX_DEPTH:
            warn("外部 $ref 展開深度過深，已停止遞迴")
            return value
        if isinstance(value, dict):
            if "$ref" in value and (
                expand_internal or bool(str(value.get("$ref") or "").partition("#")[0])
            ):
                return await resolve_ref(value, doc_url, document, depth)
            return {
                key: await walk(item, doc_url, document, expand_internal, depth + 1)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                await walk(item, doc_url, document, expand_internal, depth + 1)
                for item in value
            ]
        return value

    expanded = await walk(spec, main_key, spec, False)
    stats["warnings"] = len(warnings)
    if not isinstance(expanded, dict):
        expanded = spec
    return RefBundleResult(spec=expanded, warnings=warnings, stats=stats)


def _resolve_pointer(document: Any, fragment: str) -> Any:
    if not fragment:
        return document
    if not fragment.startswith("/"):
        return MISSING
    current = document
    for raw_part in fragment[1:].split("/"):
        part = unquote(raw_part).replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if part not in current:
                return MISSING
            current = current[part]
        elif isinstance(current, list):
            try:
                index = int(part)
            except ValueError:
                return MISSING
            if index < 0 or index >= len(current):
                return MISSING
            current = current[index]
        else:
            return MISSING
    return current
