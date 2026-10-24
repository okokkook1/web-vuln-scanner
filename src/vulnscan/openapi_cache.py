from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from .models import AuthConfig, AuthType

CACHE_FORMAT = 1
DEFAULT_TTL_SECONDS = 60 * 60
MAX_ENTRY_BYTES = 5 * 1024 * 1024


def auth_cache_key(auth: AuthConfig | None) -> str:
    if auth is None or auth.type is AuthType.NONE:
        return "anonymous"
    summary = auth.summary()
    canonical = json.dumps(
        {
            "type": summary.get("type"),
            "login_url": summary.get("login_url"),
            "verify_url": summary.get("verify_url"),
            "refresh_url": summary.get("refresh_url"),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class OpenAPIRefCache:
    """Small on-disk cache for external OpenAPI $ref documents."""

    def __init__(
        self,
        directory: Path,
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self.directory = directory
        self.ttl_seconds = max(0, ttl_seconds)

    def get(
        self,
        url: str,
        auth_key: str = "anonymous",
    ) -> tuple[dict[str, Any], str] | None:
        path = self._path(url, auth_key)
        if not path.is_file():
            return None
        try:
            if path.stat().st_size > MAX_ENTRY_BYTES:
                path.unlink(missing_ok=True)
                return None
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("format") != CACHE_FORMAT:
                path.unlink(missing_ok=True)
                return None
            fetched_at = float(payload.get("fetched_at") or 0)
            if self.ttl_seconds and time.time() - fetched_at > self.ttl_seconds:
                path.unlink(missing_ok=True)
                return None
            document = payload.get("document")
            final_url = str(payload.get("final_url") or url)
            if not isinstance(document, dict):
                path.unlink(missing_ok=True)
                return None
            return document, final_url
        except (OSError, ValueError, TypeError):
            path.unlink(missing_ok=True)
            return None

    def set(
        self,
        url: str,
        final_url: str,
        document: dict[str, Any],
        auth_key: str = "anonymous",
    ) -> None:
        if not isinstance(document, dict):
            return
        payload = {
            "format": CACHE_FORMAT,
            "url": url,
            "final_url": final_url,
            "auth_key": auth_key,
            "fetched_at": time.time(),
            "document": document,
        }
        try:
            rendered = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError):
            return
        if len(rendered) > MAX_ENTRY_BYTES:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self._path(url, auth_key)
        temp = path.with_suffix(f".{os.getpid()}.{time.time_ns()}.tmp")
        try:
            temp.write_bytes(rendered)
            temp.replace(path)
        except OSError:
            temp.unlink(missing_ok=True)

    def clear(self) -> int:
        if not self.directory.exists():
            return 0
        removed = 0
        for path in self.directory.glob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
        return removed

    def _path(self, url: str, auth_key: str) -> Path:
        digest = hashlib.sha256(
            f"{auth_key}\n{url}".encode()
        ).hexdigest()
        return self.directory / f"{digest}.json"
