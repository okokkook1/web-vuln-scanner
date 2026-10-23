from __future__ import annotations

import contextlib
import json
import threading
from pathlib import Path
from typing import Any

from .models import utcnow


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    secret_tokens = ("auth", "cookie", "token", "secret", "api-key", "apikey", "password")
    clean: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in {"authorization", "cookie", "proxy-authorization"} or any(
            token in lowered for token in secret_tokens
        ):
            clean[key] = "<redacted>"
        elif lowered == "set-cookie":
            clean[key] = "<redacted; cookie name retained separately>"
        else:
            clean[key] = value
    return clean


class AuditLogger:
    """Append-only JSONL audit trail for every outbound request."""

    def __init__(self, path: Path, scan_id: str) -> None:
        self.path = path
        self.scan_id = scan_id
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._file = path.open("a", encoding="utf-8")

    def log(
        self,
        *,
        method: str,
        url: str,
        status: int,
        request_headers: dict[str, str],
        response_headers: dict[str, str],
        body_excerpt: str = "",
        rule_id: str | None = None,
        error: str | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "ts": utcnow().isoformat(),
            "scan_id": self.scan_id,
            "method": method,
            "url": url,
            "status": status,
            "rule_id": rule_id,
            "request_headers": _redact_headers(request_headers),
            "response_headers": _redact_headers(response_headers),
            "body_excerpt": body_excerpt[:500],
        }
        if error:
            record["error"] = error
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            self._file.write(line + "\n")
            self._file.flush()

    def write_scope(self, snapshot: dict[str, Any]) -> None:
        import yaml

        scope_path = self.path.parent / "scope.yaml"
        scope_path.write_text(
            yaml.safe_dump(snapshot, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )

    def close(self) -> None:
        with self._lock, contextlib.suppress(OSError):
            self._file.close()
