from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from . import __version__

APP_NAME = "VulnScan"
DEFAULT_USER_AGENT = f"VulnScan/{__version__} (authorized security testing)"


def default_data_dir() -> Path:
    """Data directory: VULNSCAN_DATA_DIR env var, otherwise ./data."""
    env = os.environ.get("VULNSCAN_DATA_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.cwd() / "data").resolve()


class RuntimeSettings(BaseModel):
    """Defaults used by the new-scan form and the scanner."""

    default_profile: Literal["passive", "safe"] = "safe"
    rps_per_host: float = Field(default=3.0, ge=0.2, le=50)
    max_requests_per_host: int = Field(default=2000, ge=20, le=100_000)
    max_depth: int = Field(default=3, ge=0, le=10)
    timeout: float = Field(default=10.0, ge=1, le=60)
    user_agent: str = DEFAULT_USER_AGENT
    proxy: str | None = None

    @field_validator("user_agent")
    @classmethod
    def _ua_not_blank(cls, value: str) -> str:
        return value.strip() or DEFAULT_USER_AGENT


class SettingsStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.path = data_dir / "settings.json"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def load(self) -> RuntimeSettings:
        if not self.path.exists():
            return RuntimeSettings()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return RuntimeSettings.model_validate(raw)
        except (json.JSONDecodeError, OSError, ValueError):
            return RuntimeSettings()

    def save(self, settings: RuntimeSettings) -> None:
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(settings.model_dump(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(self.path)
