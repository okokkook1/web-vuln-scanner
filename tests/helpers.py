from __future__ import annotations

from datetime import date, timedelta

from vulnscan.models import Profile, ScanConfig


def make_config(base: str, **overrides) -> ScanConfig:
    data = {
        "targets": [base],
        "allow_private": True,
        "authorized_by": "測試授權人",
        "contact": "security@example.com",
        "expires": date.today() + timedelta(days=30),
        "profile": Profile.SAFE,
        "rps_per_host": 50,
        "max_requests_per_host": 500,
        "max_depth": 2,
        "timeout": 5,
        "user_agent": "VulnScan-Test",
    }
    data.update(overrides)
    if data.get("allow_api_post") and not data.get("api_post_allowlist"):
        data.setdefault("api_post_all_ack", True)
    return ScanConfig(**data)
