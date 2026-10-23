from __future__ import annotations

import asyncio
from pathlib import Path

from vulnscan.audit import AuditLogger
from vulnscan.http import HostRateLimiter, HttpEngine, RequestStats
from vulnscan.scope import build_scope

from .fixture_server import fixture_server
from .helpers import make_config


async def test_http_engines_can_share_stats_and_limiter(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(base)
        scope = build_scope(config)
        stats = RequestStats()
        limiter = HostRateLimiter(config.rps_per_host)
        audit = AuditLogger(tmp_path / "audit.jsonl", "shared-http-test")
        primary = HttpEngine(
            scope=scope,
            config=config,
            audit=audit,
            cancel_event=asyncio.Event(),
            user_agent="VulnScan-Test",
            limiter=limiter,
            stats=stats,
        )
        secondary = HttpEngine(
            scope=scope,
            config=config,
            audit=audit,
            cancel_event=asyncio.Event(),
            user_agent="VulnScan-Test",
            limiter=limiter,
            stats=stats,
            auth_cookies={"auth": "secondary"},
        )
        try:
            assert (await primary.get(f"{base}/")).status == 200
            assert (await secondary.get(f"{base}/page?x=1")).status == 200
            assert primary.stats is secondary.stats
            assert stats.total == 2
            assert stats.by_host["127.0.0.1"] == 2
            secondary.update_auth({}, {"auth": "updated"})
            assert secondary.client.cookies.get("auth") == "updated"
        finally:
            await primary.close()
            await secondary.close()
            audit.close()
