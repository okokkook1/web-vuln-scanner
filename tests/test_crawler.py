from __future__ import annotations

import asyncio
from pathlib import Path

from vulnscan.audit import AuditLogger
from vulnscan.crawler import Crawler
from vulnscan.http import HttpEngine
from vulnscan.scope import build_scope

from .fixture_server import fixture_server
from .helpers import make_config


async def test_crawler_discovers_pages_forms_and_javascript(tmp_path: Path):
    with fixture_server() as base:
        config = make_config(base)
        scope = build_scope(config)
        audit = AuditLogger(tmp_path / "audit.jsonl", "scan_test")
        engine = HttpEngine(
            scope=scope,
            config=config,
            audit=audit,
            cancel_event=asyncio.Event(),
            user_agent="VulnScan-Test",
        )
        try:
            result = await Crawler(engine, scope, config).crawl()
        finally:
            await engine.close()
            audit.close()

    urls = {page.url for page in result.pages}
    endpoint_urls = {endpoint.url for endpoint in result.endpoints}
    assert any(url.endswith("/") for url in urls)
    assert any("/app.js" in url for url in urls)
    assert any("/error" in url for url in urls)
    assert any("/hidden" in url for url in urls)
    assert any("/search" in url for url in endpoint_urls)
    assert not any("logout" in url for url in endpoint_urls)
    assert result.stats["pages"] >= 4
