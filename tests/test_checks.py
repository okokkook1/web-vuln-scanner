from __future__ import annotations

from vulnscan.checks.mixed_content import check
from vulnscan.models import Page


class DummyContext:
    pass


def test_mixed_content_only_on_https_pages():
    page = Page(
        url="https://example.com/",
        status=200,
        headers={"content-type": "text/html"},
        content_type="text/html",
        text='<html><body><script src="http://cdn.example/app.js"></script></body></html>',
    )
    findings = check([page], DummyContext())  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].rule_id == "mixed-content"
    assert findings[0].evidence["resources"] == ["http://cdn.example/app.js"]

    http_page = page.model_copy(update={"url": "http://example.com/"})
    assert check([http_page], DummyContext()) == []  # type: ignore[arg-type]
