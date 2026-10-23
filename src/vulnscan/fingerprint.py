from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from selectolax.lexbor import LexborHTMLParser as HTMLParser

from .models import Page

WAF_SIGNATURES = {
    "cloudflare": ("cloudflare", "cf-ray", "__cf_bm"),
    "akamai": ("akamai", "akamai-ghost", "ak_bmsc"),
    "sucuri": ("sucuri", "x-sucuri-id"),
    "imperva": ("imperva", "incap_ses", "visid_incap"),
    "f5": ("big-ip", "ts_", "f5_cspm"),
    "aws-waf": ("awswaf", "x-amzn-waf"),
}


def fingerprint_pages(pages: list[Page]) -> dict[str, Any]:
    result: dict[str, Any] = {"hosts": {}}
    for page in pages:
        host = urlsplit(page.url).hostname or page.url
        info = result["hosts"].setdefault(
            host,
            {
                "server": None,
                "powered_by": None,
                "generator": None,
                "title": None,
                "waf": [],
                "cookie_names": [],
                "https": page.url.startswith("https://"),
            },
        )
        info["server"] = info["server"] or page.headers.get("server")
        info["powered_by"] = info["powered_by"] or page.headers.get("x-powered-by")
        if page.is_html and page.text:
            try:
                tree = HTMLParser(page.text)
                if not info["title"]:
                    title_node = tree.css_first("title")
                    if title_node:
                        info["title"] = title_node.text(strip=True)[:120]
                if not info["generator"]:
                    generator = tree.css_first('meta[name="generator"]')
                    if generator:
                        info["generator"] = generator.attributes.get("content")
            except Exception:
                pass
        for cookie in page.set_cookie:
            name = cookie.split("=", 1)[0].strip()
            if name and name not in info["cookie_names"] and len(info["cookie_names"]) < 20:
                info["cookie_names"].append(name)
        haystack = " ".join(
            [
                str(page.headers.get("server", "")),
                str(page.headers.get("x-powered-by", "")),
                " ".join(page.headers.keys()),
                " ".join(info["cookie_names"]),
            ]
        ).lower()
        for waf, signatures in WAF_SIGNATURES.items():
            if any(signature in haystack for signature in signatures) and waf not in info["waf"]:
                info["waf"].append(waf)
    return result
