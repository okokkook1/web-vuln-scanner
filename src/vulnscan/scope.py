from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from datetime import date
from fnmatch import fnmatch
from urllib.parse import urlparse, urlunparse

from .models import ScanConfig


class ScopeError(ValueError):
    pass


DEFAULT_IGNORED_PATH_PARTS = (
    "logout",
    "signout",
    "sign-out",
    "logoff",
    "delete",
    "remove",
    "destroy",
    "unsubscribe",
    "deactivate",
    "revoke",
)


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    return not ip.is_global


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"無法解析目標主機：{host}（{exc}）") from exc
    addresses: set[str] = set()
    for info in infos:
        addresses.add(str(info[4][0]))
    return sorted(addresses)


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ScopeError("目標不可空白")
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"只支援 http/https：{raw}")
    if not parsed.hostname:
        raise ScopeError(f"目標缺少主機名稱：{raw}")
    if parsed.username or parsed.password:
        raise ScopeError("目標網址不可包含帳密")
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", parsed.query, ""))


@dataclass
class Scope:
    config: ScanConfig
    seeds: list[str]
    allowed_hosts: set[str]
    allowed_ips: set[str]
    exclude_patterns: list[str] = field(default_factory=list)
    resolved: dict[str, list[str]] = field(default_factory=dict)

    def is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        host = parsed.hostname.lower()
        if host in self.allowed_hosts:
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return str(ip) in self.allowed_ips

    def is_excluded(self, url: str) -> bool:
        parsed = urlparse(url)
        candidates = [url, parsed.path, f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path]
        for pattern in self.exclude_patterns:
            if any(fnmatch(candidate, pattern) for candidate in candidates):
                return True
        path = parsed.path.lower()
        return any(part in path for part in DEFAULT_IGNORED_PATH_PARTS)

    def base_urls(self) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for seed in self.seeds:
            parsed = urlparse(seed)
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base not in seen:
                seen.add(base)
                result.append(base + "/")
        return result

    def host_bases(self) -> list[tuple[str, str]]:
        """Return (host, base_url) pairs."""
        result: list[tuple[str, str]] = []
        seen: set[str] = set()
        for seed in self.seeds:
            parsed = urlparse(seed)
            if not parsed.hostname:
                continue
            host = parsed.hostname.lower()
            base = f"{parsed.scheme}://{parsed.netloc}/"
            key = f"{host}|{base}"
            if key not in seen:
                seen.add(key)
                result.append((host, base))
        return result

    def snapshot(self) -> dict:
        return {
            "targets": self.config.targets,
            "seeds": self.seeds,
            "allowed_hosts": sorted(self.allowed_hosts),
            "allowed_ips": sorted(self.allowed_ips),
            "exclude": self.exclude_patterns,
            "allow_private": self.config.allow_private,
            "authorized_by": self.config.authorized_by,
            "contact": self.config.contact,
            "expires": self.config.expires.isoformat(),
            "profile": self.config.profile.value,
            "advanced_checks": [item.value for item in self.config.advanced_checks],
            "advanced_ack": self.config.advanced_ack,
            "auth": self.config.auth.summary(),
            "api": {
                "openapi": bool(self.config.openapi_spec or self.config.openapi_url),
                "name": self.config.openapi_name,
                "url": self.config.openapi_url,
                "expected_spec_fingerprint": self.config.openapi_fingerprint,
                "allow_post": self.config.allow_api_post,
                "post_allowlist": self.config.api_post_allowlist,
                "post_allow_all": self.config.api_post_all_ack,
                "max_api_tests": self.config.max_api_tests,
                "bola": {
                    "enabled": self.config.enable_bola,
                    "ack": self.config.bola_ack,
                    "secondary_auth": (
                        self.config.bola_auth.summary()
                        if self.config.bola_auth
                        else None
                    ),
                    "allowlist": self.config.bola_allowlist,
                    "allow_all": self.config.bola_allow_all_ack,
                    "max_tests": self.config.max_bola_tests,
                },
            },
        }


def build_scope(config: ScanConfig) -> Scope:
    if config.expires < date.today():
        raise ScopeError("授權到期日已過，請更新授權後再掃描")

    seeds: list[str] = []
    allowed_hosts: set[str] = set()
    allowed_ips: set[str] = set()
    resolved: dict[str, list[str]] = {}
    exclude_patterns = [item.strip() for item in config.exclude if item.strip()]

    for raw in config.targets:
        raw = raw.strip()
        if not raw:
            continue

        cidr_candidate = "/" in raw and "://" not in raw
        if cidr_candidate:
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                raise ScopeError(f"無效的網段：{raw}") from exc
            if network.version != 4:
                raise ScopeError("v1 僅支援 IPv4 網段")
            if network.num_addresses > 100:
                raise ScopeError(f"網段過大（{network.num_addresses} 個位址），單次最多 100 個")
            for ip in network.hosts():
                text = str(ip)
                if _is_private_ip(text) and not config.allow_private:
                    raise ScopeError(f"目標為私有 IP：{text}；如為授權內網請開啟 allow_private")
                allowed_ips.add(text)
                allowed_hosts.add(text)
                seeds.append(f"http://{text}/")
                seeds.append(f"https://{text}/")
            continue

        url = normalize_url(raw)
        parsed = urlparse(url)
        assert parsed.hostname
        host = parsed.hostname.lower()
        allowed_hosts.add(host)

        if host not in resolved:
            try:
                ipaddress.ip_address(host)
                addresses = [host]
            except ValueError:
                addresses = _resolve(host)
            for address in addresses:
                if _is_private_ip(address) and not config.allow_private:
                    raise ScopeError(
                        f"目標 {host} 解析到私有 IP {address}；如為授權內網請開啟 allow_private"
                    )
            resolved[host] = addresses
            allowed_ips.update(addresses)

        seeds.append(url)

    if not seeds:
        raise ScopeError("沒有可掃描的目標")

    # Keep ordering but remove duplicates.
    unique_seeds = list(dict.fromkeys(seeds))
    if len(unique_seeds) > 250:
        raise ScopeError("展開後的目標過多，請縮小網段或減少目標")

    return Scope(
        config=config,
        seeds=unique_seeds,
        allowed_hosts=allowed_hosts,
        allowed_ips=allowed_ips,
        exclude_patterns=exclude_patterns,
        resolved=resolved,
    )
