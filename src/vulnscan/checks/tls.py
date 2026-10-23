from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from datetime import UTC, datetime

import certifi

from ..models import Confidence, Severity
from .base import ScanContext, make_finding


def probe_tls(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            cert = tls.getpeercert()
            protocol = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return {"error": str(exc), "cert_error": True}
    except (OSError, ssl.SSLError) as exc:
        return {"error": str(exc), "cert_error": False}

    not_after_raw = cert.get("notAfter") if cert else None
    not_after = None
    days_left = None
    if not_after_raw:
        try:
            not_after = datetime.fromtimestamp(
                ssl.cert_time_to_seconds(not_after_raw), tz=UTC
            )
            days_left = (not_after - datetime.now(UTC)).days
        except (ValueError, OSError):
            pass
    return {"protocol": protocol, "not_after": not_after, "days_left": days_left}


async def check(ctx: ScanContext) -> list:
    findings = []
    seen: set[str] = set()
    for host, base in ctx.scope.host_bases():
        if not base.startswith("https://") or host in seen:
            continue
        seen.add(host)
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        result = await asyncio.to_thread(probe_tls, host, 443, min(5.0, ctx.config.timeout))
        if result.get("cert_error"):
            message = str(result.get("error", ""))
            lowered = message.lower()
            expired = "expired" in lowered
            findings.append(
                make_finding(
                    rule_id="tls-cert-invalid",
                    title="TLS 憑證驗證失敗" + ("（已過期）" if expired else ""),
                    severity=Severity.HIGH if expired else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url=base,
                    category="TLS",
                    description="憑證無法通過驗證，可能是過期、自簽、主機名稱不符或缺少中繼憑證。",
                    evidence={"host": host, "error": message[:500]},
                    remediation="更新憑證、補齊中繼憑證，並確認憑證主機名稱與網域一致。",
                    refs={"owasp": "A02:2021", "cwe": "295"},
                )
            )
            continue
        if result.get("error"):
            continue

        days_left = result.get("days_left")
        if days_left is not None and days_left < 30:
            findings.append(
                make_finding(
                    rule_id="tls-cert-expiring",
                    title="TLS 憑證即將到期",
                    severity=Severity.HIGH if days_left < 7 else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url=base,
                    category="TLS",
                    description=f"憑證剩餘 {days_left} 天到期。",
                    evidence={
                        "host": host,
                        "days_left": days_left,
                        "not_after": result.get("not_after").isoformat()
                        if result.get("not_after")
                        else None,
                    },
                    remediation="在到期前續簽並部署憑證，建議設定到期監控。",
                    refs={"owasp": "A02:2021", "cwe": "298"},
                )
            )
        protocol = str(result.get("protocol") or "")
        if protocol in ("TLSv1", "TLSv1.1"):
            findings.append(
                make_finding(
                    rule_id="tls-old-protocol",
                    title="TLS 協定版本過舊",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    url=base,
                    category="TLS",
                    description="伺服器協商出 TLS 1.0 / 1.1，已被主流瀏覽器淘汰。",
                    evidence={"host": host, "protocol": protocol},
                    remediation="停用 TLS 1.0/1.1，只允許 TLS 1.2 以上。",
                    refs={"owasp": "A02:2021", "cwe": "326"},
                )
            )
    return findings
