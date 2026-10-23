from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlmodel import Field as SQLField
from sqlmodel import SQLModel


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_scan_id() -> str:
    return f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }[self.value]

    @property
    def label(self) -> str:
        return {
            "critical": "嚴重",
            "high": "高",
            "medium": "中",
            "low": "低",
            "info": "資訊",
        }[self.value]


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def label(self) -> str:
        return {"high": "高", "medium": "中", "low": "低"}[self.value]


class Profile(str, Enum):
    PASSIVE = "passive"
    SAFE = "safe"
    FULL = "full"

    @property
    def label(self) -> str:
        return {
            "passive": "被動盤點",
            "safe": "安全主動",
            "full": "完整",
        }[self.value]


class AdvancedCheck(str, Enum):
    SQLI_BOOLEAN = "sqli_boolean"
    TRAVERSAL = "traversal"
    SSRF = "ssrf"

    @property
    def label(self) -> str:
        return {
            "sqli_boolean": "布林型 SQL Injection",
            "traversal": "路徑遍歷",
            "ssrf": "SSRF（callback 驗證）",
        }[self.value]


class AuthType(str, Enum):
    NONE = "none"
    COOKIE = "cookie"
    HEADER = "header"
    FORM = "form"
    STATE = "state"
    BROWSER = "browser"

    @property
    def label(self) -> str:
        return {
            "none": "不使用登入",
            "cookie": "Cookie",
            "header": "自訂 Header",
            "form": "表單登入",
            "state": "瀏覽器狀態檔（SSO／MFA）",
            "browser": "瀏覽器互動登入（SSO／MFA）",
        }[self.value]


class AuthConfig(BaseModel):
    type: AuthType = AuthType.NONE
    cookie: str | None = Field(default=None, repr=False)
    header_name: str | None = None
    header_value: str | None = Field(default=None, repr=False)
    login_url: str | None = None
    username: str | None = None
    password: str | None = Field(default=None, repr=False)
    username_field: str = "username"
    password_field: str = "password"
    verify_url: str | None = None
    verify_text: str | None = None
    storage_state: dict[str, Any] | None = Field(default=None, repr=False, exclude=True)
    storage_token_key: str | None = None
    storage_header_name: str | None = None
    storage_header_prefix: str = "Bearer "

    @model_validator(mode="after")
    def _required_fields(self) -> AuthConfig:
        for value in (self.login_url, self.verify_url):
            if not value:
                continue
            parsed = urlsplit(value)
            if parsed.username or parsed.password:
                raise ValueError("登入 URL 不可包含帳密")
        if self.type is AuthType.COOKIE and not (self.cookie or "").strip():
            raise ValueError("Cookie 登入需要提供 Cookie 字串")
        if self.type is AuthType.COOKIE and ("\r" in (self.cookie or "") or "\n" in (self.cookie or "")):
            raise ValueError("Cookie 字串不可包含換行")
        if self.type is AuthType.HEADER and (
            not (self.header_name or "").strip() or not (self.header_value or "").strip()
        ):
            raise ValueError("Header 登入需要提供名稱與值")
        if self.type is AuthType.FORM:
            if not (self.login_url or "").strip():
                raise ValueError("表單登入需要登入 URL")
            if not (self.username or "").strip() or not (self.password or ""):
                raise ValueError("表單登入需要帳號與密碼")
            if not self.username_field.strip() or not self.password_field.strip():
                raise ValueError("帳號與密碼欄位名稱不可空白")
        if self.type is AuthType.STATE or self.type is AuthType.BROWSER:
            if not isinstance(self.storage_state, dict):
                raise ValueError("瀏覽器登入需要 storage state")
            if self.storage_token_key and not (self.storage_header_name or "").strip():
                raise ValueError("指定 localStorage token 時需要提供 Header 名稱")
            if self.storage_header_name and not (self.storage_token_key or "").strip():
                raise ValueError("指定 Header 時需要提供 localStorage token key")
        return self

    def summary(self) -> dict[str, str | None]:
        def safe_url(value: str | None) -> str | None:
            if not value:
                return None
            parsed = urlsplit(value)
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

        return {
            "type": self.type.value,
            "login_url": safe_url(self.login_url),
            "verify_url": safe_url(self.verify_url),
        }


class Parameter(BaseModel):
    name: str
    location: Literal["query", "body", "path", "header", "cookie"] = "query"
    value: str | None = None


class FormField(BaseModel):
    name: str
    type: str = "text"
    value: str | None = None


class FormInfo(BaseModel):
    action: str
    method: str = "GET"
    fields: list[FormField] = Field(default_factory=list)
    has_token: bool = False


class Endpoint(BaseModel):
    url: str
    method: str = "GET"
    params: list[Parameter] = Field(default_factory=list)
    source: Literal["crawl", "form", "js", "openapi", "manual"] = "crawl"
    depth: int = 0
    body: dict[str, Any] | None = None
    content_type: str = "application/json"


class Page(BaseModel):
    url: str
    status: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    set_cookie: list[str] = Field(default_factory=list)
    text: str = ""
    content_type: str = ""
    elapsed_ms: int = 0
    forms: list[FormInfo] = Field(default_factory=list)
    error: str | None = None

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type.lower() or self.text.lstrip().startswith("<")

    @property
    def is_javascript(self) -> bool:
        return "javascript" in self.content_type.lower() or self.url.lower().endswith(".js")


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    url: str
    method: str = "GET"
    parameter: str | None = None
    category: str = ""
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    refs: dict[str, str] = Field(default_factory=dict)


class ScanConfig(BaseModel):
    targets: list[str]
    exclude: list[str] = Field(default_factory=list)
    allow_private: bool = False
    authorized_by: str
    contact: str
    expires: date
    profile: Profile = Profile.SAFE
    rps_per_host: float = Field(default=3.0, ge=0.2, le=50)
    max_requests_per_host: int = Field(default=2000, ge=20, le=100_000)
    max_depth: int = Field(default=3, ge=0, le=10)
    timeout: float = Field(default=10.0, ge=1, le=60)
    user_agent: str = ""
    proxy: str | None = None
    advanced_checks: list[AdvancedCheck] = Field(default_factory=list)
    advanced_ack: bool = False
    ssrf_callback: str | None = None
    auth: AuthConfig = Field(default_factory=AuthConfig)
    openapi_spec: dict[str, Any] | None = Field(default=None, repr=False, exclude=True)
    openapi_url: str | None = None
    openapi_name: str | None = None
    openapi_fingerprint: str | None = None
    allow_api_post: bool = False
    api_post_allowlist: list[str] = Field(default_factory=list)
    api_post_all_ack: bool = False
    max_api_tests: int = Field(default=20, ge=1, le=200)
    enable_bola: bool = False
    bola_ack: bool = False
    bola_auth: AuthConfig | None = Field(default=None, exclude=True)
    bola_allowlist: list[str] = Field(default_factory=list)
    bola_allow_all_ack: bool = False
    max_bola_tests: int = Field(default=8, ge=1, le=50)

    @field_validator("targets")
    @classmethod
    def _targets_not_empty(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        if not cleaned:
            raise ValueError("請至少輸入一個目標")
        if len(cleaned) > 50:
            raise ValueError("一次最多 50 個目標")
        return cleaned

    @field_validator("authorized_by", "contact")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("授權人與聯絡人不可空白")
        return value

    @field_validator("advanced_checks")
    @classmethod
    def _dedupe_advanced(cls, value: list[AdvancedCheck]) -> list[AdvancedCheck]:
        return list(dict.fromkeys(value))

    @field_validator("api_post_allowlist", "bola_allowlist")
    @classmethod
    def _clean_api_post_allowlist(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in value:
            text = str(raw).strip()
            if not text:
                continue
            if len(text) > 300:
                raise ValueError("白名單項目過長（上限 300 字元）")
            cleaned.append(text)
        if len(cleaned) > 100:
            raise ValueError("白名單最多 100 條")
        return list(dict.fromkeys(cleaned))

    @field_validator("ssrf_callback")
    @classmethod
    def _validate_ssrf_callback(cls, value: str | None) -> str | None:
        if not value:
            return None
        value = value.strip().rstrip("/")
        parsed = urlsplit(value)
        if parsed.scheme != "http":
            raise ValueError("SSRF callback 僅支援 http://")
        if not parsed.hostname or parsed.hostname in ("0.0.0.0", "::"):
            raise ValueError(
                "SSRF callback 必須是目標可連線的主機名稱或 IP，不能使用 0.0.0.0"
            )
        if parsed.username or parsed.password:
            raise ValueError("SSRF callback 不可包含帳密")
        if parsed.query or parsed.fragment:
            raise ValueError("SSRF callback 不可包含 query 或 fragment")
        return value

    @model_validator(mode="after")
    def _advanced_consistency(self) -> ScanConfig:
        if self.profile is Profile.FULL:
            if not self.advanced_checks:
                raise ValueError("完整模式至少需要選擇一項進階檢查")
            if not self.advanced_ack:
                raise ValueError("完整模式需要明確確認進階檢查")
        elif self.advanced_checks:
            raise ValueError("進階檢查僅適用於完整模式")
        if self.allow_api_post and self.profile is Profile.PASSIVE:
            raise ValueError("API POST 主動測試需要安全主動或完整模式")
        if self.openapi_spec and self.openapi_url:
            raise ValueError("OpenAPI 檔案與 URL 只能擇一")
        if self.openapi_url:
            parsed = urlsplit(self.openapi_url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError("OpenAPI URL 必須是 http:// 或 https:// 網址")
            if parsed.username or parsed.password:
                raise ValueError("OpenAPI URL 不可包含帳密")
        if self.allow_api_post and not (self.openapi_spec or self.openapi_url):
            raise ValueError("啟用 API POST 主動測試前，請先提供 OpenAPI 檔案或 URL")
        if (
            self.allow_api_post
            and not self.api_post_allowlist
            and not self.api_post_all_ack
        ):
            raise ValueError(
                "API POST 白名單為空；請提供白名單，或明確確認要測試所有 POST 端點"
            )
        if self.enable_bola:
            if self.profile is Profile.PASSIVE:
                raise ValueError("BOLA／IDOR 檢查需要安全主動或完整模式")
            if not self.bola_ack:
                raise ValueError("BOLA／IDOR 檢查需要明確確認")
            if self.auth.type is AuthType.NONE:
                raise ValueError("BOLA／IDOR 檢查需要主要帳號的登入設定")
            if self.bola_auth is None or self.bola_auth.type is AuthType.NONE:
                raise ValueError("BOLA／IDOR 檢查需要第二個帳號的登入設定")
            if self.bola_auth == self.auth:
                raise ValueError("BOLA／IDOR 的主要與次要帳號不可相同")
            if not self.bola_allowlist and not self.bola_allow_all_ack:
                raise ValueError(
                    "BOLA GET 白名單為空；請提供白名單，"
                    "或明確確認要測試所有 BOLA 候選 GET 端點"
                )
        return self


class ScanStats(BaseModel):
    requests: int = 0
    endpoints: int = 0
    pages: int = 0
    findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    fingerprint: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    stats: ScanStats
    findings: list[Finding] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    fingerprint: dict[str, Any] = Field(default_factory=dict)


class Scan(SQLModel, table=True):
    __tablename__ = "scans"

    id: str = SQLField(primary_key=True)
    created_at: datetime = SQLField(default_factory=utcnow, index=True)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    status: str = SQLField(default="queued", index=True)
    profile: str = "safe"
    targets_json: str = "[]"
    scope_json: str = "{}"
    stats_json: str = "{}"
    phase: str = "排隊中"
    progress: int = 0
    message: str = ""
    error: str | None = None


class FindingRecord(SQLModel, table=True):
    __tablename__ = "findings"

    id: int | None = SQLField(default=None, primary_key=True)
    scan_id: str = SQLField(foreign_key="scans.id", index=True)
    fingerprint: str = SQLField(default="", index=True)
    rule_id: str = SQLField(index=True)
    title: str
    severity: str = SQLField(index=True)
    confidence: str
    url: str
    method: str = "GET"
    parameter: str | None = None
    category: str = ""
    description: str = ""
    evidence_json: str = "{}"
    remediation: str = ""
    refs_json: str = "{}"
    created_at: datetime = SQLField(default_factory=utcnow)


class EndpointRecord(SQLModel, table=True):
    __tablename__ = "endpoints"

    id: int | None = SQLField(default=None, primary_key=True)
    scan_id: str = SQLField(foreign_key="scans.id", index=True)
    url: str
    method: str = "GET"
    params_json: str = "[]"
    source: str = "crawl"
    depth: int = 0


REVIEW_STATUSES = (
    "needs_review",
    "confirmed",
    "false_positive",
    "accepted_risk",
)


class FindingReview(SQLModel, table=True):
    __tablename__ = "finding_reviews"

    finding_id: int = SQLField(primary_key=True, foreign_key="findings.id")
    status: str = SQLField(default="needs_review", index=True)
    note: str = ""
    updated_by: str = "local"
    updated_at: datetime = SQLField(default_factory=utcnow)


class FindingReviewEvent(SQLModel, table=True):
    __tablename__ = "finding_review_events"

    id: int | None = SQLField(default=None, primary_key=True)
    finding_id: int = SQLField(foreign_key="findings.id", index=True)
    status: str = SQLField(default="needs_review")
    note: str = ""
    updated_by: str = "local"
    created_at: datetime = SQLField(default_factory=utcnow)


class FindingReviewState(SQLModel, table=True):
    __tablename__ = "finding_review_states"

    fingerprint: str = SQLField(primary_key=True)
    status: str = SQLField(default="needs_review", index=True)
    note: str = ""
    updated_by: str = "local"
    updated_at: datetime = SQLField(default_factory=utcnow)
    severity: str = ""
    evidence_hash: str = ""
    expires_at: datetime | None = None


class FindingReviewStateEvent(SQLModel, table=True):
    __tablename__ = "finding_review_state_events"

    id: int | None = SQLField(default=None, primary_key=True)
    fingerprint: str = SQLField(index=True)
    status: str = SQLField(default="needs_review")
    note: str = ""
    updated_by: str = "local"
    created_at: datetime = SQLField(default_factory=utcnow)
    expires_at: datetime | None = None


class ScanBaseline(SQLModel, table=True):
    __tablename__ = "scan_baselines"

    target_key: str = SQLField(primary_key=True)
    targets_json: str = "[]"
    scan_id: str = SQLField(foreign_key="scans.id", index=True)
    created_by: str = "local"
    created_at: datetime = SQLField(default_factory=utcnow)


class Suppression(SQLModel, table=True):
    __tablename__ = "suppressions"

    id: int | None = SQLField(default=None, primary_key=True)
    fingerprint: str = SQLField(unique=True, index=True)
    rule_id: str
    host: str = ""
    path: str = ""
    method: str = "GET"
    parameter: str = ""
    reason: str = ""
    created_by: str = "local"
    created_at: datetime = SQLField(default_factory=utcnow)


@dataclass
class FindingView:
    """A finding record plus the suppression state at read time."""

    record: FindingRecord
    suppressed: bool = False
    suppression_id: int | None = None
    suppression_reason: str | None = None
    suppression_created_by: str | None = None
    suppression_created_at: datetime | None = None
    review_status: str = "needs_review"
    review_note: str = ""
    review_updated_by: str | None = None
    review_updated_at: datetime | None = None
    review_expires_at: datetime | None = None

    def __getattr__(self, name: str):
        return getattr(self.record, name)

