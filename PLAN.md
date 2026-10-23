# Web 弱點掃描器 — 開發規劃（GUI 優先）

> 定位：針對**已取得書面授權**的網站，做黑箱、非破壞性的弱點偵測與報告。
> 介面：以**本機 Web UI** 為主，瀏覽器操作；CLI 只保留 headless 模式。
> 預設行為是「被動觀察 + 無害 canary」，不包含入侵、提權、資料外洩或阻斷服務。

---

## 1. 目標與邊界

### 介面定位
- **主要介面**：執行 `vulnscan ui` 後開啟瀏覽器（預設 `http://127.0.0.1:8765`），所有操作都在圖形化介面完成。
- **次要介面**：`vulnscan scan` 保留給排程與 CI，v1 不投入太多資源。
- 選擇「本機 Web UI」而非桌面程式（PySide6 / Electron）的原因：
  - Python 生態直接支援，不需要額外打包桌面執行檔
  - 跨 Windows / macOS / Linux
  - 可直接重用 HTML 報告的版型與元件
  - 掃描器本來就是長時間背景工作，Web UI 的分頁、輪詢、非同步模型很合適
- 單機、單人使用；v1 不做多使用者與權限管理。

### 要做
- 圖形化「新增掃描」精靈：目標、授權資訊、掃描設定、確認
- 即時進度：階段、請求數、端點數、發現數、可取消
- 弱點清單與詳情：嚴重度、信心度、證據、修補建議
- 掃描歷史：查看、重新掃描、匯出
- 支援對外網站與內網系統；內網需在 scope 明確設定 `allow_private: true`
- **不需要登入目標網站**即可掃描；登入掃描列為選配，不是 v1 必要條件
- 匯出 **HTML + JSON** 報告

### 不做（v1 明確排除）
- 漏洞利用（exploit）、webshell、資料竊取、權限提升
- 密碼爆破、credential stuffing、大量目錄爆破
- DoS / 壓力測試、繞過 WAF 的攻擊性 payload
- 未授權的第三方網站掃描
- 多使用者帳號、雲端 SaaS 版、分散式掃描叢集

### 成功標準
1. 使用者能在 **3 個步驟內**啟動一次掃描
2. 掃描進度在 **1 秒內**更新，取消能在 **2 秒內**生效
3. 對 OWASP Juice Shop / DVWA 能穩定偵測出規定的基準弱點
4. 對乾淨靜態網站誤報率 < 5%（以人工複核計）
5. 所有請求都有 audit log，報告中的敏感資訊已遮罩
6. 超出 scope 的請求數為 0

---

## 2. 技術選型（已確認）

| 層 | 選擇 | 理由 |
|---|---|---|
| 語言 | Python 3.11+ | 生態完整、非同步成熟 |
| Web 框架 | FastAPI + uvicorn | 非同步、自動 API 文件、與掃描引擎同一個 event loop |
| 模板 | Jinja2 | 伺服器端渲染，不需要前端建置流程 |
| 互動 | 原生 JavaScript + fetch 輪詢 | 局部更新、進度條、取消；不用 SPA |
| CSS | 自訂 CSS（本地、無 CDN） | 離線可用、無 Node 建置流程 |
| 圖表 | CSS 長條圖 | 嚴重度分佈；減少前端依賴 |
| 資料庫 | SQLite（WAL mode） | 單機零設定；掃描歷史與發現持久化 |
| ORM | SQLModel | Pydantic + SQLAlchemy，模型與 API schema 共用 |
| 背景工作 | asyncio + 自製 JobManager | 單機單人不需要 Celery / Redis |
| HTTP | `httpx` AsyncClient | HTTP/2、timeout、proxy、連線池 |
| HTML 解析 | `selectolax` | 快；必要時用 BeautifulSoup 補 |
| CLI | `typer` | `vulnscan ui` / `vulnscan scan` |
| 報告 | Jinja2（HTML）+ 內建 JSON | 單檔 HTML、可離線分享 |
| 測試 | `pytest` + `respx` + FastAPI TestClient | 單元、API、HTML smoke test |
| 品質 | `ruff` + `mypy` | lint / 型別 |
| 可選 | `playwright` | SPA / JS 渲染與網路請求擷取 |

> 不使用 React/Vue，也不引入 Node 建置流程。原生 JS 對這種「表單 + 表格 + 進度條」的內部工具已經足夠。
> 不使用 Electron / PySide6；若之後真的需要「雙擊開啟的桌面視窗」，再包一層 WebView 即可。

---

## 3. 系統架構

```
┌──────────────────────────────────────────────────┐
│ 瀏覽器（原生 JS + 自訂 CSS）                       │
│ 儀表板 / 新增掃描 / 即時進度 / 發現 / 歷史 / 設定 │
└────────────────────┬─────────────────────────────┘
                     │ HTTP（HTML partial + JSON）
┌────────────────────▼─────────────────────────────┐
│ FastAPI（127.0.0.1:8765）                         │
│  routes：pages / scans / findings / exports       │
│  Jinja2 templates + static assets                 │
└───────┬───────────────────────────┬──────────────┘
        │                           │
┌───────▼─────────────┐   ┌─────────▼──────────────┐
│ JobManager          │   │ SQLite（WAL）           │
│ 佇列 / 取消 / 進度   │   │ scans / endpoints /    │
│ asyncio worker      │   │ findings               │
└───────┬─────────────┘   └────────────────────────┘
        │
┌───────▼──────────────────────────────────────────┐
│ Scanner Core                                     │
│ ScopeGuard → Scheduler → Crawler → Fingerprint   │
│ → Checks → Finding Engine（驗證 / 去重 / 遮罩）  │
└───────┬──────────────────────────────────────────┘
        │
   audit.jsonl + 掃描快照（scope.yaml）
```

### 運作方式
1. 使用者在 UI 建立掃描 → 寫入 `scans`（status=`queued`）
2. JobManager 一次跑一個掃描（可設定並行數，預設 1），避免互相搶資源
3. 掃描器在背景 task 執行，階段與計數更新到記憶體 + DB
4. 前端用原生 fetch 每 1 秒輪詢 `/api/scans/{id}/status`，更新進度條與計數
5. 發現即時寫入 `findings`，清單頁可邊掃邊看
6. 完成 / 失敗 / 取消 → 更新 status，產生統計，匯出按鈕生效
7. FastAPI shutdown 時取消執行中的 task，已完成的發現仍保留

### 為什麼用輪詢而不是 WebSocket
- 單機、低頻（1 秒一次）、payload 很小
- `setInterval` 直接支援輪詢，不需要額外狀態管理
- 中斷連線不會留下半開的 WebSocket
- 之後要換 SSE/WebSocket 也只影響進度端點

---

## 4. 圖形化介面設計

### 4.1 頁面清單

| 頁面 | 路徑 | 內容 |
|---|---|---|
| 儀表板 | `/` | 最近掃描、嚴重度統計、快速開始、系統狀態 |
| 新增掃描 | `/scans/new` | 三步驟精靈：目標與授權 → 掃描設定 → 確認 |
| 即時掃描 | `/scans/{id}` | 階段進度、計數、日誌、取消 |
| 弱點清單 | `/scans/{id}/findings` | 篩選、搜尋、表格、匯出 |
| 弱點詳情 | `/findings/{id}` | 說明、證據、修補建議、參考資料 |
| 掃描歷史 | `/scans` | 所有掃描、狀態、重新掃描、匯出 |
| 設定 | `/settings` | 預設速率、UA、proxy、資料目錄、規則清單 |

### 4.2 新增掃描精靈

**Step 1 — 目標與授權**
- 目標 URL / 網域 / CIDR（多筆，逐行輸入）
- 排除路徑（例如 `/logout`、`/delete/*`）
- 內網目標開關（`allow_private`），開啟時顯示警告
- 授權人、聯絡人、授權到期日
- 必勾：「我確認已取得此目標的書面授權」
- 未勾選或 scope 驗證失敗 → 無法進入下一步

**Step 2 — 掃描設定**
- 掃描模式卡片：
  - **被動盤點**：只觀察，不送任何探測字串（最安全）
  - **安全主動**（預設）：加入無害 canary，檢測重導 / 反射 / 錯誤型 SQLi
  - **完整**：再加入布林 SQLi、路徑遍歷等，需明確勾選
- 速率（預設 3 rps/host）、最大請求數（預設 2000/host）、最大深度（預設 3）
- timeout、自訂 User-Agent、proxy（選填）

**Step 3 — 確認**
- 顯示目標、授權到期日、模式、限制的摘要
- 再次顯示「非破壞性掃描」與「需人工複核」提示
- 按下「開始掃描」→ 建立 job，導向即時頁

### 4.3 即時掃描頁
- 階段 stepper：`驗證範圍 → 探索 → 檢查 → 彙整`
- 進度條：已完成請求 / 預算，或目前階段百分比
- 計數卡片：請求數、端點數、發現數（依 severity 上色）
- 最近日誌：記憶體保留最後 200 行，自動捲動
- 「取消掃描」按鈕：設定取消事件，2 秒內停止送出新的請求
- 取消後仍顯示已完成的發現，報告標記 `cancelled`

### 4.4 弱點清單與詳情
- 篩選：severity、confidence、類別、關鍵字（URL / 參數）
- 表格欄位：嚴重度、標題、URL、參數、信心度、時間
- 詳情頁：
  - 一句話說明 + 風險影響
  - 證據分頁：Request / Response（純文字、已遮罩、絕不渲染原始 HTML）
  - 修補建議（可複製）
  - 對應 OWASP / CWE / 參考連結
  - 上一個 / 下一個發現
- 空狀態：「沒有符合條件的發現」而不是空白頁

### 4.5 掃描歷史
- 列表：目標、模式、狀態、開始時間、耗時、發現數
- 操作：查看、匯出 HTML/JSON、以此設定重新掃描
- 狀態顏色：queued（灰）、running（藍）、completed（綠）、failed（紅）、cancelled（黃）

### 4.6 設定
- 預設掃描模式、速率、請求上限、timeout、UA、proxy
- 資料目錄與 DB 位置（唯讀顯示）
- 內建規則清單（v1 唯讀，顯示 id / severity / profile）
- 「開啟資料夾」按鈕（本機工具很方便）

### 4.7 UI 原則
- 繁體中文介面，技術名詞保留英文（CSP、CORS、SQLi）
- 每個模式都有白話說明，避免使用者誤選「完整」
- 危險 / 需授權的操作使用紅色或黃色警示，並二次確認
- 嚴重度色彩固定：critical 深紅、high 紅、medium 橙、low 黃、info 灰
- 桌面優先（1280px 以上），表格可水平捲動；不做手機版最佳化
- 所有回應內容都要 escape；證據只以 `<pre>` 純文字呈現

---

## 5. 核心模組設計

### 5.1 `scope.py` — 授權與範圍
- 目標支援 URL、網域、CIDR；`exclude` 支援路徑 glob
- 每個請求前檢查 host / resolved IP 是否在範圍內
- 跨網域 redirect 預設不跟隨，只記錄
- 私有 IP 預設拒絕，需 `allow_private: true`
- 啟動掃描時把 scope 快照寫入 `data/scans/{id}/scope.yaml`，作為稽核證據

### 5.2 `http.py` — HTTP 引擎
- 單一 `AsyncClient`，連線池、HTTP/2、可設定 proxy 與自訂 CA
- timeout：connect 5s / read 10s；只對 idempotent 請求重試（最多 2 次）
- 每 host 一個 token bucket（預設 3 rps）+ 抖動
- 遇 429 讀 `Retry-After` 並退避；同 host 連續 5 次 429/5xx 暫停該 host
- 記錄 TLS 憑證資訊（subject、expiry、protocol）
- 所有請求寫入 JSONL audit log

### 5.3 `crawler.py` — 探索
- BFS，佇列去重（移除 session id、排序 query、忽略 fragment）
- 解析 `<a href>`、`<form action/method/input>`、`<script src>`、`srcset`
- 從 HTML/JS 以 regex 抓 API 路徑（`/api/...`、`fetch(...)`、`axios...`）
- 選用 Playwright：攔截 XHR/fetch，補足 SPA
- 表單參數建 `Parameter` 模型（名稱、位置 query/body/path、型別）
- 尊重 `robots.txt`（可用開關關閉，僅限授權測試）

### 5.4 `fingerprint.py` — 指紋
- 標頭（Server、X-Powered-By）、meta generator、cookie 名稱、favicon hash
- 少量常見路徑特徵（僅 GET）：`/wp-login.php`、`/administrator`、`/actuator`
- WAF 偵測：特定 header/cookie/block page 特徵（只用於調整速率，不嘗試繞過）
- 指紋結果決定要跑哪些檢查（例如 WordPress 才跑對應檢查）

### 5.5 `checks/` — 檢查外掛
```python
class Check(Protocol):
    id: str
    severity: Severity
    def applicable(self, ctx: ScanContext) -> bool: ...
    async def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Candidate]: ...
```
- 單一檢查失敗不影響其他檢查（try/except + 記錄）
- 候選發現一律經過 `verify()` 再進入報告
- 檢查標記 `profiles: [passive, safe, full]`
- UI 依 profile 顯示/隱藏對應說明，後端仍做最終校驗

### 5.6 `findings.py` — 發現彙整
- 去重鍵：`rule_id + 正規化 URL path + 參數名稱`
- 信心度：`high / medium / low`
- 嚴重度：`critical / high / medium / low / info`
- 證據只留必要片段（≤ 2KB），Cookie / Authorization / token 自動遮罩

### 5.7 `jobs/` — 背景工作
- `JobManager`：佇列、狀態、取消事件、目前 job
- `ScanRunner`：呼叫 Scanner Core，回報進度 callback
- 進度資料：phase、requests_sent、endpoints_found、findings_count、message
- 取消：`asyncio.Event`，HTTP 引擎在每次請求前檢查
- 同一時間預設只跑一個掃描；其他 job 顯示 `queued`

### 5.8 `db.py` — 持久化
- SQLite WAL mode，允許掃描寫入時 UI 同時讀取
- 每 20 個發現或每 2 秒批次寫入，避免高頻 commit
- 啟動時自動 migration（v1 用簡單 schema version）

---

## 6. 檢測項目（v1）

| # | 類別 | 檢測 | 方式 | passive | safe | full |
|---|---|---|---|---|---|---|
| 1 | 標頭 | CSP / HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy 缺失或過寬 | 被動 | ✅ | ✅ | ✅ |
| 2 | Cookie | Secure / HttpOnly / SameSite 缺失、Domain 過寬 | 被動 | ✅ | ✅ | ✅ |
| 3 | TLS | 憑證即將到期、TLS 1.0/1.1、弱協定 | 連線 | ✅ | ✅ | ✅ |
| 4 | CORS | Origin 反射 + `Allow-Credentials: true` | 主動無害 | ✅ | ✅ | ✅ |
| 5 | 方法 | `OPTIONS` 允許的方法、`TRACE` 開啟 | 被動 | ✅ | ✅ | ✅ |
| 6 | 資訊洩漏 | 版本標頭、stack trace、debug 頁、目錄列表 | GET | ✅ | ✅ | ✅ |
| 7 | 敏感檔案 | `.git/HEAD`、`.env`、`backup.zip`、`phpinfo.php`（少量清單） | GET | ✅ | ✅ | ✅ |
| 8 | 混合內容 | HTTPS 頁面載入 HTTP 資源 | 被動 | ✅ | ✅ | ✅ |
| 9 | JS 洩漏 | source map、硬編碼 API key（高熵 + 已知前綴） | 被動 | ✅ | ✅ | ✅ |
| 10 | CSRF | 狀態變更表單缺少 token / SameSite 保護 | 表單分析 | ✅ | ✅ | ✅ |
| 11 | OpenAPI | Swagger / OpenAPI 文件公開暴露 | GET | ✅ | ✅ | ✅ |
| 12 | 開放重導 | 參數替換為 canary 網域，觀察 Location | 主動無害 | — | ✅ | ✅ |
| 13 | 反射 XSS | 注入唯一英數 canary，分析反射的 HTML context | 主動無害 | — | ✅ | ✅ |
| 14 | SQLi（錯誤型） | 單引號 + 錯誤訊息特徵比對 | 主動 | — | ✅ | ✅ |
| 15 | SQLi（布林型） | 成對真假條件比對 response 差異 | 主動 | — | — | ✅ |
| 16 | 路徑遍歷 | canary 檔名 / 限制路徑讀取跡象 | 主動 | — | — | ✅ |
| 17 | SSRF | 外部 canary（自架 collaborator）回連 | 主動 | — | — | ✅ |
| 18 | 目錄爆破 | 低速 wordlist（需明確設定） | 主動 | — | — | ⚠️ |
| 19 | 預設帳密 | 極少量常見組合（需明確設定） | 登入 | — | — | ⚠️ |

> ⚠️ 預設關閉，必須在掃描設定中逐項開啟；v1 建議先不做 18/19。

### 不送攻擊性 payload 的原則
- XSS 只送 `vs<random>123` 這類無害字串，靠 context 判斷是否可執行；不送 `<script>`
- SQLi 只送單引號並比對錯誤特徵；不送 `UNION`、不嘗試 dump
- 路徑遍歷只驗證是否回傳可辨識的 canary 內容，不下載敏感檔
- 所有主動檢查都可被「被動盤點」模式完全停用

---

## 7. 規則系統

### YAML 規則（簡單比對）
```yaml
id: hdr-csp-missing
title: 缺少 Content-Security-Policy
severity: medium
confidence: high
profiles: [passive, safe, full]
scope: response
when:
  all:
    - status: 2xx
    - content_type_matches: text/html
    - header_missing: content-security-policy
remediation: >
  為所有 HTML 回應加上 Content-Security-Policy，預設拒絕 inline script，
  僅允許必要的來源。
refs:
  owasp: A05:2021
  cwe: 693
```

支援的 matcher：`status`、`header_present/absent/matches`、`body_regex`、`content_type_matches`、`cookie_missing_attr`、`url_param`。
複雜邏輯（需要送請求、比對兩次回應）寫成 Python plugin。

- 內建規則放 `rules/`，使用者可用 `--rules-dir` 覆蓋/新增
- UI 的設定頁可列出規則（v1 唯讀）
- 規則 id 一旦發布不變，方便 suppress 與追蹤

---

## 8. 安全與合規設計

### 掃描安全
1. **授權閘門**：UI 必填授權人 / 聯絡人 / 到期日 + 勾選確認；後端再次驗證
2. **範圍鎖**：host/IP 白名單；redirect 到範圍外只記錄不跟隨
3. **速率與預算**：每 host 預設 3 rps、最多 2000 請求；全域併發 20
4. **非破壞性**：預設只允許 GET/HEAD/OPTIONS；完整模式才開放更多方法
5. **緊急停止**：UI 取消鈕 / Ctrl+C 都走同一個取消事件，已完成發現仍保留
6. **審計日誌**：JSONL 保存所有請求與規則 id，便於事後舉證
7. **敏感資料遮罩**：報告、UI、log 中的 Cookie、Authorization、token、密碼欄位一律遮罩
8. **不繞過防護**：遇到 WAF/429 只降速，不做繞過
9. **時間限制**：可設定 30 分鐘上限，到期停止並輸出部分結果

### Web UI 自身安全
- 預設只綁 `127.0.0.1`，避免變成內網可存取的掃描服務
- 若要綁 `0.0.0.0`，必須同時設定存取 token（`--auth-token`）
- POST 表單使用 CSRF token + `SameSite=Strict` session cookie
- 所有輸出 escape；證據以純文字顯示，不渲染目標網站的 HTML
- 回應標頭加上 `Content-Security-Policy: default-src 'self'`、`X-Frame-Options: DENY`
- 不把掃描目標的內容直接塞進 `innerHTML`

---

## 9. 資料模型與資料庫

### 資料表
```sql
CREATE TABLE scans (
  id           TEXT PRIMARY KEY,
  created_at   TEXT NOT NULL,
  started_at   TEXT,
  finished_at  TEXT,
  status       TEXT NOT NULL,        -- queued/running/completed/failed/cancelled
  profile      TEXT NOT NULL,
  targets_json TEXT NOT NULL,
  scope_json   TEXT NOT NULL,
  stats_json   TEXT,
  error        TEXT
);

CREATE TABLE endpoints (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  url         TEXT NOT NULL,
  method      TEXT NOT NULL,
  params_json TEXT,
  source      TEXT,                  -- crawl/form/js/openapi
  depth       INTEGER
);

CREATE TABLE findings (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id       TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  rule_id       TEXT NOT NULL,
  title         TEXT NOT NULL,
  severity      TEXT NOT NULL,
  confidence    TEXT NOT NULL,
  url           TEXT NOT NULL,
  method        TEXT NOT NULL,
  parameter     TEXT,
  evidence_json TEXT,
  remediation   TEXT,
  refs_json     TEXT,
  created_at    TEXT NOT NULL
);

CREATE INDEX idx_findings_scan ON findings(scan_id, severity);
CREATE UNIQUE INDEX idx_findings_dedupe
  ON findings(scan_id, rule_id, url, COALESCE(parameter, ''));
```

### 主要模型
```python
class Target(BaseModel):
    url: HttpUrl
    host: str
    resolved_ips: list[str]

class Endpoint(BaseModel):
    url: str
    method: str = "GET"
    params: list[Parameter] = []
    source: Literal["crawl", "form", "js", "openapi", "manual"]
    depth: int = 0

class Parameter(BaseModel):
    name: str
    location: Literal["query", "body", "path", "header", "cookie"]
    value: str | None = None

class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    url: str
    method: str
    parameter: str | None
    evidence: Evidence          # request/response 摘要（已遮罩）
    remediation: str
    refs: dict[str, str]        # owasp, cwe, url
    first_seen: datetime
```

---

## 10. API 端點

| Method | 路徑 | 用途 |
|---|---|---|
| GET | `/` | 儀表板 |
| GET | `/scans/new` | 新增掃描精靈 |
| POST | `/scans` | 建立掃描（驗證 scope 與授權） |
| GET | `/scans` | 掃描歷史 |
| GET | `/scans/{id}` | 即時掃描頁 |
| GET | `/api/scans/{id}/status` | 進度 JSON（前端輪詢） |
| POST | `/scans/{id}/cancel` | 取消掃描 |
| GET | `/scans/{id}/findings` | 弱點清單（可帶篩選參數） |
| GET | `/findings/{id}` | 弱點詳情 |
| GET | `/scans/{id}/export/html` | 匯出單檔 HTML |
| GET | `/scans/{id}/export/json` | 匯出 JSON |
| GET | `/settings` | 設定頁 |
| POST | `/settings` | 儲存設定 |

建立掃描的 request body（表單或 JSON）：
```json
{
  "targets": ["https://staging.acme.example", "http://192.168.10.0/24"],
  "exclude": ["https://staging.acme.example/logout"],
  "allow_private": true,
  "authorized_by": "ACME 資安主管",
  "contact": "devops@acme.example",
  "expires": "2026-11-30",
  "profile": "safe",
  "rps_per_host": 3,
  "max_requests_per_host": 2000,
  "max_depth": 3
}
```

---

## 11. 報告輸出（HTML + JSON）

### HTML 報告
- 單一檔案、CSS inline、可離線開啟與轉寄
- 內容：封面、授權與 scope、掃描摘要、嚴重度統計、發現清單、每個發現的證據與修補建議、免責聲明
- 使用 CSS 長條圖呈現嚴重度，不依賴外部 JS
- 頁首標記「需人工複核，掃描結果不保證完整」
- 由 `report/html.py` 用 Jinja2 產生，與 UI 共用部分 partial

### JSON 報告
```json
{
  "report_version": "1.0",
  "tool": {"name": "vulnscan", "version": "0.1.0"},
  "scan": {
    "id": "scan_20261023_abc123",
    "started_at": "2026-10-23T10:00:00+08:00",
    "finished_at": "2026-10-23T10:12:30+08:00",
    "profile": "safe",
    "status": "completed"
  },
  "scope": {
    "authorized_by": "ACME 資安主管",
    "expires": "2026-11-30",
    "targets": ["https://staging.acme.example"]
  },
  "stats": {"requests": 1842, "endpoints": 214, "findings": 17},
  "findings": [
    {
      "rule_id": "hdr-csp-missing",
      "title": "缺少 Content-Security-Policy",
      "severity": "medium",
      "confidence": "high",
      "url": "https://staging.acme.example/",
      "method": "GET",
      "parameter": null,
      "evidence": {"response_headers": {"content-type": "text/html"}},
      "remediation": "為所有 HTML 回應加上 Content-Security-Policy...",
      "refs": {"owasp": "A05:2021", "cwe": "693"}
    }
  ]
}
```

> v1 不做 SARIF 與 DefectDojo；欄位設計保留擴充空間，之後要加不用改資料庫。

---

## 12. 專案結構

```
web-vuln-scanner/
├── pyproject.toml
├── README.md
├── PLAN.md
├── docker-compose.yml              # Juice Shop + DVWA 測試靶場
├── examples/
│   └── scope.yaml
├── rules/
│   ├── headers.yaml
│   ├── cookies.yaml
│   └── disclosure.yaml
├── data/                           # 執行時產生（gitignore）
│   ├── vulnscan.db
│   └── scans/{scan_id}/audit.jsonl
├── src/vulnscan/
│   ├── __main__.py
│   ├── cli.py                      # vulnscan ui / scan / rules
│   ├── config.py
│   ├── models.py
│   ├── db.py
│   ├── scope.py
│   ├── http.py
│   ├── crawler.py
│   ├── fingerprint.py
│   ├── engine.py
│   ├── audit.py
│   ├── jobs/
│   │   └── manager.py
│   ├── checks/
│   │   ├── base.py
│   │   ├── active_utils.py
│   │   ├── headers.py
│   │   ├── cookies.py
│   │   ├── tls.py
│   │   ├── cors.py
│   │   ├── methods.py
│   │   ├── disclosure.py
│   │   ├── csrf.py
│   │   ├── sensitive_files.py
│   │   ├── openapi.py
│   │   ├── mixed_content.py
│   │   ├── js_secrets.py
│   │   ├── redirect.py
│   │   ├── xss.py
│   │   └── sqli.py
│   ├── report/
│   │   ├── html.py
│   │   └── json.py
│   └── web/
│       ├── app.py                  # FastAPI 建立、lifespan、middleware
│       ├── routes/
│       │   ├── pages.py
│       │   ├── scans.py
│       │   ├── findings.py
│       │   └── exports.py
│       ├── templates/
│       │   ├── base.html
│       │   ├── dashboard.html
│       │   ├── scan_new.html
│       │   ├── scan_live.html
│       │   ├── findings.html
│       │   ├── finding_detail.html
│       │   ├── history.html
│       │   └── settings.html
│       └── static/
│           ├── css/app.css
│           ├── js/app.js
│           └── favicon.svg
└── tests/
    ├── fixture_server.py
    ├── helpers.py
    ├── test_api.py
    ├── test_checks.py
    ├── test_crawler.py
    ├── test_engine.py
    ├── test_report.py
    └── test_scope.py
```

### CLI 草案
```bash
# 主要入口：啟動 UI 並自動開瀏覽器
vulnscan ui
vulnscan ui --port 8765 --no-browser

# 次要：headless 掃描（排程 / CI 用）
vulnscan scan --scope examples/scope.yaml --profile safe \
  --acknowledge-authorized --out reports/

# 管理規則
vulnscan rules list
```

---

## 13. 開發里程碑（GUI 優先）

| 階段 | 內容 | 產出 / 驗收 | 估時 |
|---|---|---|---|
| M0 | FastAPI 骨架、自訂 CSS 版型、SQLite、`vulnscan ui` | 瀏覽器可開儀表板、資料庫自動建立 | 1 天 |
| M1 | 新增掃描精靈、scope 驗證、JobManager、即時進度、取消 | 用假掃描可走完 3 步、進度會動、取消有效 | 2.5 天 |
| M2 | HTTP 引擎、爬蟲、指紋、被動檢查、發現清單/詳情 | 對真實靶場跑完被動掃描並在 UI 瀏覽結果 | 2.5 天 |
| M3 | 安全主動檢查（重導/XSS/SQLi 錯誤型）+ 驗證器 | 可重現、誤報可控、severity/confidence 正確 | 3 天 |
| M4 | HTML/JSON 匯出、掃描歷史、audit log | 單檔 HTML 可離線看、JSON schema 穩定 | 1.5 天 |
| M5 | 測試、打包（uv/pipx）、文件、靶場 demo | 新機器可安裝、pytest 全綠、Demo 流程順暢 | 2 天 |

**總計約 12.5 個工作日**（單人、含測試）。

### 建議實作順序
先做 M0–M1：**UI 骨架 + 假掃描流程**。這樣可以提早確認版面、操作流程與進度呈現，
不用等掃描引擎完成。M2 再把真實掃描接上，之後逐步加檢查與匯出。

---

## 14. 測試策略

- **單元**：URL 正規化、scope 判斷、規則 matcher、遮罩邏輯、去重
- **JobManager**：用 fake scanner 測試排隊、進度、取消、失敗處理
- **API**：FastAPI TestClient 測建立掃描、scope 驗證、匯出、404
- **UI smoke**：每個頁面回 200、關鍵元素存在；可選 Playwright 點擊流程
- **整合**：`respx` 模擬 response；docker compose 起 Juice Shop + DVWA 跑基準
- **回歸**：靶場結果存 snapshot；規則變更需人工確認 diff
- **負向測試**：乾淨靜態網站不應產生 high/medium 發現；未授權請求應被拒絕
- **CI**：`ruff` → `mypy` → `pytest` → 靶場 smoke test（可 nightly）

---

## 15. 風險與對策

| 風險 | 對策 |
|---|---|
| GUI 範圍失控 | 固定 7 個頁面；v1 不做多使用者、報表編輯器、掃描排程 |
| 掃描太久卡住 UI | 背景 task + 輪詢；一次一個掃描；可取消 |
| SQLite 寫入鎖 | WAL mode、批次寫入、縮短 transaction |
| 報告太大 | 證據上限 2KB、清單分頁、HTML 不內嵌圖片 |
| UI 被外部存取 | 預設綁 127.0.0.1；對外需 token |
| 證據含惡意 HTML | 全部 escape、以純文字呈現、CSP |
| 內網掃描誤觸 | `allow_private` 明確開啟 + 警告 + scope 白名單 |
| 誤報造成困擾 | 二次驗證、信心度、報告標明需人工複核 |
| 掃描影響服務 | 低速率、請求預算、429 退避、可中止 |
| 授權爭議 | scope 快照 + 授權欄位 + audit log + 啟動確認 |
| SPA 爬不到 | Playwright 選項、OpenAPI/JS 端點萃取 |

---

## 16. 已確認決策

| 項目 | 決定 |
|---|---|
| 語言 | Python 3.11+ |
| 介面 | **本機 Web UI 為主**（FastAPI + Jinja2 + 原生 JS + 自訂 CSS） |
| 掃描對象 | 對外網站 + 內網系統；內網需 `allow_private: true` |
| 登入 | 支援 Cookie、自訂 Header、表單登入、storage state、GUI 啟動 Playwright（SSO／MFA／localStorage）；未登入仍可掃描 |
| 報告 | **HTML + JSON**；SARIF / DefectDojo 不做 |
| 部署 | 單機 `pipx` / `uv` 安裝，`vulnscan ui` 啟動；Docker 選配 |
| 預設埠 | `127.0.0.1:8765` |

> 內網掃描注意：scope 需明確列出內網網段或主機，並確認授權涵蓋該網段；
> 掃描器也要避免被資安設備當成內網探測工具，建議先跟維運團隊報備。

---

## 17. 實作狀態（v0.25）

| 階段 | 狀態 | 說明 |
|---|---|---|
| M0 UI 骨架 | ✅ 完成 | FastAPI、Jinja2、自訂 CSS、SQLite、`vulnscan ui` |
| M1 掃描流程 | ✅ 完成 | 三步驟精靈、scope 驗證、JobManager、即時進度、取消 |
| M2 被動檢查 | ✅ 完成 | 標頭、Cookie、TLS、CORS、方法、洩漏、敏感檔案、CSRF、OpenAPI、混合內容、JS |
| M3 主動檢查 | ✅ 完成 | 安全主動：開放重導、反射 HTML 注入、錯誤型 SQLi；完整模式：布林 SQLi、路徑遍歷、SSRF |
| M4 報告 | ✅ 完成 | 單檔 HTML + JSON、歷史、audit log、Diff、抑制 |
| M5 測試與文件 | ✅ 完成 | pytest 靶場、README、範例 scope |
| 登入後掃描 | ✅ 完成 | Cookie、自訂 Header、表單登入、storage state、GUI 啟動 Playwright（SSO／MFA） |
| 掃描 Diff／抑制 | ✅ 完成 | 新增／已修復／未變、跨掃描 fingerprint 抑制、GUI 與 CLI |
| API 掃描 | ✅ 完成 | OpenAPI 3.1／3.0／Swagger 2 檔案或 URL（同 scope redirect）、scope 內外部 `$ref`、spec fingerprint／drift、認證感知預覽與 session 檢查、端點勾選與 host-aware 白名單、空白名單明確確認、請求 manifest、匯入 warning／統計、報告保存已選端點與 manifest 摘要、BOLA／BFLA 雙帳號唯讀（GET 白名單與全部確認、JSON 結構比較、每端點結果矩陣、Diff）、共用 rate limiter／request budget、表單登入 session 恢復、API 測試 budget／每端點與每檢查結果矩陣／Coverage Diff、巢狀 JSON、XSS／錯誤型與重試確認的布林型 SQLi／SSRF |
| 弱點驗證與交付 | ✅ 完成 | 待確認／已確認／誤報／接受風險、fingerprint 跨掃描狀態與一次性回填、fingerprint 索引與 `user_version` migration、跨掃描歷史頁、接受風險到期、嚴重度升級／證據改變自動重開、誤報／接受風險備註政策、篩選與批次更新、驗證歷程、Dashboard 統計、Diff 依跨掃描 review status 分流、目標 baseline、CLI `baseline set／show／clear`、掃描趨勢頁、驗證工作台（跨掃描去重／篩選／到期提醒）、CLI `--fail-on` regression gate、HTML／JSON 報告、CI coverage 門檻／wheel 安裝 smoke／baseline gate fixture／真正 scan E2E、Dependabot、可選 Playwright GUI 吸菸測試 |
| YAML 自訂規則 | ⏳ 未做 | 目前為內建 Python 檢查 |
| SARIF / DefectDojo | ⏳ 未做 | 依需求再加 |

### 與原規劃的差異
- 前端改用**原生 JavaScript + fetch**，不引入 HTMX / Alpine.js，減少依賴與 CSP 複雜度。
- 樣式改為**自訂 CSS**，不引入 Bootstrap 或外部 CDN，確保離線可用。
- 圖表使用 CSS 長條圖，不引入 Chart.js。
- v1 僅綁定 `127.0.0.1`；尚未提供遠端存取 token，因此 CLI 會拒絕非 loopback 的 bind。

### 實際入口
```powershell
vulnscan ui
vulnscan scan --scope examples/scope.yaml --profile safe --acknowledge-authorized
vulnscan scan --url https://staging.example.com --profile full `
  --enable-advanced sqli_boolean,traversal,ssrf --acknowledge-authorized
vulnscan scan --url https://staging.example.com --profile safe `
  --login-url https://staging.example.com/login --username demo --acknowledge-authorized
vulnscan login --url https://staging.example.com --out auth-state.json --acknowledge-authorized
vulnscan scan --url https://staging.example.com --profile safe `
  --auth-state auth-state.json --acknowledge-authorized
vulnscan diff --current scan_xxx --previous scan_yyy
vulnscan suppress --finding 42 --reason "accepted risk"
vulnscan scan --url https://api.example.com --openapi openapi.json --api-post --acknowledge-authorized
vulnscan scan --url https://api.example.com --openapi openapi.json --api-post `
  --api-post-allow "POST https://api.example.com/api/items/*" --acknowledge-authorized
vulnscan scan --url https://api.example.com --openapi openapi.json --api-post `
  --api-post-all --acknowledge-authorized
vulnscan scan --url https://api.example.com --openapi-url https://api.example.com/openapi.json --acknowledge-authorized
vulnscan rules
```

