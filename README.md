# VulnScan

[![CI](https://github.com/okokkook1/web-vuln-scanner/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/okokkook1/web-vuln-scanner/actions/workflows/ci.yml)

授權導向、非破壞性的網站弱點掃描器。以**本機 Web UI** 為主，支援 HTML + JSON 報告。

> **僅限已取得書面授權的目標。** 本工具不會執行漏洞利用、密碼爆破、資料竊取或阻斷服務。
> 預設的 API 檢查只使用 GET；POST/JSON 主動測試必須明確開啟，且可能讓測試環境建立資料。
> 掃描結果可能包含誤報或漏報，所有發現都應由人員複核。

## 功能

- 三步驟圖形化掃描精靈：目標與授權 → 掃描設定 → 確認
- 即時進度、階段、請求數、發現數、日誌與取消
- 被動檢查：安全標頭、Cookie、TLS 憑證、CORS、HTTP 方法、資訊洩漏、敏感檔案、CSRF、OpenAPI、混合內容、JS 機密
- 安全主動檢查：開放重導、反射型 HTML 注入 / XSS、錯誤型 SQL Injection
- 完整模式（需逐項確認）：布林型 SQL Injection、路徑遍歷錯誤訊息偵測、SSRF callback 驗證
- 登入後掃描：Cookie、自訂 Header、表單登入、GUI／CLI 瀏覽器互動（SSO／MFA／localStorage）
- 掃描 Diff：新增／已修復／未變／本次未測／已排除，可選擇前次掃描或設定目標 baseline
- CLI baseline：`vulnscan baseline set／show／clear`，可放進 CI 或排程
- 掃描趨勢：每個目標的近期新增、修復、未測、已排除與驗證狀態變化
- CI regression gate：`vulnscan diff --fail-on ...` 可依新增／已確認／待確認／已排除項目回傳非 0
- 跨掃描抑制：以 rule＋method＋host＋path＋參數為 fingerprint，需填寫原因
- OpenAPI 3.1／3.0／Swagger 2 匯入：檔案或 URL、同 scope redirect、scope 內外部 `$ref`、server variables、path／operation 層級 servers、可勾選端點、host-aware 白名單、spec fingerprint／drift 偵測、請求 manifest、匯入 warning 與報告紀錄
- JSON API 主動檢查（需明確開啟）：巢狀參數、反射注入、錯誤型／布林型 SQLi、SSRF callback；測試前會檢查登入 session 有效性
- BOLA／BFLA 雙帳號唯讀檢查：第二帳號支援 Cookie／Header／Storage state／表單登入，GET 白名單（留空需明確確認）、每端點結果矩陣、JSON 結構比較、Diff；不枚舉 ID、不保存他人回應內容
- 主要／第二／未登入 client 共用 rate limiter 與 request budget，BOLA 請求即時計入總量
- API 測試 budget 可設定，報告會列出每個 POST 端點的已測／跳過原因
- API／BOLA Coverage Diff：區分「本次未測」與「已修復」，避免 coverage 下降被誤判
- 表單登入會在主動檢查、API 與 BOLA 前確認 session；失效時嘗試重新登入一次
- Cookie／Header／Storage state 可設定 OAuth-style refresh endpoint；session 失效時取得新 access token 或 Cookie
- 掃描歷史、弱點篩選、單檔 HTML 報告、JSON 報告
- 弱點人工驗證狀態：待確認、已確認、誤報、接受風險；支援篩選、批次更新、完整驗證歷程與報告
- 驗證狀態以 fingerprint 跨掃描共用：新掃描的相同發現會自動沿用狀態、備註與歷程
- 驗證工作台：跨掃描去重、狀態／嚴重度／目標篩選、高風險待確認與接受風險到期提醒
- 誤報與接受風險必須填寫備註；接受風險可設定到期日
- 跨掃描 fingerprint 歷史頁：出現過的掃描、首次／最近出現、嚴重度變化與完整驗證時間線
- 嚴重度升級、誤報證據改變或接受風險到期時，狀態會自動回到待確認
- Dashboard 顯示各驗證狀態數量，Diff 會把誤報／接受風險排除在 regression 之外
- API 測試結果矩陣包含每個檢查的 finding／no_finding／budget 結果
- 每個請求寫入 audit JSONL；報告自動遮罩敏感欄位
- 對外網站與內網目標（內網需明確開啟 `allow_private`）

## 快速開始（Windows）

```powershell
cd web-vuln-scanner
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
vulnscan ui
```

瀏覽器會開啟 `http://127.0.0.1:8765`。若不想自動開瀏覽器：

```powershell
vulnscan ui --no-browser
```

macOS / Linux：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
vulnscan ui
```

## Headless 掃描

適合排程或 CI。仍需要 `--acknowledge-authorized`：

```powershell
vulnscan scan `
  --scope examples/scope.yaml `
  --profile safe `
  --acknowledge-authorized `
  --out reports
```

或直接指定 URL（內網測試才加 `--allow-private`）：

```powershell
vulnscan scan `
  --url http://127.0.0.1:8899 `
  --allow-private `
  --profile safe `
  --acknowledge-authorized `
  --out reports
```

完整模式需要**明確**列出進階檢查（可只選一項）：

```powershell
vulnscan scan `
  --url https://staging.example.com `
  --profile full `
  --enable-advanced sqli_boolean,traversal,ssrf `
  --acknowledge-authorized `
  --out reports
```

SSRF 預設會監聽 `127.0.0.1` 的隨機埠，只適合本機靶場。若目標在遠端，請指定目標可連回的 callback URL：

```powershell
vulnscan scan `
  --url https://staging.example.com `
  --profile full `
  --enable-advanced ssrf `
  --ssrf-callback http://203.0.113.10:8765 `
  --acknowledge-authorized `
  --out reports
```

掃描器會在該 port 啟動臨時 listener（非 loopback 時綁定 `0.0.0.0`），掃描結束即關閉。

輸出：

- `reports/vulnscan-<scan_id>.html`：單檔、可離線開啟
- `reports/vulnscan-<scan_id>.json`：固定 schema
- `data/scans/<scan_id>/audit.jsonl`：所有請求的 audit log
- `data/scans/<scan_id>/scope.yaml`：掃描當下的授權快照

## 登入後掃描

UI 在「掃描設定」的「登入後掃描」區塊支援五種方式：

- **Cookie**：貼上瀏覽器 Cookie header
- **自訂 Header**：例如 `Authorization: Bearer ...`
- **表單登入**：填入登入 URL、帳號、密碼；掃描器會自動抓取登入頁的 CSRF token
- **瀏覽器互動登入**：由 UI 直接開啟 Playwright，適合 JavaScript、SSO、MFA
- **瀏覽器狀態檔**：上傳 Playwright storage state，適合遠端產生後帶入

憑證只存在掃描記憶體，不寫入 SQLite、報告或 `scope.yaml`。
表單登入成功後會把 Cookie 帶入後續探索與檢查。正式環境請使用 HTTPS；HTTP 僅限本機或隔離測試。

Headless 範例：

```powershell
# Cookie（避免把 secret 放在命令列）
$env:VULNSCAN_AUTH_COOKIE = "session=..."
vulnscan scan --url https://staging.example.com --profile safe --acknowledge-authorized

# Header
$env:VULNSCAN_AUTH_HEADER_VALUE = "Bearer ..."
vulnscan scan --url https://staging.example.com --profile safe `
  --auth-header-name Authorization --acknowledge-authorized

# 表單登入（未提供 --password 時會以隱藏輸入提示）
vulnscan scan --url https://staging.example.com --profile safe `
  --login-url https://staging.example.com/login `
  --username demo --acknowledge-authorized
```

表單登入可選擇設定 `--auth-verify-url` 與 `--auth-verify-text`。

### JavaScript／localStorage／SSO／MFA

這些流程通常需要互動式瀏覽器（尤其 SSO 與 MFA），掃描器採「瀏覽器輔助登入」而不是保存 MFA seed。

### GUI 直接啟動瀏覽器

先安裝一次瀏覽器支援：

```powershell
pip install -e ".[browser]"
playwright install chromium
```

UI 也可以直接開啟瀏覽器：

1. 掃描設定 → 登入後掃描 → 選擇「**瀏覽器互動登入（SSO／MFA）**」
2. 填入登入 URL
3. 按「開啟瀏覽器登入」
4. 在彈出的 Chromium 完成 SSO／MFA／JavaScript 登入
5. 回到 UI 按「我已完成登入」
6. 狀態變成「登入完成」後，繼續完成掃描設定

瀏覽器會開在**執行 `vulnscan ui` 的同一台電腦**；此 UI 僅支援本機使用。若掃描器跑在遠端主機，請改用 CLI 產生狀態檔後上傳。

### CLI 產生狀態檔（替代方案）

```powershell
# 開啟瀏覽器，完成 SSO／MFA／JavaScript 登入後按 Enter
vulnscan login `
  --url https://staging.example.com `
  --out auth-state.json `
  --acknowledge-authorized
```

再使用狀態檔掃描：

```powershell
vulnscan scan `
  --url https://staging.example.com `
  --profile safe `
  --auth-state auth-state.json `
  --acknowledge-authorized
```

若 API 使用 refresh token endpoint，可加上：

```powershell
vulnscan scan `
  --url https://api.example.com `
  --profile safe `
  --auth-header-name Authorization `
  --auth-header-value "Bearer initial-token" `
  --refresh-url https://api.example.com/oauth/token `
  --refresh-token "refresh-token" `
  --refresh-header-name Authorization `
  --refresh-access-token-field access_token `
  --acknowledge-authorized
```

Refresh endpoint 以 form POST 送出 `grant_type=refresh_token` 與 refresh token；
回應需包含 access token 欄位，或設定新的 Cookie。

若 token 存在 localStorage，可選擇映射到 Header：

```powershell
vulnscan scan --url https://staging.example.com --profile safe `
  --auth-state auth-state.json `
  --storage-token-key access_token `
  --storage-header-name Authorization `
  --storage-header-prefix "Bearer " `
  --acknowledge-authorized
```

- 掃描器會依 scope 過濾 state 內的 Cookie，只使用符合目標網域的 Cookie
- 只會從符合 scope 的 origin 讀取指定的 localStorage key
- `auth-state.json` 含 session 憑證，請勿提交到版本控制（已加入 `.gitignore`）
- 所有登入方式都可設定「登入後驗證 URL／文字」；API POST 測試前會用此頁檢查 session 是否仍有效
- 目前不支援 sessionStorage、IndexedDB、自動 TOTP／推播 MFA

> 多主機 scope 會共用同一個登入 session 與自訂 Header；請避免把不同信任等級的站台放在同一次掃描。

## 掃描 Diff 與抑制

### Diff
- 掃描完成後，從掃描進度、弱點清單或歷史頁點「與前次比較」
- 可指定任意較早完成、相同目標的掃描
- 可將某次掃描設為該目標的 baseline；之後 Diff 預設使用它
- 沒有 baseline 時，自動選擇相同目標、較早完成的掃描
- 分為「新增」、「已修復」、「未變」、「本次未測」、「已排除」
- API 測試覆蓋變化：本次未測、開始測試、跳過原因改變、檢查項目改變
- BOLA 結果另外標示新出現、不再疑似、本次未測與開始測試
- 前次發現若本次沒有足夠測試覆蓋，會列入「本次未測」，不會算成已修復
- 新增發現會再區分「待確認」與「已確認」；誤報／接受風險列入「已排除」
- Diff 直接使用跨掃描驗證狀態；其他掃描已標記的誤報／接受風險不會重新變成 regression
- 已抑制的發現不列入 Diff

### Baseline 與趨勢
- 在 Diff 頁可將目前掃描設為該目標的 baseline，或清除 baseline
- baseline 依目標組合儲存；相同目標的新掃描會自動以它為預設比較對象
- 「掃描趨勢」頁依目標分組，列出最近掃描的：
  - 有效發現數
  - 新增／已確認新增／已修復
  - 本次未測／已排除
  - 已確認／待確認與嚴重度分布
- 趨勢只使用已完成或已取消的掃描

### 驗證狀態與跨掃描歷史
- 從弱點詳情或弱點清單點「跨掃描歷史」查看 fingerprint 的所有出現紀錄
- 歷史頁包含首次／最近出現、掃描次數、嚴重度分布、目前狀態與完整驗證時間線
- 狀態依 fingerprint 套用到所有掃描；單筆與批次更新都會寫入 history
- 接受風險可設定到期日；到期後下次出現會自動重開
- 嚴重度升級或誤報的證據內容改變時，會建立一筆 `system` 重開紀錄
- 「驗證工作台」跨掃描去重，預設只列待確認項目
- 工作台可依狀態、嚴重度、目標篩選，並顯示高風險待確認與 30 天內到期的 accepted risk

### 抑制
- 在弱點詳情頁填寫原因後加入抑制
- fingerprint：`rule_id + method + host + path + parameter`
- 抑制會套用到之後相同位置的發現，但仍保留原始資料
- 可在「抑制規則」頁查看與刪除
- 報告與儀表板預設只計有效發現，另列已抑制數量

> 抑制不是修補。刪除抑制規則後，相同弱點會重新出現在清單與報告中。

### CLI

```powershell
# 自動選擇相同目標的前次掃描
vulnscan diff --current scan_20261023_120000_abcd

# 指定前次掃描；--json 可輸出機器可讀結果
vulnscan diff --current scan_20261023_120000_abcd `
  --previous scan_20261020_090000_efgh --json

# 將掃描設為此目標的 baseline
vulnscan baseline set --scan scan_20261020_090000_efgh --created-by ci

# 查看或清除 baseline
vulnscan baseline show --scan scan_20261023_120000_abcd --json
vulnscan baseline clear --scan scan_20261023_120000_abcd

# 使用此目標已儲存的 baseline
vulnscan diff --current scan_20261023_120000_abcd --baseline

# CI regression gate：有新增項目時 exit code 1
vulnscan diff --current scan_20261023_120000_abcd --fail-on new

# 只擋下「新增且已確認」；待確認新增不算失敗
vulnscan diff --current scan_20261023_120000_abcd --fail-on new_confirmed

# 可用值：none、new、new_confirmed、new_needs_review、reviewed_out、any
vulnscan diff --current scan_20261023_120000_abcd --fail-on any

# 抑制單一 finding（ID 可從 /findings/<id> 取得）
vulnscan suppress --finding 42 --reason "測試環境已知誤報" --created-by alice

vulnscan suppressions
vulnscan unsuppress --finding 42
```

若使用自訂資料目錄，請在每個指令加上 `--data-dir`。

### CI pipeline

`.github/workflows/ci.yml` 會執行：

- `ruff check src tests scripts`
- JavaScript syntax check
- `pytest --cov=vulnscan --cov-fail-under=75`
- wheel build 與安裝 smoke test（含 template package data）
- 以 `scripts/ci_gate_fixture.py` 建立決定性的 baseline 資料，驗證：
  - `--fail-on new_confirmed` 遇到已確認新增時 exit 1
  - 待確認新增不會讓 `new_confirmed` gate 失敗
- 以 `scripts/ci_scan_gate_fixture.py` 執行真正的掃描流程：
  - 啟動本機 fixture server
  - 實際執行 passive／safe 掃描
  - 用 CLI 設定 baseline
  - 驗證 `new`／`new_confirmed` gate
  - 上傳 HTML／JSON 報告 artifact
- Dependabot 每週檢查 Python dependencies 與 GitHub Actions
- `.github/workflows/release.yml` 在推送 `v*` tag 時：
  - 建置 wheel
  - 驗證 tag 與套件版本一致
  - 自動建立 GitHub Release 並附上 wheel
- 可選 Playwright GUI E2E（`VULNSCAN_E2E=1`）

> Private repo 的 branch protection 需要 GitHub Pro／Team 或公開 repo；
> 免費 private repo 目前無法透過 API 啟用 required status checks。

## API 掃描與 OpenAPI 匯入

UI 的「API 掃描（OpenAPI 匯入）」可上傳 OpenAPI 3.1／3.0 或 Swagger 2 的 JSON/YAML，或直接填寫規格 URL：

- 自動依 `servers`／`host` 建立端點
- 支援 server variables 的 `default`／`enum` 展開，以及 operation／path 層級 servers 優先於根層級
- 支援 OpenAPI 3.1、`allOf`、`oneOf`／`anyOf` 的第一個可解析分支、`const`、`examples` 與型別聯集
- 匯入 GET 查詢參數與 POST JSON body 範例；巢狀物件與陣列會展開成 `user.name`、`items[0].id` 等參數
- OpenAPI URL 會在登入後以目前 session 取得，主機必須在授權 scope 內；支援最多 3 次同 scope redirect
- UI 的「預覽 POST 端點」會使用目前設定的登入方式取得規格；表單登入預覽會實際登入一次
- 預覽表可**逐項勾選端點**，按「套用到白名單」自動產生 host-aware 的 `POST https://host/path` 清單
- 預覽會顯示**實際請求 manifest**：URL、Content-Type、JSON body 與會被 canary 替換的欄位
- 預覽會顯示匯入統計與 warnings（例如外部 `$ref`、略過 scope、其他 HTTP method、無法解析的參數／body `$ref`，並標出 method 與 path）
- 預覽會計算 **spec fingerprint**；實際掃描會重新計算，若與預覽不同就保留匯入結果但**略過 API POST 測試**
- 支援 scope 內 HTTP(S) 外部 `$ref`（最多 8 個外部文件、100 個 ref）；scope 外或 local file ref 只會產生 warning
- 外部 `$ref` 文件會快取在 `data/openapi-cache/`，預設 TTL 1 小時，避免預覽與掃描重複抓取同一個文件
- `POST 端點白名單`可限制 API POST 檢查的目標；支援 `POST https://host/api/items/*`、`POST /api/items/*` 等 pattern
- **白名單留空時必須另外勾選「我確認測試所有 POST 端點」**，否則無法建立掃描
- 掃描報告會記錄已選端點、manifest 摘要、白名單、全部測試確認狀態、spec fingerprint、session 檢查與 OpenAPI warnings
- API POST 測試前會檢查登入 session；401／403、導向登入頁或驗證文字消失時會略過 API POST 並記錄原因
- **BOLA／BFLA** 需另外勾選並提供第二帳號，支援第二帳號 Cookie、Header、Storage State 或表單登入
- BOLA 只對具有 ID／UUID 參數的 GET 做唯讀比較；BFLA 檢查 admin／manage／internal／role 等管理 GET
- GET 白名單留空時必須另外確認「測試所有候選 GET」，建議限制到授權物件路徑
- BOLA／BFLA 會先確認未登入請求被拒絕，再比較主要／第二帳號的狀態與回應形狀；JSON 優先比較結構而非實際值
- 主要、第二帳號與未登入請求共用同一個 rate limiter 與 request budget；BOLA 請求即時計入進度與報告
- 報告會列出每個 POST 端點的檢查、發現數與跳過原因（沒有 JSON body／預算用盡／未執行）
- 報告會列出每個 BOLA／BFLA 候選端點的類型、primary／secondary／未登入狀態、相似度與結果分類
- Diff 頁面會顯示 API 測試覆蓋變化，以及 BOLA／BFLA 新出現、不再疑似、本次未測與開始測試
- 前次 API／BOLA 發現若本次因預算、白名單、spec drift 或 session 無效而未測試，會列為「本次未測」而不是「已修復」
- 表單登入 session 失效時會重新登入一次並重新檢查；Cookie／Header／Storage state 不支援自動恢復
- 每個弱點都可以設定人工驗證狀態與備註；驗證狀態依 fingerprint 跨掃描共用
- 弱點清單可依驗證狀態篩選並批次更新；誤報與接受風險必須填寫備註
- 每次驗證狀態變更都會保留歷史；HTML／JSON 報告都會保留目前狀態、備註、到期日與歷程
- Diff 會區分新增／已確認／待確認／已排除；誤報與接受風險不會列入新增 regression
- 跨掃描歷史頁可追蹤 fingerprint 的首次出現、最近出現、掃描來源與狀態變化
- 驗證工作台跨掃描去重，提供待確認佇列、篩選與接受風險到期提醒
- 接受風險到期、嚴重度升級或誤報證據改變時會自動重開，並保留 `system` 紀錄
- Diff 可使用目標 baseline；CLI 支援 `baseline set／show／clear` 與 `--fail-on` regression gate
- 「掃描趨勢」頁顯示每個目標最近掃描的新增／修復／未測／已排除與驗證狀態
- CI 另外執行真正的 scan → baseline → diff gate 流程，而不只依賴 seeded DB
- 從舊版升級時，既有 `finding_reviews` 會一次性回填為跨掃描狀態，原始資料表保留
- 資料庫使用 `PRAGMA user_version` 執行增量 migration；不重建既有 `data/`
- CI 會執行 ruff、pytest coverage（門檻 75%）、JavaScript syntax check、wheel build／安裝 smoke test 與 baseline gate 範例；GUI E2E 可用 `VULNSCAN_E2E=1` 執行
- 本機可用 `python scripts/ci_gate_fixture.py --data-dir .ci-gate` 重現 CI gate 的 baseline 資料
- 可選擇是否允許 **POST／JSON 主動測試**
- POST 測試會送出無害 canary，但部分 API 可能建立或修改資料；僅限已授權的 staging／測試環境

CLI 範例：

```powershell
# 只匯入 GET 端點（不會送 POST）
vulnscan scan --url https://api.example.com --profile safe `
  --openapi openapi.json --acknowledge-authorized

# 從 URL 匯入（使用與掃描相同的登入 session）
vulnscan scan --url https://api.example.com --profile safe `
  --openapi-url https://api.example.com/openapi.json --acknowledge-authorized

# 明確允許 POST/JSON 主動測試，且只測 host-aware 白名單端點
vulnscan scan --url https://api.example.com --profile safe `
  --openapi openapi.json --api-post `
  --api-post-allow "POST https://api.example.com/api/items/*" --acknowledge-authorized

# 白名單留空時，必須明確確認測試全部 POST 端點
vulnscan scan --url https://api.example.com --profile safe `
  --openapi openapi.json --api-post --api-post-all --acknowledge-authorized

# BOLA／IDOR：需要主要帳號與第二帳號（此例使用 Cookie）
vulnscan scan --url https://api.example.com --profile safe `
  --auth-cookie "session=primary" `
  --bola --bola-auth-cookie "session=secondary" `
  --bola-allow "GET https://api.example.com/orders/*" `
  --max-api-tests 30 --max-bola-tests 8 `
  --acknowledge-authorized

# 第二帳號使用表單登入
vulnscan scan --url https://api.example.com --profile safe `
  --auth-cookie "session=primary" `
  --bola --bola-login-url "/login" `
  --bola-username reviewer --bola-password "secondary-password" `
  --bola-verify-text "登出" `
  --bola-allow "GET https://api.example.com/orders/*" `
  --acknowledge-authorized

# 白名單留空時，必須明確確認測試所有 BOLA 候選 GET
vulnscan scan --url https://api.example.com --profile safe `
  --auth-cookie "session=primary" `
  --bola --bola-auth-cookie "session=secondary" `
  --bola-allow-all --acknowledge-authorized
```

目前 API 主動檢查包含：

- JSON body（含巢狀參數）反射 HTML／XSS 風險
- 錯誤型 SQL Injection
- 布林型 SQL Injection：成對真假條件會重複兩輪，兩輪都出現一致訊號才回報；不做 UNION／寫入
- SSRF callback（完整模式並勾選 SSRF）
- GET 端點仍會走原本的查詢參數檢查

限制：

- 只匯入 GET 與 POST；不主動測試 PUT／PATCH／DELETE
- JSON body 支援巢狀物件與陣列第一筆元素；`oneOf`／`anyOf` 只取第一個可解析分支
- 外部 `$ref` 僅支援 HTTP(S)，且必須在授權 scope 內；local file ref 與 scope 外 ref 會 warning
- 檔案上傳規格的相對外部 `$ref` 沒有可靠 base URL，通常會 warning；請使用絕對 URL 或 URL 匯入
- 檔案預覽的外部 `$ref` 不帶登入 session；需要認證的外部文件請使用 URL 匯入，或把 schema 一起打包在檔案內
- BOLA／BFLA 第二帳號 UI 支援 Cookie、Header、Storage state 與表單登入；不支援第二帳號瀏覽器互動登入
- BOLA 只測試具有數字／UUID／ID 參數的 GET；BFLA 只測試管理語意路徑；結果仍可能需要人工確認角色與 ownership
- Session 自動恢復支援表單重新登入與 refresh token endpoint；每次掃描最多嘗試一次
- Token refresh 需要 `verify_url` 才能在做主動檢查前主動偵測；API／BOLA 檢查仍會使用既有 session 檢查流程
- 外部 `$ref` 快取不包含主規格文件，且不會放入 backup
- 不支援 multipart、GraphQL、XML body 或檔案上傳欄位

## 掃描模式

| 模式 | 行為 |
|---|---|
| 被動盤點 | 只觀察；敏感檔案與 OpenAPI 仍會用少量 GET 確認 |
| 安全主動（預設） | 加入無害 canary，檢測重導、反射注入、錯誤型 SQLi |
| 完整 | 安全主動 + 布林 SQLi、路徑遍歷、SSRF callback；UI 需逐項勾選並確認 |

## 安全設計

- 沒有授權欄位、到期日與勾選確認，無法建立掃描
- 預設每 host 3 rps、最多 2000 請求；遇到 429 只降速，不繞過 WAF
- 預設只允許 GET / HEAD / OPTIONS
- 跨網域 redirect 不跟隨；私有 IP 預設拒絕
- UI 預設只綁 `127.0.0.1`；所有輸出 escape
- 證據以純文字呈現，不渲染目標網站 HTML
- 一般掃描仍只讀：布林 SQLi 不執行 UNION／寫入，路徑遍歷只送不存在的 canary 檔名，SSRF 只使用掃描器自己的 callback
- API POST 預覽只解析規格、不送出掃描請求；URL 預覽會使用目前登入設定，且只能存取授權 scope 內主機
- 外部 `$ref` 也只允許授權 scope 內的 HTTP(S) 文件，並有檔案數、ref 數與大小上限
- 表單登入預覽會執行一次登入並寫入 `preview-audit.jsonl`；瀏覽器互動登入的 state 不會在預覽時被消耗
- 若預覽後 OpenAPI 規格或外部 `$ref` 內容改變，spec fingerprint 會不一致，API POST 測試會自動略過
- API POST 白名單只限制 POST 端點；host-aware pattern 會比對 scheme／host／path
- 白名單留空時必須明確確認測試全部 POST；報告會保存已選端點、manifest 摘要與 session 狀態
- API POST/JSON 主動測試預設關閉；開啟後可能讓 API 建立或修改資料，僅限可接受此風險的授權測試環境
- BOLA／IDOR 只使用已發現的 GET URL 與 ID，不枚舉、不執行寫入；第二帳號憑證只存在掃描記憶體
- SSRF listener 只記錄含隨機 token 的回連請求，回應固定 `200 ok`，不提供檔案或掃描器內部資訊

## 本機測試靶場

內附一個刻意有弱點的本機 fixture，用於開發與回歸測試：

```powershell
# 終端機 1
.\.venv\Scripts\python.exe -m tests.fixture_server
# 固定顯示 http://127.0.0.1:8899，Ctrl+C 停止

# 終端機 2
.\.venv\Scripts\python.exe -m pytest -q
```

## 專案結構

```
src/vulnscan/
├── cli.py              # vulnscan ui / scan / rules
├── web/                # FastAPI、Jinja2、CSS、JS
├── jobs/               # 佇列、進度、取消
├── engine.py           # 掃描流程
├── crawler.py          # 頁面、表單、JS 探索
├── http.py             # 速率限制、請求預算、audit
├── scope.py            # 授權與範圍驗證
├── checks/             # 被動與主動檢查
└── report/             # HTML + JSON
tests/                  # pytest + 本機靶場
```

## 目前限制

- 需要互動式瀏覽器才能處理 SSO／MFA；不支援自動 TOTP／推播 MFA
- GUI 啟動瀏覽器需要本機桌面與 Playwright Chromium；無桌面環境請改用 CLI 狀態檔
- storage state 目前只處理 Cookie 與 localStorage，不支援 sessionStorage／IndexedDB
- YAML 自訂規則尚未實作；目前為內建 Python 檢查
- SSRF 只測 GET 參數；API JSON body 的 SSRF 只在完整模式且啟用 POST 測試時執行
- 尚未提供多使用者或遠端部署模式

## 資料位置

預設為專案下的 `data/`，可用 `VULNSCAN_DATA_DIR` 或 `--data-dir` 覆寫。
SQLite 使用 WAL mode；掃描歷史與發現都留在本機。
啟動時會依 `PRAGMA user_version` 套用增量 migration；舊 finding 會自動補上
fingerprint 並建立索引，既有掃描資料不會被重建或刪除。

### 備份與還原

```powershell
# 建立 ZIP 備份（DB 快照 + scans/ + settings.json）
vulnscan backup --out backups/vulnscan.zip

# 還原到新目錄
vulnscan restore --from backups/vulnscan.zip --data-dir data-restored

# 覆蓋既有資料目錄時，舊資料會先改名保留
vulnscan restore --from backups/vulnscan.zip --data-dir data --force
```

備份使用 SQLite backup API，不直接複製 WAL 中的不完整狀態。
還原前會檢查 ZIP 路徑安全、DB integrity 與 `scans` 資料表。
