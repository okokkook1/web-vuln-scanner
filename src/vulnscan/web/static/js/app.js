(function () {
  "use strict";

  function el(id) { return document.getElementById(id); }
  function setText(id, value) {
    const node = el(id);
    if (node) node.textContent = value == null ? "—" : String(value);
  }

  /* ---------- New scan wizard ---------- */
  const wizard = document.querySelector("[data-wizard]");
  if (wizard) {
    const panels = Array.from(wizard.querySelectorAll("[data-step]"));
    const indicators = Array.from(wizard.querySelectorAll("[data-step-indicator]"));
    const nextButton = wizard.querySelector("[data-next]");
    const prevButton = wizard.querySelector("[data-prev]");
    const submitButton = wizard.querySelector("[data-submit]");
    const errorBox = el("wizard-error");
    let index = 0;
    let browserSessionId = "";
    let browserSessionReady = false;
    let browserPollTimer = null;

    function showError(message) {
      if (!errorBox) return;
      errorBox.textContent = message || "";
      errorBox.hidden = !message;
    }

    function validateStepOne() {
      const panel = panels[0];
      if (!panel) return true;
      const targets = panel.querySelector('[name="targets"]');
      const authorized = panel.querySelector('[name="authorized_by"]');
      const contact = panel.querySelector('[name="contact"]');
      const expires = panel.querySelector('[name="expires"]');
      const ack = panel.querySelector('[name="authorized_ack"]');
      if (!targets || !targets.value.trim()) {
        showError("請輸入至少一個目標網址。");
        targets && targets.focus();
        return false;
      }
      if (!authorized || !authorized.value.trim()) {
        showError("請填寫授權人。");
        authorized && authorized.focus();
        return false;
      }
      if (!contact || !contact.value.trim()) {
        showError("請填寫聯絡人。");
        contact && contact.focus();
        return false;
      }
      if (!expires || !expires.value) {
        showError("請選擇授權到期日。");
        expires && expires.focus();
        return false;
      }
      if (!ack || !ack.checked) {
        showError("請確認已取得此目標的書面授權。");
        ack && ack.focus();
        return false;
      }
      showError("");
      return true;
    }

    function readValue(name) {
      const field = wizard.querySelector(`[name="${name}"]`);
      return field ? field.value : "";
    }

    function selectedProfile() {
      return wizard.querySelector('input[name="profile"]:checked');
    }

    function toggleFullOptions() {
      const selected = selectedProfile();
      const panel = el("full-options");
      if (panel) panel.hidden = !selected || selected.value !== "full";
      toggleSsrfOptions();
      updateSummary();
    }

    function toggleSsrfOptions() {
      const checkbox = el("advanced-ssrf");
      const field = el("ssrf-callback-field");
      if (field) field.hidden = !checkbox || !checkbox.checked;
    }

    function toggleAuthPanels() {
      const type = readValue("auth_type") || "none";
      wizard.querySelectorAll("[data-auth-panel]").forEach((panel) => {
        panel.hidden = panel.dataset.authPanel !== type;
      });
      updateSummary();
    }

    function toggleBolaPanels() {
      const type = readValue("bola_auth_type") || "none";
      wizard.querySelectorAll("[data-bola-panel]").forEach((panel) => {
        panel.hidden = panel.dataset.bolaPanel !== type;
      });
    }

    function validateBola() {
      const enabled = wizard.querySelector('[name="enable_bola"]');
      if (!enabled || !enabled.checked) return true;
      const selected = selectedProfile();
      if (selected && selected.value === "passive") {
        showError("BOLA／IDOR 檢查需要安全主動或完整模式。");
        return false;
      }
      const ack = wizard.querySelector('[name="bola_ack"]');
      if (!ack || !ack.checked) {
        showError("請確認已取得兩個帳號的授權，才能啟用 BOLA／IDOR 檢查。");
        return false;
      }
      const type = readValue("bola_auth_type") || "none";
      if (type === "none") {
        showError("BOLA／IDOR 檢查需要設定第二帳號登入方式。");
        return false;
      }
      if (type === "cookie" && !readValue("bola_auth_cookie").trim()) {
        showError("BOLA 第二帳號需要 Cookie 字串。");
        return false;
      }
      if (type === "header") {
        if (
          !readValue("bola_auth_header_name").trim() ||
          !readValue("bola_auth_header_value").trim()
        ) {
          showError("BOLA 第二帳號需要 Header 名稱與值。");
          return false;
        }
      }
      if (type === "state") {
        const file = wizard.querySelector('[name="bola_auth_state_file"]');
        if (!file || !file.files || !file.files.length) {
          showError("BOLA 第二帳號需要上傳 storage state JSON。");
          return false;
        }
      }
      if (type === "form") {
        if (
          !readValue("bola_login_url").trim() ||
          !readValue("bola_username").trim() ||
          !readValue("bola_password")
        ) {
          showError("BOLA 表單登入需要登入 URL、帳號與密碼。");
          return false;
        }
      }
      const allowlist = readValue("bola_allowlist")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);
      const allAck = wizard.querySelector('[name="bola_allow_all_ack"]');
      if (!allowlist.length && (!allAck || !allAck.checked)) {
        showError(
          "BOLA GET 白名單為空；請填寫白名單，或確認測試所有候選 GET 端點。"
        );
        return false;
      }
      return true;
    }

    function setBrowserStatus(message, kind) {
      const box = el("browser-login-status");
      if (!box) return;
      box.textContent = message || "";
      box.hidden = !message;
      box.className = `alert alert-${kind || "info"}`;
    }

    function setBrowserButtons(start, complete, cancel) {
      if (el("browser-login-start")) el("browser-login-start").hidden = !start;
      if (el("browser-login-complete")) el("browser-login-complete").hidden = !complete;
      if (el("browser-login-cancel")) el("browser-login-cancel").hidden = !cancel;
    }

    function stopBrowserPoll() {
      if (browserPollTimer) {
        clearInterval(browserPollTimer);
        browserPollTimer = null;
      }
    }

    function pollBrowserSession(id) {
      stopBrowserPoll();
      browserPollTimer = setInterval(async () => {
        try {
          const response = await fetch(`/auth/browser/${id}/status`, {
            headers: { Accept: "application/json" }
          });
          if (!response.ok) throw new Error("session lost");
          const data = await response.json();
          const kind = data.status === "ready" ? "success" : data.status === "failed" ? "error" : "info";
          setBrowserStatus(data.message || data.status, kind);
          if (data.status === "waiting") {
            browserSessionReady = false;
            setBrowserButtons(false, true, true);
          } else if (data.status === "ready") {
            browserSessionReady = true;
            stopBrowserPoll();
            setBrowserButtons(false, false, false);
          } else if (data.status === "failed" || data.status === "cancelled") {
            browserSessionReady = false;
            stopBrowserPoll();
            setBrowserButtons(true, false, false);
          }
        } catch (error) {
          stopBrowserPoll();
          setBrowserStatus("無法取得瀏覽器登入狀態，請重新開始。", "error");
          setBrowserButtons(true, false, false);
        }
      }, 1000);
    }

    async function startBrowserLogin() {
      const loginUrl = readValue("browser_login_url").trim();
      const ack = wizard.querySelector('[name="authorized_ack"]');
      if (!loginUrl) {
        showError("請先填寫瀏覽器登入 URL。");
        return;
      }
      if (!ack || !ack.checked) {
        showError("請先在 Step 1 勾選授權確認，才能啟動瀏覽器登入。");
        return;
      }
      showError("");
      browserSessionReady = false;
      browserSessionId = "";
      const hidden = wizard.querySelector('[name="browser_session_id"]');
      if (hidden) hidden.value = "";
      setBrowserStatus("正在啟動瀏覽器…", "info");
      setBrowserButtons(false, false, true);
      const form = new FormData();
      form.append("csrf_token", wizard.querySelector('[name="csrf_token"]').value);
      form.append("login_url", loginUrl);
      form.append("authorized_ack", "on");
      try {
        const response = await fetch("/auth/browser/start", {
          method: "POST",
          body: form,
          credentials: "same-origin"
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "瀏覽器登入啟動失敗");
        browserSessionId = data.id;
        if (hidden) hidden.value = data.id;
        setBrowserStatus(data.message || "瀏覽器已開啟，請完成登入。", "info");
        setBrowserButtons(false, false, true);
        pollBrowserSession(data.id);
      } catch (error) {
        setBrowserStatus(error.message || String(error), "error");
        setBrowserButtons(true, false, false);
      }
    }

    async function completeBrowserLogin() {
      if (!browserSessionId) return;
      const form = new FormData();
      form.append("csrf_token", wizard.querySelector('[name="csrf_token"]').value);
      try {
        const response = await fetch(`/auth/browser/${browserSessionId}/complete`, {
          method: "POST",
          body: form,
          credentials: "same-origin"
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "無法完成瀏覽器登入");
        setBrowserStatus(data.message || "正在擷取登入狀態…", "info");
        setBrowserButtons(false, false, true);
        pollBrowserSession(browserSessionId);
      } catch (error) {
        setBrowserStatus(error.message || String(error), "error");
      }
    }

    async function cancelBrowserLogin() {
      if (!browserSessionId) {
        setBrowserButtons(true, false, false);
        return;
      }
      const form = new FormData();
      form.append("csrf_token", wizard.querySelector('[name="csrf_token"]').value);
      try {
        await fetch(`/auth/browser/${browserSessionId}/cancel`, {
          method: "POST",
          body: form,
          credentials: "same-origin"
        });
      } catch (error) {
        /* best effort */
      }
      browserSessionReady = false;
      const hidden = wizard.querySelector('[name="browser_session_id"]');
      if (hidden) hidden.value = "";
      setBrowserStatus("已取消瀏覽器登入。", "warn");
      setBrowserButtons(true, false, false);
      stopBrowserPoll();
    }

    function validateAuth() {
      const type = readValue("auth_type") || "none";
      if (type === "cookie" && !readValue("auth_cookie").trim()) {
        showError("Cookie 登入需要貼上 Cookie 字串。");
        return false;
      }
      if (type === "header") {
        if (!readValue("auth_header_name").trim() || !readValue("auth_header_value").trim()) {
          showError("Header 登入需要填寫名稱與值。");
          return false;
        }
      }
      if (type === "form") {
        if (!readValue("login_url").trim() || !readValue("username").trim() || !readValue("password")) {
          showError("表單登入需要登入 URL、帳號與密碼。");
          return false;
        }
        if (!readValue("login_user_field").trim() || !readValue("login_pass_field").trim()) {
          showError("帳號與密碼欄位名稱不可空白。");
          return false;
        }
      }
      if (type === "state") {
        const file = wizard.querySelector('[name="auth_state_file"]');
        if (!file || !file.files || !file.files.length) {
          showError("瀏覽器狀態登入需要上傳 storage state JSON。");
          return false;
        }
        const key = readValue("storage_token_key").trim();
        const header = readValue("storage_header_name").trim();
        if (!!key !== !!header) {
          showError("localStorage token key 與 Header 名稱必須同時填寫或同時留空。");
          return false;
        }
      }
      if (type === "browser") {
        const hidden = wizard.querySelector('[name="browser_session_id"]');
        if (!readValue("browser_login_url").trim()) {
          showError("請填寫瀏覽器登入 URL。");
          return false;
        }
        if (!browserSessionReady || !browserSessionId || !hidden || !hidden.value) {
          showError("請先開啟瀏覽器完成登入，並按下「我已完成登入」。");
          return false;
        }
        const key = readValue("browser_token_key").trim();
        const header = readValue("browser_header_name").trim();
        if (!!key !== !!header) {
          showError("localStorage token key 與 Header 名稱必須同時填寫或同時留空。");
          return false;
        }
      }
      return true;
    }

    function validateApi() {
      const post = wizard.querySelector('[name="allow_api_post"]');
      const file = wizard.querySelector('[name="openapi_file"]');
      const url = readValue("openapi_url").trim();
      const hasFile = file && file.files && file.files.length;
      if (hasFile && url) {
        showError("OpenAPI 規格檔與 URL 只能擇一。");
        return false;
      }
      if (!post || !post.checked) return true;
      const selected = selectedProfile();
      if (selected && selected.value === "passive") {
        showError("API POST 主動測試需要安全主動或完整模式。");
        return false;
      }
      if (!hasFile && !url) {
        showError("啟用 API POST 測試前，請上傳 OpenAPI 規格檔或填寫 URL。");
        return false;
      }
      const allowlist = readValue("api_post_allowlist")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);
      const allAck = wizard.querySelector('[name="api_post_all_ack"]');
      if (!allowlist.length && (!allAck || !allAck.checked)) {
        showError(
          "白名單為空；請先勾選要測的 POST 端點，或確認要測試所有 POST 端點。"
        );
        return false;
      }
      return true;
    }

    function clearApiPreview(clearFingerprint = true) {
      const box = el("api-preview-result");
      if (box) {
        box.hidden = true;
        box.textContent = "";
      }
      const actions = el("api-preview-actions");
      if (actions) actions.hidden = true;
      if (clearFingerprint !== false) {
        const fingerprint = wizard.querySelector(
          '[name="openapi_fingerprint"]'
        );
        if (fingerprint) fingerprint.value = "";
      }
    }

    function apiAuthLabel(data) {
      if (!data.auth_used) return "未使用";
      const labels = {
        cookie: "Cookie",
        header: "自訂 Header",
        form: "表單登入",
        state: "Storage state",
        browser: "瀏覽器互動登入"
      };
      return labels[data.auth && data.auth.type] || "已使用";
    }

    function renderApiWarnings(data, box) {
      if (!data.warnings || !data.warnings.length) return;
      const details = document.createElement("details");
      details.open = true;
      details.style.marginTop = "8px";
      const summary = document.createElement("summary");
      summary.textContent = `匯入警告 ${data.warnings.length} 條`;
      const list = document.createElement("ul");
      list.style.margin = "6px 0 0";
      list.style.paddingLeft = "20px";
      data.warnings.forEach((warning) => {
        const item = document.createElement("li");
        item.textContent = warning;
        list.appendChild(item);
      });
      details.append(summary, list);
      box.appendChild(details);
    }

    function renderApiPreview(data, box) {
      box.textContent = "";
      const actions = el("api-preview-actions");
      const fingerprintField = wizard.querySelector(
        '[name="openapi_fingerprint"]'
      );
      if (fingerprintField) {
        fingerprintField.value = data.spec_fingerprint || "";
      }
      const fingerprint = data.spec_fingerprint
        ? data.spec_fingerprint.slice(0, 12)
        : "未提供";
      const heading = document.createElement("div");
      heading.textContent =
        `來源：${data.source} · 認證：${apiAuthLabel(data)} · ` +
        `POST 端點 ${data.count} 個 · Spec fingerprint：${fingerprint}`;
      box.appendChild(heading);
      if (data.stats) {
        const stats = document.createElement("div");
        stats.style.marginTop = "5px";
        stats.textContent =
          `匯入 GET ${data.stats.get || 0}、POST ${data.stats.post || 0}；` +
          `略過 scope ${data.stats.skipped_scope || 0}、其他 method ${data.stats.skipped_methods || 0}、` +
          `無法解析 body ${data.stats.unparsed_bodies || 0}` +
          (data.stats.external_documents
            ? `；外部 ref 文件 ${data.stats.external_documents}、解析 ${data.stats.resolved_refs || 0}`
            : "");
        box.appendChild(stats);
      }
      if (data.warning) {
        const warning = document.createElement("div");
        warning.style.marginTop = "6px";
        warning.textContent = data.warning;
        box.appendChild(warning);
      }
      renderApiWarnings(data, box);
      if (!data.endpoints || !data.endpoints.length) {
        const empty = document.createElement("div");
        empty.style.marginTop = "6px";
        empty.textContent = "此規格沒有可測試的 POST 端點。";
        box.appendChild(empty);
        if (actions) actions.hidden = true;
        return;
      }
      const list = document.createElement("ul");
      list.style.margin = "8px 0 0";
      list.style.paddingLeft = "0";
      list.style.listStyle = "none";
      data.endpoints.forEach((item) => {
        const row = document.createElement("li");
        row.style.margin = "9px 0";
        const label = document.createElement("label");
        label.style.display = "flex";
        label.style.alignItems = "flex-start";
        label.style.gap = "8px";
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.dataset.path = item.path;
        checkbox.dataset.pattern = item.allowlist_pattern || `POST ${item.path}`;
        checkbox.checked = !!(data.allowlist && data.allowlist.length && item.allowed);
        const text = document.createElement("span");
        const endpoint = document.createElement("code");
        endpoint.textContent = `${item.method} ${item.path}`;
        text.appendChild(endpoint);
        if (item.fields && item.fields.length) {
          const fields = document.createElement("span");
          fields.textContent = ` · 可替換欄位：${item.fields.join("、")}`;
          text.appendChild(fields);
        }
        if (data.allowlist && data.allowlist.length && !item.allowed) {
          const skipped = document.createElement("strong");
          skipped.textContent = " · 目前白名單未包含";
          skipped.style.color = "#b42318";
          text.appendChild(skipped);
        }
        label.append(checkbox, text);
        row.appendChild(label);

        const manifest = document.createElement("details");
        manifest.style.margin = "4px 0 0 24px";
        const manifestSummary = document.createElement("summary");
        manifestSummary.textContent = "查看實際請求 manifest";
        const pre = document.createElement("pre");
        pre.className = "evidence";
        pre.textContent = JSON.stringify(
          item.request || { method: item.method, url: item.url, body: item.body },
          null,
          2
        );
        manifest.append(manifestSummary, pre);
        row.appendChild(manifest);
        list.appendChild(row);
      });
      box.appendChild(list);
      if (actions) actions.hidden = false;

      const note = document.createElement("div");
      note.style.marginTop = "8px";
      note.textContent =
        "勾選要測試的端點後按「套用到白名單」；留空白名單則會測試所有 POST 端點。";
      box.appendChild(note);
    }

    function setApiPreviewChecked(checked) {
      document
        .querySelectorAll('#api-preview-result input[type="checkbox"]')
        .forEach((checkbox) => {
          checkbox.checked = checked;
        });
    }

    function applyApiPreviewAllowlist() {
      const box = el("api-preview-result");
      if (!box) return;
      const patterns = Array.from(
        box.querySelectorAll('input[type="checkbox"]:checked')
      )
        .map(
          (checkbox) =>
            checkbox.dataset.pattern || `POST ${checkbox.dataset.path || ""}`
        )
        .filter((pattern) => pattern.trim() && pattern !== "POST ");
      const unique = Array.from(new Set(patterns));
      if (!unique.length) {
        showError("請先勾選至少一個 POST 端點，再套用到白名單。");
        return;
      }
      if (unique.length > 100) {
        showError("白名單最多 100 條；請減少勾選數量，或手動使用萬用字元。");
        return;
      }
      const field = wizard.querySelector('[name="api_post_allowlist"]');
      if (!field) return;
      field.value = unique.join("\n");
      showError("");
      updateSummary();
      box.querySelectorAll("[data-preview-note]").forEach((node) => node.remove());
      const note = document.createElement("div");
      note.dataset.previewNote = "1";
      note.style.marginTop = "8px";
      note.style.fontWeight = "600";
      note.textContent =
        `已套用 ${unique.length} 條 host-aware 白名單；` +
        "掃描時只會測試勾選的 POST 端點。";
      box.appendChild(note);
    }

    async function previewApiEndpoints() {
      const button = el("api-preview-button");
      const box = el("api-preview-result");
      if (!button || !box) return;
      const file = wizard.querySelector('[name="openapi_file"]');
      const url = readValue("openapi_url").trim();
      const hasFile = file && file.files && file.files.length;
      if (hasFile && url) {
        showError("OpenAPI 規格檔與 URL 只能擇一。");
        return;
      }
      if (!hasFile && !url) {
        showError("請先上傳 OpenAPI 規格檔或填寫 URL，才能預覽 POST 端點。");
        return;
      }
      showError("");
      button.disabled = true;
      box.hidden = false;
      box.className = "alert alert-info";
      box.textContent = "解析 OpenAPI 規格中…（不會送出掃描請求）";
      const actions = el("api-preview-actions");
      if (actions) actions.hidden = true;
      const fingerprintField = wizard.querySelector(
        '[name="openapi_fingerprint"]'
      );
      if (fingerprintField) fingerprintField.value = "";
      try {
        const response = await fetch("/scans/api/preview", {
          method: "POST",
          body: new FormData(wizard),
          credentials: "same-origin",
          headers: { Accept: "application/json" }
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(data.error || data.detail || `HTTP ${response.status}`);
        }
        renderApiPreview(data, box);
      } catch (error) {
        box.className = "alert alert-error";
        box.textContent = error.message || String(error);
        if (actions) actions.hidden = true;
      } finally {
        button.disabled = false;
      }
    }

    function validateStepTwo() {
      const selected = selectedProfile();
      if (!selected || selected.value !== "full") {
        if (!validateAuth()) return false;
        if (!validateApi()) return false;
        if (!validateBola()) return false;
        showError("");
        return true;
      }
      const checks = Array.from(wizard.querySelectorAll("[data-advanced-check]:checked"));
      if (!checks.length) {
        showError("完整模式至少要選擇一項進階檢查。");
        return false;
      }
      const ack = wizard.querySelector('[name="advanced_ack"]');
      if (!ack || !ack.checked) {
        showError("請確認要啟用進階檢查。");
        ack && ack.focus();
        return false;
      }
      const ssrf = el("advanced-ssrf");
      const callback = readValue("ssrf_callback").trim();
      if (ssrf && ssrf.checked && callback && !/^http:\/\//i.test(callback)) {
        showError("SSRF callback 僅支援 http:// 開頭的網址。");
        return false;
      }
      if (!validateAuth()) return false;
      if (!validateApi()) return false;
      if (!validateBola()) return false;
      showError("");
      return true;
    }

    function updateSummary() {
      const targets = readValue("targets").split(/\r?\n|,/).map((s) => s.trim()).filter(Boolean);
      const selected = selectedProfile();
      setText("summary-targets", targets.length ? targets.join("、") : "—");
      setText("summary-auth", `${readValue("authorized_by") || "—"} / ${readValue("contact") || "—"}`);
      setText("summary-expires", readValue("expires") || "—");
      setText("summary-profile", selected ? selected.dataset.label : "—");
      const advanced = Array.from(wizard.querySelectorAll("[data-advanced-check]:checked"))
        .map((input) => input.closest(".check")?.querySelector("strong")?.textContent?.trim())
        .filter(Boolean);
      setText(
        "summary-advanced",
        selected && selected.value === "full" ? (advanced.length ? advanced.join("、") : "尚未選擇") : "—"
      );
      const ssrf = el("advanced-ssrf");
      const callback = readValue("ssrf_callback").trim();
      setText(
        "summary-callback",
        selected && selected.value === "full" && ssrf && ssrf.checked
          ? callback || "自動（127.0.0.1 隨機埠）"
          : "—"
      );
      const authType = readValue("auth_type") || "none";
      const authLabels = {
        none: "不使用登入",
        cookie: "Cookie",
        header: "自訂 Header",
        form: "表單登入",
        state: "瀏覽器狀態檔（SSO／MFA）",
        browser: "瀏覽器互動登入（SSO／MFA）"
      };
      let authSummary = authLabels[authType] || authType;
      if (authType === "form" && readValue("username").trim()) {
        authSummary += `（${readValue("username").trim()}）`;
      }
      setText("summary-login", authSummary);
      const bolaEnabled = wizard.querySelector('[name="enable_bola"]');
      const bolaType = readValue("bola_auth_type") || "none";
      const bolaLabels = {
        none: "未設定第二帳號",
        cookie: "Cookie",
        header: "自訂 Header",
        state: "Storage state",
        form: "表單登入"
      };
      const bolaAllowlist = readValue("bola_allowlist")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);
      const bolaAllAck = wizard.querySelector('[name="bola_allow_all_ack"]');
      const bolaScope = bolaAllowlist.length
        ? `${bolaAllowlist.length} 條 GET 白名單`
        : bolaAllAck && bolaAllAck.checked
          ? "全部 GET（已確認）"
          : "GET 白名單未確認";
      setText(
        "summary-bola",
        bolaEnabled && bolaEnabled.checked
          ? `啟用（${bolaLabels[bolaType] || bolaType}；${bolaScope}）`
          : "停用"
      );
      const apiFile = wizard.querySelector('[name="openapi_file"]');
      const apiPost = wizard.querySelector('[name="allow_api_post"]');
      const apiUrl = readValue("openapi_url").trim();
      setText(
        "summary-api",
        apiFile && apiFile.files && apiFile.files.length
          ? apiFile.files[0].name
          : apiUrl || "未選擇"
      );
      const allowlist = readValue("api_post_allowlist")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);
      const allAck = wizard.querySelector('[name="api_post_all_ack"]');
      setText(
        "summary-api-allow",
        allowlist.length
          ? `${allowlist.length} 條`
          : allAck && allAck.checked
            ? "全部（已確認）"
            : "未限制（未確認）"
      );
      setText(
        "summary-api-post",
        apiPost && apiPost.checked ? "啟用（可能產生資料）" : "停用"
      );
      const limits = `${readValue("rps_per_host") || "3"} rps/host · ${readValue("max_requests_per_host") || "2000"} 請求/host · 深度 ${readValue("max_depth") || "3"}`;
      setText("summary-limits", limits);
      const allowPrivate = wizard.querySelector('[name="allow_private"]');
      setText("summary-private", allowPrivate && allowPrivate.checked ? "允許（已明確開啟）" : "不允許");
    }

    function show(nextIndex) {
      index = Math.max(0, Math.min(nextIndex, panels.length - 1));
      panels.forEach((panel, i) => panel.classList.toggle("active", i === index));
      indicators.forEach((item, i) => {
        item.classList.toggle("active", i === index);
        item.classList.toggle("done", i < index);
      });
      if (prevButton) prevButton.hidden = index === 0;
      if (nextButton) nextButton.hidden = index === panels.length - 1;
      if (submitButton) submitButton.hidden = index !== panels.length - 1;
      if (index === 2) updateSummary();
      const heading = panels[index] && panels[index].querySelector("h2");
      if (heading) heading.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    if (nextButton) {
      nextButton.addEventListener("click", () => {
        if (index === 0 && !validateStepOne()) return;
        if (index === 1 && (!validateStepTwo() || !wizard.reportValidity())) return;
        show(index + 1);
      });
    }
    if (prevButton) prevButton.addEventListener("click", () => show(index - 1));
    wizard.querySelectorAll('input[name="profile"]').forEach((input) => {
      input.addEventListener("change", toggleFullOptions);
    });
    wizard.querySelectorAll("[data-advanced-check]").forEach((input) => {
      input.addEventListener("change", updateSummary);
    });
    const ssrfCheckbox = el("advanced-ssrf");
    if (ssrfCheckbox) {
      ssrfCheckbox.addEventListener("change", toggleSsrfOptions);
    }
    const apiPreviewButton = el("api-preview-button");
    if (apiPreviewButton) {
      apiPreviewButton.addEventListener("click", previewApiEndpoints);
    }
    const apiPreviewAll = el("api-preview-all");
    if (apiPreviewAll) {
      apiPreviewAll.addEventListener("click", () => setApiPreviewChecked(true));
    }
    const apiPreviewNone = el("api-preview-none");
    if (apiPreviewNone) {
      apiPreviewNone.addEventListener("click", () => setApiPreviewChecked(false));
    }
    const apiPreviewApply = el("api-preview-apply");
    if (apiPreviewApply) {
      apiPreviewApply.addEventListener("click", applyApiPreviewAllowlist);
    }
    wizard
      .querySelectorAll(
        '[name="targets"], [name="allow_private"], [name="openapi_file"], ' +
          '[name="openapi_url"], [name="auth_type"], ' +
          '[data-auth-panel] input, [data-auth-panel] select'
      )
      .forEach((field) => {
        field.addEventListener("input", clearApiPreview);
        field.addEventListener("change", clearApiPreview);
      });
    const apiAllowlistField = wizard.querySelector(
      '[name="api_post_allowlist"]'
    );
    if (apiAllowlistField) {
      const hideWithoutLosingFingerprint = () => clearApiPreview(false);
      apiAllowlistField.addEventListener("input", hideWithoutLosingFingerprint);
      apiAllowlistField.addEventListener("change", hideWithoutLosingFingerprint);
    }
    const authType = el("auth-type");
    if (authType) {
      authType.addEventListener("change", toggleAuthPanels);
    }
    const bolaAuthType = el("bola-auth-type");
    if (bolaAuthType) {
      bolaAuthType.addEventListener("change", toggleBolaPanels);
    }
    const bolaEnabled = wizard.querySelector('[name="enable_bola"]');
    if (bolaEnabled) {
      bolaEnabled.addEventListener("change", updateSummary);
    }
    const browserStart = el("browser-login-start");
    if (browserStart) {
      browserStart.addEventListener("click", startBrowserLogin);
    }
    const browserComplete = el("browser-login-complete");
    if (browserComplete) {
      browserComplete.addEventListener("click", completeBrowserLogin);
    }
    const browserCancel = el("browser-login-cancel");
    if (browserCancel) {
      browserCancel.addEventListener("click", cancelBrowserLogin);
    }
    wizard.addEventListener("input", (event) => {
      if (index === 2 && event.target.name) updateSummary();
    });
    wizard.addEventListener("submit", (event) => {
      if (index !== panels.length - 1) {
        event.preventDefault();
        if (index === 0 && !validateStepOne()) return;
        if (index === 1 && (!validateStepTwo() || !wizard.reportValidity())) return;
        show(index + 1);
      }
    });
    show(Number(wizard.dataset.initialStep || 0));
    toggleFullOptions();
    toggleAuthPanels();
    toggleBolaPanels();
  }

  /* ---------- Live scan ---------- */
  const live = document.querySelector("[data-live-scan]");
  if (live) {
    const statusUrl = live.dataset.statusUrl;
    const scanId = live.dataset.scanId;
    const terminalStates = ["completed", "failed", "cancelled"];
    const phaseOrder = ["validate", "crawl", "passive", "active", "report"];
    const statusLabels = {
      queued: "排隊中",
      running: "掃描中",
      completed: "已完成",
      failed: "失敗",
      cancelled: "已取消"
    };
    let timer = null;
    let stopped = false;

    function updatePhases(phaseKey) {
      const current = phaseOrder.indexOf(phaseKey);
      document.querySelectorAll("[data-phase]").forEach((node) => {
        const idx = phaseOrder.indexOf(node.dataset.phase);
        node.classList.toggle("active", idx === current);
        node.classList.toggle("done", current >= 0 && idx < current);
      });
    }

    function updateFindings(rows) {
      const body = el("live-findings-body");
      if (!body) return;
      if (!rows || !rows.length) {
        body.innerHTML = '<tr><td colspan="4" class="muted">目前還沒有發現，掃描仍在進行中。</td></tr>';
        return;
      }
      body.innerHTML = "";
      rows.slice(0, 8).forEach((row) => {
        const tr = document.createElement("tr");
        const sev = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = `badge ${row.severity}`;
        badge.textContent = severityLabel(row.severity);
        sev.appendChild(badge);
        const title = document.createElement("td");
        const link = document.createElement("a");
        link.href = `/findings/${row.id}`;
        link.textContent = row.title;
        title.appendChild(link);
        const where = document.createElement("td");
        where.className = "mono muted";
        where.textContent = row.url + (row.parameter ? ` · ${row.parameter}` : "");
        const conf = document.createElement("td");
        conf.textContent = confidenceLabel(row.confidence);
        tr.append(sev, title, where, conf);
        body.appendChild(tr);
      });
    }

    function updateLogs(logs) {
      const box = el("scan-log");
      if (!box) return;
      const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
      box.innerHTML = "";
      if (!logs || !logs.length) {
        const empty = document.createElement("div");
        empty.className = "log-empty";
        empty.textContent = "等待掃描開始…";
        box.appendChild(empty);
        return;
      }
      logs.forEach((item) => {
        const line = document.createElement("div");
        line.className = "log-line";
        const ts = document.createElement("span");
        ts.className = "log-ts";
        ts.textContent = item.ts || "";
        line.appendChild(ts);
        line.appendChild(document.createTextNode(item.message || ""));
        box.appendChild(line);
      });
      if (nearBottom) box.scrollTop = box.scrollHeight;
    }

    function update(payload) {
      const status = payload.status || "queued";
      const progress = Number(payload.progress || 0);
      setText("live-status", statusLabels[status] || status);
      const badge = el("live-status-badge");
      if (badge) {
        badge.className = `badge status-${status}`;
        badge.textContent = statusLabels[status] || status;
      }
      setText("live-phase", payload.phase || "—");
      setText("live-message", payload.message || "");
      setText("live-progress-value", `${progress}%`);
      const bar = el("live-progress-bar");
      if (bar) bar.style.width = `${Math.min(100, Math.max(0, progress))}%`;
      const stats = payload.stats || {};
      setText("stat-requests", stats.requests || 0);
      setText("stat-pages", stats.pages || 0);
      setText("stat-endpoints", stats.endpoints || 0);
      setText("stat-findings", stats.findings || 0);
      const sev = stats.by_severity || {};
      setText("stat-critical", sev.critical || 0);
      setText("stat-high", sev.high || 0);
      setText("stat-medium", sev.medium || 0);
      setText("stat-low", sev.low || 0);
      const resultLink = el("terminal-findings-link");
      if (resultLink) resultLink.textContent = `查看弱點（${stats.findings || 0}）`;
      updatePhases(payload.phase_key || "");
      updateFindings(payload.recent_findings || []);
      updateLogs(payload.logs || []);
      const errorBox = el("live-error");
      if (errorBox) {
        errorBox.hidden = !payload.error;
        errorBox.textContent = payload.error ? `錯誤：${payload.error}` : "";
      }
      if (terminalStates.includes(status)) {
        stopped = true;
        if (timer) clearInterval(timer);
        const cancel = el("cancel-form");
        if (cancel) cancel.hidden = true;
        const actions = el("terminal-actions");
        if (actions) actions.hidden = false;
      }
    }

    async function poll() {
      if (stopped) return;
      try {
        const response = await fetch(statusUrl, { headers: { Accept: "application/json" } });
        if (!response.ok) throw new Error(String(response.status));
        update(await response.json());
      } catch (error) {
        setText("live-message", "無法取得掃描狀態，將自動重試…");
      }
    }

    poll();
    timer = setInterval(poll, 1000);
  }

  function severityLabel(value) {
    return { critical: "嚴重", high: "高", medium: "中", low: "低", info: "資訊" }[value] || value;
  }
  function confidenceLabel(value) {
    return { high: "高", medium: "中", low: "低" }[value] || value;
  }

  /* ---------- Confirm destructive actions ---------- */
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  /* ---------- Copy buttons ---------- */
  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.querySelector(button.dataset.copyTarget);
      if (!target) return;
      try {
        await navigator.clipboard.writeText(target.textContent || "");
        const original = button.textContent;
        button.textContent = "已複製";
        setTimeout(() => { button.textContent = original; }, 1400);
      } catch (error) {
        /* clipboard may be blocked on http */
      }
    });
  });
})();
