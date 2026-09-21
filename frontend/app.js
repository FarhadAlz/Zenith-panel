"use strict";

/* ============================================================
   THEME
   ============================================================ */
const THEME_KEY = "zenith-theme";
function initTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  const theme = saved || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.documentElement.setAttribute("data-theme", theme);
}
function toggleTheme() {
  const cur = document.documentElement.getAttribute("data-theme");
  const next = cur === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem(THEME_KEY, next);
}
initTheme();
document.getElementById("themeToggle").addEventListener("click", toggleTheme);

/* ============================================================
   TINY HELPERS
   ============================================================ */
async function api(method, path, body) {
  const resp = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const err = new Error(data.detail || `HTTP ${resp.status}`);
    err.data = data;
    throw err;
  }
  return data;
}
function el(id) { return document.getElementById(id); }
function show(id) { el(id).classList.remove("hidden"); }
function hide(id) { el(id).classList.add("hidden"); }

/* ============================================================
   AUTH (setup / unlock)
   ============================================================ */
async function bootAuth() {
  const status = await api("GET", "/api/auth/status");
  if (status.unlocked) {
    startApp();
    return;
  }
  show("authScreen");
  if (!status.initialized) {
    el("authTitle").textContent = "راه‌اندازی صندوق امن";
    el("authSubtitle").textContent =
      "یک رمز اصلی انتخاب کنید. این رمز هرگز ذخیره نمی‌شود؛ فقط برای رمزگذاری اطلاعات ورود سرورها و کلید API روی همین دستگاه استفاده می‌شود.";
  } else {
    el("authTitle").textContent = "ورود به پنل";
    el("authSubtitle").textContent = "برای رمزگشایی اطلاعات ذخیره‌شده، رمز اصلی را وارد کنید.";
  }
}

el("authSubmit").addEventListener("click", async () => {
  const password = el("authPassword").value;
  hide("authError");
  try {
    const status = await api("GET", "/api/auth/status");
    if (!status.initialized) {
      await api("POST", "/api/auth/setup", { password });
    } else {
      await api("POST", "/api/auth/unlock", { password });
    }
    hide("authScreen");
    startApp();
  } catch (e) {
    el("authError").textContent = e.message;
    show("authError");
  }
});
el("authPassword").addEventListener("keydown", (e) => {
  if (e.key === "Enter") el("authSubmit").click();
});

el("lockBtn").addEventListener("click", async () => {
  await api("POST", "/api/auth/lock");
  location.reload();
});

/* ============================================================
   APP STATE
   ============================================================ */
let servers = [];
let selectedServerId = null;

async function startApp() {
  show("app");
  await refreshServerList();
}

async function refreshServerList() {
  servers = await api("GET", "/api/servers");
  renderServerList();
  if (selectedServerId) renderServerView();
}

function renderServerList() {
  const list = el("serverList");
  list.innerHTML = "";
  if (servers.length === 0) {
    show("serverListEmpty");
  } else {
    hide("serverListEmpty");
  }
  for (const s of servers) {
    const card = document.createElement("div");
    card.className = "server-card" + (s.id === selectedServerId ? " selected" : "");
    const domCount = s.domains ? s.domains.length : 0;
    card.innerHTML = `
      <div class="sc-top">
        <span class="sc-name">${escapeHtml(s.name)}</span>
        <span class="dot ${s.connected ? "dot-on" : "dot-off"}"></span>
      </div>
      <div class="sc-host">${escapeHtml(s.username)}@${escapeHtml(s.host)}:${s.port}</div>
      <div class="sc-host">${domCount} دامنه</div>
    `;
    card.addEventListener("click", () => {
      selectedServerId = s.id;
      renderServerList();
      renderServerView();
    });
    list.appendChild(card);
  }
}

function renderServerView() {
  const server = servers.find((s) => s.id === selectedServerId);
  if (!server) return;
  hide("noServerSelected");
  show("serverView");

  el("serverViewTitle").textContent = server.name;
  el("serverViewSub").textContent = `${server.username}@${server.host}:${server.port}`;
  const badge = el("serverConnBadge");
  badge.textContent = server.connected ? "● متصل" : "○ قطع شده";
  badge.style.color = server.connected ? "var(--accent-2)" : "var(--text-muted)";

  const grid = el("domainGrid");
  grid.innerHTML = "";
  const domains = server.domains || [];
  if (domains.length === 0) {
    show("domainGridEmpty");
  } else {
    hide("domainGridEmpty");
  }
  for (const d of domains) {
    const card = document.createElement("div");
    card.className = "domain-card";
    card.innerHTML = `
      <div class="dc-name">${escapeHtml(d.domain)}</div>
      <div class="dc-owner">کاربر: ${escapeHtml(d.owner_user || "-")}</div>
      ${d.subdomains && d.subdomains.length ? `<div class="dc-sub">${d.subdomains.length} ساب‌دامنه</div>` : ""}
    `;
    card.addEventListener("click", () => openDomainModal(server, d.domain));
    grid.appendChild(card);
  }
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

/* ============================================================
   ADD SERVER MODAL
   ============================================================ */
el("addServerBtn").addEventListener("click", () => {
  el("asName").value = "";
  el("asHost").value = "";
  el("asPort").value = "22";
  el("asUsername").value = "root";
  el("asPassword").value = "";
  el("asKeyText").value = "";
  el("asKeyPassphrase").value = "";
  hide("addServerError");
  setAuthTab("password");
  show("addServerModal");
});
el("asCancel").addEventListener("click", () => hide("addServerModal"));

let currentAuthTab = "password";
function setAuthTab(tab) {
  currentAuthTab = tab;
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.auth === tab));
  if (tab === "password") { show("authPasswordFields"); hide("authKeyFields"); }
  else { hide("authPasswordFields"); show("authKeyFields"); }
}
document.querySelectorAll(".tab-btn").forEach((b) => b.addEventListener("click", () => setAuthTab(b.dataset.auth)));

el("asSubmit").addEventListener("click", async () => {
  hide("addServerError");
  const body = {
    name: el("asName").value.trim(),
    host: el("asHost").value.trim(),
    port: parseInt(el("asPort").value, 10) || 22,
    username: el("asUsername").value.trim(),
    auth_type: currentAuthTab,
    secret: currentAuthTab === "password" ? el("asPassword").value : el("asKeyText").value,
    passphrase: currentAuthTab === "key" ? (el("asKeyPassphrase").value || null) : null,
  };
  if (!body.name || !body.host || !body.username || !body.secret) {
    el("addServerError").textContent = "همه فیلدهای لازم را پر کنید.";
    show("addServerError");
    return;
  }
  const btn = el("asSubmit");
  btn.disabled = true;
  btn.textContent = "در حال تست اتصال…";
  try {
    const result = await api("POST", "/api/servers", body);
    hide("addServerModal");
    if (result.warning) {
      alert("سرور ذخیره شد، اما هشدار: " + result.warning);
    }
    selectedServerId = result.id;
    await refreshServerList();
  } catch (e) {
    el("addServerError").textContent = e.message;
    show("addServerError");
  } finally {
    btn.disabled = false;
    btn.textContent = "تست اتصال و ذخیره";
  }
});

/* ============================================================
   SERVER VIEW ACTIONS
   ============================================================ */
el("reconnectBtn").addEventListener("click", async () => {
  const btn = el("reconnectBtn");
  btn.disabled = true;
  try {
    await api("POST", `/api/servers/${selectedServerId}/reconnect`);
    await refreshServerList();
  } catch (e) {
    alert("اتصال ناموفق: " + e.message);
  } finally {
    btn.disabled = false;
  }
});

el("refreshDomainsBtn").addEventListener("click", async () => {
  const btn = el("refreshDomainsBtn");
  btn.disabled = true;
  try {
    await api("POST", `/api/servers/${selectedServerId}/domains/refresh`);
    await refreshServerList();
  } catch (e) {
    alert("بروزرسانی ناموفق: " + e.message);
  } finally {
    btn.disabled = false;
  }
});

el("deleteServerBtn").addEventListener("click", async () => {
  if (!confirm("این سرور از تاریخچه حذف شود؟")) return;
  await api("DELETE", `/api/servers/${selectedServerId}`);
  selectedServerId = null;
  hide("serverView");
  show("noServerSelected");
  await refreshServerList();
});

/* ============================================================
   SETTINGS MODAL (API key)
   ============================================================ */
el("settingsBtn").addEventListener("click", async () => {
  el("apiKeyInput").value = "";
  try {
    const status = await api("GET", "/api/settings/api-key");
    el("apiKeyStatus").textContent = status.is_set ? "کلید API قبلاً ذخیره شده است." : "کلید API هنوز تنظیم نشده.";
  } catch (e) {
    el("apiKeyStatus").textContent = "";
  }
  show("settingsModal");
});
el("settingsCancel").addEventListener("click", () => hide("settingsModal"));
el("apiKeySave").addEventListener("click", async () => {
  const key = el("apiKeyInput").value.trim();
  if (!key) return;
  await api("POST", "/api/settings/api-key", { api_key: key });
  hide("settingsModal");
});

/* ============================================================
   DOMAIN MODAL + CHECK + INVESTIGATE
   ============================================================ */
let activeDomain = null;
let activeServer = null;
let ws = null;

function openDomainModal(server, domain) {
  activeServer = server;
  activeDomain = domain;
  el("domainModalTitle").textContent = domain;
  el("domainStatusBox").innerHTML = '<div class="spinner"></div> در حال بررسی وضعیت…';
  hide("domainActions");
  hide("investigatePanel");
  el("invLog").innerHTML = "";
  hide("approvalBox");
  hide("reportBox");
  el("reportBox").innerHTML = "";
  el("investigateBtn").classList.add("hidden");
  show("domainModal");
  checkDomain();
}

el("domainModalClose").addEventListener("click", () => {
  hide("domainModal");
  if (ws) { ws.close(); ws = null; }
});

async function checkDomain() {
  el("domainStatusBox").innerHTML = '<div class="spinner"></div> در حال بررسی وضعیت…';
  hide("domainActions");
  try {
    const result = await api("POST", `/api/servers/${activeServer.id}/check`, { domain: activeDomain });
    if (!result.ok) {
      el("domainStatusBox").innerHTML = `<span class="chip chip-error">خطا</span> ${escapeHtml(result.error || "")}`;
      show("domainActions");
      return;
    }
    const httpCheck = result.http_check || {};
    const up = !!httpCheck.ok && (httpCheck.status_code || 0) < 500;
    const statusCode = httpCheck.status_code ?? "-";
    if (up) {
      el("domainStatusBox").innerHTML = `<span class="chip chip-up">سالم است ✓</span> کد وضعیت: ${statusCode} · زمان پاسخ: ${httpCheck.elapsed_ms ?? "-"}ms`;
      el("investigateBtn").classList.add("hidden");
    } else {
      el("domainStatusBox").innerHTML = `<span class="chip chip-down">مشکل دارد ✗</span> کد وضعیت: ${statusCode}${httpCheck.error ? " · " + escapeHtml(httpCheck.error) : ""}`;
      el("investigateBtn").classList.remove("hidden");
    }
    show("domainActions");
  } catch (e) {
    el("domainStatusBox").innerHTML = `<span class="chip chip-error">خطا</span> ${escapeHtml(e.message)}`;
    show("domainActions");
  }
}
el("recheckBtn").addEventListener("click", checkDomain);

el("investigateBtn").addEventListener("click", () => {
  show("investigatePanel");
  el("invLog").innerHTML = "";
  hide("approvalBox");
  hide("reportBox");
  el("reportBox").innerHTML = "";
  setAgentChip("idle");
  setSiteChip(null, "بررسی نشده");
  el("invTurn").textContent = "";
  startInvestigation();
});

function setAgentChip(status) {
  const map = {
    idle: ["در انتظار", "chip-idle"],
    running: ["در حال بررسی…", "chip-running"],
    waiting_approval: ["نیازمند تأیید", "chip-waiting_approval"],
    done: ["پایان یافت", "chip-done"],
    error: ["خطا", "chip-error"],
  };
  const [label, cls] = map[status] || [status, "chip-idle"];
  const chip = el("invAgentStatus");
  chip.className = "chip " + cls;
  chip.textContent = label;
}
function setSiteChip(ok, detail) {
  const chip = el("invSiteStatus");
  if (ok === true) { chip.className = "chip chip-up"; chip.textContent = "سایت: بالا است"; }
  else if (ok === false) { chip.className = "chip chip-down"; chip.textContent = "سایت: خطا دارد"; }
  else { chip.className = "chip chip-unknown"; chip.textContent = "سایت: " + (detail || "نامشخص"); }
}

function addLogRow(tool, level, ok, detail) {
  const row = document.createElement("div");
  row.className = "inv-row";
  const time = new Date().toLocaleTimeString("fa-IR");
  row.innerHTML = `
    <span class="muted">${time}</span>
    <span class="lvl lvl-${level}">${level}</span>
    <span>${escapeHtml(tool)}</span>
    <span class="${ok ? "ok-yes" : "ok-no"}">${ok ? "✓" : "✗"}</span>
  `;
  const log = el("invLog");
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
}

function renderReport(text) {
  const box = el("reportBox");
  box.innerHTML = "";
  const lines = text.split("\n");
  let currentTitle = "خلاصه";
  let buffer = [];

  function flush() {
    if (buffer.length === 0 && currentTitle === "خلاصه") return;
    const section = document.createElement("div");
    section.className = "report-section";
    const h = document.createElement("h4");
    h.textContent = currentTitle;
    section.appendChild(h);
    for (const line of buffer) {
      const p = document.createElement("p");
      p.innerHTML = line;
      section.appendChild(p);
    }
    box.appendChild(section);
  }

  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith("## ")) {
      flush();
      currentTitle = line.slice(3).trim();
      buffer = [];
    } else if (line.startsWith("> ")) {
      buffer.push(`<span class="report-quote">❝ ${escapeHtml(line.slice(2))} ❞</span>`);
    } else if (line) {
      buffer.push(escapeHtml(line));
    }
  }
  flush();
  show("reportBox");
}

function startInvestigation() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws/investigate`);

  ws.onopen = () => {
    ws.send(JSON.stringify({ server_id: activeServer.id, domain: activeDomain, auto_approve: false }));
  };

  ws.onmessage = (msg) => {
    const event = JSON.parse(msg.data);
    switch (event.type) {
      case "agent_status":
        setAgentChip(event.status);
        break;
      case "site_status":
        setSiteChip(event.ok, event.detail);
        break;
      case "turn":
        el("invTurn").textContent = (parseInt(el("invTurn").dataset.n || "0", 10) + 1) + " مرحله طی شده";
        el("invTurn").dataset.n = String(parseInt(el("invTurn").dataset.n || "0", 10) + 1);
        break;
      case "tool_log":
        addLogRow(event.tool, event.level, event.ok, event.detail);
        break;
      case "blocked_red":
        addLogRow(event.tool, "RED", false, "مسدود شده توسط سیاست امنیتی");
        break;
      case "approval_request":
        setAgentChip("waiting_approval");
        el("approvalDetail").innerHTML =
          `ابزار: <b>${escapeHtml(event.tool)}</b><br>پارامترها: <code>${escapeHtml(JSON.stringify(event.args))}</code><br>دلیل: ${escapeHtml(event.reason)}`;
        show("approvalBox");
        pendingApprovalWs = ws;
        break;
      case "report":
        setAgentChip("done");
        hide("approvalBox");
        renderReport(event.text);
        checkDomain();
        break;
      case "error":
        setAgentChip("error");
        addLogRow("خطا", "RED", false, event.message);
        break;
    }
  };

  ws.onerror = () => setAgentChip("error");
}

let pendingApprovalWs = null;
el("approveBtn").addEventListener("click", () => {
  if (pendingApprovalWs) pendingApprovalWs.send(JSON.stringify({ approved: true }));
  hide("approvalBox");
});
el("denyBtn").addEventListener("click", () => {
  if (pendingApprovalWs) pendingApprovalWs.send(JSON.stringify({ approved: false }));
  hide("approvalBox");
});

/* ============================================================
   BOOT
   ============================================================ */
bootAuth();
