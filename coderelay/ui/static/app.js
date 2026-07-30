"use strict";

const stateLabels = {
  ready: "可用",
  experimental: "实验性",
  requires_setup: "需要授权",
  disabled: "已停用",
};

function qs(selector, root = document) {
  return root.querySelector(selector);
}

async function jsonRequest(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers: { Accept: "application/json", ...(options.headers || {}) },
  });
  let payload = null;
  try {
    payload = await response.json();
  } catch (_) {
    payload = null;
  }
  if (response.status === 401) {
    window.location.replace("/login");
    throw new Error("登录已失效");
  }
  if (!response.ok) {
    const error = new Error(payload?.error?.message || `请求失败（${response.status}）`);
    error.code = payload?.error?.code || "REQUEST_FAILED";
    error.retryAfter = payload?.error?.retry_after_seconds ?? null;
    throw error;
  }
  return payload;
}

function initializeLogin() {
  const form = qs("#login-form");
  if (!form) return;
  const input = qs("#password", form);
  const error = qs("#login-error", form);
  const button = qs("button[type=submit]", form);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    button.disabled = true;
    button.textContent = "正在登录…";
    try {
      await jsonRequest("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: input.value }),
      });
      input.value = "";
      window.location.replace("/app");
    } catch (requestError) {
      error.textContent = requestError.code === "AUTHENTICATION_REQUIRED" ? "访问密码不正确。" : requestError.message;
      error.hidden = false;
      input.select();
    } finally {
      button.disabled = false;
      button.textContent = "登录";
    }
  });
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).format(date);
}

function createSourceCard(source) {
  const card = element("article", "source-card");
  card.dataset.sourceId = source.id;

  const heading = element("div", "source-heading");
  const titleGroup = element("div");
  titleGroup.append(element("h3", "", source.display_name));
  titleGroup.append(element("div", "source-kind", source.kind === "totp" ? "TOTP · 本地生成" : source.provider_type === "flysms" ? "FlySMS · 邮件" : "Microsoft Graph · 邮件"));
  const badgeState = source.experimental ? "experimental" : source.state;
  heading.append(titleGroup, element("span", `badge ${badgeState}`, stateLabels[badgeState] || badgeState));

  const identity = element("p", "identity", source.identity_hint || " ");
  const codeArea = element("div", "code-area");
  codeArea.append(element("span", "code-placeholder", source.state === "requires_setup" ? "请先通过 CLI 完成 Microsoft 授权" : source.state === "disabled" ? "此来源已停用" : "尚未获取验证码"));
  const meta = element("div", "source-meta", " ");
  const cardError = element("div", "card-error");
  cardError.setAttribute("role", "alert");

  const actions = element("div", "source-actions");
  const getButton = element("button", "primary", source.kind === "totp" ? "显示验证码" : "获取最新验证码");
  getButton.type = "button";
  getButton.disabled = source.state === "requires_setup" || source.state === "disabled";
  const copyButton = element("button", "copy-button", "复制");
  copyButton.type = "button";
  copyButton.disabled = true;
  actions.append(getButton, copyButton);

  let currentCode = "";
  let countdownTimer = null;

  function clearCountdown() {
    if (countdownTimer !== null) window.clearInterval(countdownTimer);
    countdownTimer = null;
  }

  function showCode(result) {
    clearCountdown();
    currentCode = result.code;
    codeArea.replaceChildren(element("span", "code-value", result.code));
    copyButton.disabled = false;
    cardError.textContent = "";
    if (result.kind === "totp") {
      const expires = new Date(result.expires_at).getTime();
      const update = () => {
        const remaining = Math.max(0, Math.ceil((expires - Date.now()) / 1000));
        meta.textContent = `剩余 ${remaining} 秒 · ${formatTime(result.expires_at)} 失效`;
        if (remaining <= 0) {
          clearCountdown();
          currentCode = "";
          copyButton.disabled = true;
          codeArea.replaceChildren(element("span", "code-placeholder", "验证码已过期，请重新获取"));
        }
      };
      update();
      countdownTimer = window.setInterval(update, 500);
    } else {
      const sender = result.evidence?.sender || "未知发件人";
      const received = formatTime(result.received_at);
      meta.textContent = `${sender} · ${received}${result.evidence?.subject ? ` · ${result.evidence.subject}` : ""}`;
      const captured = result.code;
      window.setTimeout(() => {
        if (currentCode !== captured) return;
        currentCode = "";
        copyButton.disabled = true;
        codeArea.replaceChildren(element("span", "code-placeholder", "验证码已自动隐藏"));
      }, 90_000);
    }
  }

  getButton.addEventListener("click", async () => {
    getButton.disabled = true;
    getButton.textContent = source.kind === "totp" ? "计算中…" : "等待新邮件…";
    cardError.textContent = "";
    try {
      const params = new URLSearchParams();
      if (source.kind === "totp") {
        params.set("min_ttl", "5");
      } else {
        params.set("not_before", new Date(Date.now() - 120_000).toISOString());
        params.set("wait_seconds", "20");
      }
      const result = await jsonRequest(`/api/v1/codes/${encodeURIComponent(source.id)}?${params.toString()}`);
      showCode(result);
    } catch (requestError) {
      const suffix = requestError.retryAfter ? `，约 ${requestError.retryAfter} 秒后可重试` : "";
      cardError.textContent = `${requestError.message}${suffix}`;
    } finally {
      getButton.disabled = false;
      getButton.textContent = source.kind === "totp" ? "重新获取" : "获取最新验证码";
    }
  });

  copyButton.addEventListener("click", async () => {
    if (!currentCode) return;
    try {
      await navigator.clipboard.writeText(currentCode);
      copyButton.textContent = "已复制";
      window.setTimeout(() => { copyButton.textContent = "复制"; }, 1_500);
    } catch (_) {
      cardError.textContent = "浏览器拒绝访问剪贴板，请手动复制。";
    }
  });

  card.append(heading, identity, codeArea, meta, cardError, actions);
  return card;
}

async function loadSources() {
  const grid = qs("#source-grid");
  const globalError = qs("#global-error");
  if (!grid) return;
  grid.setAttribute("aria-busy", "true");
  globalError.hidden = true;
  grid.replaceChildren(element("div", "panel loading-card", "正在读取来源…"));
  try {
    const sources = await jsonRequest("/api/v1/sources");
    grid.replaceChildren(...sources.map(createSourceCard));
    if (!sources.length) grid.append(element("div", "panel loading-card", "没有已配置的来源"));
  } catch (requestError) {
    grid.replaceChildren();
    globalError.textContent = requestError.message;
    globalError.hidden = false;
  } finally {
    grid.setAttribute("aria-busy", "false");
  }
}

function initializeDashboard() {
  if (!qs("#source-grid")) return;
  const clock = qs("#clock");
  const updateClock = () => {
    if (clock) clock.textContent = new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).format(new Date());
  };
  updateClock();
  window.setInterval(updateClock, 1_000);
  qs("#reload-sources")?.addEventListener("click", loadSources);
  qs("#logout")?.addEventListener("click", async () => {
    try { await jsonRequest("/auth/logout", { method: "POST" }); } catch (_) { /* redirect regardless */ }
    window.location.replace("/login");
  });
  loadSources();
}

document.addEventListener("DOMContentLoaded", () => {
  initializeLogin();
  initializeDashboard();
});
