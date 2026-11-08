/** Web 桌面入口（M0 原型）：登录检查 → 桌面壳 → 窗口管理 → 布局持久化。 */

import { api } from "./api.js";
import { WindowManager } from "./wm.js";
import { mountTerminal } from "./apps/terminal.js";

const els = {
  workspace: document.getElementById("workspace"),
  layer: document.getElementById("window-layer"),
  dock: document.getElementById("dock"),
  clock: document.getElementById("tb-clock"),
  mode: document.getElementById("tb-mode"),
  appTitle: document.getElementById("tb-app"),
  hint: document.getElementById("empty-hint"),
  launcher: document.getElementById("launcher"),
  activities: document.getElementById("btn-activities"),
  iconTerminal: document.getElementById("icon-terminal"),
  toasts: document.getElementById("toast-layer"),
  login: document.getElementById("login"),
  loginForm: document.getElementById("login-form"),
  loginSub: document.getElementById("login-sub"),
  loginUserRow: document.getElementById("login-user-row"),
  loginUser: document.getElementById("login-user"),
  loginPassword: document.getElementById("login-password"),
  loginCodeRow: document.getElementById("login-code-row"),
  loginCode: document.getElementById("login-code"),
  loginError: document.getElementById("login-error"),
  loginSubmit: document.getElementById("login-submit"),
};

let username = "admin";
let internalMode = false;
let savedLayout = null;
let wm = null;
let saveTimer = null;
let saveErrorShown = false;

/* ----------------------------- 通用小工具 ----------------------------- */

function toast(message, kind = "") {
  const node = document.createElement("div");
  node.className = `toast ${kind}`.trim();
  node.textContent = message;
  els.toasts.append(node);
  setTimeout(() => node.remove(), 4200);
}

function lsKey() {
  return `aegis.desktop.layout.v1.${username}`;
}

function readLocalLayout() {
  try {
    const raw = localStorage.getItem(lsKey());
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && Array.isArray(parsed.windows) ? parsed : null;
  } catch (err) {
    return null;
  }
}

function tickClock() {
  const now = new Date();
  const text = new Intl.DateTimeFormat("zh-CN", {
    weekday: "short", month: "long", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  }).format(now);
  els.clock.textContent = text;
}

/* ----------------------------- 登录 ----------------------------- */

function showLogin(status) {
  els.login.hidden = false;
  els.loginUserRow.hidden = !status.multi_user;
  els.loginCodeRow.hidden = !status.totp_enabled;
  if (!status.initialized) {
    els.loginSub.textContent = "面板尚未初始化：请先打开控制台首页设置访问密码，再回到桌面登录。";
    [els.loginUser, els.loginPassword, els.loginCode].forEach((input) => { input.disabled = true; });
    els.loginSubmit.disabled = true;
    els.loginSubmit.textContent = "请先初始化面板";
    return;
  }
  els.loginSub.textContent = status.multi_user
    ? "使用面板账号进入 Web 桌面"
    : "使用面板密码进入 Web 桌面";
  els.loginPassword.focus();
}

function bindLogin() {
  els.loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    els.loginError.hidden = true;
    els.loginSubmit.disabled = true;
    try {
      await api.post("/api/auth/login", {
        password: els.loginPassword.value,
        username: els.loginUser.value.trim(),
        code: els.loginCode.value.trim(),
      });
      location.reload();
    } catch (err) {
      els.loginError.textContent = err.message || "登录失败";
      els.loginError.hidden = false;
      els.loginSubmit.disabled = false;
    }
  });
}

/* ----------------------------- 桌面壳 ----------------------------- */

function setMode(mode, label) {
  internalMode = mode === "internal";
  els.mode.textContent = label || (internalMode ? "内网模式" : "公网模式");
  els.mode.classList.toggle("internal", internalMode);
  els.mode.classList.toggle("public", !internalMode);
}

function toggleLauncher(force) {
  const show = force === undefined ? els.launcher.hidden : force;
  els.launcher.hidden = !show;
}

function updateEmptyHint() {
  const hasWindow = wm && wm.windows.size > 0;
  els.hint.classList.toggle("hidden", Boolean(hasWindow));
}

function updateDock() {
  if (!wm) return;
  const wins = [...wm.windows.values()];
  const terminals = wins.filter((win) => win.appId === "terminal");
  els.dock.textContent = "";

  const launch = document.createElement("button");
  launch.type = "button";
  launch.className = `dock-item${terminals.length ? " running" : ""}`;
  launch.title = "终端：新建窗口";
  launch.innerHTML = '<span class="dock-glyph" aria-hidden="true">&gt;_</span>'
    + '<span class="dock-label">终端</span>';
  launch.addEventListener("click", () => openTerminal());
  els.dock.append(launch);

  if (!wins.length) return;

  const divider = document.createElement("span");
  divider.className = "dock-divider";
  divider.setAttribute("aria-hidden", "true");
  els.dock.append(divider);

  wins.forEach((win) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = ["dock-chip", win.minimized ? "minimized" : "",
      wm.activeId === win.id ? "active" : ""].join(" ").trim();
    chip.title = win.title;
    chip.innerHTML = '<span class="chip-title"></span><span class="chip-sub"></span>';
    chip.querySelector(".chip-title").textContent = win.title;
    chip.querySelector(".chip-sub").textContent = win.minimized
      ? "已最小化"
      : (wm.activeId === win.id ? "当前窗口" : "点击切换");
    chip.addEventListener("click", () => {
      if (win.minimized) wm.show(win.id);
      else if (wm.activeId === win.id) wm.minimize(win.id);
      else wm.focus(win.id);
    });
    els.dock.append(chip);
  });
}

function onWmChange(info) {
  updateDock();
  updateEmptyHint();
  const active = wm && wm.activeId ? wm.windows.get(wm.activeId) : null;
  els.appTitle.textContent = active ? active.title : "Aegis 桌面";
  if (info.reason !== "focus") scheduleSave();
}

/* ----------------------------- 应用 ----------------------------- */

function openTerminal(restore = null) {
  if (!wm) return;
  if (!internalMode) {
    toast("终端需要内网模式：请在服务器上启动面板时加 --enable-internal");
    return;
  }
  const count = [...wm.windows.values()].filter((win) => win.appId === "terminal").length;
  const offset = (count % 6) * 26;
  const win = wm.create({
    id: restore ? restore.id : undefined,
    appId: "terminal",
    title: (restore && restore.title) || `终端 ${count + 1}`,
    x: restore ? restore.x : 96 + offset,
    y: restore ? restore.y : 56 + offset,
    w: restore ? restore.w : 860,
    h: restore ? restore.h : 520,
    state: restore ? restore.state : undefined,
    minimized: restore ? restore.minimized : false,
  });
  if (!win.terminal) win.terminal = mountTerminal(win.body);
  win.dispose = () => {
    if (win.terminal) {
      win.terminal.dispose();
      win.terminal = null;
    }
  };
  updateDock();
}

/* ----------------------------- 布局持久化 ----------------------------- */

function scheduleSave() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveLayout, 500);
}

async function saveLayout() {
  if (!wm) return;
  const layout = {
    version: 1,
    theme: (savedLayout && savedLayout.theme)
      || { accent: "#E95420", dark: true, wallpaper: "default" },
    dock: ["terminal"],
    windows: wm.toLayout(),
  };
  savedLayout = { ...(savedLayout || {}), ...layout };
  try {
    await api.put("/api/desktop/layout", { layout });
    localStorage.removeItem(lsKey());
    saveErrorShown = false;
  } catch (err) {
    // 后端拒绝（只读角色 / 网络故障）时保留本地副本，至少刷新不丢布局
    try {
      localStorage.setItem(lsKey(), JSON.stringify({
        ...layout, updated_at: Math.floor(Date.now() / 1000),
      }));
    } catch (storageErr) {
      // 隐私模式等场景下 localStorage 不可用，忽略
    }
    if (!saveErrorShown) {
      saveErrorShown = true;
      toast(err.status === 403
        ? "当前账号为只读角色，桌面布局只保存在本浏览器"
        : `布局保存失败：${err.message}`, "err");
    }
  }
}

/* ----------------------------- 启动 ----------------------------- */

async function enterDesktop(status) {
  let boot = null;
  try {
    boot = await api.get("/api/desktop/bootstrap");
  } catch (err) {
    if (err.status === 401) {
      location.reload();
      return;
    }
    toast(`桌面初始化接口不可用：${err.message}`, "err");
  }

  username = (boot && boot.username) || status.username || "admin";
  internalMode = (boot ? boot.mode : status.mode) === "internal";
  setMode(boot ? boot.mode : status.mode,
    boot ? boot.mode_label : status.mode_label);

  const serverLayout = boot && boot.layout ? boot.layout : null;
  const localLayout = readLocalLayout();
  savedLayout = serverLayout;
  if ((!serverLayout || !serverLayout.updated_at) && localLayout) savedLayout = localLayout;

  wm = new WindowManager({
    layer: els.layer,
    workspace: els.workspace,
    onChange: onWmChange,
  });
  wm.setFocusHandler((win) => {
    if (win.terminal && win.terminal.focus) win.terminal.focus();
  });

  const windows = (savedLayout && Array.isArray(savedLayout.windows)) ? savedLayout.windows : [];
  // 公网模式不恢复终端窗口（否则每个窗口都会弹一次"需要内网模式"的提示）
  windows.forEach((item) => {
    if (internalMode && item && item.appId === "terminal") openTerminal(item);
  });

  // 首次进入桌面自动开一个终端，避免空白页；之后完全按保存的布局来
  if (!windows.length && internalMode) openTerminal();

  updateDock();
  updateEmptyHint();
  els.appTitle.textContent = "Aegis 桌面";
}

async function init() {
  tickClock();
  setInterval(tickClock, 1000);
  bindLogin();

  els.activities.addEventListener("click", () => toggleLauncher());
  els.iconTerminal.addEventListener("dblclick", () => openTerminal());
  els.iconTerminal.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openTerminal();
    }
  });
  els.launcher.addEventListener("click", (event) => {
    if (event.target === els.launcher) toggleLauncher(false);
  });
  els.launcher.querySelectorAll('[data-app="terminal"]').forEach((button) => {
    button.addEventListener("click", () => {
      toggleLauncher(false);
      openTerminal();
    });
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") toggleLauncher(false);
  });

  let status;
  try {
    status = await api.get("/api/auth/status");
  } catch (err) {
    showLogin({ initialized: true, authenticated: false, multi_user: false, totp_enabled: false });
    els.loginSub.textContent = `无法连接面板服务：${err.message}`;
    return;
  }

  if (!status.authenticated) {
    showLogin(status);
    return;
  }
  await enterDesktop(status);
}

init();
