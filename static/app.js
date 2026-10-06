/* ServerPanel 前端主程序 —— 无构建依赖的原生实现 */
'use strict';

/* ============================ 基础工具 ============================ */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const S = String;

function esc(value) {
  return S(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

async function copyText(text, label = '已复制到剪贴板') {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const area = document.createElement('textarea');
      area.value = text;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
    toast(label);
  } catch (err) {
    toast('复制失败，请手动选择文本', 'err');
  }
}

function bytes(n, digits = 1) {
  if (n === null || n === undefined || Number.isNaN(Number(n))) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let value = Number(n), i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
  return `${value.toFixed(i === 0 ? 0 : digits)} ${units[i]}`;
}

const rate = (n) => `${bytes(n, 1)}/s`;

function duration(seconds) {
  if (seconds === null || seconds === undefined) return '-';
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400), hr = Math.floor((s % 86400) / 3600);
  const mi = Math.floor((s % 3600) / 60), se = s % 60;
  if (d) return `${d} 天 ${hr} 小时`;
  if (hr) return `${hr} 小时 ${mi} 分`;
  if (mi) return `${mi} 分 ${se} 秒`;
  return `${se} 秒`;
}

function datetime(ts) {
  if (!ts) return '-';
  const d = new Date(Number(ts) * 1000);
  const p = (n) => S(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function levelClass(pct) {
  if (pct >= 90) return 'danger';
  if (pct >= 70) return 'warn';
  return 'ok';
}

function bar(pct, cls) {
  const value = Math.max(0, Math.min(100, Number(pct) || 0));
  return `<div class="bar ${cls || levelClass(value)}"><span style="width:${value}%"></span></div>`;
}

/* ============================ Toast / 模态框 ============================ */

function toast(message, type = 'ok', timeout = 3400) {
  const node = document.createElement('div');
  node.className = `toast ${type}`;
  node.innerHTML = esc(message);
  $('#toast-wrap').appendChild(node);
  setTimeout(() => {
    node.style.opacity = '0';
    node.style.transition = 'opacity .3s';
    setTimeout(() => node.remove(), 320);
  }, timeout);
}

let modalStack = [];

function openModal({ title, body, footer, size = '' }) {
  const root = $('#modal-root');
  const overlay = document.createElement('div');
  overlay.className = 'modal';
  overlay.innerHTML = `
    <div class="modal-box ${size}">
      <div class="modal-head">
        <h3>${esc(title)}</h3>
        <div class="spacer"></div>
        <button class="btn sm ghost" data-close>✕</button>
      </div>
      <div class="modal-body"></div>
      ${footer ? '<div class="modal-foot"></div>' : ''}
    </div>`;
  const bodyEl = $('.modal-body', overlay);
  if (typeof body === 'string') bodyEl.innerHTML = body;
  else if (body) bodyEl.appendChild(body);
  if (footer) {
    const footEl = $('.modal-foot', overlay);
    if (typeof footer === 'string') footEl.innerHTML = footer;
    else footEl.appendChild(footer);
  }
  root.appendChild(overlay);
  const handle = {
    overlay, body: bodyEl, foot: $('.modal-foot', overlay),
    close() {
      overlay.remove();
      modalStack = modalStack.filter((m) => m !== handle);
    },
  };
  modalStack.push(handle);
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay || event.target.hasAttribute('data-close')) handle.close();
  });
  return handle;
}

function confirmDialog({ title, message, confirmText = '确认', danger = false, phrase = '' }) {
  return new Promise((resolve) => {
    const body = document.createElement('div');
    body.innerHTML = `
      <div style="line-height:1.7">${message}</div>
      ${phrase ? `<label class="field"><span>请输入 <b class="mono">${esc(phrase)}</b> 以继续</span>
        <input class="input" id="confirm-phrase" autocomplete="off"></label>` : ''}`;
    const foot = document.createElement('div');
    foot.className = 'row';
    foot.innerHTML = `<button class="btn" data-cancel>取消</button>
      <button class="btn ${danger ? 'danger' : 'primary'}" data-ok>${esc(confirmText)}</button>`;
    const modal = openModal({ title, body, footer: foot, size: 'narrow' });
    const finish = (value) => { modal.close(); resolve(value); };
    $('[data-cancel]', foot).onclick = () => finish(false);
    $('[data-ok]', foot).onclick = () => {
      if (phrase) {
        const typed = ($('#confirm-phrase', modal.body)?.value || '').trim();
        if (typed !== phrase) { toast('确认文本不匹配', 'err'); return; }
      }
      finish(true);
    };
    if (phrase) setTimeout(() => $('#confirm-phrase', modal.body)?.focus(), 30);
  });
}

function promptDialog({ title, label, value = '', confirmText = '确定' }) {
  return new Promise((resolve) => {
    const body = document.createElement('div');
    body.innerHTML = `<label class="field"><span>${esc(label)}</span>
      <input class="input" id="prompt-input" value="${esc(value)}" autocomplete="off"></label>`;
    const foot = document.createElement('div');
    foot.className = 'row';
    foot.innerHTML = `<button class="btn" data-cancel>取消</button>
      <button class="btn primary" data-ok>${esc(confirmText)}</button>`;
    const modal = openModal({ title, body, footer: foot, size: 'narrow' });
    const input = $('#prompt-input', modal.body);
    setTimeout(() => { input.focus(); input.select(); }, 30);
    const finish = (val) => { modal.close(); resolve(val); };
    $('[data-cancel]', foot).onclick = () => finish(null);
    $('[data-ok]', foot).onclick = () => finish(input.value);
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') finish(input.value);
    });
  });
}

/* ============================ API 客户端 ============================ */

class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

async function request(method, url, payload, isForm = false) {
  const options = { method, headers: {}, credentials: 'same-origin' };
  if (payload !== undefined && payload !== null) {
    if (isForm) {
      options.body = payload;
    } else {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(payload);
    }
  }
  let response;
  try {
    response = await fetch(url, options);
  } catch (err) {
    throw new ApiError('无法连接服务器', 0);
  }
  if (response.status === 401) {
    showLogin(true);
    throw new ApiError('登录已过期，请重新登录', 401);
  }
  let data = null;
  const text = await response.text();
  if (text) {
    try { data = JSON.parse(text); } catch (err) { data = { detail: text }; }
  }
  if (!response.ok) {
    throw new ApiError((data && data.detail) || `请求失败 (${response.status})`, response.status);
  }
  return data;
}

const api = {
  get: (url) => request('GET', url),
  post: (url, body) => request('POST', url, body),
  del: (url) => request('DELETE', url),
  upload: (url, formData) => request('POST', url, formData, true),
};

/* ============================ 折线图 ============================ */

class Chart {
  constructor(canvas, opts = {}) {
    this.canvas = canvas;
    this.series = opts.series || [{ color: '#38bdf8' }];
    this.capacity = opts.capacity || 60;
    this.fixedMax = opts.max ?? null;
    this.height = opts.height || 46;
    this.fmt = opts.fmt || ((v) => S(Math.round(v)));
    this.data = [];
    canvas.style.height = `${this.height}px`;
    this.observer = new ResizeObserver(() => this.draw());
    this.observer.observe(canvas);
  }

  push(values) {
    this.data.push(values.map(Number));
    while (this.data.length > this.capacity) this.data.shift();
    this.draw();
  }

  load(points, pick) {
    this.data = points.map((p) => pick(p).map(Number)).slice(-this.capacity);
    this.draw();
  }

  destroy() { this.observer.disconnect(); }

  draw() {
    const canvas = this.canvas;
    const width = canvas.clientWidth || 300;
    const height = this.height;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.round(width * dpr));
    canvas.height = Math.round(height * dpr);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const flat = this.data.flat();
    let max = this.fixedMax ?? (flat.length ? Math.max(...flat) : 1);
    if (!this.fixedMax) {
      max = max <= 0 ? 1 : max * 1.25;
      const mag = 10 ** Math.floor(Math.log10(max));
      max = Math.ceil(max / mag) * mag;
    }

    // 横向网格
    ctx.strokeStyle = 'rgba(255,255,255,.06)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 2; i += 1) {
      const y = Math.round((height - 1) * (i / 2)) + 0.5;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
    }

    // 上限标注
    ctx.fillStyle = 'rgba(157,176,197,.65)';
    ctx.font = '10px ui-monospace, monospace';
    ctx.fillText(this.fmt(max), 3, 11);

    if (this.data.length < 2) return;
    const stepX = width / (this.capacity - 1);
    const offset = width - (this.data.length - 1) * stepX;

    this.series.forEach((serie, index) => {
      const points = this.data.map((row, i) => [
        offset + i * stepX,
        height - 3 - (Math.max(0, Math.min(row[index] ?? 0, max)) / max) * (height - 10),
      ]);
      if (serie.fill && points.length > 1) {
        const gradient = ctx.createLinearGradient(0, 0, 0, height);
        gradient.addColorStop(0, serie.fill);
        gradient.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.beginPath();
        ctx.moveTo(points[0][0], height);
        points.forEach(([x, y]) => ctx.lineTo(x, y));
        ctx.lineTo(points[points.length - 1][0], height);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();
      }
      ctx.beginPath();
      points.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
      ctx.strokeStyle = serie.color;
      ctx.lineWidth = 1.6;
      ctx.lineJoin = 'round';
      ctx.stroke();
      const last = points[points.length - 1];
      ctx.beginPath();
      ctx.arc(last[0], last[1], 2.2, 0, Math.PI * 2);
      ctx.fillStyle = serie.color;
      ctx.fill();
    });
  }
}

/* ============================ 实时指标总线 ============================ */

const live = {
  metrics: null,
  capabilities: null,
  subscribers: new Set(),
  timer: null,
  failures: 0,

  subscribe(fn) { this.subscribers.add(fn); return () => this.subscribers.delete(fn); },

  start() {
    if (this.timer) return;
    const tick = async () => {
      try {
        const data = await api.get('/api/system/metrics');
        this.metrics = data;
        this.failures = 0;
        renderTopbar(data);
        Array.from(this.subscribers).forEach((fn) => {
          try { fn(data); } catch (err) { console.error(err); }
        });
        setMode(data.mode);  // 服务器端切换模式后，界面自动跟随
      } catch (err) {
        if (err.status !== 401) this.failures += 1;
      }
    };
    tick();
    this.timer = setInterval(tick, 2000);
  },

  stop() { clearInterval(this.timer); this.timer = null; },
};

function renderTopbar(m) {
  if (!m) return;
  $('#topbar-stats').innerHTML = [
    `<span class="badge info">CPU ${m.cpu.toFixed(1)}%</span>`,
    `<span class="badge ${m.mem.percent > 85 ? 'danger' : 'ok'}">内存 ${m.mem.percent.toFixed(0)}%</span>`,
    `<span class="badge">负载 ${m.load[0].toFixed(2)}</span>`,
    `<span class="badge">进程 ${m.processes}</span>`,
  ].join('');
  $('#footer-uptime').textContent = `运行 ${duration(m.uptime)}`;
}

/* ============================ 视图注册与路由 ============================ */

const views = {};
const NAV = [
  { id: 'overview', label: '概览', icon: '▤' },
  { id: 'performance', label: '性能监控', icon: '◉' },
  { id: 'terminal', label: '网页终端', icon: '▶', internalOnly: true },
  { id: 'apps', label: '常驻应用', icon: '⏱', internalOnly: true },
  { id: 'logs', label: '控制台 / 日志', icon: '☰' },
  { id: 'storage', label: '存储空间', icon: '⛁' },
  { id: 'processes', label: '进程管理', icon: '⚙' },
  { id: 'services', label: '服务管理', icon: '⏻' },
  { id: 'apps-port', label: '应用与端口', icon: '⧉', internalOnly: true },
  { id: 'files', label: '文件管理', icon: '🗀', internalOnly: true },
  { id: 'agent', label: 'Agent 接入', icon: '⌘', internalOnly: true },
  { id: 'settings', label: '设置', icon: '⚒' },
];

function registerView(id, def) { views[id] = def; }

/* ============================ 运行模式 ============================ */
// public  公网模式：只读监控
// internal 内网模式：完全控制（仅在服务器本机执行命令后激活）
let appMode = 'public';
const isInternal = () => appMode === 'internal';

function visibleNav() {
  return NAV.filter((item) => !item.internalOnly || isInternal());
}

function renderModeBadge() {
  const badge = $('#mode-badge');
  if (badge) {
    badge.textContent = isInternal() ? '内网模式 · 完全控制' : '公网模式 · 只读';
    badge.className = `badge mode-badge ${isInternal() ? 'internal' : 'public'}`;
  }
  const footer = $('#footer-mode');
  if (footer) footer.textContent = isInternal() ? '已连接 · 完全控制' : '已连接 · 只读监控';
}

function renderModeBanner() {
  const el = $('#mode-banner');
  if (!el) return;
  el.className = `mode-banner ${isInternal() ? 'internal' : 'public'}`;
  el.innerHTML = isInternal()
    ? `<span class="mb-icon">⚡</span><div><b>内网模式已激活</b> · 终端、文件管理、电源与系统控制全部可用。
       使用完毕后，请在服务器上执行 <span class="mono">serverpanel --disable-internal</span> 关闭。</div>`
    : `<span class="mb-icon">🔒</span><div><b>公网模式（只读监控）</b> · 当前仅开放性能、存储概览、进程与日志查看。
       需要终端与全部控制权限时，请在服务器上执行 <span class="mono">serverpanel --enable-internal</span> 激活。</div>`;
}

function showModeHelp() {
  const body = document.createElement('div');
  body.innerHTML = `
    <div style="line-height:1.9;font-size:13px">
      <p style="margin-top:0">ServerPanel 提供两种运行模式，在「随时可看」和「完整控制」之间取得平衡。</p>
      <h3 style="margin:14px 0 6px;font-size:14px">公网模式（默认 · 只读）</h3>
      <ul style="padding-left:18px;margin:0">
        <li>开放：系统概览、性能监控、存储空间查看、进程列表、服务与日志查看</li>
        <li>禁止：网页终端、文件读写/上传/删除、结束进程、服务启停、挂载/卸载、开关机</li>
      </ul>
      <h3 style="margin:14px 0 6px;font-size:14px">内网模式（完全控制）</h3>
      <ul style="padding-left:18px;margin:0">
        <li>开放全部功能，包括 root 网页终端与文件管理</li>
        <li>只能通过在服务器本机执行命令激活，面板界面无法自行切换</li>
        <li>关闭模式后，已打开的终端会话会被立即终止</li>
      </ul>
      <h3 style="margin:14px 0 6px;font-size:14px">在服务器上执行</h3>
      <div class="log-output" style="padding:12px;white-space:pre">serverpanel --enable-internal    # 激活内网模式，解锁全部功能
serverpanel --disable-internal   # 关闭内网模式，回到只读
serverpanel --show-mode          # 查看当前模式</div>
    </div>`;
  openModal({ title: '运行模式说明', body, size: 'wide' });
}

/** 模式变化时同步界面：侧边栏、标签、横幅，并重新渲染当前视图。 */
function setMode(mode) {
  if (!mode) return;
  if (mode === appMode) return;
  appMode = mode;
  renderModeBadge();
  renderModeBanner();
  buildNav();
  const allowed = new Set(visibleNav().map((item) => item.id));
  openTabs = openTabs.filter((id) => allowed.has(id));
  if (!allowed.has(currentView)) { navigate('overview'); return; }
  renderTabs();
  navigate(currentView);
}

/* ============================ 多标签 ============================ */

let openTabs = [];
let currentCleanup = null;
let currentView = null;

function renderTabs() {
  const bar = $('#tabbar');
  if (!bar) return;
  bar.innerHTML = openTabs.map((id) => {
    const item = NAV.find((n) => n.id === id) || { label: id, icon: '' };
    return `<button class="tab${id === currentView ? ' active' : ''}" data-tab="${id}">
      <span class="tab-ico">${item.icon}</span><span class="tab-label">${esc(item.label)}</span>
      <span class="tab-close" data-close="${id}" title="关闭标签">×</span></button>`;
  }).join('');
}

function activateTab(id) {
  if (views[id] && id !== currentView) navigate(id);
}

function closeTab(id) {
  const index = openTabs.indexOf(id);
  if (index < 0) return;
  openTabs.splice(index, 1);
  if (currentView !== id) { renderTabs(); return; }
  const next = openTabs[index] || openTabs[index - 1];
  navigate(next || 'overview');
}

function initTabs() {
  const bar = $('#tabbar');
  if (!bar) return;
  bar.onclick = (event) => {
    const close = event.target.closest('[data-close]');
    if (close) { closeTab(close.dataset.close); return; }
    const tab = event.target.closest('[data-tab]');
    if (tab) activateTab(tab.dataset.tab);
  };
}

async function navigate(id) {
  const wanted = NAV.find((n) => n.id === id);
  if (wanted && wanted.internalOnly && !isInternal()) id = 'overview';  // 公网模式下禁止直达内网视图
  const def = views[id] || views.overview;
  const viewId = views[id] ? id : 'overview';
  if (!openTabs.includes(viewId)) openTabs.push(viewId);
  if (currentCleanup) {
    try { currentCleanup(); } catch (err) { console.error(err); }
    currentCleanup = null;
  }
  currentView = viewId;
  location.hash = `#/${viewId}`;
  renderTabs();
  $('#page-title').textContent = def.title;
  $$('#nav .nav-item').forEach((el) => el.classList.toggle('active', el.dataset.id === viewId));
  const container = $('#view');
  container.className = def.fullbleed ? 'view terminal-view' : 'view';
  container.innerHTML = '<div class="empty">加载中…</div>';
  try {
    currentCleanup = (await def.render(container)) || null;
  } catch (err) {
    container.innerHTML = `<div class="card"><h2>加载失败</h2><div class="dim">${esc(err.message)}</div></div>`;
  }
}

function buildNav() {
  const items = visibleNav();
  $('#nav').innerHTML = items.map((item) => `
    <button class="nav-item" data-id="${item.id}">
      <span class="ico">${item.icon}</span><span>${item.label}</span>
    </button>`).join('');
  $$('#nav .nav-item').forEach((el) => {
    el.onclick = () => navigate(el.dataset.id);
  });
  $$('#nav .nav-item').forEach((el) => el.classList.toggle('active', el.dataset.id === currentView));
}

/* ============================ 登录流程 ============================ */

let authState = { initialized: false, authenticated: false };

function showLogin(expired = false) {
  live.stop();
  $('#app').classList.add('hidden');
  $('#login-screen').classList.remove('hidden');
  const initialized = authState.initialized;
  $('#login-label').textContent = initialized ? '面板密码' : '设置面板密码';
  $('#login-submit').textContent = initialized ? '登录' : '设置密码并登录';
  $('#confirm-field').classList.toggle('hidden', initialized);
  $('#login-password').setAttribute('autocomplete', initialized ? 'current-password' : 'new-password');
  $('#login-error').textContent = expired ? '会话已过期，请重新登录' : '';
  const modeNote = authState.mode === 'internal'
    ? '<span class="badge mode-badge internal">内网模式 · 完全控制</span>'
    : '<span class="badge mode-badge public">公网模式 · 只读监控</span>';
  $('#login-hint').innerHTML = (initialized
    ? '密码通过 PBKDF2 加盐哈希后保存在本机配置文件中。忘记密码可在服务器上执行：<span class="mono">serverpanel --set-password 新密码</span>'
    : '首次使用，请设置访问密码（至少 8 位）。密码只保存在本机，用于登录本控制台。')
    + `<div style="margin-top:10px">${modeNote}</div>`;
  setTimeout(() => $('#login-password').focus(), 50);
}

async function submitLogin(event) {
  event.preventDefault();
  const password = $('#login-password').value;
  const errorEl = $('#login-error');
  errorEl.textContent = '';
  const button = $('#login-submit');
  button.disabled = true;
  try {
    if (!authState.initialized) {
      const confirm = $('#login-confirm').value;
      if (password !== confirm) throw new ApiError('两次输入的密码不一致', 0);
    }
    const url = authState.initialized ? '/api/auth/login' : '/api/auth/setup';
    await api.post(url, { password });
    $('#login-form').reset();
    await startApp();
  } catch (err) {
    errorEl.textContent = err.message;
    button.disabled = false;
  }
}

/* ============================ 启动 ============================ */

async function startApp() {
  const status = await api.get('/api/auth/status');
  authState = status;
  if (!status.authenticated) { showLogin(false); return; }
  appMode = status.mode || 'public';
  $('#login-screen').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#brand-host').textContent = status.hostname || '-';
  renderModeBadge();
  renderModeBanner();
  initTabs();
  buildNav();
  try { live.capabilities = await api.get('/api/system/capabilities'); } catch (err) { /* 忽略 */ }
  live.start();
  const hashView = location.hash.replace('#/', '');
  navigate(views[hashView] ? hashView : 'overview');
}

async function boot() {
  try {
    authState = await api.get('/api/auth/status');
  } catch (err) {
    authState = { initialized: true, authenticated: false };
  }
  $('#login-host').textContent = authState.hostname ? `主机 ${authState.hostname}` : '本机系统控制台';
  $('#login-form').addEventListener('submit', submitLogin);
  if (authState.authenticated) await startApp();
  else showLogin(false);
}

$('#btn-refresh')?.addEventListener('click', () => navigate(currentView || 'overview'));
$('#mode-badge')?.addEventListener('click', showModeHelp);
$('#btn-logout')?.addEventListener('click', async () => {
  await api.post('/api/auth/logout', {});
  location.reload();
});
window.addEventListener('hashchange', () => {
  const id = location.hash.replace('#/', '');
  if (id && views[id] && id !== currentView) navigate(id);
});

/* ============================ 视图：概览 ============================ */

registerView('overview', {
  title: '概览',
  async render(root) {
    const info = await api.get('/api/system/info');
    const addressRows = info.addresses.length
      ? info.addresses.map((a) => `<dd>${esc(a.address)} <span class="dim">(${esc(a.interface)})</span></dd>`).join('')
      : '<dd class="dim">未检测到局域网地址</dd>';

    root.innerHTML = `
      <div class="grid c4" style="margin-bottom:14px">
        <div class="card">
          <div class="metric-label">CPU 使用率</div>
          <div class="metric-value" id="ov-cpu-val">--%</div>
          <canvas class="spark" id="ov-cpu"></canvas>
          <div class="metric-sub" id="ov-cpu-sub">-- 核心</div>
        </div>
        <div class="card">
          <div class="metric-label">内存使用</div>
          <div class="metric-value" id="ov-mem-val">--%</div>
          <canvas class="spark" id="ov-mem"></canvas>
          <div class="metric-sub" id="ov-mem-sub">--</div>
        </div>
        <div class="card">
          <div class="metric-label">磁盘吞吐</div>
          <div class="metric-value" id="ov-disk-val">--</div>
          <canvas class="spark" id="ov-disk"></canvas>
          <div class="metric-sub" id="ov-disk-sub">--</div>
        </div>
        <div class="card">
          <div class="metric-label">网络吞吐</div>
          <div class="metric-value" id="ov-net-val">--</div>
          <canvas class="spark" id="ov-net"></canvas>
          <div class="metric-sub" id="ov-net-sub">--</div>
        </div>
      </div>

      <div class="grid c2" style="margin-bottom:14px">
        <div class="card">
          <h2>系统信息</h2>
          <dl class="kv">
            <dt>主机名</dt><dd>${esc(info.hostname)}</dd>
            <dt>操作系统</dt><dd>${esc(info.distro)}</dd>
            <dt>内核版本</dt><dd>${esc(info.kernel)}</dd>
            <dt>架构</dt><dd>${esc(info.arch)}</dd>
            <dt>处理器</dt><dd>${esc(info.cpu_model)}</dd>
            <dt>CPU 核心</dt><dd>${info.cpu_cores_physical} 物理 / ${info.cpu_cores_logical} 逻辑</dd>
            <dt>内存总量</dt><dd>${bytes(info.mem_total)}</dd>
            <dt>交换分区</dt><dd>${info.swap_total ? bytes(info.swap_total) : '未启用'}</dd>
            <dt>运行时长</dt><dd>${duration(info.uptime)}</dd>
            <dt>启动时间</dt><dd>${datetime(info.boot_time)}</dd>
            <dt>当前用户</dt><dd>${esc(info.user)}${info.is_root ? ' <span class="badge warn">root</span>' : ''}</dd>
            <dt>局域网地址</dt>${addressRows}
          </dl>
        </div>
        <div>
          <div class="card" style="margin-bottom:14px">
            <h2>快捷操作</h2>
            <div class="row">
              ${isInternal() ? '<button class="btn sm" data-act="go-terminal">打开终端</button>' : ''}
              <button class="btn sm" data-act="go-logs">查看日志</button>
              ${isInternal() ? '<button class="btn sm" data-act="go-files">文件管理</button>' : ''}
              <div class="spacer"></div>
              ${isInternal() ? `<button class="btn sm danger" data-act="reboot">重启系统</button>
              <button class="btn sm danger" data-act="shutdown">关机</button>` : ''}
            </div>
            ${isInternal() ? '' : '<div class="dim" style="font-size:12px;margin-top:10px">公网模式下已隐藏终端、文件与电源操作。</div>'}
          </div>
          <div class="card">
            <h2>温度传感器</h2>
            <div class="row" id="ov-temps"><span class="dim">未检测到温度传感器</span></div>
          </div>
        </div>
      </div>

      <div class="grid c2">
        <div class="card flush">
          <h2 style="padding:16px 16px 12px">资源占用最高的进程</h2>
          <div class="table-wrap" id="ov-procs"><div class="empty">加载中…</div></div>
        </div>
        <div class="card flush">
          <h2 style="padding:16px 16px 12px">网络接口</h2>
          <div class="table-wrap" id="ov-nets"><div class="empty">加载中…</div></div>
        </div>
      </div>`;

    const charts = {
      cpu: new Chart($('#ov-cpu'), { max: 100, series: [{ color: '#38bdf8', fill: 'rgba(56,189,248,.25)' }], fmt: (v) => `${v.toFixed(0)}%` }),
      mem: new Chart($('#ov-mem'), { max: 100, series: [{ color: '#a78bfa', fill: 'rgba(167,139,250,.25)' }], fmt: (v) => `${v.toFixed(0)}%` }),
      disk: new Chart($('#ov-disk'), { series: [{ color: '#38bdf8', fill: 'rgba(56,189,248,.22)' }, { color: '#fbbf24' }], fmt: rate }),
      net: new Chart($('#ov-net'), { series: [{ color: '#34d399', fill: 'rgba(52,211,153,.22)' }, { color: '#f472b6' }], fmt: rate }),
    };

    const history = await api.get('/api/system/history').catch(() => ({ points: [] }));
    charts.cpu.load(history.points, (p) => [p.cpu]);
    charts.mem.load(history.points, (p) => [p.mem]);
    charts.disk.load(history.points, (p) => [p.disk_read, p.disk_write]);
    charts.net.load(history.points, (p) => [p.net_recv, p.net_sent]);

    const update = (m) => {
      $('#ov-cpu-val').textContent = `${m.cpu.toFixed(1)}%`;
      $('#ov-cpu-sub').textContent = `${m.cpu_per_core.length} 核心 · 负载 ${m.load.join(' / ')}`;
      $('#ov-mem-val').textContent = `${m.mem.percent.toFixed(0)}%`;
      $('#ov-mem-sub').textContent = `${bytes(m.mem.used)} / ${bytes(m.mem.total)}`;
      $('#ov-disk-val').textContent = `${bytes(m.disk.total - m.disk.used)} 可用`;
      $('#ov-disk-sub').textContent = `读 ${rate(m.disk.disk_read)} · 写 ${rate(m.disk.disk_write)}`;
      $('#ov-net-val').textContent = `${rate(m.net.net_recv)} 下行`;
      $('#ov-net-sub').textContent = `收 ${bytes(m.net.net_recv)}/s · 发 ${bytes(m.net.net_sent)}/s`;
      charts.cpu.push([m.cpu]);
      charts.mem.push([m.mem.percent]);
      charts.disk.push([m.disk.disk_read, m.disk.disk_write]);
      charts.net.push([m.net.net_recv, m.net.net_sent]);
      $('#ov-temps').innerHTML = m.temps.length
        ? m.temps.map((t) => `<span class="badge ${t.current > 80 ? 'danger' : t.current > 65 ? 'warn' : 'ok'} temp-chip">${esc(t.label)} ${t.current}°C</span>`).join('')
        : '<span class="dim">未检测到温度传感器</span>';
    };
    if (live.metrics) update(live.metrics);
    const unsubscribe = live.subscribe(update);

    async function loadProcs() {
      try {
        const rows = await api.get('/api/system/processes?limit=8&sort=cpu');
        $('#ov-procs').innerHTML = rows.length ? `
          <table class="data"><thead><tr><th>PID</th><th>进程</th><th>用户</th><th class="num">CPU</th><th class="num">内存</th></tr></thead>
          <tbody>${rows.map((p) => `<tr><td class="num">${p.pid}</td>
            <td><div class="cell-main">${esc(p.name)}</div><div class="cell-sub">${esc(p.cmdline.slice(0, 70))}</div></td>
            <td>${esc(p.user)}</td><td class="num">${p.cpu.toFixed(1)}%</td><td class="num">${p.mem.toFixed(1)}%</td></tr>`).join('')}
          </tbody></table>` : '<div class="empty">无数据</div>';
      } catch (err) { /* 忽略 */ }
    }

    async function loadNets() {
      try {
        const data = await api.get('/api/system/network');
        const rows = data.interfaces.filter((i) => i.name !== 'lo');
        $('#ov-nets').innerHTML = rows.length ? `
          <table class="data"><thead><tr><th>接口</th><th>地址</th><th>状态</th><th class="num">接收</th><th class="num">发送</th></tr></thead>
          <tbody>${rows.map((i) => {
            const v4 = i.addresses.find((a) => a.family === '2' && !a.address.startsWith('127.'));
            return `<tr><td class="cell-main">${esc(i.name)}</td>
              <td class="cell-main">${esc(v4 ? v4.address : '-')}</td>
              <td><span class="badge ${i.up ? 'ok' : 'danger'}">${i.up ? '已启用' : '已关闭'}</span></td>
              <td class="num">${bytes(i.bytes_recv)}</td><td class="num">${bytes(i.bytes_sent)}</td></tr>`;
          }).join('')}</tbody></table>` : '<div class="empty">无网络接口</div>';
      } catch (err) { /* 忽略 */ }
    }

    await Promise.all([loadProcs(), loadNets()]);
    const procTimer = setInterval(loadProcs, 6000);

    root.onclick = async (event) => {
      const action = event.target.dataset?.act;
      if (!action) return;
      if (action === 'go-terminal') navigate('terminal');
      if (action === 'go-logs') navigate('logs');
      if (action === 'go-files') navigate('files');
      if (action === 'reboot' || action === 'shutdown') {
        const label = action === 'reboot' ? '重启' : '关机';
        const ok = await confirmDialog({
          title: `${label}系统`,
          message: `确定要${label}主机 <b>${esc(info.hostname)}</b> 吗？所有连接会立即中断。`,
          confirmText: label,
          danger: true,
          phrase: action.toUpperCase(),
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/system/power', { action, confirm: 'CONFIRM' });
          toast(res.message, 'warn');
        } catch (err) { toast(err.message, 'err'); }
      }
    };

    return () => {
      unsubscribe();
      clearInterval(procTimer);
      Object.values(charts).forEach((c) => c.destroy());
    };
  },
});

/* ============================ 视图：性能监控 ============================ */

registerView('performance', {
  title: '性能监控',
  async render(root) {
    root.innerHTML = `
      <div class="grid c2" style="margin-bottom:14px">
        <div class="card">
          <h2>CPU 总使用率 <span class="spacer"></span><span class="badge info" id="pf-cpu-now">--%</span></h2>
          <canvas class="spark" id="pf-cpu" style="height:120px"></canvas>
          <div class="metric-sub" id="pf-cpu-sub">--</div>
        </div>
        <div class="card">
          <h2>内存 / 交换分区 <span class="spacer"></span><span class="badge info" id="pf-mem-now">--%</span></h2>
          <canvas class="spark" id="pf-mem" style="height:120px"></canvas>
          <div class="metric-sub" id="pf-mem-sub">--</div>
        </div>
      </div>
      <div class="grid c2" style="margin-bottom:14px">
        <div class="card">
          <h2>磁盘 I/O <span class="spacer"></span><span class="badge" id="pf-disk-now">--</span></h2>
          <canvas class="spark" id="pf-disk" style="height:110px"></canvas>
          <div class="metric-sub">蓝：读取　黄：写入</div>
        </div>
        <div class="card">
          <h2>网络吞吐 <span class="spacer"></span><span class="badge" id="pf-net-now">--</span></h2>
          <canvas class="spark" id="pf-net" style="height:110px"></canvas>
          <div class="metric-sub">绿：接收　粉：发送</div>
        </div>
      </div>
      <div class="grid c2" style="margin-bottom:14px">
        <div class="card"><h2>每个核心的负载</h2><div class="bars" id="pf-cores"><span class="dim">采集数据中…</span></div></div>
        <div class="card"><h2>磁盘空间与系统负载</h2><div id="pf-summary"></div></div>
      </div>
      <div class="card flush">
        <h2 style="padding:16px 16px 12px">占用最高的进程 <span class="spacer"></span>
          <span class="dim" style="font-size:12px;font-weight:400;text-transform:none">每 5 秒自动刷新</span></h2>
        <div class="table-wrap" id="pf-procs"><div class="empty">加载中…</div></div>
      </div>`;

    const charts = {
      cpu: new Chart($('#pf-cpu'), { max: 100, height: 120, series: [{ color: '#38bdf8', fill: 'rgba(56,189,248,.25)' }], fmt: (v) => `${v.toFixed(0)}%` }),
      mem: new Chart($('#pf-mem'), { max: 100, height: 120, series: [{ color: '#a78bfa', fill: 'rgba(167,139,250,.25)' }], fmt: (v) => `${v.toFixed(0)}%` }),
      disk: new Chart($('#pf-disk'), { height: 110, series: [{ color: '#38bdf8', fill: 'rgba(56,189,248,.22)' }, { color: '#fbbf24' }], fmt: rate }),
      net: new Chart($('#pf-net'), { height: 110, series: [{ color: '#34d399', fill: 'rgba(52,211,153,.22)' }, { color: '#f472b6' }], fmt: rate }),
    };

    const history = await api.get('/api/system/history').catch(() => ({ points: [] }));
    charts.cpu.load(history.points, (p) => [p.cpu]);
    charts.mem.load(history.points, (p) => [p.mem]);
    charts.disk.load(history.points, (p) => [p.disk_read, p.disk_write]);
    charts.net.load(history.points, (p) => [p.net_recv, p.net_sent]);

    let coresBuilt = -1;
    const update = (m) => {
      $('#pf-cpu-now').textContent = `${m.cpu.toFixed(1)}%`;
      $('#pf-cpu-sub').textContent = `${m.cpu_per_core.length} 逻辑核心`
        + (m.cpu_mhz ? ` · 当前 ${m.cpu_mhz} MHz` : '')
        + ` · 负载 ${m.load.join(' / ')}`;
      $('#pf-mem-now').textContent = `${m.mem.percent.toFixed(0)}%`;
      $('#pf-mem-sub').textContent = `已用 ${bytes(m.mem.used)} / ${bytes(m.mem.total)} · 可用 ${bytes(m.mem.available)}`;
      $('#pf-disk-now').textContent = `读 ${rate(m.disk.disk_read)}　写 ${rate(m.disk.disk_write)}`;
      $('#pf-net-now').textContent = `收 ${rate(m.net.net_recv)}　发 ${rate(m.net.net_sent)}`;
      charts.cpu.push([m.cpu]);
      charts.mem.push([m.mem.percent]);
      charts.disk.push([m.disk.disk_read, m.disk.disk_write]);
      charts.net.push([m.net.net_recv, m.net.net_sent]);

      if (coresBuilt !== m.cpu_per_core.length) {
        coresBuilt = m.cpu_per_core.length;
        $('#pf-cores').innerHTML = m.cpu_per_core.map((_, i) => `
          <div class="core-row"><span>核心 ${i}</span>
            <div class="bar"><span data-core="${i}" style="width:0%"></span></div>
            <span data-core-val="${i}">0%</span></div>`).join('');
      }
      m.cpu_per_core.forEach((value, i) => {
        const fill = $(`[data-core="${i}"]`, root);
        const label = $(`[data-core-val="${i}"]`, root);
        if (fill) {
          fill.style.width = `${Math.min(100, value)}%`;
          fill.parentElement.className = `bar ${levelClass(value)}`;
        }
        if (label) label.textContent = `${value.toFixed(0)}%`;
      });

      $('#pf-summary').innerHTML = `
        <div class="metric-label">根分区使用率</div>
        <div class="metric-value">${m.disk.percent.toFixed(0)}%</div>
        ${bar(m.disk.percent)}
        <div class="metric-sub">已用 ${bytes(m.disk.used)} / ${bytes(m.disk.total)}</div>
        <div class="metric-label" style="margin-top:18px">交换分区使用率</div>
        <div class="metric-value">${m.swap.total ? `${m.swap.percent.toFixed(0)}%` : '未启用'}</div>
        ${m.swap.total ? bar(m.swap.percent) : ''}
        <div class="metric-sub">${m.swap.total ? `已用 ${bytes(m.swap.used)} / ${bytes(m.swap.total)}` : '系统未配置 swap'}</div>
        <div class="metric-label" style="margin-top:18px">进程 / 线程</div>
        <div class="metric-sub" style="margin-top:0">${m.processes} 个进程 · ${m.threads} 个线程 · 运行 ${duration(m.uptime)}</div>`;
    };
    if (live.metrics) update(live.metrics);
    const unsubscribe = live.subscribe(update);

    async function loadProcs() {
      try {
        const rows = await api.get('/api/processes?limit=15&sort=cpu');
        $('#pf-procs').innerHTML = rows.processes.length ? `
          <table class="data"><thead><tr><th>PID</th><th>名称</th><th>用户</th>
            <th class="num">CPU</th><th class="num">内存</th><th class="num">RSS</th><th>命令</th></tr></thead>
          <tbody>${rows.processes.map((p) => `<tr>
            <td class="num">${p.pid}</td><td class="cell-main">${esc(p.name)}</td><td>${esc(p.user)}</td>
            <td class="num">${p.cpu.toFixed(1)}%</td><td class="num">${p.mem.toFixed(1)}%</td>
            <td class="num">${bytes(p.rss)}</td>
            <td class="cell-sub">${esc(p.cmdline.slice(0, 90))}</td></tr>`).join('')}</tbody></table>`
          : '<div class="empty">无数据</div>';
      } catch (err) { /* 忽略 */ }
    }
    await loadProcs();
    const procTimer = setInterval(loadProcs, 5000);

    return () => {
      unsubscribe();
      clearInterval(procTimer);
      Object.values(charts).forEach((c) => c.destroy());
    };
  },
});

/* ============================ 视图：网页终端 ============================ */

registerView('terminal', {
  title: '网页终端',
  fullbleed: true,
  async render(root) {
    const info = await api.get('/api/terminal/info').catch(() => ({ shell: '/bin/bash', user: 'root' }));
    root.innerHTML = `
      <div class="terminal-bar">
        <span class="badge info">${esc(info.user)}@${esc($('#brand-host').textContent)}</span>
        <span class="mono">${esc(info.shell)}</span>
        <span class="badge warn">root 权限</span>
        <div class="spacer"></div>
        <span class="badge" id="term-status">连接中…</span>
        <button class="btn sm ghost" data-act="clear">清屏</button>
        <button class="btn sm ghost" data-act="reconnect">重连</button>
        <button class="btn sm ghost" data-act="font-">A−</button>
        <button class="btn sm ghost" data-act="font+">A+</button>
      </div>
      <div class="terminal-host" id="terminal-host"></div>`;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13.5,
      fontFamily: '"JetBrains Mono", Menlo, Consolas, "Noto Sans Mono CJK SC", monospace',
      scrollback: 5000,
      allowProposedApi: true,
      theme: {
        background: '#05080c', foreground: '#dce7f3', cursor: '#38bdf8',
        selectionBackground: 'rgba(56,189,248,.3)',
        black: '#1b2530', red: '#f87171', green: '#34d399', yellow: '#fbbf24',
        blue: '#60a5fa', magenta: '#c084fc', cyan: '#22d3ee', white: '#dce7f3',
      },
    });
    const fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open($('#terminal-host'));

    let socket = null, disposed = false, reconnectTimer = null, fontSize = 13.5;
    let everConnected = false;
    const statusEl = $('#term-status');

    const doFit = () => {
      try { fit.fit(); } catch (err) { /* 容器尺寸为 0 时忽略 */ }
      if (socket && socket.readyState === WebSocket.OPEN && term.cols && term.rows) {
        socket.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
      }
    };

    function connect() {
      if (disposed) return;
      statusEl.textContent = '连接中…';
      statusEl.className = 'badge';
      const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
      socket = new WebSocket(`${protocol}://${location.host}/api/terminal/ws`);
      socket.binaryType = 'arraybuffer';
      socket.onopen = () => {
        statusEl.textContent = '已连接';
        statusEl.className = 'badge ok';
        if (everConnected) {
          term.write('\r\n\x1b[33m[连接已恢复。每次连接都是新终端会话，服务升级后原会话已结束]\x1b[0m\r\n');
        }
        everConnected = true;
        doFit();
        term.focus();
      };
      socket.onmessage = (event) => {
        if (typeof event.data === 'string') term.write(event.data);
        else term.write(new Uint8Array(event.data));
      };
      socket.onclose = () => {
        statusEl.textContent = '已断开';
        statusEl.className = 'badge danger';
        if (!disposed) {
          term.write('\r\n\x1b[31m[连接已断开，1.5 秒后自动重连…]\x1b[0m\r\n');
          reconnectTimer = setTimeout(connect, 1500);
        }
      };
      socket.onerror = () => { statusEl.textContent = '连接错误'; statusEl.className = 'badge danger'; };
    }

    const dataSub = term.onData((data) => {
      if (socket && socket.readyState === WebSocket.OPEN) socket.send(data);
    });
    const resizeSub = term.onResize(({ cols, rows }) => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'resize', cols, rows }));
      }
    });

    const hostObserver = new ResizeObserver(() => doFit());
    hostObserver.observe($('#terminal-host'));
    const onWindowResize = () => doFit();
    window.addEventListener('resize', onWindowResize);

    connect();
    setTimeout(() => { doFit(); term.focus(); }, 60);

    root.querySelector('.terminal-bar').onclick = (event) => {
      const action = event.target.dataset?.act;
      if (action === 'clear') term.clear();
      if (action === 'reconnect') {
        if (socket) { socket.onclose = null; socket.close(); }
        term.reset();
        connect();
      }
      if (action === 'font+' || action === 'font-') {
        fontSize = Math.min(22, Math.max(9, fontSize + (action === 'font+' ? 1 : -1)));
        term.options.fontSize = fontSize;
        doFit();
      }
    };

    return () => {
      disposed = true;
      clearTimeout(reconnectTimer);
      window.removeEventListener('resize', onWindowResize);
      hostObserver.disconnect();
      try { dataSub.dispose(); resizeSub.dispose(); } catch (err) { /* 忽略 */ }
      if (socket) { socket.onclose = null; socket.close(); }
      term.dispose();
    };
  },
});

/* ============================ 视图：控制台 / 日志 ============================ */

registerView('logs', {
  title: '控制台 / 日志',
  async render(root) {
    const sources = await api.get('/api/logs/sources').catch(() => ({ journal: false, dmesg: false, files: [] }));
    const fileOptions = sources.files
      .map((f) => `<option value="${esc(f.path)}">${esc(f.path)} (${bytes(f.size)})</option>`).join('');

    root.innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <div class="toolbar" style="margin-bottom:0">
          <label class="field" style="flex-direction:row;align-items:center;gap:8px">
            <span>来源</span>
            <select class="input" id="log-source">
              ${sources.journal ? '<option value="journal">系统日志 (journalctl)</option>' : ''}
              ${sources.journal ? '<option value="boot">本次启动日志</option>' : ''}
              ${sources.dmesg ? '<option value="dmesg">内核日志 (dmesg)</option>' : ''}
              <option value="file">日志文件</option>
            </select>
          </label>
          <select class="input hidden" id="log-file">${fileOptions}</select>
          <label class="field" style="flex-direction:row;align-items:center;gap:8px">
            <span>级别</span>
            <select class="input" id="log-priority">
              <option value="">全部</option><option value="err">错误及以上</option>
              <option value="warning">警告及以上</option><option value="info">信息及以上</option>
            </select>
          </label>
          <label class="field" style="flex-direction:row;align-items:center;gap:8px">
            <span>行数</span>
            <select class="input" id="log-lines">
              <option>100</option><option selected>300</option><option>1000</option><option>2000</option>
            </select>
          </label>
          <label class="field" style="flex-direction:row;align-items:center;gap:8px">
            <span>过滤</span>
            <input class="input" id="log-filter" placeholder="关键字…" style="width:150px">
          </label>
          <div class="spacer"></div>
          <label class="row" style="font-size:13px;gap:6px">
            <input type="checkbox" id="log-auto"> 自动刷新
          </label>
          <button class="btn sm primary" id="log-refresh">刷新</button>
          <button class="btn sm ghost" id="log-copy">复制</button>
        </div>
        <div class="dim" id="log-meta" style="font-size:12px;margin-top:10px"></div>
      </div>
      <div class="log-output" id="log-output">加载中…</div>`;

    const sourceEl = $('#log-source');
    const fileEl = $('#log-file');
    const output = $('#log-output');
    const meta = $('#log-meta');
    let rawLines = [];
    let timer = null;
    let busy = false;

    const lineClass = (line) => {
      const lower = line.toLowerCase();
      if (/\b(error|failed|failure|fatal|critical|denied|panic)\b/.test(lower)) return 'log-line err';
      if (/\b(warn|warning|deprecated)\b/.test(lower)) return 'log-line warn';
      return '';
    };

    function paint() {
      const keyword = $('#log-filter').value.trim().toLowerCase();
      const lines = keyword ? rawLines.filter((l) => l.toLowerCase().includes(keyword)) : rawLines;
      const atBottom = output.scrollTop + output.clientHeight >= output.scrollHeight - 40;
      output.innerHTML = lines.length
        ? lines.map((line) => `<span class="${lineClass(line)}">${esc(line) || '&nbsp;'}</span>`).join('\n')
        : '<span class="dim">没有匹配的日志行</span>';
      if (atBottom) output.scrollTop = output.scrollHeight;
      meta.textContent = `共 ${rawLines.length} 行`
        + (keyword ? `，匹配 ${lines.length} 行` : '')
        + `　更新于 ${new Date().toLocaleTimeString()}`;
    }

    async function load() {
      if (busy) return;
      busy = true;
      const lines = $('#log-lines').value;
      try {
        const source = sourceEl.value;
        if (source === 'dmesg') {
          rawLines = (await api.get(`/api/logs/dmesg?lines=${lines}`)).lines;
        } else if (source === 'file') {
          const path = fileEl.value;
          if (!path) throw new ApiError('没有可用的日志文件', 0);
          const data = await api.get(`/api/logs/file?path=${encodeURIComponent(path)}`);
          rawLines = data.content.split('\n');
          if (data.truncated) rawLines.unshift(`… 文件较大（${bytes(data.size)}），仅显示末尾部分 …`);
        } else {
          const priority = $('#log-priority').value;
          const boot = source === 'boot' ? '&boot=true' : '';
          const data = await api.get(`/api/logs/journal?lines=${lines}${boot}${priority ? `&priority=${priority}` : ''}`);
          if (!data.ok && data.error) throw new ApiError(data.error, 500);
          rawLines = data.lines;
        }
        paint();
      } catch (err) {
        output.innerHTML = `<span class="log-line err">读取失败：${esc(err.message)}</span>`;
        meta.textContent = '';
      } finally {
        busy = false;
      }
    }

    sourceEl.onchange = () => {
      const isFile = sourceEl.value === 'file';
      fileEl.classList.toggle('hidden', !isFile);
      $('#log-priority').parentElement.classList.toggle('hidden', isFile || sourceEl.value === 'dmesg');
      load();
    };
    fileEl.onchange = load;
    $('#log-priority').onchange = load;
    $('#log-lines').onchange = load;
    $('#log-refresh').onclick = load;
    $('#log-filter').oninput = paint;
    $('#log-copy').onclick = async () => {
      try {
        await navigator.clipboard.writeText(rawLines.join('\n'));
        toast('日志已复制到剪贴板');
      } catch (err) { toast('复制失败，浏览器限制', 'err'); }
    };
    $('#log-auto').onchange = (event) => {
      clearInterval(timer);
      timer = null;
      if (event.target.checked) {
        timer = setInterval(load, 3000);
        toast('已开启自动刷新（3 秒）');
      }
    };

    await load();
    return () => clearInterval(timer);
  },
});

/* ============================ 视图：存储空间 ============================ */

registerView('storage', {
  title: '存储空间',
  async render(root) {
    root.innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <h2>磁盘分区使用情况 <span class="spacer"></span>
          <button class="btn sm ghost" id="st-refresh">刷新</button></h2>
        <div class="grid c3" id="st-parts"><div class="empty">加载中…</div></div>
      </div>
      <div class="grid c2" style="margin-bottom:14px">
        <div class="card">
          <h2>目录占用分析</h2>
          <div class="row" style="margin-bottom:12px">
            <input class="input" id="st-path" value="/" style="flex:1;min-width:160px">
            <button class="btn primary" id="st-analyze">分析</button>
          </div>
          <div id="st-dirsize"><div class="dim" style="font-size:12px">输入目录路径后点击“分析”，统计各子目录占用（大目录可能较慢）。</div></div>
        </div>
        ${isInternal() ? `<div class="card">
          <h2>挂载 / 卸载</h2>
          <div class="grid" style="grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px">
            <label class="field"><span>设备</span><input class="input" id="st-device" placeholder="/dev/sdb1"></label>
            <label class="field"><span>挂载点</span><input class="input" id="st-mountpoint" placeholder="/mnt/data"></label>
            <label class="field"><span>文件系统（可选）</span><input class="input" id="st-fstype" placeholder="ext4 / ntfs-3g"></label>
            <label class="field"><span>挂载参数（可选）</span><input class="input" id="st-options" placeholder="defaults,noatime"></label>
          </div>
          <button class="btn ok" id="st-mount">挂载</button>
        </div>` : `<div class="card">
          <h2>挂载 / 卸载</h2>
          <div class="dim" style="font-size:13px;line-height:1.9">
            公网模式下已锁定挂载与卸载操作。<br>
            需要时请在服务器上执行 <span class="mono">serverpanel --enable-internal</span> 激活内网模式。
          </div>
        </div>`}
      </div>
      <div class="card flush" style="margin-bottom:14px">
        <h2 style="padding:16px 16px 12px">当前挂载表</h2>
        <div class="table-wrap" id="st-mounts"><div class="empty">加载中…</div></div>
      </div>
      <div class="card flush">
        <h2 style="padding:16px 16px 12px">块设备（lsblk）</h2>
        <div class="table-wrap" id="st-block"><div class="empty">加载中…</div></div>
      </div>`;

    async function loadOverview() {
      try {
        const data = await api.get('/api/storage/overview');
        $('#st-parts').innerHTML = data.partitions.length ? data.partitions.map((p) => `
          <div class="card" style="background:var(--panel-2)">
            <div class="metric-label">${esc(p.mountpoint)}</div>
            <div class="metric-value" style="font-size:22px">${p.percent !== null ? `${p.percent.toFixed(0)}%` : '-'}</div>
            ${p.percent !== null ? bar(p.percent) : ''}
            <div class="metric-sub">${esc(p.device)}<br>${esc(p.fstype)}</div>
            <div class="metric-sub">已用 ${bytes(p.used)} / ${bytes(p.total)} · 可用 ${bytes(p.free)}</div>
          </div>`).join('') : '<div class="empty">未检测到可用的磁盘分区（容器环境常见）</div>';

        const io = data.disks.filter((d) => !d.name.startsWith('loop') && !d.name.startsWith('ram'));
        $('#st-block').innerHTML = `
          <table class="data"><thead><tr><th>设备</th><th>类型</th><th class="num">容量</th><th>文件系统</th>
            <th>挂载点</th><th class="num">累计读取</th><th class="num">累计写入</th></tr></thead>
          <tbody>${(data.blockdevices || []).map(function row(dev, depth) {
            const children = dev.children || [];
            const name = dev.name || dev.kname || '';
            const size = dev.size ? bytes(dev.size) : '-';
            return `<tr><td class="cell-main" style="padding-left:${12 + depth * 18}px">${esc(name)}</td>
              <td>${esc(dev.type || '-')}</td><td class="num">${size}</td>
              <td>${esc(dev.fstype || '-')}</td><td class="cell-main">${esc(dev.mountpoint || '-')}</td>
              <td class="num">-</td><td class="num">-</td></tr>`
              + children.map((c) => row(c, depth + 1)).join('');
          }).join('') || ''}</tbody>
          <tfoot>${io.length ? `<tr><td colspan="7" class="dim" style="font-size:12px">I/O 统计：${
            io.map((d) => `${esc(d.name)} 读 ${bytes(d.read_bytes)} / 写 ${bytes(d.write_bytes)}`).join('　')
          }</td></tr>` : ''}</tfoot></table>`;
      } catch (err) {
        $('#st-parts').innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
      }
    }

    async function loadMounts() {
      try {
        const data = await api.get('/api/storage/mounts');
        const rows = data.mounts.filter((m) => !['proc', 'sysfs', 'devpts', 'cgroup', 'cgroup2', 'tmpfs', 'devtmpfs', 'securityfs', 'pstore', 'bpf', 'tracefs', 'debugfs', 'configfs', 'fusectl', 'mqueue', 'hugetlbfs', 'autofs', 'binfmt_misc', 'rpc_pipefs'].includes(m.fstype));
        $('#st-mounts').innerHTML = rows.length ? `
          <table class="data"><thead><tr><th>设备</th><th>挂载点</th><th>类型</th><th>参数</th><th></th></tr></thead>
          <tbody>${rows.map((m) => `<tr>
            <td class="cell-main">${esc(m.device)}</td><td class="cell-main">${esc(m.mountpoint)}</td>
            <td>${esc(m.fstype)}</td><td class="cell-sub">${esc(m.options)}</td>
            <td class="actions">${isInternal() ? `<button class="btn sm" data-umount="${esc(m.mountpoint)}">卸载</button>` : ''}</td>
          </tr>`).join('')}</tbody></table>` : '<div class="empty">无挂载记录</div>';
      } catch (err) { /* 忽略 */ }
    }

    $('#st-refresh').onclick = () => { loadOverview(); loadMounts(); };
    $('#st-analyze').onclick = async () => {
      const path = $('#st-path').value.trim() || '/';
      const box = $('#st-dirsize');
      box.innerHTML = '<div class="dim">统计中，请稍候…</div>';
      try {
        const data = await api.get(`/api/storage/dirsize?path=${encodeURIComponent(path)}&depth=1`);
        if (!data.entries.length) { box.innerHTML = '<div class="empty">目录为空或没有子项</div>'; return; }
        const total = data.mount_used || 1;
        box.innerHTML = `<div class="metric-sub" style="margin-bottom:10px">${esc(data.path)} · 所在分区已用 ${bytes(data.mount_used)} / ${bytes(data.mount_total)}</div>
          <div class="bars">${data.entries.slice(0, 40).map((e) => {
            const pct = Math.max(0.5, (e.size / total) * 100);
            return `<div class="core-row" style="grid-template-columns:200px 1fr 76px">
              <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.path)}">${esc(e.name)}</span>
              <div class="bar ${pct > 60 ? 'danger' : pct > 30 ? 'warn' : ''}"><span style="width:${Math.min(100, pct)}%"></span></div>
              <a style="text-align:right" href="#" data-open="${esc(e.path)}" data-dir="${e.isdir}">${bytes(e.size)}</a></div>`;
          }).join('')}</div>`;
      } catch (err) {
        box.innerHTML = `<div class="empty">分析失败：${esc(err.message)}</div>`;
      }
    };

    const mountBtn = $('#st-mount');  // 公网模式下该按钮不存在
    if (mountBtn) {
      mountBtn.onclick = async () => {
        const device = $('#st-device').value.trim();
        const mountpoint = $('#st-mountpoint').value.trim();
        if (!device || !mountpoint) { toast('请填写设备与挂载点', 'err'); return; }
        try {
          const res = await api.post('/api/storage/mount', {
            device, mountpoint,
            fstype: $('#st-fstype').value.trim() || null,
            options: $('#st-options').value.trim() || null,
          });
          toast(res.message);
          loadOverview(); loadMounts();
        } catch (err) { toast(err.message, 'err'); }
      };
    }

    root.onclick = async (event) => {
      const umountBtn = event.target.closest('[data-umount]');
      if (umountBtn) {
        const umount = umountBtn.dataset.umount;
        const ok = await confirmDialog({
          title: '卸载分区', danger: true, confirmText: '卸载',
          message: `确定要卸载 <b class="mono">${esc(umount)}</b> 吗？请确保没有程序正在使用该目录。`,
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/storage/unmount', { path: umount });
          toast(res.message);
          loadOverview(); loadMounts();
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      const openLink = event.target.closest('[data-open]');
      if (openLink) {
        event.preventDefault();
        if (openLink.dataset.dir !== 'true') return;
        sessionStorage.setItem('sp_cwd', openLink.dataset.open);
        navigate('files');
      }
    };

    await Promise.all([loadOverview(), loadMounts()]);
  },
});

/* ============================ 视图：进程管理 ============================ */

registerView('processes', {
  title: '进程管理',
  async render(root) {
    root.innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <div class="toolbar" style="margin-bottom:0">
          <input class="input" id="ps-search" placeholder="搜索进程名或命令行…" style="width:230px">
          <select class="input" id="ps-sort">
            <option value="cpu">按 CPU 排序</option><option value="mem">按内存排序</option>
            <option value="rss">按常驻内存排序</option><option value="pid">按 PID 排序</option>
          </select>
          <span class="badge" id="ps-count">-</span>
          <div class="spacer"></div>
          <label class="row" style="font-size:13px;gap:6px"><input type="checkbox" id="ps-auto" checked> 自动刷新</label>
          <button class="btn sm primary" id="ps-refresh">刷新</button>
        </div>
      </div>
      <div class="card flush"><div class="table-wrap" id="ps-table"><div class="empty">加载中…</div></div></div>`;

    let timer = null;
    let rows = [];

    async function load() {
      const q = encodeURIComponent($('#ps-search').value.trim());
      const sort = $('#ps-sort').value;
      try {
        const data = await api.get(`/api/processes?limit=200&sort=${sort}&q=${q}`);
        rows = data.processes;
        $('#ps-count').textContent = `${data.total} 个进程`;
        $('#ps-table').innerHTML = rows.length ? `
          <table class="data"><thead><tr>
            <th class="sortable" data-sort="pid">PID</th><th>名称</th><th>用户</th>
            <th class="num">CPU%</th><th class="num">内存%</th><th class="num">RSS</th>
            <th>状态</th><th>启动时间</th><th>命令</th><th></th></tr></thead>
          <tbody>${rows.map((p, index) => `<tr data-index="${index}">
            <td class="num">${p.pid}</td>
            <td class="cell-main">${esc(p.name)}</td>
            <td>${esc(p.user)}</td>
            <td class="num">${p.cpu.toFixed(1)}</td>
            <td class="num">${p.mem.toFixed(1)}</td>
            <td class="num">${bytes(p.rss)}</td>
            <td><span class="badge ${p.status === 'running' ? 'ok' : ''}">${esc(p.status)}</span></td>
            <td class="cell-sub">${datetime(p.create_time)}</td>
            <td class="cell-sub" title="${esc(p.cmdline)}">${esc(p.cmdline.slice(0, 80))}</td>
            <td class="actions">
              <button class="btn sm ghost" data-act="detail" data-index="${index}">详情</button>
              ${isInternal() ? `<button class="btn sm" data-act="term" data-index="${index}">结束</button>
              <button class="btn sm danger" data-act="kill" data-index="${index}">强制</button>` : ''}
            </td></tr>`).join('')}</tbody></table>`
          : '<div class="empty">没有匹配的进程</div>';
      } catch (err) {
        $('#ps-table').innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
      }
    }

    async function sendSignal(proc, signal) {
      const label = signal === 'kill' ? '强制结束（SIGKILL）' : '结束（SIGTERM）';
      const ok = await confirmDialog({
        title: label, danger: true, confirmText: '确定',
        message: `确定要${label}进程 <b class="mono">${esc(proc.name)}</b>（PID ${proc.pid}）吗？<div class="dim mono" style="margin-top:8px;font-size:12px">${esc(proc.cmdline.slice(0, 160))}</div>`,
      });
      if (!ok) return;
      try {
        const res = await api.post(`/api/processes/${proc.pid}/signal`, { signal });
        toast(res.message);
        load();
      } catch (err) { toast(err.message, 'err'); }
    }

    async function showDetail(proc) {
      const body = document.createElement('div');
      body.innerHTML = '<div class="empty">加载中…</div>';
      const modal = openModal({ title: `进程详情 · ${proc.name} (${proc.pid})`, body, size: 'wide' });
      try {
        const d = await api.get(`/api/processes/${proc.pid}`);
        const envRows = Object.entries(d.environ || {}).map(([k, v]) => `<div class="cell-sub">${esc(k)}=${esc(v)}</div>`).join('');
        body.innerHTML = `
          <dl class="kv" style="grid-template-columns:110px 1fr">
            <dt>PID / PPID</dt><dd>${d.pid} / ${d.ppid}</dd>
            <dt>用户</dt><dd>${esc(d.user)}</dd>
            <dt>状态</dt><dd>${esc(d.status)} · nice ${d.nice}</dd>
            <dt>CPU / 内存</dt><dd>${d.cpu.toFixed(1)}% / ${d.mem.toFixed(2)}% (RSS ${bytes(d.rss)})</dd>
            <dt>线程数</dt><dd>${d.threads}</dd>
            <dt>启动时间</dt><dd>${datetime(d.create_time)}</dd>
            <dt>可执行文件</dt><dd>${esc(d.exe || '-')}</dd>
            <dt>工作目录</dt><dd>${esc(d.cwd || '-')}</dd>
            <dt>命令行</dt><dd>${esc(d.cmdline)}</dd>
          </dl>
          <div>
            <h2 style="font-size:12px;color:var(--text-dim);margin:4px 0 8px">打开的端口 / 连接</h2>
            ${d.connections.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>类型</th><th>状态</th><th>本地</th><th>远端</th></tr></thead>
              <tbody>${d.connections.map((c) => `<tr><td>${esc(c.type)}</td><td>${esc(c.status)}</td>
                <td class="cell-main">${esc(c.laddr || '-')}</td><td class="cell-main">${esc(c.raddr || '-')}</td></tr>`).join('')}</tbody></table></div>`
              : '<div class="dim" style="font-size:12px">无连接信息</div>'}
          </div>
          <div>
            <h2 style="font-size:12px;color:var(--text-dim);margin:4px 0 8px">打开的文件</h2>
            <div class="cell-sub" style="max-height:130px;overflow:auto">${(d.open_files || []).map(esc).join('<br>') || '无'}</div>
          </div>
          <div>
            <h2 style="font-size:12px;color:var(--text-dim);margin:4px 0 8px">环境变量（部分）</h2>
            <div style="max-height:150px;overflow:auto">${envRows || '无'}</div>
          </div>`;
      } catch (err) {
        body.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
      }
      return modal;
    }

    $('#ps-refresh').onclick = load;
    $('#ps-sort').onchange = load;
    let searchTimer = null;
    $('#ps-search').oninput = () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(load, 260);
    };
    $('#ps-auto').onchange = (event) => {
      clearInterval(timer);
      timer = null;
      if (event.target.checked) timer = setInterval(load, 4000);
    };
    timer = setInterval(load, 4000);

    $('#ps-table').onclick = (event) => {
      const target = event.target.closest('[data-act]');
      if (!target) return;
      const proc = rows[Number(target.dataset.index)];
      if (!proc) return;
      const action = target.dataset.act;
      if (action === 'detail') showDetail(proc);
      if (action === 'term') sendSignal(proc, 'term');
      if (action === 'kill') sendSignal(proc, 'kill');
    };

    await load();
    return () => { clearInterval(timer); clearTimeout(searchTimer); };
  },
});

/* ============================ 视图：应用与端口 ============================ */

registerView('apps-port', {
  title: '应用与端口',
  async render(root) {
    root.innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <div class="toolbar" style="margin-bottom:0">
          <input class="input" id="apps-search" placeholder="搜索应用名、命令或端口…" style="width:250px">
          <span class="badge" id="apps-count">加载中…</span>
          <div class="spacer"></div>
          <label class="row" style="font-size:13px;gap:6px"><input type="checkbox" id="apps-auto" checked> 自动刷新</label>
          <button class="btn sm primary" id="apps-refresh">刷新</button>
        </div>
      </div>
      <div class="card flush"><div class="table-wrap" id="apps-table"><div class="empty">加载中…</div></div></div>`;

    let timer = null;

    function portChips(ports) {
      return ports.map((p) => {
        if (p.non_web) {
          return `<span class="port-chip raw" title="非网页服务，仅列出监听地址">
            <span class="pc-proto">${esc(p.proto)}</span>
            <span class="pc-addr">${esc(p.address)}:${p.port}</span></span>`;
        }
        if (!p.urls.length) {
          return `<span class="port-chip local" title="仅监听本机回环地址，只能在这台服务器上访问">
            <span class="pc-proto">仅本机</span>
            <span class="pc-addr">${esc(p.address)}:${p.port}</span></span>`;
        }
        return p.urls.map((u) => `<a class="port-chip web" href="${esc(u.url)}" target="_blank" rel="noreferrer"
            title="在新标签页打开 ${esc(u.url)}">
            <span class="pc-proto">${esc(p.protocol)}</span>
            <span class="pc-addr">${esc(u.label)}</span>
            <span class="pc-go">↗</span></a>`).join('');
      }).join('');
    }

    async function load() {
      try {
        const data = await api.get('/api/apps');
        $('#apps-count').textContent = `${data.total_apps} 个应用 · ${data.total_ports} 个监听端口`;
        const q = $('#apps-search').value.trim().toLowerCase();
        const rows = (data.apps || []).filter((a) => !q
          || a.name.toLowerCase().includes(q)
          || (a.cmdline || '').toLowerCase().includes(q)
          || a.ports.some((p) => S(p.port).includes(q)));
        $('#apps-table').innerHTML = rows.length ? `
          <table class="data"><thead><tr>
            <th>应用</th><th>PID</th><th>用户</th><th class="num">内存%</th>
            <th>监听端口 / 访问入口</th><th>命令行</th></tr></thead>
          <tbody>${rows.map((a) => `<tr>
            <td class="cell-main">${esc(a.name)}</td>
            <td class="num">${a.pid || '-'}</td>
            <td>${esc(a.user)}</td>
            <td class="num">${a.mem ? a.mem.toFixed(1) : '-'}</td>
            <td><div class="port-list">${portChips(a.ports)}</div></td>
            <td class="cell-sub" title="${esc(a.cmdline)}">${esc((a.cmdline || '').slice(0, 64))}</td>
          </tr>`).join('')}</tbody></table>`
          : '<div class="empty">没有匹配的应用</div>';
      } catch (err) {
        $('#apps-table').innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
      }
    }

    $('#apps-refresh').onclick = load;
    let searchTimer = null;
    $('#apps-search').oninput = () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(load, 200);
    };
    $('#apps-auto').onchange = (event) => {
      clearInterval(timer);
      timer = null;
      if (event.target.checked) timer = setInterval(load, 5000);
    };
    timer = setInterval(load, 5000);

    await load();
    return () => { clearInterval(timer); clearTimeout(searchTimer); };
  },
});

/* ============================ 视图：服务管理 ============================ */

registerView('services', {
  title: '服务管理',
  async render(root) {
    const caps = live.capabilities || {};
    if (!caps.systemd) {
      root.innerHTML = `
        <div class="card">
          <h2>服务管理不可用</h2>
          <div style="line-height:1.8">
            当前主机没有以 systemd 作为初始化进程（PID 1），因此无法管理 systemd 服务。<br>
            <span class="dim">常见于容器环境。在标准 Ubuntu 主机上运行本面板即可使用该功能。</span>
          </div>
          <div class="row" style="margin-top:14px">
            <button class="btn" data-act="go-processes">改用进程管理</button>
          </div>
        </div>`;
      root.onclick = (event) => {
        if (event.target.dataset?.act === 'go-processes') navigate('processes');
      };
      return;
    }

    root.innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <div class="toolbar" style="margin-bottom:0">
          <input class="input" id="sv-search" placeholder="搜索服务名或描述…" style="width:230px">
          <select class="input" id="sv-state">
            <option value="all">全部服务</option><option value="running">正在运行</option>
            <option value="stopped">已停止</option><option value="failed">启动失败</option>
          </select>
          <span class="badge" id="sv-count">-</span>
          <div class="spacer"></div>
          <button class="btn sm primary" id="sv-refresh">刷新</button>
        </div>
      </div>
      <div class="card flush"><div class="table-wrap" id="sv-table"><div class="empty">加载中…</div></div></div>`;

    let services = [];

    const stateBadge = (s) => {
      if (s.active === 'active') return `<span class="badge ok">运行中</span>`;
      if (s.active === 'failed') return `<span class="badge danger">失败</span>`;
      if (s.active === 'activating') return `<span class="badge warn">启动中</span>`;
      return `<span class="badge">已停止</span>`;
    };

    async function load() {
      const q = encodeURIComponent($('#sv-search').value.trim());
      const state = $('#sv-state').value;
      try {
        const data = await api.get(`/api/services?q=${q}&state=${state}`);
        services = data.services;
        $('#sv-count').textContent = `${data.total} 个服务`;
        $('#sv-table').innerHTML = services.length ? `
          <table class="data"><thead><tr><th>服务</th><th>状态</th><th>开机自启</th><th>描述</th><th></th></tr></thead>
          <tbody>${services.map((s, index) => `<tr>
            <td class="cell-main">${esc(s.unit)}</td>
            <td>${stateBadge(s)} <span class="cell-sub">${esc(s.sub)}</span></td>
            <td>${s.enabled === 'enabled' ? '<span class="badge ok">已启用</span>' : `<span class="badge">${esc(s.enabled)}</span>`}</td>
            <td class="cell-sub">${esc(s.description.slice(0, 70))}</td>
            <td class="actions">
              <button class="btn sm ghost" data-act="logs" data-index="${index}">日志</button>
              ${isInternal() ? (s.active === 'active'
                ? `<button class="btn sm" data-act="restart" data-index="${index}">重启</button>
                   <button class="btn sm danger" data-act="stop" data-index="${index}">停止</button>`
                : `<button class="btn sm ok" data-act="start" data-index="${index}">启动</button>`)
                + (s.enabled === 'enabled'
                  ? `<button class="btn sm" data-act="disable" data-index="${index}">取消自启</button>`
                  : `<button class="btn sm" data-act="enable" data-index="${index}">开机自启</button>`)
                : ''}
            </td></tr>`).join('')}</tbody></table>`
          : '<div class="empty">没有匹配的服务</div>';
      } catch (err) {
        $('#sv-table').innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
      }
    }

    async function act(service, action, needConfirm) {
      if (needConfirm) {
        const ok = await confirmDialog({
          title: '确认操作', danger: action === 'stop' || action === 'disable', confirmText: '确定',
          message: `确定要对 <b class="mono">${esc(service.unit)}</b> 执行「${esc(action)}」吗？`,
        });
        if (!ok) return;
      }
      try {
        const res = await api.post(`/api/services/${encodeURIComponent(service.unit)}/action`, { action });
        toast(res.message);
        setTimeout(load, 700);
      } catch (err) { toast(err.message, 'err'); }
    }

    async function showLogs(service) {
      const body = document.createElement('div');
      body.innerHTML = '<div class="empty">加载中…</div>';
      openModal({ title: `服务日志 · ${service.unit}`, body, size: 'wide' });
      try {
        const data = await api.get(`/api/services/${encodeURIComponent(service.unit)}/logs?lines=400`);
        body.innerHTML = `<div class="log-output" style="max-height:60vh">${
          data.lines.length ? data.lines.map((l) => esc(l)).join('\n') : '<span class="dim">暂无日志</span>'
        }</div>`;
      } catch (err) {
        body.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
      }
    }

    $('#sv-refresh').onclick = load;
    $('#sv-state').onchange = load;
    let searchTimer = null;
    $('#sv-search').oninput = () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(load, 280);
    };

    $('#sv-table').onclick = (event) => {
      const target = event.target.closest('[data-act]');
      if (!target) return;
      const service = services[Number(target.dataset.index)];
      if (!service) return;
      const action = target.dataset.act;
      if (action === 'logs') showLogs(service);
      else act(service, action, ['stop', 'restart', 'disable'].includes(action));
    };

    await load();
    return () => clearTimeout(searchTimer);
  },
});

/* ============================ 视图：文件管理 ============================ */

registerView('files', {
  title: '文件管理',
  async render(root) {
    let cwd = sessionStorage.getItem('sp_cwd') || '/';
    let entries = [];

    const roots = (await api.get('/api/files/roots').catch(() => ({ roots: [] }))).roots;

    root.innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <div class="toolbar">
          <button class="btn sm" data-act="up">↑ 上级</button>
          <button class="btn sm" data-act="refresh">刷新</button>
          <button class="btn sm" data-act="mkdir">新建文件夹</button>
          <button class="btn sm" data-act="newfile">新建文件</button>
          <button class="btn sm" data-act="upload">上传文件</button>
          <input type="file" id="file-input" multiple class="hidden">
          <div class="spacer"></div>
          <input class="input" id="file-search" placeholder="在当前目录搜索…" style="width:190px">
          <button class="btn sm" data-act="search">搜索</button>
        </div>
        <div class="crumbs" id="file-crumbs"></div>
        <div class="dim mono" id="file-meta" style="font-size:12px;margin-top:9px"></div>
      </div>

      <div class="card" style="margin-bottom:14px">
        <h2>快捷位置</h2>
        <div class="row" id="file-roots">${roots.filter((r) => r.exists).map((r) =>
          `<button class="btn sm ghost" data-root="${esc(r.path)}">${esc(r.label)} <span class="dim">${esc(r.path)}</span></button>`).join('')}</div>
      </div>

      <div class="card flush"><div class="table-wrap" id="file-table"><div class="empty">加载中…</div></div></div>`;

    function renderCrumbs(path) {
      const parts = path.split('/').filter(Boolean);
      const nodes = ['<button data-crumb="/">/</button>'];
      let acc = '';
      parts.forEach((part) => {
        acc += `/${part}`;
        nodes.push('<span class="sep">/</span>', `<button data-crumb="${esc(acc)}">${esc(part)}</button>`);
      });
      $('#file-crumbs').innerHTML = nodes.join('');
    }

    function renderTable() {
      if (!entries.length) {
        $('#file-table').innerHTML = '<div class="empty">此目录为空</div>';
        return;
      }
      $('#file-table').innerHTML = `
        <table class="data"><thead><tr>
          <th style="width:44%">名称</th><th class="num">大小</th><th>权限</th><th>所有者</th>
          <th>修改时间</th><th></th></tr></thead>
        <tbody>${entries.map((e, index) => `<tr>
          <td><span class="file-icon">${e.is_dir ? '🗀' : e.is_link ? '🔗' : '📄'}</span>
            <span class="cell-main">${esc(e.name)}</span>
            ${e.link_target ? `<span class="cell-sub"> → ${esc(e.link_target)}</span>` : ''}</td>
          <td class="num">${e.is_dir ? '-' : bytes(e.size)}</td>
          <td class="cell-sub">${esc(e.mode)}</td>
          <td class="cell-sub">${e.uid}:${e.gid}</td>
          <td class="cell-sub">${datetime(e.mtime)}</td>
          <td class="actions">
            ${e.is_dir ? `<button class="btn sm ghost" data-act="open" data-index="${index}">打开</button>` : ''}
            ${e.is_dir ? '' : '<a class="btn sm ghost" href="#" data-act="edit" data-index="' + index + '">编辑</a>'}
            <a class="btn sm ghost" href="/api/files/download?path=${encodeURIComponent(e.path)}">下载</a>
            <button class="btn sm ghost" data-act="rename" data-index="${index}">重命名</button>
            <button class="btn sm danger" data-act="delete" data-index="${index}">删除</button>
          </td></tr>`).join('')}</tbody></table>`;
    }

    async function load(path) {
      try {
        const data = await api.get(`/api/files/list?path=${encodeURIComponent(path)}`);
        cwd = data.path;
        sessionStorage.setItem('sp_cwd', cwd);
        entries = data.entries;
        renderCrumbs(cwd);
        renderTable();
        $('#file-meta').textContent = `${entries.length} 项`
          + (data.disk ? ` · 分区可用 ${bytes(data.disk.free)} / ${bytes(data.disk.total)}` : '');
      } catch (err) {
        $('#file-table').innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
        $('#file-meta').textContent = '';
      }
    }

    async function openEditor(entry) {
      const body = document.createElement('div');
      body.innerHTML = '<div class="empty">加载中…</div>';
      const foot = document.createElement('div');
      foot.className = 'row';
      foot.innerHTML = `<span class="dim mono" id="editor-path" style="font-size:12px"></span>
        <div class="spacer"></div><button class="btn" data-close>关闭</button>
        <button class="btn primary" data-save>保存</button>`;
      const modal = openModal({ title: `编辑 · ${entry.name}`, body, footer: foot, size: 'wide' });
      $('#editor-path', foot).textContent = entry.path;
      try {
        const data = await api.get(`/api/files/read?path=${encodeURIComponent(entry.path)}`);
        body.innerHTML = `<textarea class="input" id="editor-area" spellcheck="false"
          style="width:100%;height:52vh;font-size:13px"></textarea>`;
        const area = $('#editor-area', body);
        area.value = data.content;
        area.focus();
        $('[data-save]', foot).onclick = async () => {
          try {
            const res = await api.post('/api/files/write', { path: entry.path, content: area.value });
            toast(res.message);
            modal.close();
            load(cwd);
          } catch (err) { toast(err.message, 'err'); }
        };
      } catch (err) {
        body.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
      }
    }

    async function doUpload(fileList) {
      if (!fileList.length) return;
      const form = new FormData();
      form.append('path', cwd);
      form.append('overwrite', 'true');
      Array.from(fileList).forEach((file) => form.append('files', file, file.name));
      toast(`正在上传 ${fileList.length} 个文件…`, 'warn', 2000);
      try {
        const res = await api.upload('/api/files/upload', form);
        res.failed.length ? toast(`${res.message}：${res.failed.map((f) => f.name).join(', ')}`, 'warn') : toast(res.message);
        load(cwd);
      } catch (err) { toast(err.message, 'err'); }
    }

    async function doSearch() {
      const keyword = $('#file-search').value.trim();
      if (!keyword) { load(cwd); return; }
      try {
        const data = await api.get(`/api/files/search?path=${encodeURIComponent(cwd)}&q=${encodeURIComponent(keyword)}&limit=300`);
        $('#file-crumbs').innerHTML = `<span class="dim">搜索结果</span>`;
        $('#file-meta').textContent = `在 ${data.root} 下找到 ${data.matches.length} 项${data.truncated ? '（已截断）' : ''}`;
        entries = data.matches.map((m) => ({
          name: m.name, path: m.path, is_dir: m.is_dir, is_link: false,
          size: 0, mode: '', uid: '', gid: '', mtime: 0,
        }));
        renderTable();
      } catch (err) { toast(err.message, 'err'); }
    }

    root.onclick = async (event) => {
      const crumb = event.target.closest('[data-crumb]');
      if (crumb) { load(crumb.dataset.crumb); return; }
      const rootPath = event.target.closest('[data-root]');
      if (rootPath) { load(rootPath.dataset.root); return; }
      const target = event.target.closest('[data-act]');
      if (!target) return;
      const action = target.dataset.act;
      const entry = entries[Number(target.dataset.index)];
      if (target.tagName === 'A' && action === 'edit') event.preventDefault();

      if (action === 'up') load(cwd.replace(/\/[^/]+\/?$/, '') || '/');
      if (action === 'refresh') load(cwd);
      if (action === 'search') doSearch();
      if (action === 'open' && entry) load(entry.path);
      if (action === 'edit' && entry) openEditor(entry);
      if (action === 'mkdir') {
        const name = await promptDialog({ title: '新建文件夹', label: '文件夹名称', confirmText: '创建' });
        if (!name) return;
        try {
          const res = await api.post('/api/files/mkdir', { path: `${cwd.replace(/\/$/, '')}/${name}` });
          toast(res.message); load(cwd);
        } catch (err) { toast(err.message, 'err'); }
      }
      if (action === 'newfile') {
        const name = await promptDialog({ title: '新建文件', label: '文件名称', confirmText: '创建' });
        if (!name) return;
        try {
          const res = await api.post('/api/files/write', { path: `${cwd.replace(/\/$/, '')}/${name}`, content: '' });
          toast(res.message); load(cwd);
        } catch (err) { toast(err.message, 'err'); }
      }
      if (action === 'upload') $('#file-input').click();
      if (action === 'rename' && entry) {
        const name = await promptDialog({ title: '重命名 / 移动', label: '新的名称或绝对路径', value: entry.name, confirmText: '确定' });
        if (!name || name === entry.name) return;
        try {
          const res = await api.post('/api/files/rename', { path: entry.path, target: name });
          toast(res.message); load(cwd);
        } catch (err) { toast(err.message, 'err'); }
      }
      if (action === 'delete' && entry) {
        const ok = await confirmDialog({
          title: '删除确认', danger: true, confirmText: '删除',
          message: `确定要删除 <b class="mono">${esc(entry.path)}</b> 吗？${entry.is_dir ? '目录及其内容将<b>永久删除</b>。' : ''}`,
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/files/delete', { paths: [entry.path] });
          toast(res.message, res.ok ? 'ok' : 'warn'); load(cwd);
        } catch (err) { toast(err.message, 'err'); }
      }
    };

    const fileInput = $('#file-input');
    fileInput.onchange = async () => {
      await doUpload(fileInput.files);
      fileInput.value = '';
    };
    $('#file-search').addEventListener('keydown', (event) => {
      if (event.key === 'Enter') doSearch();
      if (event.key === 'Escape') { $('#file-search').value = ''; load(cwd); }
    });

    await load(cwd);
  },
});

/* ============================ 视图：Agent 接入 ============================ */

registerView('agent', {
  title: 'Agent 接入',
  async render(root) {
    let info = null;
    let revealed = false;
    let timer = null;
    let snippets = [];          // 由 /api/snippets 提供（服务端按当前地址渲染）
    let snippetQuery = '';

    const mask = (t) => (t ? `${t.slice(0, 6)}••••••${t.slice(-4)}` : '');

    async function loadSnippets() {
      // 令牌未「显示」时不带 reveal_token，服务端渲染为 YOUR_TOKEN 占位符
      const params = new URLSearchParams();
      if (revealed) params.set('reveal_token', '1');
      if (snippetQuery) params.set('q', snippetQuery);
      const query = params.toString();
      const data = await api.get(`/api/snippets${query ? `?${query}` : ''}`);
      snippets = data.snippets;
    }

    function snippetHTML() {
      if (!snippets.length) return '<div class="empty">没有匹配的片段</div>';
      const groups = [];
      snippets.forEach((s) => {
        let group = groups.find((g) => g.name === s.category);
        if (!group) { group = { name: s.category, items: [] }; groups.push(group); }
        group.items.push(s);
      });
      return groups.map((group) => `
        <div class="snippet-group">
          <h3 class="section-title">${esc(group.name)}</h3>
          <div class="snippet-list">${group.items.map((s) => `<div class="snippet">
            <div class="snippet-head">
              <span>${esc(s.title)}
                ${(s.requires || []).map((r) => `<span class="badge">依赖 ${esc(r)}</span>`).join('')}</span>
              <div class="spacer"></div>
              ${s.exec ? `<button class="btn sm ghost" data-run-snippet="${s.id}">运行</button>` : ''}
              <button class="btn sm ghost" data-copy-snippet="${s.id}">复制</button>
            </div>
            ${s.note ? `<div class="dim" style="font-size:11px;margin:2px 0 4px">${esc(s.note)}</div>` : ''}
            <pre class="snippet-body">${esc(s.code)}</pre>
          </div>`).join('')}</div>
        </div>`).join('');
    }

    function recentRows(records) {
      if (!records || !records.length) return '<div class="empty">暂无执行记录</div>';
      return `<div class="table-wrap"><table class="data"><thead><tr>
        <th>时间</th><th>来源</th><th>来源 IP</th><th>命令</th>
        <th class="num">退出码</th><th class="num">耗时</th></tr></thead>
        <tbody>${records.map((r) => `<tr>
          <td class="cell-sub">${datetime(r.time)}</td>
          <td>${r.kind === 'agent'
            ? '<span class="badge warn">Agent</span>'
            : '<span class="badge info">面板</span>'}</td>
          <td class="cell-sub">${esc(r.ip || '-')}</td>
          <td class="cell-main" title="${esc(r.command)}">${esc(S(r.command).slice(0, 80))}</td>
          <td class="num"><span class="badge ${r.code === 0 ? 'ok' : 'danger'}">${r.code}</span></td>
          <td class="num">${r.duration}s</td>
        </tr>`).join('')}</tbody></table></div>`;
    }

    async function loadRecent() {
      const box = $('#agt-recent');
      if (!box) return;
      try {
        const data = await api.get('/api/agent/info');
        info.recent = data.recent;
        box.innerHTML = recentRows(data.recent);
      } catch (err) {
        box.innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
      }
    }

    function paint() {
      const tokenShown = info.enabled ? (revealed ? info.token : mask(info.token)) : '';
      root.innerHTML = `
        <div class="grid c2">
          <div class="card">
            <h2>Agent 令牌</h2>
            <div class="row">
              <span class="badge ${info.enabled ? 'ok' : 'danger'}">${info.enabled ? '已启用' : '未生成'}</span>
              <span class="dim" style="font-size:12px">${info.token_updated_at ? `更新于 ${datetime(info.token_updated_at)}` : ''}</span>
            </div>
            <div class="token-box">
              <code id="agt-token">${info.enabled ? esc(tokenShown) : '尚未生成令牌'}</code>
            </div>
            <div class="row" style="margin-top:12px">
              <button class="btn sm ghost" data-act="reveal" ${info.enabled ? '' : 'disabled'}>显示 / 隐藏</button>
              <button class="btn sm ghost" data-act="copy" ${info.enabled ? '' : 'disabled'}>复制令牌</button>
              <div class="spacer"></div>
              <button class="btn sm primary" data-act="rotate">生成 / 轮换</button>
              <button class="btn sm danger" data-act="revoke" ${info.enabled ? '' : 'disabled'}>吊销</button>
            </div>
            <div class="dim" style="font-size:12px;margin-top:12px;line-height:1.7">
              令牌保存在服务器本机配置文件（权限 0600），<b>仅在【内网模式】下生效</b>；
              关闭内网模式后所有 Agent 请求立即被拒绝。也可在服务器执行
              <span class="mono">serverpanel --agent-token</span> 生成。
            </div>
          </div>

          <div class="card">
            <h2>接入方式</h2>
            <dl class="kv" style="grid-template-columns:96px 1fr">
              <dt>请求地址</dt><dd>POST ${esc(info.base_url)}${esc(info.endpoint)}</dd>
              <dt>鉴权头</dt><dd>X-Agent-Token: &lt;令牌&gt;</dd>
              <dt>兼容方式</dt><dd>Authorization: Bearer &lt;令牌&gt; 或 ?token=&lt;令牌&gt;</dd>
              <dt>请求体</dt><dd>{"command":"ls -al","cwd":"/opt","timeout":60}</dd>
              <dt>返回体</dt><dd>{"code":0,"stdout":"...","stderr":"..."}</dd>
              <dt>运行身份</dt><dd>${info.is_root ? '<span class="badge warn">root</span>' : '<span class="badge danger">非 root</span>'} · ${esc(info.shell)}</dd>
            </dl>
            <div class="dim" style="font-size:12px;margin-top:12px;line-height:1.7">
              一条请求执行一条命令，等价于在服务器上直接敲这条命令；执行记录会显示在下方。
            </div>
          </div>

          <div class="card" style="grid-column:1/-1">
            <h2>快速执行 <span class="spacer"></span><span class="dim" style="font-size:12px">以面板登录身份运行，用于自测</span></h2>
            <div class="row">
              <input class="input" id="agt-cmd" placeholder="例如：systemctl status nginx" style="flex:1;min-width:220px">
              <button class="btn sm primary" id="agt-run">执行</button>
            </div>
            <pre class="log-output" id="agt-out" style="margin-top:12px;max-height:260px">输出会显示在这里…</pre>
          </div>

          <div class="card" style="grid-column:1/-1">
            <h2>代码 / 命令片段库 <span class="spacer"></span>
              <input class="input" id="snp-search" placeholder="搜索片段…" style="width:170px"
                value="${esc(snippetQuery)}">
              <span class="dim" style="font-size:12px">占位符已按当前面板地址渲染</span></h2>
            <div id="agt-snippets">${snippetHTML()}</div>
          </div>

          <div class="card" style="grid-column:1/-1">
            <h2>最近执行记录 <span class="spacer"></span>
              <button class="btn sm ghost" data-act="refresh-recent">刷新</button></h2>
            <div id="agt-recent">${recentRows(info.recent)}</div>
          </div>
        </div>`;
    }

    async function refresh() {
      info = await api.get('/api/agent/info');
      if (!snippets.length) {
        await loadSnippets().catch(() => { snippets = []; });
      }
      paint();
    }

    let searchTimer = null;

    root.onclick = async (event) => {
      if (event.target.closest('#agt-run')) { await runCommand(); return; }
      const copyBtn = event.target.closest('[data-copy-snippet]');
      if (copyBtn) {
        const snippet = snippets.find((s) => s.id === copyBtn.dataset.copySnippet);
        if (snippet) copyText(snippet.code, '片段已复制');
        return;
      }
      const runBtn = event.target.closest('[data-run-snippet]');
      if (runBtn) {
        const snippet = snippets.find((s) => s.id === runBtn.dataset.runSnippet);
        if (snippet) await runSnippet(snippet);
        return;
      }
      const button = event.target.closest('[data-act]');
      if (!button) return;
      const action = button.dataset.act;

      if (action === 'reveal') {
        revealed = !revealed;
        $('#agt-token').textContent = revealed ? info.token : mask(info.token);
        try {
          await loadSnippets();               // 示例中的令牌同步显示/占位
          $('#agt-snippets').innerHTML = snippetHTML();
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      if (action === 'copy') {
        if (!info.token) { toast('尚未生成令牌', 'err'); return; }
        copyText(info.token, '令牌已复制');
        return;
      }
      if (action === 'rotate') {
        const ok = await confirmDialog({
          title: '生成 / 轮换 Agent 令牌', confirmText: '生成',
          message: '生成新令牌后，<b>旧令牌会立即失效</b>，正在使用旧令牌的脚本或 Agent 需要更新。确定继续吗？',
        });
        if (!ok) return;
        try {
          await api.post('/api/agent/token', { token: '' });
          revealed = true;
          await refresh();
          toast('新令牌已生成');
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      if (action === 'revoke') {
        const ok = await confirmDialog({
          title: '吊销 Agent 令牌', danger: true, confirmText: '吊销',
          message: '吊销后所有使用该令牌的脚本与 Agent 将立即失去访问权限。确定继续吗？',
        });
        if (!ok) return;
        try {
          await api.del('/api/agent/token');
          revealed = false;
          await refresh();
          toast('令牌已吊销');
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      if (action === 'refresh-recent') { await loadRecent(); toast('记录已刷新'); }
    };

    async function execInto(display, command, timeout = 60) {
      const out = $('#agt-out');
      if (out) out.textContent = `$ ${display} 执行中…`;
      try {
        const res = await api.post('/api/terminal/exec', { command, timeout });
        const text = [res.stdout, res.stderr].filter((part) => part && part.trim()).join('\n');
        if (out) out.textContent = `$ ${display}\n${text || '(无输出)'}\n[退出码 ${res.code}]`;
        await loadRecent();
      } catch (err) {
        if (out) out.textContent = `执行失败：${err.message}`;
      }
    }

    /** 一键运行片段：只对标记 exec 的非破坏性 bash 片段开放，且需二次确认。 */
    async function runSnippet(snippet) {
      const ok = await confirmDialog({
        title: `运行片段 · ${snippet.title}`, confirmText: '执行',
        message: `将在服务器上以面板身份执行该片段：<pre class="snippet-body" style="max-height:180px">${esc(snippet.code)}</pre>`,
      });
      if (!ok) return;
      await execInto(snippet.title, snippet.code, 120);
    }

    async function runCommand() {
      const command = $('#agt-cmd').value.trim();
      if (!command) { toast('请输入要执行的命令', 'err'); return; }
      await execInto(command, command, 60);
    }

    root.onkeydown = (event) => {
      if (event.target.id === 'agt-cmd' && event.key === 'Enter') runCommand();
    };
    root.oninput = (event) => {
      if (event.target.id !== 'snp-search') return;
      clearTimeout(searchTimer);
      searchTimer = setTimeout(async () => {
        snippetQuery = event.target.value.trim();
        try {
          await loadSnippets();
          $('#agt-snippets').innerHTML = snippetHTML();
        } catch (err) { toast(err.message, 'err'); }
      }, 220);
    };

    await refresh();
    timer = setInterval(loadRecent, 8000);
    return () => { clearInterval(timer); clearTimeout(searchTimer); };
  },
});

/* ============================ 视图：常驻应用 / 常用操作 ============================ */
// 「常驻应用」解决"跑起来就不该死"：命令交给面板托管，脱离浏览器会话长期运行、
// 崩溃按策略自动拉起、输出落盘可随时回看。
// 「常用操作」把经常要敲的一长串命令做成一张卡片，一次点击拿结果。
// 两个能力共用同一页（tab 切换）：都是"让服务器替我把事做完"。

function formDialog({ title, fields, confirmText = '确定', note = '' }) {
  return new Promise((resolve) => {
    const body = document.createElement('div');
    body.innerHTML = `${fields.map((f) => `<label class="field"><span>${esc(f.label)}</span>
      <input class="input" data-field="${esc(f.name)}" value="${esc(f.value ?? '')}"
        placeholder="${esc(f.placeholder || '')}" autocomplete="off"></label>`).join('')}
      ${note ? `<div class="dim" style="font-size:12px;line-height:1.7">${note}</div>` : ''}`;
    const foot = document.createElement('div');
    foot.className = 'row';
    foot.innerHTML = `<button class="btn" data-cancel>取消</button>
      <button class="btn primary" data-ok>${esc(confirmText)}</button>`;
    const modal = openModal({ title, body, footer: foot, size: 'narrow' });
    const inputs = $$('[data-field]', modal.body);
    setTimeout(() => inputs[0]?.focus(), 30);
    const finish = (value) => { modal.close(); resolve(value); };
    const collect = () => {
      const out = {};
      inputs.forEach((input) => { out[input.dataset.field] = input.value.trim(); });
      return out;
    };
    $('[data-cancel]', foot).onclick = () => finish(null);
    $('[data-ok]', foot).onclick = () => finish(collect());
    inputs.forEach((input) => input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') finish(collect());
    }));
  });
}

registerView('apps', {
  title: '常驻应用',
  async render(root) {
    let tab = localStorage.getItem('sp-apps-tab') === 'tasks' ? 'tasks' : 'apps';
    let data = { apps: [], self: {}, audit: [] };
    let tasks = { tasks: [], recent: [] };
    let timer = null;
    let logState = null;   // { id, name, offset, follow }
    let lastRun = null;

    const STATUS = {
      running: ['ok', '运行中'], starting: ['warn', '启动中'], restarting: ['warn', '重启中'],
      failed: ['danger', '已失败'], stopped: ['', '未运行'],
    };

    function statusBadge(runtime) {
      const [cls, label] = STATUS[runtime.status] || ['', runtime.status];
      return `<span class="badge ${cls}">${esc(label)}</span>`;
    }

    function appCard(app) {
      const r = app.runtime || {};
      const metas = [
        r.pid ? `PID ${r.pid}` : null,
        r.uptime ? `已运行 ${duration(r.uptime)}` : null,
        r.pid && r.memory_rss ? `内存 ${bytes(r.memory_rss)}` : null,
        r.restart_count ? `重启 ${r.restart_count} 次` : null,
        r.last_code !== null && r.last_code !== undefined && !r.pid ? `上次退出码 ${r.last_code}` : null,
        app.autostart ? '开机自启' : null,
      ].filter(Boolean).map((m) => `<span class="badge">${esc(m)}</span>`).join('');
      return `<div class="card app-card" data-card="${app.id}">
        <div class="app-head">
          <div>
            <div class="app-name">${esc(app.name)} ${statusBadge(r)}
              <span class="badge">${esc(app.restart)}</span></div>
            <div class="dim" style="font-size:12px;margin-top:4px">
              ${esc(app.description || '无描述')}</div>
          </div>
          <div class="spacer"></div>
          <div class="row" style="gap:6px">
            <button class="btn sm ghost" data-app="logs" data-id="${app.id}">日志</button>
            <button class="btn sm ghost" data-app="probe" data-id="${app.id}">试运行</button>
            ${r.status === 'running' || r.status === 'starting' || r.status === 'restarting'
              ? `<button class="btn sm" data-app="stop" data-id="${app.id}">停止</button>
                 <button class="btn sm" data-app="restart" data-id="${app.id}">重启</button>`
              : `<button class="btn sm primary" data-app="start" data-id="${app.id}">启动</button>`}
            <button class="btn sm ghost" data-app="edit" data-id="${app.id}">编辑</button>
            <button class="btn sm danger" data-app="delete" data-id="${app.id}">删除</button>
          </div>
        </div>
        <div class="row" style="margin-top:10px">${metas || '<span class="dim" style="font-size:12px">尚未运行过</span>'}</div>
        <div class="app-cmd mono" title="${esc(app.command)}">$ ${esc(app.command)}</div>
        <div class="dim mono" style="font-size:11px">工作目录 ${esc(app.cwd || '-')}</div>
      </div>`;
    }

    function auditRows(records) {
      if (!records || !records.length) return '<div class="empty">暂无操作记录</div>';
      return `<div class="table-wrap"><table class="data"><thead><tr>
        <th>时间</th><th>操作</th><th>应用</th><th>详情</th></tr></thead>
        <tbody>${records.slice(0, 12).map((r) => `<tr>
          <td class="cell-sub">${datetime(r.time)}</td>
          <td><span class="badge info">${esc(r.action)}</span></td>
          <td class="cell-main">${esc(r.app || '-')}</td>
          <td class="cell-sub" title="${esc(r.detail || '')}">${esc((r.detail || '').slice(0, 70))}</td>
        </tr>`).join('')}</tbody></table></div>`;
    }

    function tasksTab() {
      const groups = [];
      tasks.tasks.forEach((task) => {
        let group = groups.find((g) => g.name === task.group);
        if (!group) { group = { name: task.group, items: [] }; groups.push(group); }
        group.items.push(task);
      });
      const caps = live.capabilities || {};
      const runFor = (task) => {
        const finished = tasks.recent.find((r) => r.task_id === task.id);
        if (finished) {
          return `<div class="dim" style="font-size:11px">上次 ${datetime(finished.time)} ·
            ${finished.duration}s · 退出码 ${finished.code}</div>`;
        }
        return '';
      };
      return `
        <div class="card" style="margin-bottom:14px">
          <div class="row">
            <span class="badge info">${tasks.tasks.length} 个内置任务</span>
            <span class="dim" style="font-size:12px">
              常用命令已预先写好，点击即执行；带参数的会先弹出输入框。</span>
            <div class="spacer"></div>
            <button class="btn sm ghost" data-act="tasks-refresh">刷新</button>
            <button class="btn sm ghost" data-act="recent-clear">清空记录</button>
          </div>
        </div>
        ${groups.map((group) => `
          <h2 class="section-title">${esc(group.name)}</h2>
          <div class="task-grid">
            ${group.items.map((task) => {
              const missing = (task.requires || []).filter((dep) => caps[dep] === false);
              const disabled = missing.length ? 'disabled' : '';
              return `<div class="card task-card ${disabled ? 'disabled' : ''}">
                <div class="row">
                  <b>${esc(task.title)}</b>
                  ${task.danger ? '<span class="badge danger">危险</span>' : ''}
                  ${missing.length ? `<span class="badge danger">缺 ${esc(missing.join('/'))}</span>` : ''}
                </div>
                <div class="dim" style="font-size:12px;min-height:32px;margin:6px 0">
                  ${esc(task.description || task.group)}</div>
                ${runFor(task)}
                <div class="row" style="margin-top:8px">
                  <button class="btn sm ${task.danger ? 'danger' : 'primary'}"
                    data-task="${task.id}" ${disabled}>${task.params.length ? '填参数并运行' : '运行'}</button>
                </div>
              </div>`;
            }).join('')}
          </div>`).join('')}
        <div class="card" style="margin-top:14px">
          <h2>本次会话输出</h2>
          <pre class="log-output" id="task-out" style="max-height:320px">${lastRun
            ? esc(`$ ${lastRun.command}\n${lastRun.text || '(无输出)'}\n[退出码 ${lastRun.code} · ${lastRun.duration}s]`)
            : '运行任务后，输出会显示在这里…'}</pre>
        </div>
        <div class="card" style="margin-top:14px">
          <h2>最近执行记录</h2>
          ${auditRows((tasks.recent || []).map((r) => ({
            time: r.time, action: r.code === 0 ? 'ok' : `exit ${r.code}`,
            app: r.title, detail: r.command,
          })))}
        </div>`;
    }

    function appsTab() {
      const self = data.self || {};
      return `
        <div class="card" style="margin-bottom:14px">
          <div class="row">
            <span class="badge info">${data.apps.length} 个常驻应用</span>
            ${self.systemd ? '<span class="badge">systemd 环境</span>'
              : '<span class="badge warn">无 systemd，由面板守护</span>'}
            <span class="dim" style="font-size:12px">
              托管进程独立成会话：关掉浏览器、断开终端都不会中断；进程崩溃按策略自动拉起。</span>
            <div class="spacer"></div>
            <button class="btn sm ghost" data-act="apps-refresh">刷新</button>
            <button class="btn sm primary" data-act="apps-new">添加常驻应用</button>
          </div>
          <div class="dim mono" style="font-size:11px;margin-top:8px">
            注册表 ${esc(self.registry || '-')} · 日志目录 ${esc(self.log_dir || '-')}</div>
        </div>
        ${data.apps.length ? data.apps.map(appCard).join('')
          : `<div class="card"><div class="empty">
              还没有常驻应用。点右上角「添加常驻应用」，把一条需要长期运行的命令交给面板托管。<br><br>
              典型用途：内网穿透客户端、定时爬虫、个人服务、uvicorn / frpc / syncthing 等。</div></div>`}
        <div class="card" style="margin-top:14px">
          <h2>最近操作</h2>
          ${auditRows(data.audit)}
        </div>`;
    }

    function paint() {
      root.innerHTML = `
        <div class="tabs-head">
          <button class="tab-btn ${tab === 'apps' ? 'active' : ''}" data-tab-btn="apps">常驻应用</button>
          <button class="tab-btn ${tab === 'tasks' ? 'active' : ''}" data-tab-btn="tasks">常用操作</button>
        </div>
        <div id="apps-panel">${tab === 'apps' ? appsTab() : tasksTab()}</div>`;
      paintLogPanel();
    }

    function paintLogPanel() {
      const existing = $('#app-log-drawer');
      if (existing) existing.remove();
      if (!logState) return;
      const drawer = document.createElement('div');
      drawer.id = 'app-log-drawer';
      drawer.className = 'log-drawer';
      drawer.innerHTML = `
        <div class="log-drawer-head">
          <b>${esc(logState.name)} · 运行日志</b>
          <div class="spacer"></div>
          <label class="row" style="font-size:12px;gap:6px">
            <input type="checkbox" id="log-follow" ${logState.follow ? 'checked' : ''}> 跟随</label>
          <button class="btn sm ghost" data-log="refresh">刷新</button>
          <button class="btn sm ghost" data-log="clear">清空日志</button>
          <button class="btn sm" data-log="close">关闭</button>
        </div>
        <pre class="log-output" id="app-log-body">加载中…</pre>`;
      root.appendChild(drawer);
      $('#log-follow', drawer).onchange = (event) => { logState.follow = event.target.checked; };
      drawer.onclick = (event) => {
        const action = event.target.dataset?.log;
        if (action === 'close') { logState = null; paintLogPanel(); return; }
        if (action === 'refresh') { loadLog(true); return; }
        if (action === 'clear') { clearLog(); }
      };
    }

    async function loadLog(manual = false) {
      if (!logState) return;
      try {
        const url = `/api/panel/apps/${logState.id}/logs?offset=${logState.offset}`;
        const res = await api.get(url);
        const body = $('#app-log-body');
        if (!body) return;
        if (logState.offset === 0 || res.offset !== logState.offset) {
          body.textContent = res.content || '（暂无输出）';
        } else if (res.content) {
          body.textContent += res.content;
        }
        logState.offset = res.next_offset;
        if (logState.follow && body.scrollHeight - body.scrollTop - body.clientHeight < 60) {
          body.scrollTop = body.scrollHeight;
        }
        if (manual) toast('日志已刷新');
      } catch (err) {
        const body = $('#app-log-body');
        if (body) body.textContent = `读取失败：${err.message}`;
      }
    }

    async function clearLog() {
      if (!logState) return;
      const ok = await confirmDialog({
        title: '清空日志', danger: true, confirmText: '清空',
        message: `确定清空 <b class="mono">${esc(logState.name)}</b> 的运行日志吗？
          已写入磁盘的日志文件会被截断，历史输出不可恢复。`,
      });
      if (!ok) return;
      try {
        await api.del(`/api/panel/apps/${logState.id}/logs`);
        logState.offset = 0;
        $('#app-log-body').textContent = '（日志已清空，新输出会继续显示在这里）';
        toast('日志已清空');
      } catch (err) { toast(err.message, 'err'); }
    }

    function appFields(app) {
      const a = app || {};
      return [
        { name: 'name', label: '名称（字母数字._-，1~48 位）', value: a.name || '', placeholder: 'frpc' },
        { name: 'command', label: '启动命令', value: a.command || '', placeholder: '/opt/frp/frpc -c /opt/frp/frpc.toml' },
        { name: 'cwd', label: '工作目录（必须存在）', value: a.cwd || '', placeholder: '/opt/frp' },
        { name: 'description', label: '描述（可选）', value: a.description || '', placeholder: '内网穿透客户端' },
        { name: 'restart', label: '重启策略：never / on-failure / always', value: a.restart || 'on-failure' },
        { name: 'max_restarts', label: '5 分钟内最多重启次数', value: S(a.max_restarts ?? 5) },
        { name: 'restart_delay', label: '重启间隔（秒，0.5~300）', value: S(a.restart_delay ?? 2) },
        { name: 'autostart', label: '开机自启：yes / no', value: a.autostart ? 'yes' : 'no' },
      ];
    }

    function toPayload(values) {
      const autostart = ['yes', 'y', 'true', '1', '是'].includes(S(values.autostart).toLowerCase());
      return {
        name: values.name, command: values.command, cwd: values.cwd || '',
        description: values.description || '', restart: values.restart || 'on-failure',
        max_restarts: Number(values.max_restarts || 5),
        restart_delay: Number(values.restart_delay || 2),
        autostart,
      };
    }

    async function editApp(app) {
      const values = await formDialog({
        title: app ? `编辑 · ${app.name}` : '添加常驻应用',
        fields: appFields(app),
        confirmText: app ? '保存' : '注册',
        note: app ? '运行中的改动需重启应用后生效。' : '注册后不会自动启动，建议先「试运行」确认配置。',
      });
      if (!values) return;
      const payload = toPayload(values);
      try {
        if (app) {
          await api.put(`/api/panel/apps/${app.id}`, payload);
          toast('配置已保存');
        } else {
          const res = await api.post('/api/panel/apps', payload);
          toast(res.message);
        }
        await loadApps();
        paint();
      } catch (err) { toast(err.message, 'err'); }
    }

    async function probeApp(app) {
      const box = document.createElement('div');
      box.innerHTML = '<div class="empty">试运行中…（观察 6 秒内的输出）</div>';
      const modal = openModal({ title: `试运行 · ${app.name}`, body: box, size: 'wide' });
      try {
        const res = await api.post(`/api/panel/apps/${app.id}/probe`, { seconds: 6 });
        box.innerHTML = `<div class="row" style="margin-bottom:10px">
            <span class="badge ${res.survived ? 'ok' : 'warn'}">${esc(res.message)}</span>
            ${res.code === null ? '' : `<span class="badge">退出码 ${res.code}</span>`}</div>
          <pre class="log-output" style="max-height:320px">${esc(res.output || '(无输出)')}</pre>`;
      } catch (err) {
        box.innerHTML = `<div class="empty">试运行失败：${esc(err.message)}</div>`;
      }
      return modal;
    }

    function openLogs(app) {
      logState = { id: app.id, name: app.name, offset: 0, follow: true };
      paintLogPanel();
      loadLog();
    }

    async function loadApps() {
      data = await api.get('/api/panel/apps');
    }

    async function loadTasks() {
      tasks = await api.get('/api/panel/tasks');
    }

    async function refresh() {
      try {
        if (tab === 'apps') await loadApps(); else await loadTasks();
      } catch (err) {
        $('#apps-panel').innerHTML = `<div class="card"><div class="empty">读取失败：${esc(err.message)}</div></div>`;
        return;
      }
      paint();
      if (logState) loadLog();
    }

    async function runTask(task) {
      let values = {};
      if (task.params.length) {
        const input = await formDialog({
          title: `运行 · ${task.title}`,
          fields: task.params.map((p) => ({
            name: p.name, label: p.label, value: p.default, placeholder: p.placeholder,
          })),
          confirmText: '运行',
        });
        if (!input) return;
        values = input;
      }
      if (task.danger) {
        const ok = await confirmDialog({
          title: `危险操作 · ${task.title}`, danger: true, confirmText: '确认执行',
          message: `该任务会修改系统状态，请确认：<b>${esc(task.title)}</b><br>
            <span class="dim">${esc(task.description || '')}</span>`,
        });
        if (!ok) return;
      }
      const out = $('#task-out');
      if (out) out.textContent = `$ ${task.title} 执行中…`;
      try {
        const res = await api.post(`/api/panel/tasks/${task.id}/run`, { params: values });
        const text = [res.stdout, res.stderr].filter((p) => p && p.trim()).join('\n');
        lastRun = { command: res.command, text, code: res.code, duration: res.duration };
        if (out) {
          out.textContent = `$ ${res.command}\n\n${text || '(无输出)'}\n\n[退出码 ${res.code} · 耗时 ${res.duration}s]`;
        }
        await loadTasks();
        toast(res.code === 0 ? '执行完成' : `执行结束（退出码 ${res.code}）`, res.code === 0 ? 'ok' : 'err');
      } catch (err) {
        if (out) out.textContent = `执行失败：${err.message}`;
        toast(err.message, 'err');
      }
    }

    root.onclick = async (event) => {
      const tabBtn = event.target.closest('[data-tab-btn]');
      if (tabBtn) {
        tab = tabBtn.dataset.tabBtn;
        localStorage.setItem('sp-apps-tab', tab);
        // 切 tab 时重新拉一次数据再重绘，避免展示上一次进入时的陈旧状态
        try {
          if (tab === 'apps') await loadApps(); else await loadTasks();
        } catch (err) { toast(err.message, 'err'); }
        paint();
        return;
      }
      const act = event.target.dataset?.act;
      if (act === 'apps-refresh') { await refresh(); toast('已刷新'); return; }
      if (act === 'apps-new') { await editApp(null); return; }
      if (act === 'tasks-refresh') { await refresh(); toast('已刷新'); return; }
      if (act === 'recent-clear') {
        try { await api.del('/api/panel/tasks/recent'); await refresh(); toast('记录已清空'); }
        catch (err) { toast(err.message, 'err'); }
        return;
      }
      const taskBtn = event.target.closest('[data-task]');
      if (taskBtn) {
        const task = tasks.tasks.find((t) => t.id === taskBtn.dataset.task);
        if (task) await runTask(task);
        return;
      }
      const appBtn = event.target.closest('[data-app]');
      if (!appBtn) return;
      const app = data.apps.find((a) => a.id === appBtn.dataset.id);
      if (!app) return;
      const action = appBtn.dataset.app;
      try {
        if (action === 'start' || action === 'stop' || action === 'restart') {
          const labels = { start: '启动', stop: '停止', restart: '重启' };
          if (action !== 'start') {
            const ok = await confirmDialog({
              title: `${labels[action]} · ${app.name}`, danger: action === 'stop', confirmText: labels[action],
              message: action === 'stop'
                ? `停止后该应用会退出，直到你再次启动（已开启自启的会在面板下次启动时拉起）。`
                : `重启会先结束当前进程，再按同样的配置重新拉起。`,
            });
            if (!ok) return;
          }
          const res = await api.post(`/api/panel/apps/${app.id}/${action}`, {});
          toast(res.message);
          await refresh();
        } else if (action === 'probe') {
          await probeApp(app);
        } else if (action === 'logs') {
          openLogs(app);
        } else if (action === 'edit') {
          await editApp(app);
        } else if (action === 'delete') {
          const values = await formDialog({
            title: `删除 · ${app.name}`,
            fields: [{ name: 'confirm', label: `输入应用名 ${app.name} 以确认删除`, value: '' }],
            confirmText: '删除',
            note: '仅删除托管配置与日志，不会删除应用自身的文件。',
          });
          if (!values) return;
          if (values.confirm !== app.name) { toast('名称不匹配，已取消', 'err'); return; }
          const res = await api.del(`/api/panel/apps/${app.id}`);
          if (logState && logState.id === app.id) { logState = null; }
          toast(res.message);
          await refresh();
        }
      } catch (err) {
        toast(err.message, 'err');
      }
    };

    try {
      await Promise.all([loadApps(), loadTasks()]);
    } catch (err) {
      root.innerHTML = `<div class="card"><div class="empty">读取失败：${esc(err.message)}</div></div>`;
      return null;
    }
    paint();
    timer = setInterval(() => { if (!logState) refresh().catch(() => {}); else loadLog(); }, 3000);
    return () => { clearInterval(timer); };
  },
});

/* ============================ 视图：设置 ============================ */

registerView('settings', {
  title: '设置',
  async render(root) {
    const caps = live.capabilities || {};
    const info = await api.get('/api/system/info').catch(() => ({}));
    const hz = await fetch('/healthz').then((r) => r.json()).catch(() => null);
    root.innerHTML = `
      <div class="grid c2">
        <div class="card">
          <h2>修改面板密码</h2>
          <form id="pwd-form" style="display:flex;flex-direction:column;gap:12px;max-width:360px">
            <label class="field"><span>当前密码</span>
              <input class="input" type="password" id="pwd-current" autocomplete="current-password" required></label>
            <label class="field"><span>新密码（至少 8 位）</span>
              <input class="input" type="password" id="pwd-new" autocomplete="new-password" required></label>
            <label class="field"><span>确认新密码</span>
              <input class="input" type="password" id="pwd-confirm" autocomplete="new-password" required></label>
            <button class="btn primary" type="submit">更新密码</button>
          </form>
          <div class="dim" style="font-size:12px;margin-top:12px">
            修改成功后，其他已登录设备会被强制退出。忘记密码时可在服务器执行
            <span class="mono">serverpanel --set-password 新密码</span>。
          </div>
        </div>

        <div class="card">
          <h2>运行环境</h2>
          <dl class="kv">
            <dt>主机名</dt><dd>${esc(info.hostname || '-')}</dd>
            <dt>系统</dt><dd>${esc(info.distro || '-')}</dd>
            <dt>内核</dt><dd>${esc(info.kernel || '-')}</dd>
            <dt>面板身份</dt><dd>${info.is_root ? '<span class="badge warn">root（完整权限）</span>' : '<span class="badge danger">非 root（部分功能受限）</span>'}</dd>
            <dt>Python</dt><dd>${esc(info.python || '-')}</dd>
          </dl>
          <h2 style="margin-top:18px">系统能力探测</h2>
          <div class="row">
            <span class="badge ${caps.systemd ? 'ok' : 'danger'}">systemd 服务 ${caps.systemd ? '可用' : '不可用'}</span>
            <span class="badge ${caps.dmesg ? 'ok' : 'danger'}">dmesg ${caps.dmesg ? '可用' : '不可用'}</span>
            <span class="badge ${caps.lsblk ? 'ok' : 'danger'}">lsblk ${caps.lsblk ? '可用' : '不可用'}</span>
            <span class="badge ${caps.du ? 'ok' : 'danger'}">du ${caps.du ? '可用' : '不可用'}</span>
            <span class="badge ${caps.smartctl ? 'ok' : ''}">smartctl ${caps.smartctl ? '可用' : '未安装'}</span>
          </div>
        </div>

        <div class="card">
          <h2>面板升级</h2>
          <dl class="kv">
            <dt>当前版本</dt><dd id="upd-version">${esc(hz?.version || '-')}</dd>
            <dt>部署标记</dt><dd class="mono">${esc(hz?.build || '未知')}</dd>
          </dl>
          <div class="row" style="margin-top:12px">
            <button class="btn primary" id="btn-self-update" ${isInternal() ? '' : 'disabled'}>一键升级（git 拉取最新代码）</button>
            <span class="dim" style="font-size:12px">${isInternal() ? '' : '仅内网模式可用'}</span>
          </div>
          <div class="dim" style="font-size:12px;margin-top:12px">
            升级在后台执行：自动备份配置 → 拉取 → 装依赖 → 重启 → 健康检查，<b>失败自动回滚</b>。
            过程约 1 分钟，期间登录态保持、指标曲线中断一拍，正在打开的网页终端会断开并自动重连。
            详情见 <span class="mono">panel.log</span>。
          </div>
        </div>

        <div class="card">
          <h2>安全说明</h2>
          <ul style="line-height:1.9;padding-left:18px;margin:0;font-size:13px">
            <li>密码使用 PBKDF2-HMAC-SHA256（26 万次迭代 + 随机盐）存储在本地配置文件，权限 0600。</li>
            <li>登录会话默认 12 小时，写入 HttpOnly Cookie，并落盘保存——服务重启后面板登录态保持。</li>
            <li>连续 5 次密码错误后，该来源 IP 会被锁定 60 秒。</li>
            <li>默认处于<b>公网模式</b>：即使登录成功，也只开放只读监控，终端与写操作全部锁定。</li>
            <li>只有 <b>内网模式</b>才能获得完整控制权；它必须登录服务器本机执行命令才能激活。</li>
            <li>面板默认监听 0.0.0.0，<b>请只在可信局域网内使用</b>，不要直接暴露到公网。</li>
            <li>建议用防火墙限制访问来源，例如：<span class="mono">ufw allow from 192.168.1.0/24 to any port 8787</span></li>
          </ul>
        </div>

        <div class="card">
          <h2>运行模式 <span class="spacer"></span>
            <button class="badge mode-badge ${isInternal() ? 'internal' : 'public'}" data-act="mode-help">
              ${isInternal() ? '内网模式 · 完全控制' : '公网模式 · 只读'}</button></h2>
          <div style="font-size:13px;line-height:1.9">
            ${isInternal()
              ? '当前已解锁全部功能。关闭后已打开的终端会被立即终止，敏感操作随即锁定。'
              : '当前仅开放只读监控。激活内网模式后可解锁网页终端、文件管理与电源控制。'}
          </div>
          <div class="log-output" style="padding:12px;margin-top:12px;white-space:pre">serverpanel --enable-internal    # 激活内网模式
serverpanel --disable-internal   # 关闭内网模式
serverpanel --show-mode          # 查看当前模式</div>
          <div class="dim" style="font-size:12px;margin-top:10px">
            模式只能在服务器本机通过命令切换，面板界面不提供切换入口。
          </div>
        </div>

        <div class="card">
          <h2>快捷操作</h2>
          <div class="row">
            ${isInternal() ? '<button class="btn" data-act="terminal">打开终端</button>' : ''}
            ${isInternal() ? `<button class="btn danger" data-act="reboot">重启系统</button>
            <button class="btn danger" data-act="shutdown">关机</button>` : ''}
            <button class="btn ghost" data-act="logout">退出登录</button>
          </div>
          <div class="dim" style="font-size:12px;margin-top:14px">
            重启与关机需要输入确认词，且仅在主机以 systemd 启动时可用。
          </div>
        </div>
      </div>`;

    $('#pwd-form').onsubmit = async (event) => {
      event.preventDefault();
      const current = $('#pwd-current').value;
      const next = $('#pwd-new').value;
      if (next !== $('#pwd-confirm').value) { toast('两次输入的新密码不一致', 'err'); return; }
      try {
        const res = await api.post('/api/auth/password', { current, new: next });
        toast(res.message);
        $('#pwd-form').reset();
      } catch (err) { toast(err.message, 'err'); }
    };

    $('#btn-self-update').onclick = async () => {
      const before = hz?.build || hz?.version || '';
      const ok = await confirmDialog({
        title: '面板一键升级', confirmText: '开始升级',
        message: '将拉取远端最新代码并重启面板。失败会自动回滚到当前版本，确定继续吗？',
      });
      if (!ok) return;
      const btn = $('#btn-self-update');
      btn.disabled = true;
      btn.textContent = '升级中…';
      try {
        await api.post('/api/system/self-update', {});
      } catch (err) { toast(err.message, 'err'); btn.disabled = false; btn.textContent = '一键升级（git 拉取最新代码）'; return; }
      toast('升级已在后台启动，等待面板重启…');
      const deadline = Date.now() + 180000;
      const timer = setInterval(async () => {
        let done = false;
        try {
          const v = await fetch('/healthz').then((r) => r.json());
          if ((v.build || v.version) && (v.build || v.version) !== before) {
            clearInterval(timer);
            toast(`升级完成：${v.version}（${v.build || ''}）`, 'ok');
            setTimeout(() => location.reload(), 1200);
            done = true;
          }
        } catch (err) { /* 重启间隙，继续等 */ }
        if (done) return;
        if (Date.now() > deadline) {
          clearInterval(timer);
          toast('升级未在预期时间内完成，请通过终端查看 panel.log', 'err');
          btn.disabled = false;
          btn.textContent = '一键升级（git 拉取最新代码）';
        }
      }, 3000);
    };

    root.onclick = async (event) => {
      const action = event.target.dataset?.act || event.target.closest('[data-act]')?.dataset.act;
      if (!action) return;
      if (action === 'mode-help') { showModeHelp(); return; }
      if (action === 'terminal') navigate('terminal');
      if (action === 'logout') { await api.post('/api/auth/logout', {}); location.reload(); }
      if (action === 'reboot' || action === 'shutdown') {
        const label = action === 'reboot' ? '重启' : '关机';
        const ok = await confirmDialog({
          title: `${label}系统`, danger: true, confirmText: label,
          message: `确定要${label}主机 <b>${esc(info.hostname || '')}</b> 吗？`,
          phrase: action.toUpperCase(),
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/system/power', { action, confirm: 'CONFIRM' });
          toast(res.message, 'warn');
        } catch (err) { toast(err.message, 'err'); }
      }
    };
  },
});

boot();
