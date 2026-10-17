/* ServerPanel 前端主程序 —— 无构建依赖的原生实现 */
'use strict';

/* ============================ 基础工具 ============================ */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const S = String;

/* ============================ i18n ============================ */
// 框架 + 基础覆盖（2.0 M4）：导航、视图标题与常见按钮走字典，业务文案按需
// 逐步补——未命中的键一律回退中文，界面不会出现空字符串或 key 本身。
const I18N = {
  locale: 'zh-CN',
  dict: {},

  async load(locale) {
    const wanted = locale === 'en-US' ? 'en-US' : 'zh-CN';
    try {
      const res = await fetch(`/static/i18n/${wanted}.json`, { credentials: 'same-origin' });
      if (!res.ok) throw new Error(String(res.status));
      this.dict = await res.json();
      this.locale = wanted;
    } catch (err) {
      this.dict = {};
      this.locale = 'zh-CN';
    }
    try { localStorage.setItem('sp-locale', this.locale); } catch (err) { /* 隐私模式忽略 */ }
    return this.locale;
  },

  t(key, fallback = '') {
    const hit = S(key).split('.').reduce(
      (node, part) => (node && typeof node === 'object' && part in node ? node[part] : undefined),
      this.dict,
    );
    return S(hit === undefined || hit === null || hit === '' ? (fallback || key) : hit);
  },

  /** 把 data-i18n / data-i18n-placeholder 应用到静态 DOM（只翻译，不重绘）。 */
  apply(root = document) {
    $$('[data-i18n]', root).forEach((el) => {
      el.textContent = this.t(el.dataset.i18n, el.textContent);
    });
    $$('[data-i18n-placeholder]', root).forEach((el) => {
      el.placeholder = this.t(el.dataset.i18nPlaceholder, el.placeholder);
    });
  },
};

// 当前登录账号（2.0 M4）：单密码模式下角色恒为 admin、用户名恒为 admin，
// 因此下面这些判断在兼容模式下永远等价于"全部允许"。
let authUser = { username: 'admin', role: 'admin', multiUser: false };
const isAdmin = () => authUser.role === 'admin';
const canOperate = () => authUser.role === 'admin' || authUser.role === 'operator';

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
  node.setAttribute('role', type === 'err' ? 'alert' : 'status');  // 错误即时播报给读屏
  node.innerHTML = esc(message);
  $('#toast-wrap').appendChild(node);
  setTimeout(() => {
    node.style.opacity = '0';
    node.style.transition = 'opacity .3s';
    setTimeout(() => node.remove(), 320);
  }, timeout);
}

let modalStack = [];

function openModal({ title, body, footer, size = '', onEscape = null, onClose = null }) {
  const root = $('#modal-root');
  const overlay = document.createElement('div');
  overlay.className = 'modal';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
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
  let closed = false;
  const handle = {
    overlay, body: bodyEl, foot: $('.modal-foot', overlay),
    // ESC 语义由调用方定：对话框走「取消」（resolve 出值），普通弹窗直接关闭
    escape: onEscape || (() => handle.close()),
    close() {
      if (closed) return;
      closed = true;
      overlay.remove();
      modalStack = modalStack.filter((m) => m !== handle);
      // 任何关闭路径（✕ / 遮罩 / Esc / 主动调用）都要回收资源：
      // 回放定时器、上传轮询等曾只在某个路径清理，导致对话框关了还在跑
      if (onClose) {
        try { onClose(); } catch (err) { /* 关闭回调不允许影响关闭本身 */ }
      }
    },
  };
  modalStack.push(handle);
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay || event.target.hasAttribute('data-close')) handle.close();
  });
  return handle;
}

// ESC 关闭最上层弹窗：键盘用户不必 Tab 去找 ✕
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && modalStack.length) {
    event.preventDefault();
    modalStack[modalStack.length - 1].escape();
  }
});

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
    const finish = (value) => { modal.close(); resolve(value); };
    const modal = openModal({ title, body, footer: foot, size: 'narrow', onEscape: () => finish(false) });
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
    const finish = (val) => { modal.close(); resolve(val); };
    const modal = openModal({ title, body, footer: foot, size: 'narrow', onEscape: () => finish(null) });
    const input = $('#prompt-input', modal.body);
    setTimeout(() => { input.focus(); input.select(); }, 30);
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

let netFailures = 0;  // 连续失败计数：达到阈值显示断网横幅，成功即归零

function setOfflineBanner(show) {
  let banner = document.getElementById('offline-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'offline-banner';
    banner.setAttribute('role', 'status');
    banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;background:#2a0d0d;'
      + 'box-shadow:inset 0 -2px 0 #ff4d4d;color:#fff;text-align:center;padding:6px 12px;font-size:13px;display:none';
    banner.textContent = '⚠ 与服务器的连接中断，正在自动重试…（页面数据可能不是最新）';
    document.body.appendChild(banner);
  }
  banner.style.display = show ? 'block' : 'none';
}

async function request(method, url, payload, isForm = false, timeoutMs = 120000, extraHeaders = null) {
  const options = { method, headers: {}, credentials: 'same-origin' };
  if (extraHeaders) Object.assign(options.headers, extraHeaders);
  if (payload !== undefined && payload !== null) {
    if (isForm) {
      options.body = payload;
    } else {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(payload);
    }
  }
  // 超时兜底：后端挂死 / 网络半死时请求不再永远悬着，界面不会永久卡在「加载中」
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  options.signal = controller.signal;
  let response;
  try {
    response = await fetch(url, options);
  } catch (err) {
    netFailures += 1;
    if (netFailures >= 2) setOfflineBanner(true);
    throw new ApiError(
      err && err.name === 'AbortError' ? `请求超时（${Math.round(timeoutMs / 1000)}s），请稍后重试` : '无法连接服务器',
      0,
    );
  } finally {
    clearTimeout(timer);
  }
  netFailures = 0;
  setOfflineBanner(false);
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

/** 高危操作的服务端确认令牌（2.0）：2 分钟有效、绑定动作。 */
async function confirmToken(action) {
  const res = await request('POST', '/api/panel/confirm', { action });
  return res.token;
}

const api = {
  get: (url, timeoutMs) => request('GET', url, undefined, false, timeoutMs || 120000),
  post: (url, body, timeoutMs) => request('POST', url, body, false, timeoutMs || 120000),
  put: (url, body, timeoutMs) => request('PUT', url, body, false, timeoutMs || 120000),
  del: (url, timeoutMs) => request('DELETE', url, undefined, false, timeoutMs || 120000),
  // 需要请求体的 DELETE（如删除某一行 SSH 公钥）
  delBody: (url, body, timeoutMs) => request('DELETE', url, body, false, timeoutMs || 120000),
  upload: (url, formData, timeoutMs) => request('POST', url, formData, true, timeoutMs || 600000),
  postConfirmed: async (url, body, action, timeoutMs) =>
    request('POST', url, body, false, timeoutMs || 120000,
            { 'X-Confirm-Token': await confirmToken(action) }),
  delConfirmed: async (url, action, timeoutMs) =>
    request('DELETE', url, undefined, false, timeoutMs || 120000,
            { 'X-Confirm-Token': await confirmToken(action) }),
  uploadConfirmed: async (url, formData, action, timeoutMs) =>
    request('POST', url, formData, true, timeoutMs || 600000,
            { 'X-Confirm-Token': await confirmToken(action) }),
};

/* ============================ 折线图 ============================ */

class Chart {
  constructor(canvas, opts = {}) {
    this.canvas = canvas;
    this.series = opts.series || [{ color: '#ffd802' }];
    this.capacity = opts.capacity || 60;
    this.fixedMax = opts.max ?? null;
    this.height = opts.height || 46;
    this.fmt = opts.fmt || ((v) => S(Math.round(v)));
    this.data = [];
    canvas.style.height = `${this.height}px`;
    // 宽度只在尺寸变化时读一次并缓存：draw 里再读 clientWidth 会在每次
    // push（每 2 秒 × 8 个图）都强制一次同步布局
    this.width = canvas.clientWidth || 300;
    if (window.ResizeObserver) {
      this.observer = new ResizeObserver(() => {
        this.width = canvas.clientWidth || 300;
        this.draw();
      });
      this.observer.observe(canvas);
    } else {
      // Safari 13 / 旧 Android WebView 没有 ResizeObserver：
      // 直接抛错会让整个概览/性能视图渲染失败，退化为 window.resize
      this.observer = null;
      this._onResize = () => {
        this.width = canvas.clientWidth || 300;
        this.draw();
      };
      window.addEventListener('resize', this._onResize);
    }
  }

  push(values) {
    this.data.push(values.map(Number));
    while (this.data.length > this.capacity) this.data.shift();
    // 后台标签页不重绘（2.0 能耗优化）：数据照常累积，切回前台后下一次 push 会补画
    if (!document.hidden) this.draw();
  }

  load(points, pick) {
    this.data = points.map((p) => pick(p).map(Number)).slice(-this.capacity);
    this.draw();
  }

  destroy() {
    if (this.observer) this.observer.disconnect();
    else if (this._onResize) window.removeEventListener('resize', this._onResize);
  }

  draw() {
    const canvas = this.canvas;
    const width = this.width || canvas.clientWidth || 300;
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
    ctx.strokeStyle = 'rgba(107,116,128,.18)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 2; i += 1) {
      const y = Math.round((height - 1) * (i / 2)) + 0.5;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
    }

    // 上限标注
    ctx.fillStyle = 'rgba(154,162,173,.75)';
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

// 可见性感知轮询：页面切到后台（标签隐藏/最小化）时让轮询空转，回前台再继续。
// 否则一堆 setInterval 在后台标签里照样每 2~5 秒打一轮接口，纯浪费服务器。
function every(ms, fn) {
  return setInterval(() => { if (!document.hidden) fn(); }, ms);
}

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
        const data = await api.get('/api/system/metrics', 8000);
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
    this.timer = every(2000, tick);
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
  { id: 'terminal', label: '网页终端', icon: '▶', internalOnly: true, adminOnly: true },
  // 2.1.0：常驻应用的启动 = 执行 shell 命令，属「等同 root」能力，仅 admin
  { id: 'apps', label: '常驻应用', icon: '⏱', internalOnly: true, adminOnly: true },
  { id: 'market', label: '应用市场', icon: '⌸', internalOnly: true, adminOnly: true },
  { id: 'logs', label: '控制台 / 日志', icon: '☰' },
  { id: 'storage', label: '存储空间', icon: '⛁' },
  { id: 'processes', label: '进程管理', icon: '⚙' },
  { id: 'services', label: '服务管理', icon: '⏻' },
  // 运维页全是系统级变更（cron / 备份 / 更新 / Docker / 防火墙 / SSH / 挂载），仅 admin
  { id: 'ops', label: '运维', icon: '⛭', internalOnly: true, adminOnly: true },
  { id: 'apps-port', label: '应用与端口', icon: '⧉', internalOnly: true },
  { id: 'files', label: '文件管理', icon: '▦', internalOnly: true },
  { id: 'agent', label: 'Agent 接入', icon: '⌘', internalOnly: true, adminOnly: true },
  { id: 'security', label: '安全中心', icon: '◈', internalOnly: true },
  { id: 'settings', label: '设置', icon: '⚒' },
];

function registerView(id, def) { views[id] = def; }

/* ============================ 运行模式 ============================ */
// public  公网模式：只读监控
// internal 内网模式：完全控制（仅在服务器本机执行命令后激活）
let appMode = 'public';
const isInternal = () => appMode === 'internal';

function visibleNav() {
  return NAV
    .filter((item) => (!item.internalOnly || isInternal())
      && (!item.adminOnly || isAdmin()))
    .map((item) => ({ ...item, label: I18N.t(`nav.${item.id}`, item.label) }));
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
    const label = I18N.t(`nav.${id}`, item.label);
    return `<button class="tab${id === currentView ? ' active' : ''}" data-tab="${id}">
      <span class="tab-ico">${item.icon}</span><span class="tab-label">${esc(label)}</span>
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

let viewSeq = 0;  // 视图代际：每次导航自增，过期的异步渲染结果一律丢弃
let inflightResources = null;  // 正在渲染（还没 return cleanup）的那次导航的资源登记表

/**
 * 视图资源登记表：render 想随视图一起销毁、但**必须在渲染期间就登记**的东西
 * （定时器 / 订阅 / 观察器）。
 * 为什么不能只靠 render 的返回值：render 抛错时返回值根本拿不到，路由就永远
 * 回收不了这个视图已经建好的定时器——那正是「进程管理 / 应用与端口」每 4~5 秒
 * 在已卸载 DOM 上抛 TypeError 的来源（首屏 await 期间被切走 → reject → cleanup 丢失）。
 * 登记过的资源在三种情况下都会被回收：视图正常销毁（cleanup）、render 抛错、
 * 渲染期间被切走（seq 过期）。dispose() 可重复调用。
 */
function makeViewResources() {
  const owned = [];
  let disposed = false;
  return {
    get disposed() { return disposed; },
    own(fn) {
      if (typeof fn !== 'function') return fn;
      if (disposed) {
        // 视图已经被回收（render 还在跑，或结算得太晚）：后到的登记立刻执行，
        // 否则「先切走、后订阅实时总线」这种竞态会留下一个对着空 DOM 的订阅
        try { fn(); } catch (err) { console.error(err); }
        return fn;
      }
      owned.push(fn);
      return fn;
    },
    dispose() {
      disposed = true;
      while (owned.length) {
        const fn = owned.pop();
        try { fn(); } catch (err) { console.error(err); }
      }
    },
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
  // 上一次导航的 render 可能还没结算（首屏请求很慢、甚至永远不结算）：
  // 它的 cleanup 还没拿到，但它已经登记的资源现在就回收，不能无限期等它
  if (inflightResources) { inflightResources.dispose(); inflightResources = null; }
  const seq = (viewSeq += 1);
  const resources = makeViewResources();
  inflightResources = resources;
  currentView = viewId;
  location.hash = `#/${viewId}`;
  renderTabs();
  $('#page-title').textContent = I18N.t(`view.${viewId}`, def.title);
  $$('#nav .nav-item').forEach((el) => el.classList.toggle('active', el.dataset.id === viewId));
  const host = $('#view');
  // 清掉上个视图挂在容器上的事件属性与残留监听，避免旧闭包跨视图继续收事件
  host.onclick = host.onchange = host.oninput = host.onkeydown = null;
  host.className = def.fullbleed ? 'view terminal-view' : 'view';
  // 每次导航给视图一个全新的 slot 容器（display:contents 不占布局）：
  // 旧视图迟到的异步写入只会落在已脱离文档的旧 slot 里，盖不掉新视图
  const container = document.createElement('div');
  container.className = 'view-slot';
  container.innerHTML = '<div class="empty">加载中…</div>';
  host.innerHTML = '';
  host.appendChild(container);
  try {
    const cleanup = (await def.render(container, resources)) || null;
    if (inflightResources === resources) inflightResources = null;
    if (seq !== viewSeq) {
      // 渲染期间用户已切去别的视图：立刻回收这个过期视图的定时器/监听
      if (cleanup) { try { cleanup(); } catch (err) { console.error(err); } }
      resources.dispose();
      return;
    }
    currentCleanup = cleanup;
  } catch (err) {
    if (inflightResources === resources) inflightResources = null;
    // render 抛错也必须回收它已经登记的资源：视图没起来，定时器却活着会一直报错
    resources.dispose();
    if (seq !== viewSeq) return;
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
  $('#login-label').textContent = initialized
    ? I18N.t('login.password', '面板密码') : '设置面板密码';
  $('#login-submit').textContent = initialized
    ? I18N.t('btn.login', '登录') : '设置密码并登录';
  $('#confirm-field').classList.toggle('hidden', initialized);
  $('#login-password').setAttribute('autocomplete', initialized ? 'current-password' : 'new-password');
  // 多用户（2.0 M4）：仅当已进入多用户模式时显示用户名输入框
  const needUser = initialized && !!authState.multi_user;
  $('#username-field').classList.toggle('hidden', !needUser);
  // 二次认证（1.4.0）：仅在已启用 TOTP 且是登录（非首次设置）时要求动态码
  const needTotp = initialized && !!(authState.user_totp_enabled ?? authState.totp_enabled);
  $('#totp-field').classList.toggle('hidden', !needTotp);
  $('#totp-hint').classList.toggle('hidden', !needTotp);
  $('#login-error').textContent = expired ? '会话已过期，请重新登录' : '';
  const modeNote = authState.mode === 'internal'
    ? '<span class="badge mode-badge internal">内网模式 · 完全控制</span>'
    : '<span class="badge mode-badge public">公网模式 · 只读监控</span>';
  $('#login-hint').innerHTML = (initialized
    ? '密码通过 PBKDF2 加盐哈希后保存在本机配置文件中。忘记密码可在服务器上执行：<span class="mono">serverpanel --set-password 新密码</span>'
    : '首次使用，请设置访问密码（至少 12 位）。密码只保存在本机，用于登录本控制台。')
    + `<div style="margin-top:10px">${modeNote}</div>`;
  setTimeout(() => (needTotp ? $('#login-totp') : $('#login-password')).focus(), 50);
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
    const code = ($('#login-totp').value || '').trim();
    const username = ($('#login-username')?.value || '').trim();
    await api.post(url, { password, code, username });
    $('#login-form').reset();
    await startApp();
  } catch (err) {
    // 服务端提示「需要二次验证码」：密码已通过，展开动态码输入框引导补登
    if (err.status === 401 && /二次验证码/.test(err.message || '')) {
      authState.totp_enabled = true;
      $('#totp-field').classList.remove('hidden');
      $('#totp-hint').classList.remove('hidden');
      errorEl.textContent = '请输入二次验证码后继续';
      $('#login-totp').focus();
      button.disabled = false;
      return;
    }
    errorEl.textContent = err.message;
    button.disabled = false;
  }
}

/* ============================ 启动 ============================ */

async function startApp(precached = null) {
  // 状态与能力探测并行；boot 已拿到 status 时直接复用，首屏少一次串行往返
  const [status] = await Promise.all([
    precached || api.get('/api/auth/status'),
    api.get('/api/system/capabilities').then((c) => { live.capabilities = c; }).catch(() => {}),
  ]);
  authState = status;
  if (!status.authenticated) { showLogin(false); return; }
  appMode = status.mode || 'public';
  authUser = {
    username: status.username || 'admin',
    role: status.role || 'admin',
    multiUser: !!status.multi_user,
  };
  renderUserBadge();
  await syncLocale();
  $('#login-screen').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#brand-host').textContent = status.hostname || '-';
  renderModeBadge();
  renderModeBanner();
  initTabs();
  buildNav();
  live.start();
  const hashView = location.hash.replace('#/', '');
  navigate(views[hashView] ? hashView : 'overview');
}

async function boot() {
  // 语言包先加载：即便未登录，登录页的按钮/标签也要立刻是正确语言
  await I18N.load(localStorage.getItem('sp-locale') || 'zh-CN');
  registerServiceWorker();
  try {
    authState = await api.get('/api/auth/status');
  } catch (err) {
    authState = { initialized: true, authenticated: false };
  }
  I18N.apply();
  $('#login-host').textContent = authState.hostname ? `主机 ${authState.hostname}` : '本机系统控制台';
  $('#login-form').addEventListener('submit', submitLogin);
  if (authState.authenticated) await startApp(authState);  // 复用已拉到的状态，不重复请求
  else showLogin(false);
}

$('#btn-refresh')?.addEventListener('click', async () => {
  // 网页终端的刷新 = 销毁 term + 断开 WS；用户往往只是想"刷新数据"，
  // 结果把正在跑的编译/部署打断，这里必须先说清楚
  if (currentView === 'terminal') {
    const ok = await confirmDialog({
      title: '刷新会断开终端',
      message: '重新加载视图会终止当前终端会话，正在前台运行的命令也会被结束。确定继续？',
      confirmText: '断开并刷新',
      danger: true,
    });
    if (!ok) return;
  }
  navigate(currentView || 'overview');
});
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
  async render(root, res) {
    const info = await api.get('/api/system/info');
    // 概览页的回收站水位告警（1.6.0 U3）：仅内网模式下可读安全摘要
    const security = isInternal()
      ? await api.get('/api/panel/security').catch(() => null)
      : null;
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
              ${isInternal() && isAdmin() ? '<button class="btn sm" data-act="go-terminal">打开终端</button>' : ''}
              <button class="btn sm" data-act="go-logs">查看日志</button>
              ${isInternal() ? '<button class="btn sm" data-act="go-files">文件管理</button>' : ''}
              <div class="spacer"></div>
              ${isInternal() ? `<button class="btn sm danger" data-act="reboot">重启系统</button>
              <button class="btn sm danger" data-act="shutdown">关机</button>` : ''}
            </div>
            ${security?.trash?.over_limit
              ? `<div style="margin-top:10px"><span class="badge warn">回收站占用超过水位</span>
                 <span class="dim" style="font-size:12px">占用 ${bytes(security.trash.bytes || 0)}，建议到「文件管理 → 回收站」清理</span></div>`
              : ''}
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
      cpu: new Chart($('#ov-cpu'), { max: 100, series: [{ color: '#ffd802', fill: 'rgba(255,216,2,.16)' }], fmt: (v) => `${v.toFixed(0)}%` }),
      mem: new Chart($('#ov-mem'), { max: 100, series: [{ color: '#4aa3ff', fill: 'rgba(74,163,255,.16)' }], fmt: (v) => `${v.toFixed(0)}%` }),
      disk: new Chart($('#ov-disk'), { series: [{ color: '#ffd802', fill: 'rgba(255,216,2,.14)' }, { color: '#b26bff' }], fmt: rate }),
      net: new Chart($('#ov-net'), { series: [{ color: '#b8e619', fill: 'rgba(184,230,25,.14)' }, { color: '#4aa3ff' }], fmt: rate }),
    };
    res.own(() => Object.values(charts).forEach((c) => c.destroy()));

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
    // 订阅必须**当场**登记到路由：下面还有首屏 await（几秒），
    // 期间被切走的话，晚登记的订阅会继续每 2 秒往已卸载的 DOM 写数据
    res.own(unsubscribe);

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
        // 容器 / Android（PRoot）会屏蔽 /proc/net/dev，计数读不到时后端只报 0 并给出原因，
        // 这里把原因显示出来，免得用户以为是"真的没流量"
        const note = (data.degraded || []).length
          ? `<div class="dim" style="font-size:12px;margin-top:6px">本机限制了部分网络计数：${esc(data.degraded.join('；'))}</div>`
          : '';
        $('#ov-nets').innerHTML = (rows.length ? `
          <table class="data"><thead><tr><th>接口</th><th>地址</th><th>状态</th><th class="num">接收</th><th class="num">发送</th></tr></thead>
          <tbody>${rows.map((i) => {
            const v4 = i.addresses.find((a) => a.family === '2' && !a.address.startsWith('127.'));
            return `<tr><td class="cell-main">${esc(i.name)}</td>
              <td class="cell-main">${esc(v4 ? v4.address : '-')}</td>
              <td><span class="badge ${i.up ? 'ok' : 'danger'}">${i.up ? '已启用' : '已关闭'}</span></td>
              <td class="num">${bytes(i.bytes_recv)}</td><td class="num">${bytes(i.bytes_sent)}</td></tr>`;
          }).join('')}</tbody></table>` : '<div class="empty">无网络接口</div>') + note;
      } catch (err) { /* 忽略 */ }
    }

    await Promise.all([loadProcs(), loadNets()]);
    const procTimer = every(6000, loadProcs);
    res.own(() => clearInterval(procTimer));

    root.onclick = async (event) => {
      const action = event.target.dataset?.act;
      if (!action) return;
      if (action === 'go-terminal') { if (!isAdmin()) return; navigate('terminal'); }
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
          const res = await api.postConfirmed('/api/system/power', { action, confirm: 'CONFIRM' }, 'power');
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
  async render(root, res) {
    let historyRange = '1h';
    root.innerHTML = `
      <div class="toolbar" style="margin-bottom:12px">
        <span class="dim" style="font-size:12px">历史范围</span>
        ${[['1h', '1 小时'], ['1d', '1 天'], ['30d', '30 天'], ['365d', '365 天']]
    .map(([v, label]) => `<button class="btn sm ${v === '1h' ? 'primary' : 'ghost'}" data-history-range="${v}">${label}</button>`).join('')}
        <div class="spacer"></div>
        <span class="badge" id="pf-power" title="整机功耗（Intel RAPL，部分机器不可读）">功耗 -- W</span>
      </div>
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
          <div class="metric-sub">黄：读取　紫：写入</div>
        </div>
        <div class="card">
          <h2>网络吞吐 <span class="spacer"></span><span class="badge" id="pf-net-now">--</span></h2>
          <canvas class="spark" id="pf-net" style="height:110px"></canvas>
          <div class="metric-sub">酸绿：接收　蓝：发送</div>
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
      cpu: new Chart($('#pf-cpu'), { max: 100, height: 120, series: [{ color: '#ffd802', fill: 'rgba(255,216,2,.16)' }], fmt: (v) => `${v.toFixed(0)}%` }),
      mem: new Chart($('#pf-mem'), { max: 100, height: 120, series: [{ color: '#4aa3ff', fill: 'rgba(74,163,255,.16)' }], fmt: (v) => `${v.toFixed(0)}%` }),
      disk: new Chart($('#pf-disk'), { height: 110, series: [{ color: '#ffd802', fill: 'rgba(255,216,2,.14)' }, { color: '#b26bff' }], fmt: rate }),
      net: new Chart($('#pf-net'), { height: 110, series: [{ color: '#b8e619', fill: 'rgba(184,230,25,.14)' }, { color: '#4aa3ff' }], fmt: rate }),
    };
    res.own(() => Object.values(charts).forEach((c) => c.destroy()));

    let histSeq = 0;
    async function loadHistory() {
      // 请求序号：连点「1 小时 → 30 天」时，慢的旧请求不能覆盖新选择
      const seq = ++histSeq;
      const data = await api.get(`/api/system/history?period=${encodeURIComponent(historyRange)}`)
        .catch(() => ({ points: [] }));
      if (seq !== histSeq) return;
      const points = data.points || [];
      charts.cpu.load(points, (p) => [p.cpu]);
      charts.mem.load(points, (p) => [p.mem]);
      charts.disk.load(points, (p) => [p.disk_read, p.disk_write]);
      charts.net.load(points, (p) => [p.net_recv, p.net_sent]);
    }
    await loadHistory();
    $$('[data-history-range]', root).forEach((btn) => btn.addEventListener('click', async () => {
      historyRange = btn.dataset.historyRange;
      $$('[data-history-range]', root).forEach((b) => {
        b.className = `btn sm ${b.dataset.historyRange === historyRange ? 'primary' : 'ghost'}`;
      });
      await loadHistory();
    }));

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
      const power = $('#pf-power');
      if (power) power.textContent = m.power_w == null ? '功耗 -- W' : `功耗 ${m.power_w} W`;
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
    // 订阅必须**当场**登记到路由：下面还有首屏 await（几秒），
    // 期间被切走的话，晚登记的订阅会继续每 2 秒往已卸载的 DOM 写数据
    res.own(unsubscribe);

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
    const procTimer = every(5000, loadProcs);
    res.own(() => clearInterval(procTimer));

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
    // xterm 是本地 vendor 文件：缺失（安装不完整/离线壳未缓存）时给出可操作提示，
    // 而不是整页"加载失败"并抛 ReferenceError
    if (typeof Terminal === 'undefined') {
      root.innerHTML = '<div class="card"><div class="empty">终端组件未加载'
        + '（/static/vendor/xterm.js 缺失）。请重新执行安装脚本，或改用系统 SSH。</div></div>';
      return null;
    }
    const info = await api.get('/api/terminal/info').catch(() => ({ shell: '/bin/bash', user: 'root' }));
    root.innerHTML = `
      <div class="terminal-bar">
        <span class="badge info">${esc(info.user)}@${esc($('#brand-host').textContent)}</span>
        <span class="mono">${esc(info.shell)}</span>
        ${info.is_root ? '<span class="badge warn">root 权限</span>' : `<span class="badge">${esc(info.user)} 权限</span>`}
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
        background: '#08090b', foreground: '#e9ebee', cursor: '#ffd802',
        selectionBackground: 'rgba(255,216,2,.24)',
        black: '#1b1f24', red: '#ff4d4d', green: '#b8e619', yellow: '#ffd802',
        blue: '#4aa3ff', magenta: '#b26bff', cyan: '#58c8c8', white: '#e9ebee',
      },
    });
    const fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open($('#terminal-host'));

    let socket = null, disposed = false, reconnectTimer = null, fontSize = 13.5;
    let everConnected = false;
    let reconnectDelay = 1500;  // 重连退避：1.5s 起步，每次翻倍，30s 封顶
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
        reconnectDelay = 1500;  // 连上了就把退避复位
        doFit();
        term.focus();
      };
      socket.onmessage = (event) => {
        if (typeof event.data === 'string') term.write(event.data);
        else term.write(new Uint8Array(event.data));
      };
      socket.onclose = () => {
        statusEl.textContent = `已断开，${Math.round(reconnectDelay / 1000)} 秒后重连`;
        statusEl.className = 'badge danger';
        if (!disposed) {
          // 只在首次断开写一行终端红字；之后靠状态栏提示，
          // 不再固定 1.5s 一轮把屏幕刷成红字瀑布
          if (reconnectDelay <= 1500) {
            term.write('\r\n\x1b[31m[连接已断开，正在自动重连（间隔逐步加大）…]\x1b[0m\r\n');
          }
          reconnectTimer = setTimeout(connect, reconnectDelay);
          reconnectDelay = Math.min(reconnectDelay * 2, 30000);
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

    // ResizeObserver 只负责容器尺寸变化（侧栏折叠等）；老浏览器没有它时
    // window.resize 已覆盖窗口缩放，不需要为了适配让整个终端视图渲染失败
    const hostObserver = window.ResizeObserver
      ? new ResizeObserver(() => doFit())
      : null;
    if (hostObserver) hostObserver.observe($('#terminal-host'));
    const onWindowResize = () => doFit();
    window.addEventListener('resize', onWindowResize);

    connect();
    // 延后布局一次（终端容器尺寸稳定后 fit）；路由切走时必须清掉，
    // 否则对已 dispose 的 term 调 focus 会抛异常
    const focusTimer = setTimeout(() => { doFit(); term.focus(); }, 60);

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
      clearTimeout(focusTimer);
      window.removeEventListener('resize', onWindowResize);
      hostObserver?.disconnect();
      try { dataSub.dispose(); resizeSub.dispose(); } catch (err) { /* 忽略 */ }
      if (socket) { socket.onclose = null; socket.close(); }
      term.dispose();
    };
  },
});

/* ============================ 视图：控制台 / 日志 ============================ */

registerView('logs', {
  title: '控制台 / 日志',
  async render(root, res) {
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
          <label class="row" style="font-size:13px;gap:6px">
            <input type="checkbox" id="log-follow"> 实时跟随
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
    // 与 rawLines 同下标的样式缓存：每条新行只算一次正则，重绘时不再逐行匹配
    let rawClasses = [];
    let timer = null;
    let busy = false;
    let followWs = null;
    let paintTimer = null;

    function paintSoon() {
      // 高频日志（journalctl -f / nginx access）按 120ms 合并重绘：
      // 每条 WS 消息都重建最多 3000 行 DOM 会让标签页直接卡死
      if (paintTimer) return;
      paintTimer = setTimeout(() => { paintTimer = null; paint(); }, 120);
    }
    res.own(() => clearTimeout(paintTimer));

    function stopFollow() {
      if (followWs) {
        try { followWs.close(); } catch (_) { /* 已关闭 */ }
        followWs = null;
      }
      const box = $('#log-follow');
      if (box) box.checked = false;
    }

    function setLines(lines) {
      rawLines = lines || [];
      rawClasses = rawLines.map((line) => lineClass(line));
    }

    function startFollow() {
      stopFollow();
      if (sourceEl.value !== 'file') {
        toast('实时跟随仅支持「日志文件」来源', 'warn');
        return;
      }
      const path = fileEl.value;
      if (!path) { toast('没有可用的日志文件', 'warn'); return; }
      const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
      const ws = new WebSocket(
        `${scheme}://${location.host}/api/logs/ws?path=${encodeURIComponent(path)}&lines=100`);
      followWs = ws;
      ws.onmessage = (event) => {
        if (String(event.data).startsWith('[error]')) {
          toast(String(event.data).replace('[error] ', ''), 'err');
          stopFollow();
          return;
        }
        rawLines.push(event.data);
        rawClasses.push(lineClass(event.data));
        if (rawLines.length > 6000) {
          rawLines = rawLines.slice(-4000);
          rawClasses = rawClasses.slice(-4000);
        }
        paintSoon();
      };
      ws.onclose = () => {
        if (followWs === ws) {
          followWs = null;
          const box = $('#log-follow');
          if (box) box.checked = false;
        }
      };
    }

    const lineClass = (line) => {
      const lower = line.toLowerCase();
      if (/\b(error|failed|failure|fatal|critical|denied|panic)\b/.test(lower)) return 'log-line err';
      if (/\b(warn|warning|deprecated)\b/.test(lower)) return 'log-line warn';
      return '';
    };

    function paint() {
      const keyword = $('#log-filter').value.trim().toLowerCase();
      // 无过滤时直接用缓存样式；有过滤才重算（用户主动操作，频率低）
      const matched = keyword
        ? rawLines.map((line) => ({ line, cls: lineClass(line) }))
          .filter((item) => item.line.toLowerCase().includes(keyword))
        : rawLines.map((line, index) => ({ line, cls: rawClasses[index] || '' }));
      const shown = matched.slice(0, 3000);  // 渲染上限：几千行 innerHTML 重建会明显掉帧
      const atBottom = output.scrollTop + output.clientHeight >= output.scrollHeight - 40;
      output.innerHTML = shown.length
        ? shown.map(({ line, cls }) => `<span class="${cls}">${esc(line) || '&nbsp;'}</span>`).join('\n')
        : '<span class="dim">没有匹配的日志行</span>';
      if (atBottom) output.scrollTop = output.scrollHeight;
      meta.textContent = `共 ${rawLines.length} 行`
        + (keyword ? `，匹配 ${matched.length} 行${matched.length > 3000 ? '（仅渲染前 3000 行）' : ''}` : '')
        + `　更新于 ${new Date().toLocaleTimeString()}`;
    }

    async function load() {
      if (busy) return;
      busy = true;
      const lines = $('#log-lines').value;
      try {
        const source = sourceEl.value;
        if (source === 'dmesg') {
          setLines((await api.get(`/api/logs/dmesg?lines=${lines}`)).lines);
        } else if (source === 'file') {
          const path = fileEl.value;
          if (!path) throw new ApiError('没有可用的日志文件', 0);
          const data = await api.get(`/api/logs/file?path=${encodeURIComponent(path)}`);
          setLines(data.content.split('\n'));
          if (data.truncated) {
            const hint = `… 文件较大（${bytes(data.size)}），仅显示末尾部分 …`;
            rawLines.unshift(hint);
            rawClasses.unshift(lineClass(hint));
          }
        } else {
          const priority = $('#log-priority').value;
          const boot = source === 'boot' ? '&boot=true' : '';
          const data = await api.get(`/api/logs/journal?lines=${lines}${boot}${priority ? `&priority=${priority}` : ''}`);
          if (!data.ok && data.error) throw new ApiError(data.error, 500);
          setLines(data.lines);
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
      stopFollow();
      const isFile = sourceEl.value === 'file';
      fileEl.classList.toggle('hidden', !isFile);
      $('#log-priority').parentElement.classList.toggle('hidden', isFile || sourceEl.value === 'dmesg');
      load();
    };
    fileEl.onchange = () => { stopFollow(); load(); };
    $('#log-priority').onchange = load;
    $('#log-lines').onchange = load;
    $('#log-refresh').onclick = load;
    $('#log-follow').onchange = (event) => {
      if (event.target.checked) startFollow(); else stopFollow();
    };
    res.own(stopFollow);   // 切视图时必须关闭 WS，否则 tail 进程会一直跟着文件
    let filterTimer = null;
    $('#log-filter').oninput = () => {
      clearTimeout(filterTimer);
      filterTimer = setTimeout(paint, 200);  // 200ms 防抖：逐字符重绘大日志会掉帧
    };
    $('#log-copy').onclick = () => copyText(rawLines.join('\n'), '日志已复制到剪贴板');
    $('#log-auto').onchange = (event) => {
      clearInterval(timer);
      timer = null;
      if (event.target.checked) {
        timer = every(3000, load);
        toast('已开启自动刷新（3 秒）');
      }
    };
    res.own(() => clearInterval(timer));   // 自动刷新定时器也登记到路由

    await load();
    return () => { clearInterval(timer); clearTimeout(filterTimer); };
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
        // 容器 / Android 可能读不到分区表与块设备计数，后端降级为 0 并给原因
        const pnote = (data.degraded || []).length
          ? `<div class="dim" style="font-size:12px;margin-top:6px">本机限制了部分存储信息：${esc(data.degraded.join('；'))}</div>`
          : '';
        $('#st-parts').innerHTML = (data.partitions.length ? data.partitions.map((p) => `
          <div class="card" style="background:var(--panel-2)">
            <div class="metric-label">${esc(p.mountpoint)}</div>
            <div class="metric-value" style="font-size:22px">${p.percent !== null ? `${p.percent.toFixed(0)}%` : '-'}</div>
            ${p.percent !== null ? bar(p.percent) : ''}
            <div class="metric-sub">${esc(p.device)}<br>${esc(p.fstype)}</div>
            <div class="metric-sub">已用 ${bytes(p.used)} / ${bytes(p.total)} · 可用 ${bytes(p.free)}</div>
          </div>`).join('') : '<div class="empty">未检测到可用的磁盘分区（容器环境常见）</div>') + pnote;

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
  async render(root, res) {
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
    let loadSeq = 0;

    async function load() {
      // 先把本次要写的节点抓在手里。视图可能已经被切走（上一代定时器 / 迟到的防抖回调），
      // 这时读文档里的 #ps-search 会拿到 null，写入落在已脱离文档的旧节点上则无害作废。
      const searchEl = $('#ps-search');
      const sortEl = $('#ps-sort');
      const table = $('#ps-table');
      if (!searchEl || !sortEl || !table) {
        // 残骸回调：顺手把定时器关掉（根因已在 navigate() 修掉，这里是双保险，
        // 保证即使将来再出现孤儿定时器，也只在第一次触发时报一次）
        clearInterval(timer);
        return;
      }
      const seq = ++loadSeq;  // 请求序号：自动刷新与搜索并发时只认最后一次结果
      const q = encodeURIComponent(searchEl.value.trim());
      const sort = sortEl.value;
      try {
        const data = await api.get(`/api/processes?limit=200&sort=${sort}&q=${q}`);
        if (seq !== loadSeq) return;  // 期间已有更新的请求返回，这份旧数据作废
        rows = data.processes;
        const countEl = $('#ps-count');
        if (countEl) countEl.textContent = `${data.total} 个进程`;
        table.innerHTML = rows.length ? `
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
        table.innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
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
    res.own(() => clearTimeout(searchTimer));
    $('#ps-search').oninput = () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(load, 260);
    };
    $('#ps-auto').onchange = (event) => {
      clearInterval(timer);
      timer = null;
      if (event.target.checked) timer = every(4000, load);
    };
    timer = every(4000, load);
    res.own(() => clearInterval(timer));   // 先登记再生效：render 抛错时路由也能关掉它

    $('#ps-table').onclick = (event) => {
      const sorter = event.target.closest('[data-sort]');
      if (sorter) {  // PID 表头接上排序（此前是死交互）
        $('#ps-sort').value = sorter.dataset.sort;
        load();
        return;
      }
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
  async render(root, res) {
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
      // 同「进程管理」：节点先抓在手里；视图已被切走就让旧回调作废并关掉定时器
      const countEl = $('#apps-count');
      const searchEl = $('#apps-search');
      const table = $('#apps-table');
      if (!countEl || !searchEl || !table) {
        clearInterval(timer);
        return;
      }
      try {
        const data = await api.get('/api/apps');
        countEl.textContent = `${data.total_apps} 个应用 · ${data.total_ports} 个监听端口`;
        const q = searchEl.value.trim().toLowerCase();
        const rows = (data.apps || []).filter((a) => !q
          || a.name.toLowerCase().includes(q)
          || (a.cmdline || '').toLowerCase().includes(q)
          || a.ports.some((p) => S(p.port).includes(q)));
        table.innerHTML = rows.length ? `
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
        table.innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
      }
    }

    $('#apps-refresh').onclick = load;
    let searchTimer = null;
    res.own(() => clearTimeout(searchTimer));
    $('#apps-search').oninput = () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(load, 200);
    };
    $('#apps-auto').onchange = (event) => {
      clearInterval(timer);
      timer = null;
      if (event.target.checked) timer = every(5000, load);
    };
    timer = every(5000, load);
    res.own(() => clearInterval(timer));   // 先登记再生效：render 抛错时路由也能关掉它

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
    let reloadTimer = null;
    let loadSeq = 0;

    const stateBadge = (s) => {
      if (s.active === 'active') return `<span class="badge ok">运行中</span>`;
      if (s.active === 'failed') return `<span class="badge danger">失败</span>`;
      if (s.active === 'activating') return `<span class="badge warn">启动中</span>`;
      return `<span class="badge">已停止</span>`;
    };

    async function load() {
      // 同「进程管理」：节点先抓在手里，视图已被切走就让迟到的回调作废
      const searchEl = $('#sv-search');
      const stateEl = $('#sv-state');
      const table = $('#sv-table');
      if (!searchEl || !stateEl || !table) return;
      const seq = ++loadSeq;  // 请求序号：搜索与手动刷新并发时只认最后一次结果
      const q = encodeURIComponent(searchEl.value.trim());
      const state = stateEl.value;
      try {
        const data = await api.get(`/api/services?q=${q}&state=${state}`);
        if (seq !== loadSeq) return;
        services = data.services;
        const countEl = $('#sv-count');
        if (countEl) countEl.textContent = `${data.total} 个服务`;
        table.innerHTML = services.length ? `
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
        table.innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
      }
    }

    async function act(service, action, needConfirm) {
      const actionLabel = { start: '启动', stop: '停止', restart: '重启',
        enable: '设为开机自启', disable: '取消开机自启' }[action] || action;
      if (needConfirm) {
        const ok = await confirmDialog({
          title: '确认操作', danger: action === 'stop' || action === 'disable', confirmText: '确定',
          message: `确定要对 <b class="mono">${esc(service.unit)}</b> 执行「${actionLabel}」吗？`,
        });
        if (!ok) return;
      }
      try {
        const res = await api.postConfirmed(`/api/services/${encodeURIComponent(service.unit)}/action`, { action }, 'service');
        toast(res.message);
        reloadTimer = setTimeout(load, 700);  // systemd 状态切换有延迟，稍后再刷一次
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
    return () => { clearTimeout(searchTimer); clearTimeout(reloadTimer); };
  },
});

/* ============================ 视图：文件管理 ============================ */

registerView('files', {
  title: '文件管理',
  async render(root) {
    let cwd = sessionStorage.getItem('sp_cwd') || '/';
    let entries = [];
    let sortKey = 'name';
    let sortDir = 1;
    const selected = new Set();
    const IMAGE_RE = /\.(png|jpe?g|gif|webp|svg|bmp|ico|avif)$/i;
    const ARCHIVE_RE = /\.(zip|tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz)$/i;

    const roots = (await api.get('/api/files/roots').catch(() => ({ roots: [] }))).roots;

    root.innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <div class="toolbar">
          <button class="btn sm" data-act="up">↑ 上级</button>
          <button class="btn sm" data-act="refresh">刷新</button>
          <button class="btn sm" data-act="mkdir">新建文件夹</button>
          <button class="btn sm" data-act="newfile">新建文件</button>
          <button class="btn sm" data-act="upload">上传文件</button>
          <button class="btn sm" data-act="upload-dir">上传文件夹</button>
          <button class="btn sm" data-act="fetch-url">从 URL 拉取</button>
          <button class="btn sm" data-act="trash">回收站</button>
          <input type="file" id="file-input" multiple class="hidden">
          <input type="file" id="dir-input" webkitdirectory multiple class="hidden">
          <label class="dim" style="font-size:12px;display:flex;align-items:center;gap:4px">
            <input type="checkbox" id="upload-overwrite"> 覆盖同名</label>
          <label class="dim" style="font-size:12px;display:flex;align-items:center;gap:4px">
            <input type="checkbox" id="show-hidden" checked> 隐藏文件</label>
          <div class="spacer"></div>
          <input class="input" id="file-search" placeholder="在当前目录搜索…" style="width:190px">
          <button class="btn sm" data-act="search">搜索</button>
        </div>
        <div class="batch-bar hidden" id="batch-bar"></div>
        <div class="crumbs" id="file-crumbs"></div>
        <div class="dim mono" id="file-meta" style="font-size:12px;margin-top:9px"></div>
        <div id="upload-progress"></div>
      </div>

      <div class="card" style="margin-bottom:14px">
        <h2>快捷位置</h2>
        <div class="row" id="file-roots">${roots.filter((r) => r.exists).map((r) =>
          `<button class="btn sm ghost" data-root="${esc(r.path)}">${esc(r.label)} <span class="dim">${esc(r.path)}</span></button>`).join('')}</div>
      </div>

      <div class="card flush drop-zone" id="drop-zone"><div class="table-wrap" id="file-table"><div class="empty">加载中…</div></div></div>`;

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

    function sortEntries() {
      entries.sort((a, b) => {
        if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
        let r = 0;
        if (sortKey === 'size') r = (a.size || 0) - (b.size || 0);
        else if (sortKey === 'mtime') r = (a.mtime || 0) - (b.mtime || 0);
        else r = String(a.name).localeCompare(String(b.name), 'zh-Hans-CN', { numeric: true });
        return r * sortDir;
      });
    }

    function sortArrow(key) {
      if (sortKey !== key) return '';
      return sortDir === 1 ? ' ↑' : ' ↓';
    }

    function paintBatch() {
      const bar = $('#batch-bar');
      if (!selected.size) { bar.classList.add('hidden'); bar.innerHTML = ''; return; }
      bar.classList.remove('hidden');
      bar.innerHTML = `<span class="badge info">已选 ${selected.size} 项</span>
        <button class="btn sm" data-act="batch-move">移动到…</button>
        <button class="btn sm" data-act="batch-archive">打包下载</button>
        <button class="btn sm danger" data-act="batch-delete">批量删除</button>
        <button class="btn sm ghost" data-act="batch-clear">取消选择</button>`;
    }

    function renderTable() {
      if (!entries.length) {
        $('#file-table').innerHTML = '<div class="empty">此目录为空</div>';
        return;
      }
      $('#file-table').innerHTML = `
        <table class="data"><thead><tr>
          <th style="width:36px"><input type="checkbox" id="sel-all" ${selected.size && selected.size === entries.length ? 'checked' : ''}></th>
          <th style="width:34%"><span class="th-sort" data-sort="name">名称${sortArrow('name')}</span></th>
          <th class="num"><span class="th-sort" data-sort="size">大小${sortArrow('size')}</span></th>
          <th class="file-hide-sm">权限</th><th class="file-hide-sm">所有者</th>
          <th><span class="th-sort" data-sort="mtime">修改时间${sortArrow('mtime')}</span></th><th></th></tr></thead>
        <tbody>${entries.map((e, index) => `<tr>
          <td><input type="checkbox" data-sel="${esc(e.path)}" ${selected.has(e.path) ? 'checked' : ''}></td>
          <td><span class="file-icon">${e.is_dir ? '🗀' : e.is_link ? '🔗' : '📄'}</span>
            <span class="cell-main">${esc(e.name)}</span>
            ${e.link_target ? `<span class="cell-sub"> → ${esc(e.link_target)}</span>` : ''}</td>
          <td class="num">${e.is_dir ? '-' : bytes(e.size)}</td>
          <td class="cell-sub file-hide-sm">${esc(e.mode)}</td>
          <td class="cell-sub file-hide-sm">${e.uid}:${e.gid}</td>
          <td class="cell-sub">${datetime(e.mtime)}</td>
          <td class="actions">
            ${e.is_dir ? `<button class="btn sm ghost" data-act="open" data-index="${index}">打开</button>` : ''}
            ${e.is_dir ? '' : '<a class="btn sm ghost" href="#" data-act="edit" data-index="' + index + '">编辑</a>'}
            ${!e.is_dir && IMAGE_RE.test(e.name) ? `<button class="btn sm ghost" data-act="preview" data-index="${index}">预览</button>` : ''}
            ${ARCHIVE_RE.test(e.name) ? `<button class="btn sm ghost" data-act="extract" data-index="${index}">解压</button>` : ''}
            ${e.is_dir ? `<button class="btn sm ghost" data-act="du" data-index="${index}">大小</button>` : ''}
            <a class="btn sm ghost" href="/api/files/download?path=${encodeURIComponent(e.path)}">下载</a>
            <button class="btn sm ghost" data-act="chmod" data-index="${index}">权限</button>
            <button class="btn sm ghost" data-act="rename" data-index="${index}">重命名</button>
            <button class="btn sm danger" data-act="delete" data-index="${index}">删除</button>
          </td></tr>`).join('')}</tbody></table>`;
    }

    let loadSeq = 0;  // 请求序号：连点面包屑/搜索时，旧响应不能把目录倒回去

    async function load(path) {
      const seq = ++loadSeq;
      try {
        const showHidden = $('#show-hidden')?.checked ?? true;
        const data = await api.get(`/api/files/list?path=${encodeURIComponent(path)}`
          + `&show_hidden=${showHidden}`);
        if (seq !== loadSeq) return;  // 期间已有更新的导航返回，这份旧列表作废
        cwd = data.path;
        sessionStorage.setItem('sp_cwd', cwd);
        entries = data.entries;
        selected.clear();
        paintBatch();
        sortEntries();
        renderCrumbs(cwd);
        renderTable();
        $('#file-meta').textContent = (data.truncated
          ? `显示前 ${entries.length} 项（共 ${data.total} 项，目录过大已截断）`
          : `${entries.length} 项`)
          + (data.disk ? ` · 分区可用 ${bytes(data.disk.free)} / ${bytes(data.disk.total)}` : '');
      } catch (err) {
        if (seq !== loadSeq) return;
        $('#file-table').innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
        $('#file-meta').textContent = '';
      }
    }

    function openPreview(entry) {
      openModal({
        title: `预览 · ${entry.name}`,
        body: `<div style="text-align:center"><img
          src="/api/files/download?path=${encodeURIComponent(entry.path)}"
          alt="${esc(entry.name)}" style="max-width:100%;max-height:70vh;border-radius:6px"></div>`,
      });
    }

    async function openEditor(entry) {
      const body = document.createElement('div');
      body.innerHTML = '<div class="empty">加载中…</div>';
      const foot = document.createElement('div');
      foot.className = 'row';
      foot.innerHTML = `<span class="dim mono" id="editor-path" style="font-size:12px"></span>
        <div class="spacer"></div><button class="btn" data-manual-close>关闭</button>
        <button class="btn primary" data-save>保存</button>`;
      const modal = openModal({ title: `编辑 · ${entry.name}`, body, footer: foot, size: 'wide' });
      $('#editor-path', foot).textContent = entry.path;
      try {
        const data = await api.get(`/api/files/read?path=${encodeURIComponent(entry.path)}`);
        body.innerHTML = `<textarea class="input" id="editor-area" spellcheck="false"
          style="width:100%;height:52vh;font-size:13px"></textarea>`;
        const area = $('#editor-area', body);
        area.value = data.content;
        if (data.content.length > 512 * 1024) {
          toast('大文件编辑可能卡顿，建议下载后在本地编辑', 'warn', 6000);  // 软提示，不阻断
        }
        area.focus();
        let dirty = false;
        const markDirty = () => { dirty = true; };
        area.addEventListener('input', markDirty);
        const baseClose = modal.close.bind(modal);
        modal.close = () => {
          if (dirty) {
            confirmDialog({
              title: '放弃修改？', danger: true, confirmText: '放弃修改',
              message: '内容尚未保存，关闭后将丢失修改。',
            }).then((ok) => { if (ok) { dirty = false; baseClose(); } });
            return;
          }
          baseClose();
        };
        $('[data-manual-close]', foot).onclick = () => modal.close();
        async function save(expected) {
          const saveBtn = $('[data-save]', foot);
          if (saveBtn.disabled) return;  // 保存期间禁用按钮，防连点重复写盘
          saveBtn.disabled = true;
          saveBtn.textContent = '保存中…';
          try {
            const payload = { path: entry.path, content: area.value };
            if (expected !== null) payload.expected_mtime = expected;
            const res = await api.post('/api/files/write', payload);
            toast(res.message);
            dirty = false;
            modal.close();
            load(cwd);
          } catch (err) {
            if (err.status !== 409) { toast(err.message, 'err'); return; }
            const ok = await confirmDialog({
              title: '文件已被修改', danger: true, confirmText: '覆盖保存',
              message: `${esc(err.message)}<br><span class="dim">覆盖将丢弃磁盘上的新版本，建议先「关闭」后重新打开比对。</span>`,
            });
            if (ok) {
              saveBtn.disabled = false;
              saveBtn.textContent = '保存';
              await save(null);  // 覆盖保存：走一次新的保存流程（不带乐观锁）
              return;
            }
          } finally {
            saveBtn.disabled = false;
            saveBtn.textContent = '保存';
          }
        }
        $('[data-save]', foot).onclick = () => save(data.mtime);
        area.addEventListener('keydown', (event) => {
          if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
            event.preventDefault();
            save(data.mtime);
          }
        });
      } catch (err) {
        body.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
      }
    }

    /** 用 XHR 逐个上传：只有 XHR 能上报上传进度（fetch 目前不支持可靠的 upload onprogress）。 */
    function xhrUpload(form, onProgress) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/files/upload');
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable && onProgress) onProgress(e.loaded, e.total);
        };
        xhr.onload = () => {
          let data = null;
          try { data = JSON.parse(xhr.responseText); } catch (err) { /* 空响应体 */ }
          if (xhr.status >= 200 && xhr.status < 300) resolve(data);
          else reject(new Error((data && data.detail) || `上传失败（HTTP ${xhr.status}）`));
        };
        xhr.onerror = () => reject(new Error('网络错误，上传中断'));
        xhr.send(form);
      });
    }

    async function doUpload(fileList) {
      const files = Array.from(fileList || []);
      if (!files.length) return;
      const overwrite = $('#upload-overwrite')?.checked ?? false;
      const box = $('#upload-progress');
      let saved = 0;
      const failed = [];
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        box.innerHTML = `<div class="upload-bar"><div class="upload-fill" style="width:0%"></div>
          <span class="upload-label">上传 ${i + 1}/${files.length} · ${esc(file.name)}</span></div>`;
        const fill = $('.upload-fill', box);
        const form = new FormData();
        form.append('path', cwd);
        form.append('overwrite', overwrite ? 'true' : 'false');
        // 文件夹上传时用 webkitRelativePath 保留目录结构，服务端会逐级创建
        form.append('files', file, file.webkitRelativePath || file.name);
        try {
          await xhrUpload(form, (loaded, total) => {
            fill.style.width = `${Math.round((loaded / total) * 100)}%`;
          });
          saved++;
        } catch (err) {
          failed.push(`${file.name}：${err.message}`);
        }
      }
      box.innerHTML = '';
      if (failed.length) {
        toast(`上传完成，${failed.length} 个失败：${failed.slice(0, 3).join('；')}${failed.length > 3 ? '…' : ''}`, 'warn', 6000);
      } else {
        toast(`已上传 ${saved} 个文件${overwrite ? '' : '（同名文件已跳过）'}`);
      }
      load(cwd);
    }

    async function doSearch(rootOverride) {
      const keyword = $('#file-search').value.trim();
      if (!keyword) { load(cwd); return; }
      const target = rootOverride || cwd;
      const btn = $('[data-act="search"]');
      if (btn) btn.disabled = true;
      $('#file-meta').textContent = `正在搜索「${keyword}」…（大目录可能要几十秒）`;
      try {
        const data = await api.get(`/api/files/search?path=${encodeURIComponent(target)}&q=${encodeURIComponent(keyword)}&limit=300`);
        $('#file-crumbs').innerHTML = `<span class="dim">搜索结果</span>`;
        $('#file-meta').textContent = `在 ${data.root} 下找到 ${data.matches.length} 项`
          + (data.truncated ? '（已截断）' : '')
          + (data.note ? ` · ${data.note}` : '');
        entries = data.matches;
        selected.clear();
        paintBatch();
        renderTable();
        if (!entries.length && target !== '/') {
          $('#file-table').innerHTML = `<div class="empty">当前目录下没有匹配项
            <div style="margin-top:10px"><button class="btn sm" data-act="search-root">改在全盘 / 下搜索</button></div></div>`;
        }
      } catch (err) {
        toast(err.message, 'err');
        $('#file-meta').textContent = '';
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    async function doChmod(entry) {
      const current = String(entry.mode || '').replace(/^0o/, '') || '644';
      const body = document.createElement('div');
      body.innerHTML = `<label class="field"><span>权限（八进制，如 644 / 755）</span>
        <input class="input" id="chmod-input" value="${esc(current)}" autocomplete="off"></label>
        ${entry.is_dir ? `<label class="switch-row"><input type="checkbox" id="chmod-rec">
          <span><b>递归应用</b><div class="dim" style="font-size:11.5px">目录内所有文件与子目录都改成该权限</div></span></label>` : ''}`;
      const foot = document.createElement('div');
      foot.className = 'row';
      foot.innerHTML = `<button class="btn" data-cancel>取消</button>
        <button class="btn primary" data-ok>应用</button>`;
      const modal = openModal({ title: `权限 · ${entry.name}`, body, footer: foot });
      $('[data-cancel]', foot).onclick = () => modal.close();
      $('[data-ok]', foot).onclick = async () => {
        const mode = $('#chmod-input', body).value.trim();
        if (!/^[0-7]{3,4}$/.test(mode)) { toast('权限必须是 3~4 位八进制', 'err'); return; }
        try {
          const res = await api.post('/api/files/chmod', {
            path: entry.path, mode, recursive: $('#chmod-rec', body)?.checked ?? false,
          });
          toast(res.message, res.ok ? 'ok' : 'warn');
          modal.close();
          load(cwd);
        } catch (err) { toast(err.message, 'err'); }
      };
    }

    /** 回收站（1.4.0）：覆盖写 / 删除 / 上传覆盖前的自动备份，可还原或彻底删除。 */
    async function openTrash() {
      let modal = null;
      async function paintTrash() {
        try {
          const data = await api.get('/api/files/trash');
          const { entries, usage } = data;
          const reasonLabel = {
            delete: '<span class="badge warn">删除</span>',
            overwrite: '<span class="badge info">覆盖写</span>',
            'upload-overwrite': '<span class="badge info">上传覆盖</span>',
          };
          const body = modal.body;
          body.innerHTML = `
            <div class="dim" style="font-size:12px;line-height:1.7;margin-bottom:10px">
              共 ${usage.count} 项，占用 ${bytes(usage.bytes)}，保留 ${usage.retention_days} 天后自动清理。
              还原时若原始路径已存在同名文件会被拒绝，请先处理原文件。
            </div>
            <div class="row" style="margin-bottom:10px">
              <button class="btn sm ghost" id="trash-refresh">刷新</button>
              <button class="btn sm danger" id="trash-purge-all" ${entries.length ? '' : 'disabled'}>清空回收站</button>
            </div>
            <div class="table-wrap"><table class="data"><thead><tr>
              <th>名称</th><th>原路径</th><th class="num">大小</th><th>来源</th><th>删除时间</th><th></th></tr></thead>
              <tbody>${entries.length ? entries.map((e) => `<tr>
                <td class="cell-main">${e.is_dir ? '🗀' : '📄'} ${esc(e.name)}</td>
                <td class="cell-sub mono" title="${esc(e.original)}">${esc(e.original)}</td>
                <td class="num">${bytes(e.size)}</td>
                <td>${reasonLabel[e.reason] || esc(e.reason || '-')}</td>
                <td class="cell-sub">${datetime(e.time)}</td>
                <td>
                  <button class="btn sm ghost" data-trash-restore="${esc(e.id)}">还原</button>
                  <button class="btn sm danger" data-trash-purge="${esc(e.id)}">彻底删除</button>
                </td>
              </tr>`).join('') : '<tr><td colspan="6"><div class="empty">回收站为空</div></td></tr>'}</tbody></table></div>`;
          $('#trash-refresh', body).onclick = () => paintTrash();
          $('#trash-purge-all', body).onclick = async () => {
            const ok = await confirmDialog({
              title: '清空回收站', danger: true, confirmText: '全部删除', phrase: 'EMPTY',
              message: '回收站内所有条目将被<b>永久删除</b>，无法恢复。',
            });
            if (!ok) return;
            try {
              await api.post('/api/files/trash/purge-all', {});
              toast('回收站已清空', 'ok');
              paintTrash();
            } catch (err) { toast(err.message, 'err'); }
          };
          $$('[data-trash-restore]', body).forEach((btn) => btn.onclick = async () => {
            try {
              const res = await api.post('/api/files/trash/restore', { id: btn.dataset.trashRestore });
              toast(res.message, 'ok');
              paintTrash(); load(cwd);
            } catch (err) { toast(err.message, 'err'); }
          });
          $$('[data-trash-purge]', body).forEach((btn) => btn.onclick = async () => {
            const ok = await confirmDialog({
              title: '彻底删除', danger: true, confirmText: '删除',
              message: '该条目将被<b>永久删除</b>，无法恢复。',
            });
            if (!ok) return;
            try {
              await api.post('/api/files/trash/purge', { id: btn.dataset.trashPurge });
              toast('已彻底删除', 'ok');
              paintTrash();
            } catch (err) { toast(err.message, 'err'); }
          });
        } catch (err) {
          if (modal) modal.body.innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
        }
      }
      modal = openModal({ title: '回收站', body: '<div class="empty">加载中…</div>', size: 'wide' });
      paintTrash();
    }

    async function doFetchUrl() {
      const url = await promptDialog({
        title: '从 URL 拉取文件', label: '文件直链（http/https，下载到当前目录）',
        confirmText: '下载',
      });
      if (!url) return;
      toast('正在下载…', 'warn', 2000);
      try {
        const res = await api.post('/api/files/fetch', { url, dest_dir: cwd });
        toast(res.message);
        load(cwd);
      } catch (err) { toast(err.message, 'err'); }
    }

    async function doBatchDelete() {
      const paths = [...selected];
      const preview = paths.slice(0, 4).map((p) => esc(p)).join('<br>');
      const ok = await confirmDialog({
        title: '批量删除', danger: true, confirmText: `移入回收站 ${paths.length} 项`,
        message: `将以下 ${paths.length} 项（含目录内容）<b>移入回收站</b>，可在工具栏「回收站」中还原或彻底删除：<br><span class="mono" style="font-size:12px">${preview}${paths.length > 4 ? '<br>…' : ''}</span>`,
      });
      if (!ok) return;
      try {
        const res = await api.post('/api/files/delete', { paths });
        toast(res.message, res.ok ? 'ok' : 'warn');
        selected.clear();
        paintBatch();
        load(cwd);
      } catch (err) { toast(err.message, 'err'); }
    }

    async function doBatchMove() {
      const paths = [...selected];
      const dest = await promptDialog({
        title: '批量移动', label: '目标目录（绝对路径，必须已存在）', value: cwd, confirmText: '移动',
      });
      if (!dest) return;
      try {
        const res = await api.post('/api/files/move', { paths, dest });
        toast(res.message, res.ok ? 'ok' : 'warn');
        selected.clear();
        paintBatch();
        load(cwd);
      } catch (err) { toast(err.message, 'err'); }
    }

    async function doBatchArchive() {
      const paths = [...selected];
      if (!paths.length) return;
      toast('正在打包…', 'warn', 2000);
      try {
        // 路径列表走 POST body，拿到 zip 后交给隐藏 <a> 触发原生下载
        const res = await fetch('/api/files/archive', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ paths }),
          cache: 'no-store',
        });
        if (!res.ok) {
          let detail = `打包失败（HTTP ${res.status}）`;
          try { detail = (await res.json()).detail || detail; } catch (_) { /* 非 JSON 响应 */ }
          throw new Error(detail);
        }
        const now = new Date();
        const pad = (n) => String(n).padStart(2, '0');
        const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`
          + `-${pad(now.getHours())}${pad(now.getMinutes())}`;
        const url = URL.createObjectURL(await res.blob());
        const link = document.createElement('a');
        link.href = url;
        link.download = `batch-${stamp}.zip`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        selected.clear();
        paintBatch();
        load(cwd);
      } catch (err) { toast(err.message, 'err'); }
    }

    root.onclick = async (event) => {
      const crumb = event.target.closest('[data-crumb]');
      if (crumb) { load(crumb.dataset.crumb); return; }
      const rootPath = event.target.closest('[data-root]');
      if (rootPath) { load(rootPath.dataset.root); return; }
      const sortHead = event.target.closest('[data-sort]');
      if (sortHead) {
        const key = sortHead.dataset.sort;
        sortDir = sortKey === key ? -sortDir : 1;
        sortKey = key;
        sortEntries();
        renderTable();
        return;
      }
      const target = event.target.closest('[data-act]');
      if (!target) return;
      const action = target.dataset.act;
      const entry = entries[Number(target.dataset.index)];
      if (target.tagName === 'A' && action === 'edit') event.preventDefault();

      if (action === 'up') load(cwd.replace(/\/[^/]+\/?$/, '') || '/');
      if (action === 'refresh') load(cwd);
      if (action === 'search') doSearch();
      if (action === 'search-root') doSearch('/');
      if (action === 'open' && entry) load(entry.path);
      if (action === 'edit' && entry) openEditor(entry);
      if (action === 'preview' && entry) openPreview(entry);
      if (action === 'chmod' && entry) doChmod(entry);
      if (action === 'fetch-url') doFetchUrl();
      if (action === 'trash') openTrash();
      if (action === 'batch-delete') doBatchDelete();
      if (action === 'batch-move') doBatchMove();
      if (action === 'batch-archive') doBatchArchive();
      if (action === 'batch-clear') { selected.clear(); paintBatch(); renderTable(); }
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
      if (action === 'upload-dir') $('#dir-input').click();
      if (action === 'extract' && entry) {
        const ok = await confirmDialog({
          title: '解压压缩包', confirmText: '解压',
          message: `将解压到同级同名目录（已存在则拒绝）。压缩包 <b class="mono">${esc(entry.name)}</b> 不会被删除。`,
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/files/extract', { path: entry.path });
          toast(res.message);
          load(cwd);
        } catch (err) { toast(err.message, 'err'); }
      }
      if (action === 'du' && entry) {
        try {
          const res = await api.get(`/api/files/usage?path=${encodeURIComponent(entry.path)}`);
          toast(res.size === null || res.size === undefined
            ? (res.error || '无法统计大小')
            : `${entry.name} 共占用 ${bytes(res.size)}`);
        } catch (err) { toast(err.message, 'err'); }
      }
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
          title: '删除确认', danger: true, confirmText: '移入回收站',
          message: `确定要删除 <b class="mono">${esc(entry.path)}</b> 吗？<br>
            <span class="dim">将移入回收站（可在工具栏「回收站」中还原或彻底删除），并非立即抹除。</span>`,
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/files/delete', { paths: [entry.path] });
          toast(res.message, res.ok ? 'ok' : 'warn'); load(cwd);
        } catch (err) { toast(err.message, 'err'); }
      }
    };

    root.onchange = (event) => {
      const box = event.target.closest('[data-sel]');
      if (box) {
        if (box.checked) selected.add(box.dataset.sel);
        else selected.delete(box.dataset.sel);
        paintBatch();
        return;
      }
      if (event.target.id === 'show-hidden') { load(cwd); }
    };

    root.addEventListener('change', (event) => {
      if (event.target.id === 'sel-all') {
        entries.forEach((e) => {
          if (event.target.checked) selected.add(e.path);
          else selected.delete(e.path);
        });
        paintBatch();
        renderTable();
      }
    });

    const fileInput = $('#file-input');
    fileInput.onchange = async () => {
      await doUpload(fileInput.files);
      fileInput.value = '';
    };
    const dirInput = $('#dir-input');
    dirInput.onchange = async () => {
      await doUpload(dirInput.files);
      dirInput.value = '';
    };

    const zone = $('#drop-zone');
    ['dragover', 'dragenter'].forEach((type) => zone.addEventListener(type, (event) => {
      event.preventDefault();
      zone.classList.add('drag-over');
    }));
    ['dragleave', 'drop'].forEach((type) => zone.addEventListener(type, (event) => {
      event.preventDefault();
      zone.classList.remove('drag-over');
    }));
    zone.addEventListener('drop', (event) => {
      if (event.dataTransfer?.files?.length) doUpload(event.dataTransfer.files);
    });

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
  async render(root, res) {
    let info = null;
    let timer = null;
    let snippets = [];          // 由 /api/snippets 提供（服务端按当前地址渲染）
    let snippetQuery = '';

    async function loadSnippets() {
      // 令牌只存哈希、无法回显：片段里的令牌位固定是 YOUR_TOKEN 占位符
      const params = new URLSearchParams();
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
          <td>${(r.kind || r.source) === 'agent'
            ? '<span class="badge warn">Agent</span>'
            : '<span class="badge info">面板</span>'}</td>
          <td class="cell-sub">${esc(r.ip || '-')}</td>
          <td class="cell-main" title="${esc(r.command || r.target || '')}">${esc(S(r.command || r.target).slice(0, 80))}</td>
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

    /** 一次性展示令牌明文（磁盘只存哈希，关掉就找不回来）。 */
    function showPlainToken(token) {
      const body = document.createElement('div');
      body.innerHTML = `
        <div style="line-height:1.8;font-size:13px">
          <p style="margin-top:0">令牌明文<b>仅此一次</b>展示，关闭后无法找回；磁盘上只保存 SHA-256 哈希。</p>
          <div class="token-box"><code>${esc(token || '')}</code></div>
          <div class="row" style="margin-top:10px">
            <button class="btn sm ghost" id="agt-token-copy">复制令牌</button>
          </div>
        </div>`;
      const foot = document.createElement('div');
      foot.className = 'row';
      foot.innerHTML = '<button class="btn primary" data-ok>我已保存</button>';
      const modal = openModal({ title: '令牌已生成', body, footer: foot, size: 'narrow' });
      $('#agt-token-copy', body).onclick = () => copyText(token, '令牌已复制');
      $('[data-ok]', foot).onclick = () => modal.close();
    }

    function paint() {
      root.innerHTML = `
        <div class="grid c2">
          <div class="card">
            <h2>Agent 令牌</h2>
            <div class="row">
              <span class="badge ${info.enabled ? 'ok' : 'danger'}">${info.enabled ? `已启用 ${info.token_count || 0} 个` : '未生成'}</span>
              ${info.full_tokens ? `<span class="badge warn">${info.full_tokens} 个完整权限</span>` : '<span class="badge">无完整权限令牌</span>'}
              <span class="dim" style="font-size:12px">${info.token_updated_at ? `更新于 ${datetime(info.token_updated_at)}` : ''}</span>
            </div>
            <div class="token-box">
              <code>令牌以 SHA-256 哈希存储，创建后<b>无法再次回显</b>；请在「安全中心 → Agent 令牌」按最小权限签发</code>
            </div>
            <div class="row" style="margin-top:12px">
              <button class="btn sm primary" data-act="rotate">生成新令牌（full）</button>
              <button class="btn sm ghost" data-act="goto-security">安全中心管理令牌</button>
            </div>
            <div class="dim" style="font-size:12px;margin-top:12px;line-height:1.7">
              令牌保存在服务器本机配置文件（权限 0600），磁盘上只有哈希，明文仅在创建时展示一次；
              <b>仅在【内网模式】下生效</b>，关闭内网模式后所有 Agent 请求立即被拒绝。也可在服务器执行
              <span class="mono">serverpanel --agent-token</span> 生成。
            </div>
          </div>

          <div class="card">
            <h2>接入方式</h2>
            <dl class="kv" style="grid-template-columns:96px 1fr">
              <dt>请求地址</dt><dd>POST ${esc(info.base_url)}${esc(info.endpoint)}</dd>
              <dt>鉴权头</dt><dd>X-Agent-Token: &lt;令牌&gt;</dd>
              <dt>兼容方式</dt><dd>Authorization: Bearer &lt;令牌&gt;（不再支持 ?token= 查询参数）</dd>
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

      if (action === 'goto-security') { navigate('security'); return; }
      if (action === 'rotate') {
        const ok = await confirmDialog({
          title: '生成 Agent 令牌', confirmText: '生成',
          message: '将新建一个 <b>完整权限（full）</b>令牌，明文只在下一步展示一次。'
            + '建议改用「安全中心 → 创建令牌」按最小权限签发。确定继续吗？',
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/agent/token', { token: '' });
          await refresh();
          showPlainToken(res.token);
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
    timer = every(8000, loadRecent);
    res.own(() => clearInterval(timer));   // 登记到路由：render 抛错也能回收
    res.own(() => clearTimeout(searchTimer));
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
    // ESC 必须走「取消」把 Promise resolve 掉，否则 await formDialog(...) 永久悬挂，
    // 调用方（编辑常驻应用 / 填参数运行 / 删除确认）的后续刷新永远不会执行
    const modal = openModal({
      title, body, footer: foot, size: 'narrow',
      onEscape: () => { modal.close(); resolve(null); },
    });
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
  async render(root, res) {
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
          const res = await api.delConfirmed(`/api/panel/apps/${app.id}`, 'apps');
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
    timer = every(3000, () => { if (!logState) refresh().catch(() => {}); else loadLog(); });
    res.own(() => clearInterval(timer));   // 登记到路由：render 抛错也能回收
    return () => { clearInterval(timer); };
  },
});

/* ============================ 视图：安全中心（1.4.0） ============================ */

const SCOPE_LABEL = { full: '完整权限', readonly: '只读命令', custom: '自定义白名单' };

registerView('security', {
  title: '安全中心',
  async render(root, res) {
    let summary = null;
    let totp = null;
    let tokens = [];
    let sessions = [];
    let checkup = [];
    let auditDays = 7;
    let auditSource = '';
    let auditQ = '';
    let auditEvents = [];
    let loginEvents = [];

    async function loadAll() {
      const [s, t, tk, ss, ck] = await Promise.all([
        api.get('/api/panel/security'),
        api.get('/api/auth/totp/status'),
        api.get('/api/agent/tokens'),
        api.get('/api/panel/sessions'),
        api.get('/api/panel/security/checkup'),
      ]);
      summary = s; totp = t; tokens = tk.tokens; sessions = ss.sessions;
      checkup = ck.items || [];
    }

    // ---------------- TOTP ----------------

    async function openTotpSetup() {
      const setup = await api.post('/api/auth/totp/setup', {});
      const body = document.createElement('div');
      body.innerHTML = `
        <div style="line-height:1.8;font-size:13px">
          <p style="margin-top:0">用 authenticator App（Microsoft / Google Authenticator、
            1Password、Bitwarden 等）<b>手动添加密钥</b>，或粘贴下方配置链接：</p>
          <div class="token-box"><code id="totp-secret">${esc(setup.secret)}</code></div>
          <div class="row" style="margin:8px 0 12px">
            <button class="btn sm ghost" id="totp-copy-secret">复制密钥</button>
            <button class="btn sm ghost" id="totp-copy-uri">复制配置链接</button>
          </div>
          <div class="log-output" style="padding:10px;white-space:pre-wrap;word-break:break-all">${esc(setup.uri)}</div>
          <label class="field" style="margin-top:12px"><span>输入 App 显示的 6 位动态码</span>
            <input class="input" id="totp-code" inputmode="numeric" autocomplete="one-time-code"
                   placeholder="000000" maxlength="6" style="letter-spacing:4px"></label>
          <div class="dim" style="font-size:12px">启用后每次登录都需要动态码；请确认设备时间与服务器同步。</div>
        </div>`;
      const foot = document.createElement('div');
      foot.className = 'row';
      foot.innerHTML = `<button class="btn" data-cancel>取消</button>
        <button class="btn primary" data-ok>校验并启用</button>`;
      const modal = openModal({ title: '启用二次认证（TOTP）', body, footer: foot, size: 'wide' });
      $('#totp-copy-secret', body).onclick = () => copyText(setup.secret, '密钥已复制');
      $('#totp-copy-uri', body).onclick = () => copyText(setup.uri, '配置链接已复制');
      $('[data-cancel]', foot).onclick = () => modal.close();
      $('[data-ok]', foot).onclick = async () => {
        const code = ($('#totp-code', body).value || '').trim();
        if (!/^\d{6}$/.test(code)) { toast('请输入 6 位数字动态码', 'err'); return; }
        try {
          const res = await api.post('/api/auth/totp/enable', { code });
          modal.close();
          showRecoveryCodes(res.recovery_codes, '二次认证已启用');
          await loadAll(); paint();
        } catch (err) { toast(err.message, 'err'); }
      };
      setTimeout(() => $('#totp-code', body).focus(), 40);
    }

    function showRecoveryCodes(codes, title) {
      const body = document.createElement('div');
      body.innerHTML = `
        <div style="line-height:1.8;font-size:13px">
          <p style="margin-top:0">以下是 <b>10 个一次性恢复码</b>，每个只能使用一次。
            遗失验证设备时，可输其中任意一个代替动态码登录。</p>
          <div class="log-output" style="padding:12px;white-space:pre;font-size:14px;letter-spacing:1px">${codes.map(esc).join('\n')}</div>
          <div class="dim" style="font-size:12px;margin-top:8px">恢复码仅此一次展示，关闭后无法再次查看；请立即保存到密码管理器。</div>
        </div>`;
      const foot = document.createElement('div');
      foot.className = 'row';
      foot.innerHTML = `<button class="btn" data-cancel>关闭</button>
        <button class="btn primary" data-ok>复制全部</button>`;
      const modal = openModal({ title, body, footer: foot, size: 'narrow' });
      $('[data-cancel]', foot).onclick = () => modal.close();
      $('[data-ok]', foot).onclick = async () => {
        await copyText(codes.join('\n'), '恢复码已复制');
        modal.close();
      };
    }

    async function totpDisable() {
      const password = await promptDialog({
        title: '关闭二次认证', label: '请输入当前面板密码以确认', confirmText: '验证并关闭',
      });
      if (!password) return;
      try {
        const res = await api.post('/api/auth/totp/disable', { password });
        toast(res.message, 'ok');
        await loadAll(); paint();
      } catch (err) { toast(err.message, 'err'); }
    }

    async function totpRegenerate() {
      const code = await promptDialog({
        title: '重新生成恢复码', label: '请输入当前 6 位动态码', confirmText: '验证并重新生成',
      });
      if (!code) return;
      try {
        const res = await api.post('/api/auth/totp/recovery-codes', { code: code.trim() });
        showRecoveryCodes(res.recovery_codes, '恢复码已重新生成');
        await loadAll(); paint();
      } catch (err) { toast(err.message, 'err'); }
    }

    // ---------------- Agent 令牌 ----------------

    async function openTokenCreate() {
      const body = document.createElement('div');
      body.innerHTML = `
        <label class="field"><span>名称</span>
          <input class="input" id="tk-name" value="未命名令牌" maxlength="60" autocomplete="off"></label>
        <label class="field"><span>作用域</span>
          <select class="input" id="tk-scope">
            <option value="full">完整权限（等价 root shell）</option>
            <option value="readonly">只读命令（白名单内的查看类命令）</option>
            <option value="custom">自定义前缀白名单</option>
          </select></label>
        <label class="field hidden" id="tk-prefixes-field"><span>允许的命令前缀（每行一个，如 <code>systemctl restart nginx</code>）</span>
          <textarea class="input" id="tk-prefixes" rows="3" style="font-family:ui-monospace,monospace"></textarea>
          <p class="dim" id="tk-prefixes-hint" style="font-size:12px;line-height:1.6;margin-top:6px">custom 作用域不支持 <code>$()</code>、反引号、<code>&gt;</code>、<code>&gt;&gt;</code>、<code>&lt;</code>、<code>*</code>、<code>?</code>、<code>&amp;</code>（单个）、换行等 shell 元字符，含这些字符的命令会被拒绝。</p></label>
        <label class="field"><span>过期天数（0 = 永不过期）</span>
          <input class="input" id="tk-expires" type="number" value="0" min="0" max="3650"></label>
        <label class="field"><span>备注（用途说明，可选）</span>
          <input class="input" id="tk-note" maxlength="120" autocomplete="off"></label>`;
      const foot = document.createElement('div');
      foot.className = 'row';
      foot.innerHTML = `<button class="btn" data-cancel>取消</button>
        <button class="btn primary" data-ok>创建令牌</button>`;
      const modal = openModal({ title: '创建 Agent 令牌', body, footer: foot });
      $('#tk-scope', body).onchange = (event) => {
        $('#tk-prefixes-field', body).classList.toggle('hidden', event.target.value !== 'custom');
      };
      $('[data-cancel]', foot).onclick = () => modal.close();
      $('[data-ok]', foot).onclick = async () => {
        const scope = $('#tk-scope', body).value;
        const prefixes = scope === 'custom'
          ? ($('#tk-prefixes', body).value || '').split('\n').map((line) => line.trim()).filter(Boolean)
          : [];
        const payload = {
          name: ($('#tk-name', body).value || '').trim() || '未命名令牌',
          scope,
          prefixes,
          expires_days: Number($('#tk-expires', body).value || 0),
          note: ($('#tk-note', body).value || '').trim(),
        };
        try {
          const res = await api.post('/api/agent/tokens', payload);
          modal.close();
          showTokenPlain(res.token, payload.name);
          await loadAll(); paint();
        } catch (err) { toast(err.message, 'err'); }
      };
    }

    function showTokenPlain(token, name) {
      const body = document.createElement('div');
      body.innerHTML = `
        <div style="line-height:1.8;font-size:13px">
          <p style="margin-top:0">令牌 <b>${esc(name)}</b> 已创建。明文仅此一次展示，关闭后无法找回；磁盘上只保存哈希。</p>
          <div class="token-box"><code>${esc(token)}</code></div>
          <div class="row" style="margin-top:10px">
            <button class="btn sm ghost" id="tk-copy">复制令牌</button>
          </div>
        </div>`;
      const foot = document.createElement('div');
      foot.className = 'row';
      foot.innerHTML = `<button class="btn primary" data-ok>我已保存</button>`;
      const modal = openModal({ title: '令牌已创建', body, footer: foot, size: 'narrow' });
      $('#tk-copy', body).onclick = () => copyText(token, '令牌已复制');
      $('[data-ok]', foot).onclick = () => modal.close();
    }

    async function tokenRevoke(item) {
      const ok = await confirmDialog({
        title: '吊销令牌', danger: true, confirmText: '吊销',
        message: `令牌 <b class="mono">${esc(item.name)}</b> 将立即失效，使用该令牌的脚本会收到 401。`,
      });
      if (!ok) return;
      try {
        await api.del(`/api/agent/tokens/${encodeURIComponent(item.id)}`);
        toast('令牌已吊销', 'ok');
        await loadAll(); paint();
      } catch (err) { toast(err.message, 'err'); }
    }

    async function tokensRevokeAll() {
      const ok = await confirmDialog({
        title: '吊销全部令牌', danger: true, confirmText: '全部吊销', phrase: 'REVOKE',
        message: '所有 Agent 令牌将立即失效，正在使用令牌的自动化会全部中断。',
      });
      if (!ok) return;
      try {
        const res = await api.delConfirmed('/api/agent/tokens', 'tokens');
        toast(res.message, 'ok');
        await loadAll(); paint();
      } catch (err) { toast(err.message, 'err'); }
    }

    // ---------------- 会话 ----------------

    async function sessionRevoke(item) {
      const ok = await confirmDialog({
        title: '踢出会话', danger: true, confirmText: '踢出',
        message: `将强制下线来自 <b class="mono">${esc(item.ip || '未知 IP')}</b> 的会话（${datetime(item.created)} 创建）。`,
      });
      if (!ok) return;
      try {
        await api.post('/api/panel/sessions/revoke', { id: item.id });
        toast('会话已踢出', 'ok');
        await loadAll(); paint();
      } catch (err) { toast(err.message, 'err'); }
    }

    async function sessionsRevokeOthers() {
      const ok = await confirmDialog({
        title: '踢出其他会话', danger: true, confirmText: '全部踢出',
        message: '除当前会话外的所有登录会话将立即失效，其他设备需要重新登录。',
      });
      if (!ok) return;
      try {
        const res = await api.post('/api/panel/sessions/revoke-others', {});
        toast(res.message, 'ok');
        await loadAll(); paint();
      } catch (err) { toast(err.message, 'err'); }
    }

    // ---------------- 审计日志 ----------------

    function auditTable(events) {
      if (!events.length) return '<div class="empty">没有匹配的审计记录</div>';
      return `<div class="table-wrap"><table class="data"><thead><tr>
        <th>时间</th><th>操作</th><th>对象 / 摘要</th><th>来源</th>
        <th>来源 IP</th><th class="num">结果</th><th class="num">耗时</th></tr></thead>
        <tbody>${events.map((e) => `<tr>
          <td class="cell-sub">${datetime(e.time)}</td>
          <td><span class="badge ${e.ok ? 'info' : 'danger'}">${esc(e.action)}</span></td>
          <td class="cell-main" title="${esc(e.summary || '')}">${esc(e.target || '-')}
            ${e.summary ? `<span class="cell-sub">${esc(S(e.summary).slice(0, 60))}</span>` : ''}</td>
          <td>${e.source === 'agent' ? '<span class="badge warn">Agent</span>'
            : e.source === 'cli' ? '<span class="badge">CLI</span>'
            : e.source === 'system' ? '<span class="badge">系统</span>'
            : '<span class="badge info">面板</span>'}
            ${e.actor ? `<span class="cell-sub">${esc(e.actor)}</span>` : ''}</td>
          <td class="cell-sub">${esc(e.ip || '-')}</td>
          <td class="num"><span class="badge ${e.ok ? 'ok' : 'danger'}">${e.ok ? '成功' : '失败'}</span></td>
          <td class="num">${e.duration == null ? '-' : `${e.duration}s`}</td>
        </tr>`).join('')}</tbody></table></div>`;
    }

    // CSV 单元格转义：Excel / WPS 会把以 = + - @、TAB、CR 开头的单元格当公式
    // 执行（CSV 注入），前置一个单引号让它按纯文本处理；含引号/逗号/换行时按
    // RFC 4180 用双引号包裹，内部双引号翻倍。
    function csvCell(value) {
      let text = value == null ? '' : String(value);
      if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
      if (/[",\n\r]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
      return text;
    }

    function buildAuditCsv(events) {
      const header = ['时间', '动作', '来源', '来源IP', '执行者', '目标', '摘要', '结果', '退出码', '耗时'];
      const rows = events.map((e) => [
        datetime(e.time), e.action, e.source, e.ip, e.actor, e.target, e.summary,
        e.ok ? '成功' : '失败', e.code == null ? '' : e.code,
        e.duration == null ? '' : `${e.duration}s`,
      ]);
      return [header, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n');
    }

    function exportAuditCsv() {
      if (!auditEvents.length) {
        toast('当前筛选结果为空，没有可导出的记录', 'warn');
        return;
      }
      const now = new Date();
      const pad = (n) => String(n).padStart(2, '0');
      const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`
        + `-${pad(now.getHours())}${pad(now.getMinutes())}`;
      // BOM 让 Excel/WPS 正确识别 UTF-8 中文
      const blob = new Blob([`\ufeff${buildAuditCsv(auditEvents)}`],
        { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `audit-${stamp}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      // 导出动作本身也留痕（只记录条数与筛选条件，不回传导出数据）
      api.post('/api/panel/audit/export', {
        count: auditEvents.length,
        filters: [`${auditDays}天`, auditSource || '全部来源', auditQ].filter(Boolean).join(' / '),
      }).catch(() => {});
    }

    async function loadLogins() {
      const box = $('#sec-logins-body');
      if (!box) return;
      try {
        // 复用现有审计查询接口（不新增端点）：成功与失败各取最近 20 条
        const [okRes, badRes] = await Promise.all([
          api.get('/api/panel/audit/log?days=7&action=login&limit=20'),
          api.get('/api/panel/audit/log?days=7&action=login_failed&limit=20'),
        ]);
        loginEvents = [
          ...okRes.events.map((e) => ({ ...e, success: true })),
          ...badRes.events.map((e) => ({ ...e, success: false })),
        ].sort((a, b) => (b.time || 0) - (a.time || 0)).slice(0, 20);
        paintLogins();
      } catch (err) {
        box.innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
      }
    }

    function paintLogins() {
      const box = $('#sec-logins-body');
      if (!box) return;
      if (!loginEvents.length) {
        box.innerHTML = '<div class="empty">最近 7 天没有登录记录</div>';
        return;
      }
      box.innerHTML = `<div class="table-wrap"><table class="data"><thead><tr>
        <th>时间</th><th>结果</th><th>来源 IP</th></tr></thead>
        <tbody>${loginEvents.map((e) => `<tr>
          <td class="cell-sub">${datetime(e.time)}</td>
          <td><span class="badge ${e.success ? 'ok' : 'danger'}">${e.success ? '成功' : '失败'}</span></td>
          <td class="cell-sub mono">${esc(e.ip || '-')}</td>
        </tr>`).join('')}</tbody></table></div>`;
    }

    async function loadAudit() {
      const box = $('#sec-audit-body');
      if (!box) return;
      box.innerHTML = '<div class="empty">加载中…</div>';
      try {
        const params = new URLSearchParams({ days: S(auditDays), limit: '300' });
        if (auditSource) params.set('source', auditSource);
        if (auditQ) params.set('q', auditQ);
        const data = await api.get(`/api/panel/audit/log?${params.toString()}`);
        auditEvents = data.events || [];
        box.innerHTML = auditTable(auditEvents);
      } catch (err) {
        box.innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
      }
    }

    // ---------------- 渲染 ----------------

    function checkupCard() {
      const badge = { ok: 'ok', warn: 'warn', bad: 'danger' };
      const label = { ok: '正常', warn: '建议处理', bad: '需立即处理' };
      const worst = checkup.some((it) => it.level === 'bad') ? 'bad'
        : checkup.some((it) => it.level === 'warn') ? 'warn' : 'ok';
      const rows = checkup.map((it) => `
        <button class="checkup-item" data-checkup-target="${esc(it.target || '')}"
                style="display:flex;gap:10px;align-items:flex-start;width:100%;text-align:left;background:none;border:0;padding:8px 0;color:inherit;cursor:${it.target ? 'pointer' : 'default'}">
          <span class="badge ${badge[it.level] || 'ok'}">${esc(label[it.level] || it.level)}</span>
          <span style="flex:1">
            <span class="cell-main">${esc(it.title)}</span>
            <span class="cell-sub">${esc(it.detail)}</span>
          </span>
        </button>`).join('');
      return `<div class="card" id="security-checkup" style="margin-bottom:14px">
        <h2>安全巡检
          <span class="badge ${badge[worst]}">${worst === 'ok' ? '未发现待处理项' : '有待办'}</span>
        </h2>
        <div class="dim" style="font-size:12px;margin:4px 0 6px">汇总当前安全短板，点击条目跳到对应卡片。</div>
        ${rows}
      </div>`;
    }

    function paint() {
      const lock = summary?.lockout || {};
      root.innerHTML = `
        ${checkupCard()}

        <div class="grid c4" style="margin-bottom:14px">
          <div class="card" id="security-totp">
            <div class="metric-label">二次认证（TOTP）</div>
            <div class="metric-value" style="font-size:20px">
              ${totp?.enabled ? '<span class="badge ok">已启用</span>' : '<span class="badge danger">未启用</span>'}</div>
            <div class="metric-sub">剩余恢复码 ${totp?.recovery_left ?? 0} 个</div>
          </div>
          <div class="card" id="security-lockout">
            <div class="metric-label">登录防爆破</div>
            <div class="metric-value" style="font-size:20px">${lock.ip_failures ?? 0} 次失败</div>
            <div class="metric-sub">${lock.locked_seconds > 0
              ? `<span class="badge danger">锁定中 · 剩余 ${lock.locked_seconds}s</span>`
              : `当前 IP 未锁定 · 全局 ${lock.global_failures ?? 0} 次`}</div>
          </div>
          <div class="card" id="security-sessions">
            <div class="metric-label">活跃会话 / Agent 令牌</div>
            <div class="metric-value" style="font-size:20px">${summary?.sessions?.active ?? 0} / ${summary?.tokens?.total ?? 0}</div>
            <div class="metric-sub">完整权限令牌 ${summary?.tokens?.full ?? 0} 个</div>
          </div>
          <div class="card" id="security-trash">
            <div class="metric-label">回收站</div>
            <div class="metric-value" style="font-size:20px">${summary?.trash?.count ?? 0} 项</div>
            <div class="metric-sub">占用 ${bytes(summary?.trash?.bytes || 0)} · 保留 ${summary?.trash?.retention_days ?? 0} 天</div>
            ${summary?.trash?.over_limit
              ? '<div style="margin-top:6px"><span class="badge warn">占用超过水位</span></div>' : ''}
          </div>
        </div>

        <div class="grid c2">
          <div class="card">
            <h2>二次认证</h2>
            <div class="dim" style="font-size:12px;line-height:1.7;margin:4px 0 10px">
              启用后登录需要「密码 + 6 位动态码」，动态码错误同样计入失败锁定；
              恢复码可在遗失设备时兜底登录（一次性）。
            </div>
            <div class="row">
              ${totp?.enabled
                ? `<button class="btn sm ghost" id="sec-totp-recovery">重新生成恢复码</button>
                   <button class="btn sm danger" id="sec-totp-disable">关闭二次认证</button>`
                : `<button class="btn sm primary" id="sec-totp-enable">启用二次认证</button>`}
            </div>
            ${totp?.enabled && totp.enabled_at
              ? `<div class="dim" style="font-size:12px;margin-top:8px">启用时间 ${datetime(totp.enabled_at)}</div>` : ''}
          </div>

          <div class="card">
            <h2>活跃会话</h2>
            <div class="dim" style="font-size:12px;margin:4px 0 10px">登录态保存在服务器本机（哈希存储），重启面板不失效。</div>
            <div class="row" style="margin-bottom:10px">
              <button class="btn sm ghost" id="sec-session-refresh">刷新</button>
              <button class="btn sm danger" id="sec-session-revoke-others">踢出其他会话</button>
            </div>
            <div class="table-wrap"><table class="data"><thead><tr>
              <th>会话</th><th>来源 IP</th><th>创建时间</th><th>过期时间</th><th></th></tr></thead>
              <tbody>${sessions.length ? sessions.map((it) => `<tr>
                <td class="cell-main">${it.current ? '<span class="badge ok">当前会话</span>' : `<span class="mono">${esc(it.id)}…</span>`}
                  ${it.label ? `<span class="cell-sub">${esc(it.label)}</span>` : ''}</td>
                <td class="cell-sub">${esc(it.ip || '-')}</td>
                <td class="cell-sub">${datetime(it.created)}</td>
                <td class="cell-sub">${datetime(it.expires)}</td>
                <td><button class="btn sm ghost" data-session-revoke="${esc(it.id)}" ${it.current ? 'disabled' : ''}>踢出</button></td>
              </tr>`).join('') : '<tr><td colspan="5"><div class="empty">暂无活跃会话</div></td></tr>'}</tbody></table></div>
          </div>
        </div>

        <div class="card" style="margin-top:14px" id="security-logins">
          <h2>最近登录</h2>
          <div class="dim" style="font-size:12px;margin:4px 0 10px">
            最近 7 天成功与失败的登录记录（数据来自审计日志，每 30 秒刷新）。
          </div>
          <div id="sec-logins-body"><div class="empty">加载中…</div></div>
        </div>

        <div class="card" style="margin-top:14px" id="security-tokens">
          <h2>Agent 令牌</h2>
          <div class="dim" style="font-size:12px;margin:4px 0 10px">
            令牌按「名称 + 作用域」管理：只读令牌只能执行查看类命令，自定义令牌按前缀白名单放行。
            令牌仅在内网模式下生效，磁盘上只存 SHA-256 哈希。
          </div>
          <div class="row" style="margin-bottom:10px">
            <button class="btn sm primary" id="sec-token-create">创建令牌</button>
            <button class="btn sm danger" id="sec-token-revoke-all" ${tokens.length ? '' : 'disabled'}>吊销全部</button>
          </div>
          <div class="table-wrap"><table class="data"><thead><tr>
            <th>名称</th><th>作用域</th><th>创建时间</th><th>最近使用</th><th>过期</th><th></th></tr></thead>
            <tbody>${tokens.length ? tokens.map((t) => `<tr>
              <td class="cell-main">${esc(t.name)}
                ${t.note ? `<span class="cell-sub">${esc(t.note)}</span>` : ''}
                ${t.prefixes?.length ? `<span class="cell-sub mono">${t.prefixes.map(esc).join(' · ')}</span>` : ''}</td>
              <td><span class="badge ${t.scope === 'full' ? 'warn' : 'info'}">${esc(SCOPE_LABEL[t.scope] || t.scope)}</span></td>
              <td class="cell-sub">${t.created_at ? datetime(t.created_at) : '-'}</td>
              <td class="cell-sub">${t.last_used_at ? datetime(t.last_used_at) : '未使用'}</td>
              <td>${t.expires_at
                ? (t.expired ? '<span class="badge danger">已过期</span>' : `<span class="cell-sub">${datetime(t.expires_at)}</span>`)
                : '<span class="badge">永久</span>'}</td>
              <td><button class="btn sm ghost" data-token-revoke="${esc(t.id)}">吊销</button></td>
            </tr>`).join('') : '<tr><td colspan="6"><div class="empty">尚未创建令牌</div></td></tr>'}</tbody></table></div>
        </div>

        <div class="card" style="margin-top:14px" id="security-audit">
          <h2>审计日志</h2>
          <div class="dim" style="font-size:12px;margin:4px 0 10px">
            所有敏感操作（登录、命令执行、文件变更、令牌与会话管理）统一记录，按天滚动、保留 90 天，不可删除。
          </div>
          <div class="toolbar" style="margin-bottom:10px">
            <select class="input" id="sec-audit-days" style="width:110px">
              <option value="1" ${auditDays === 1 ? 'selected' : ''}>最近 1 天</option>
              <option value="7" ${auditDays === 7 ? 'selected' : ''}>最近 7 天</option>
              <option value="30" ${auditDays === 30 ? 'selected' : ''}>最近 30 天</option>
            </select>
            <select class="input" id="sec-audit-source" style="width:110px">
              <option value="" ${auditSource === '' ? 'selected' : ''}>全部来源</option>
              <option value="web" ${auditSource === 'web' ? 'selected' : ''}>面板</option>
              <option value="agent" ${auditSource === 'agent' ? 'selected' : ''}>Agent</option>
              <option value="cli" ${auditSource === 'cli' ? 'selected' : ''}>CLI</option>
              <option value="system" ${auditSource === 'system' ? 'selected' : ''}>系统</option>
            </select>
            <input class="input" id="sec-audit-q" placeholder="搜索对象 / 摘要…" value="${esc(auditQ)}" style="width:200px">
            <button class="btn sm" id="sec-audit-search">查询</button>
            <button class="btn sm ghost" id="sec-audit-export" title="导出当前筛选结果（CSV）">导出 CSV</button>
          </div>
          <div id="sec-audit-body"><div class="empty">加载中…</div></div>
        </div>`;

      $('#sec-totp-enable')?.addEventListener('click', () => {
        openTotpSetup().catch((err) => toast(err.message, 'err'));
      });
      $('#sec-totp-disable')?.addEventListener('click', () => totpDisable());
      $('#sec-totp-recovery')?.addEventListener('click', () => totpRegenerate());
      $('#sec-token-create')?.addEventListener('click', () => openTokenCreate());
      $('#sec-token-revoke-all')?.addEventListener('click', () => tokensRevokeAll());
      $('#sec-session-refresh')?.addEventListener('click', async () => {
        try { await loadAll(); paint(); } catch (err) { toast(err.message, 'err'); }
      });
      $('#sec-session-revoke-others')?.addEventListener('click', () => sessionsRevokeOthers());
      $('#sec-audit-search')?.addEventListener('click', () => {
        auditDays = Number($('#sec-audit-days').value || 7);
        auditSource = $('#sec-audit-source').value;
        auditQ = ($('#sec-audit-q').value || '').trim();
        loadAudit();
      });
      $('#sec-audit-export')?.addEventListener('click', () => exportAuditCsv());
      $('#sec-audit-q')?.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') $('#sec-audit-search').click();
      });
      $$('[data-checkup-target]', root).forEach((btn) => {
        btn.addEventListener('click', () => {
          const target = btn.dataset.checkupTarget;
          if (!target) return;
          if (target === 'settings') { navigate('settings'); return; }
          document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
      });
      $$('[data-token-revoke]', root).forEach((btn) => btn.addEventListener('click', () => {
        const item = tokens.find((t) => t.id === btn.dataset.tokenRevoke);
        if (item) tokenRevoke(item);
      }));
      $$('[data-session-revoke]', root).forEach((btn) => btn.addEventListener('click', () => {
        const item = sessions.find((s) => s.id === btn.dataset.sessionRevoke);
        if (item) sessionRevoke(item);
      }));
      loadAudit();
      loadLogins();
    }

    try {
      await loadAll();
    } catch (err) {
      root.innerHTML = `<div class="card"><div class="empty">安全中心加载失败：${esc(err.message)}</div></div>`;
      return;
    }
    paint();
    // 最近登录定时刷新；定时器登记到路由资源表，切视图时回收（1.5.0 规范）
    const loginTimer = setInterval(loadLogins, 30000);
    res.own(() => clearInterval(loginTimer));
  },
});

/* ============================ 视图：设置 ============================ */

/** 探测面板版本端点（需登录）。返回 { up, version, build, relogin }。
 *  up=false 表示面板还在重启（网络不可达）；relogin=true 表示面板已恢复但会话失效
 *  （升级耗时超过会话时长时会走到这里，交给上层重新登录）。 */
async function probeVersion(url = '/api/system/version') {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (r.status === 401) return { up: true, relogin: true, version: '', build: '' };
    if (!r.ok) return { up: false, version: '', build: '' };
    const data = await r.json().catch(() => ({}));
    return { up: true, version: data.version || '', build: data.build || '' };
  } catch (err) {
    return { up: false, version: '', build: '' };
  }
}

/** 等待面板重启完成（升级 / 改监听地址后都会用），返回是否成功恢复。 */
function waitForPanelRestart({ before = '', expected = null, timeoutMs = 180000,
                              onProgress = null, probeUrl = '/api/system/version' } = {}) {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const timer = every(2500, async () => {  // every：切后台暂停探测，回前台继续
      const probe = await probeVersion(probeUrl);
      if (probe.up) {
        // 401（会话失效）时没有版本信息可比：面板已经恢复，直接放行让上层处理登录
        const stamp = probe.build || probe.version || '';
        const hit = probe.relogin
          ? true
          : (expected ? (probe.version === expected || stamp === expected)
                      : (stamp && stamp !== before));
        if (hit) {
          clearInterval(timer);
          resolve({ ok: true, health: probe, relogin: !!probe.relogin });
          return;
        }
        if (onProgress) onProgress('面板已响应，等待新版本生效…');
      } else if (onProgress) {
        onProgress('面板重启中，等待恢复…');
      }
      if (Date.now() > deadline) {
        clearInterval(timer);
        resolve({ ok: false, health: null });
      }
    });
  });
}

/* ============================ 视图：运维（2.0 M3） ============================ */

/*
 * 九个面板全部基于系统自带 CLI（crontab / tar / rclone / apt / docker / ufw /
 * nginx / openssl / mysql / psql / redis-cli / ssh-keygen / ping / traceroute /
 * mtr / curl）。能力探测不通过时只显示 dim 提示，不提供"假装可用"的按钮。
 */

const OPS_TABS = [
  { id: 'cron', label: '定时任务' },
  { id: 'backup', label: '备份' },
  { id: 'update', label: '系统更新' },
  { id: 'docker', label: 'Docker' },
  { id: 'firewall', label: '防火墙' },
  { id: 'proxy', label: '反代 / 证书' },
  { id: 'db', label: '数据库' },
  { id: 'ssh', label: 'SSH 密钥' },
  { id: 'net', label: '网络工具' },
  { id: 'recording', label: '会话录制' },
];

const opsHint = (title, hint) => `<div class="card"><h2>${esc(title)}</h2>
  <div class="dim" style="line-height:1.8">${hint}</div></div>`;

const opsFail = (err) => `<div class="card"><div class="empty">读取失败：${esc(err.message)}</div></div>`;

/** 与后端 app/ops.py 同规则的轻量解析：只用于在表格里预览/切启停。 */
function cronParse(line) {
  const text = S(line || '').trim();
  const off = text.startsWith('#');
  const body = off ? text.replace(/^#\s*/, '') : text;
  const parts = body.split(/\s+/).filter(Boolean);
  let schedule = '';
  let command = '';
  if (parts.length) {
    if (parts[0].startsWith('@')) {
      schedule = parts[0];
      command = parts.slice(1).join(' ');
    } else {
      schedule = parts.slice(0, 5).join(' ');
      command = parts.slice(5).join(' ');
    }
  }
  return { off, schedule, command };
}

/* ---------- 定时任务 ---------- */

async function opsCron(host, ctx) {
  const data = await api.get('/api/panel/maintenance/cron');
  if (!data.capabilities.crontab) {
    host.innerHTML = opsHint('定时任务不可用',
      '本机没有 <span class="mono">crontab</span> 命令（容器与精简系统常见）。<br>'
      + '需要后台常驻时，可改用「常驻应用」托管进程。');
    return null;
  }
  host.innerHTML = `
    <div class="card">
      <div class="toolbar" style="margin-bottom:8px">
        <span class="badge">${data.lines.length} 行</span>
        ${data.error ? `<span class="badge warn">${esc(data.error)}</span>` : ''}
        <div class="spacer"></div>
        <button class="btn sm" data-act="cron-reload">重新读取</button>
        <button class="btn sm primary" data-act="cron-save">保存 crontab</button>
      </div>
      <div class="dim" style="margin-bottom:8px">
        每行一条任务，以 <span class="mono">#</span> 开头的行表示停用。保存前会自动备份到配置目录，
        写入后读回校验，不一致立即回滚。
      </div>
      <textarea class="input mono" id="cron-text" spellcheck="false"
        style="width:100%;height:200px;line-height:1.6"></textarea>
    </div>
    <div class="card flush"><div class="table-wrap" id="cron-table"></div></div>`;

  const textarea = $('#cron-text', host);
  textarea.value = data.lines.map((item) => item.raw).join('\n');

  const paint = () => {
    const table = $('#cron-table', host);
    if (!table) return;
    const rows = textarea.value.split('\n')
      .map((line, index) => ({ line, index }))
      .filter((row) => row.line.trim());
    table.innerHTML = rows.length ? `<table class="data">
      <thead><tr><th>状态</th><th>计划</th><th>命令</th><th></th></tr></thead><tbody>
      ${rows.map((row) => {
    const parsed = cronParse(row.line);
    return `<tr>
        <td>${parsed.off ? '<span class="badge">已停用</span>' : '<span class="badge ok">已启用</span>'}</td>
        <td class="mono">${esc(parsed.schedule || '-')}</td>
        <td class="cell-sub mono" style="max-width:520px;overflow:hidden;text-overflow:ellipsis">${esc(parsed.command || row.line.trim())}</td>
        <td class="actions"><button class="btn sm" data-act="cron-toggle" data-index="${row.index}">
          ${parsed.off ? '启用' : '停用'}</button></td></tr>`;
  }).join('')}</tbody></table>` : '<div class="empty">还没有定时任务</div>';
  };
  paint();

  host.onclick = async (event) => {
    const btn = event.target.closest('[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;
    if (act === 'cron-toggle') {
      const arr = textarea.value.split('\n');
      const index = Number(btn.dataset.index);
      const line = arr[index];
      if (line === undefined) return;
      arr[index] = line.trim().startsWith('#')
        ? line.trim().replace(/^#\s*/, '')
        : `# ${line.trim()}`;
      textarea.value = arr.join('\n');
      paint();
      return;
    }
    if (act === 'cron-reload') { await ctx.open('cron'); return; }
    if (act === 'cron-save') {
      const ok = await confirmDialog({
        title: '写入 crontab', confirmText: '写入',
        message: '将用当前内容<b>覆盖</b>系统 crontab（写入前自动备份到配置目录）。确定继续？',
      });
      if (!ok) return;
      try {
        const res = await api.post('/api/panel/maintenance/cron', { content: textarea.value });
        toast(res.message);
        await ctx.open('cron');
      } catch (err) { toast(err.message, 'err'); }
    }
  };
  return null;
}

/* ---------- 备份 ---------- */

function opsBackupTable(items, rclone) {
  if (!items.length) return '<div class="empty">还没有备份</div>';
  return `<table class="data"><thead><tr>
      <th>备份文件</th><th>大小</th><th>创建时间</th><th></th></tr></thead><tbody>
    ${items.map((item) => `<tr>
      <td class="cell-main mono">${esc(item.name)}</td>
      <td>${bytes(item.size)}</td>
      <td class="cell-sub">${datetime(item.mtime)}</td>
      <td class="actions">
        ${rclone ? `<button class="btn sm ghost" data-act="bk-upload" data-name="${esc(item.name)}">上传</button>` : ''}
        <button class="btn sm danger" data-act="bk-del" data-name="${esc(item.name)}">删除</button>
      </td></tr>`).join('')}</tbody></table>`;
}

async function opsBackup(host, ctx) {
  const data = await api.get('/api/panel/maintenance/backups');
  const remote = await api.get('/api/panel/maintenance/backups/remotes')
    .catch(() => ({ remotes: [], capabilities: {} }));
  const rclone = !!data.capabilities.rclone;
  host.innerHTML = `
    <div class="card">
      <div class="toolbar" style="margin-bottom:10px">
        <span class="badge">${data.items.length} 个备份</span>
        <span class="dim mono">${esc(data.dir)}</span>
        <div class="spacer"></div>
        <button class="btn sm" data-act="bk-refresh">刷新</button>
      </div>
      <label class="field"><span>要备份的路径（每行一个，必须是绝对路径）</span>
        <textarea class="input mono" id="bk-paths" spellcheck="false" style="height:84px"
          placeholder="/etc/serverpanel&#10;/root/.ssh"></textarea></label>
      <label class="field"><span>备份名（可留空自动生成，需以 .tar.gz 结尾）</span>
        <input class="input mono" id="bk-name" placeholder="backup-20250101-000000.tar.gz"></label>
      <label class="field"><span>备份目录（绝对路径，对应设置项 backup.dir；留空回到默认目录）</span>
        <div class="row">
          <input class="input mono" id="bk-dir" value="${esc(data.dir)}" style="flex:1">
          <button class="btn sm" data-act="bk-dir-save">保存目录</button>
        </div></label>
      <div class="row">
        <button class="btn sm primary" data-act="bk-create">创建备份</button>
        <span class="dim">单次总体积上限 ${bytes(data.max_bytes)}；
          ${rclone ? `已检测到 rclone（${(remote.remotes || []).length} 个远程）`
    : '未安装 rclone，仅支持本地备份'}</span>
      </div>
    </div>
    <div class="card flush"><div class="table-wrap" id="bk-table">${opsBackupTable(data.items, rclone)}</div></div>`;

  host.onclick = async (event) => {
    const btn = event.target.closest('[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;
    if (act === 'bk-refresh') { await ctx.open('backup'); return; }
    if (act === 'bk-dir-save') {
      const value = $('#bk-dir', host).value.trim();
      try {
        await api.put('/api/panel/prefs', { values: { 'backup.dir': value } });
        toast('备份目录已更新');
        await ctx.open('backup');
      } catch (err) { toast(err.message, 'err'); }
      return;
    }
    if (act === 'bk-create') {
      const paths = $('#bk-paths', host).value.split('\n').map((s) => s.trim()).filter(Boolean);
      if (!paths.length) { toast('请先填写要备份的路径', 'err'); return; }
      const name = $('#bk-name', host).value.trim();
      const ok = await confirmDialog({
        title: '创建备份', confirmText: '开始打包',
        message: `将打包 ${paths.length} 个路径到 <span class="mono">${esc(data.dir)}</span>，可能要几十秒。`,
      });
      if (!ok) return;
      btn.disabled = true;
      try {
        const res = await api.post('/api/panel/maintenance/backups',
          name ? { paths, name } : { paths }, 600000);
        toast(`${res.message}（${bytes(res.size)}）`);
        await ctx.open('backup');
      } catch (err) { toast(err.message, 'err'); } finally { btn.disabled = false; }
      return;
    }
    if (act === 'bk-del') {
      const name = btn.dataset.name;
      const ok = await confirmDialog({
        title: '删除备份', danger: true, confirmText: '删除',
        message: `确定删除备份 <b class="mono">${esc(name)}</b>？此操作不可恢复。`,
      });
      if (!ok) return;
      try {
        const res = await api.del(`/api/panel/maintenance/backups/${encodeURIComponent(name)}`);
        toast(res.message);
        await ctx.open('backup');
      } catch (err) { toast(err.message, 'err'); }
      return;
    }
    if (act === 'bk-upload') {
      const name = btn.dataset.name;
      const first = (remote.remotes || [])[0];
      const value = await promptDialog({
        title: '上传到远程存储', label: 'rclone 目标（形如 gdrive:backups）',
        value: first ? `${first.name}backups` : '',
      });
      if (value === null || !value.trim()) return;
      try {
        const res = await api.post(
          `/api/panel/maintenance/backups/${encodeURIComponent(name)}/upload`,
          { remote: value.trim() }, 360000,
        );
        toast(res.message);
      } catch (err) { toast(err.message, 'err'); }
    }
  };
  return null;
}

/* ---------- 系统更新 ---------- */

async function opsUpdate(host, ctx) {
  const data = await api.get('/api/panel/maintenance/updates');
  if (!data.capabilities.apt) {
    host.innerHTML = opsHint('系统更新不可用',
      '本机没有 <span class="mono">apt-get</span>（非 Debian 系发行版）。<br>请使用发行版自带的包管理器维护更新。');
    return null;
  }
  host.innerHTML = `
    <div class="card">
      <div class="toolbar" style="margin-bottom:0">
        <span class="badge">${data.count} 个可升级</span>
        <span class="badge ${data.security ? 'warn' : ''}">${data.security} 个安全更新</span>
        ${data.error ? `<span class="dim">${esc(data.error)}</span>` : ''}
        <div class="spacer"></div>
        <button class="btn sm" data-act="up-reload">重新检查</button>
        ${data.count && isInternal()
    ? '<button class="btn sm primary" data-act="up-apply">一键升级</button>' : ''}
      </div>
      <div class="dim" style="margin-top:8px">
        只执行 <span class="mono">apt-get install --only-upgrade</span>，不会安装新包也不会卸载已有包。
        升级内核等组件后需要重启系统才会生效。
      </div>
    </div>
    <div class="card flush"><div class="table-wrap">
      ${data.packages.length ? `<table class="data"><thead><tr>
          <th>软件包</th><th>可升级到</th><th>来源</th><th>类型</th></tr></thead><tbody>
        ${data.packages.map((item) => `<tr>
          <td class="cell-main mono">${esc(item.name)}</td>
          <td class="mono">${esc(item.version)}</td>
          <td class="cell-sub">${esc(item.repo)}</td>
          <td>${item.security ? '<span class="badge warn">安全更新</span>' : '<span class="badge">常规</span>'}</td>
        </tr>`).join('')}</tbody></table>` : '<div class="empty">系统已是最新</div>'}
    </div></div>`;

  host.onclick = async (event) => {
    const btn = event.target.closest('[data-act]');
    if (!btn) return;
    if (btn.dataset.act === 'up-reload') { await ctx.open('update'); return; }
    if (btn.dataset.act !== 'up-apply') return;
    const ok = await confirmDialog({
      title: '一键升级系统', danger: true, confirmText: '立即升级',
      message: `将升级 ${data.count} 个软件包（其中 ${data.security} 个安全更新），耗时可能较长。是否继续？`,
    });
    if (!ok) return;
    btn.disabled = true;
    btn.textContent = '升级中…';
    try {
      const res = await api.postConfirmed('/api/panel/maintenance/updates/apply', {}, 'update', 900000);
      toast(res.message);
      await ctx.open('update');
    } catch (err) { toast(err.message, 'err'); } finally { btn.disabled = false; btn.textContent = '一键升级'; }
  };
  return null;
}

/* ---------- Docker ---------- */

async function opsDockerLogs(id) {
  const body = document.createElement('div');
  body.innerHTML = '<div class="empty">加载中…</div>';
  openModal({ title: `容器日志 · ${id}`, body, size: 'wide' });
  try {
    const data = await api.get(`/api/panel/infra/docker/containers/${encodeURIComponent(id)}/logs?tail=200`);
    body.innerHTML = `<div class="log-output" style="max-height:60vh">${
      data.lines.length ? data.lines.map((line) => esc(line)).join('\n') : '<span class="dim">暂无日志</span>'}</div>`;
  } catch (err) {
    body.innerHTML = `<div class="empty">读取失败：${esc(err.message)}</div>`;
  }
}

async function opsDocker(host, ctx) {
  const data = await api.get('/api/panel/infra/docker/containers');
  if (!data.capabilities.docker) {
    host.innerHTML = opsHint('Docker 不可用',
      '本机没有 <span class="mono">docker</span> 命令，无法管理容器。'
      + '需要容器管理能力时请先安装 Docker Engine。');
    return null;
  }
  const images = await api.get('/api/panel/infra/docker/images')
    .catch(() => ({ images: [], error: '' }));
  const stateBadge = (state) => {
    if (state === 'running') return '<span class="badge ok">运行中</span>';
    if (state === 'exited') return '<span class="badge">已退出</span>';
    if (state === 'paused') return '<span class="badge warn">已暂停</span>';
    return `<span class="badge">${esc(state || '未知')}</span>`;
  };
  host.innerHTML = `
    <div class="card">
      <div class="toolbar" style="margin-bottom:0">
        <span class="badge info">${data.containers.length} 个容器</span>
        <span class="badge">${images.images.length} 个镜像</span>
        ${data.error ? `<span class="dim">${esc(data.error)}</span>` : ''}
        <div class="spacer"></div>
        <button class="btn sm" data-act="dk-reload">刷新</button>
      </div>
    </div>
    <div class="card flush"><div class="table-wrap">
      ${data.containers.length ? `<table class="data"><thead><tr>
          <th>容器</th><th>镜像</th><th>状态</th><th>端口</th><th></th></tr></thead><tbody>
        ${data.containers.map((item) => `<tr>
          <td class="cell-main mono">${esc(item.name || item.id)}<div class="cell-sub">${esc(item.id.slice(0, 12))}</div></td>
          <td class="cell-sub mono">${esc(item.image)}</td>
          <td>${stateBadge(item.state)}<div class="cell-sub">${esc(item.status)}</div></td>
          <td class="cell-sub mono">${esc(item.ports || '-')}</td>
          <td class="actions">
            <button class="btn sm ghost" data-act="dk-logs" data-id="${esc(item.id)}">日志</button>
            ${isInternal() ? (item.state === 'running'
    ? `<button class="btn sm" data-act="dk-restart" data-id="${esc(item.id)}">重启</button>
                 <button class="btn sm danger" data-act="dk-stop" data-id="${esc(item.id)}">停止</button>`
    : `<button class="btn sm ok" data-act="dk-start" data-id="${esc(item.id)}">启动</button>`)
    + `<button class="btn sm danger" data-act="dk-remove" data-id="${esc(item.id)}">删除</button>` : ''}
          </td></tr>`).join('')}</tbody></table>` : '<div class="empty">没有容器</div>'}
    </div></div>
    <div class="card flush" style="margin-top:14px"><div class="table-wrap">
      ${images.images.length ? `<table class="data"><thead><tr>
          <th>镜像</th><th>标签</th><th>大小</th><th>创建时间</th></tr></thead><tbody>
        ${images.images.map((item) => `<tr>
          <td class="cell-main mono">${esc(item.repository)}</td>
          <td class="mono">${esc(item.tag)}</td>
          <td>${esc(item.size)}</td>
          <td class="cell-sub">${esc(item.created)}</td></tr>`).join('')}</tbody></table>`
    : '<div class="empty">没有镜像</div>'}
    </div></div>`;

  const act = async (id, action) => {
    const label = { start: '启动', stop: '停止', restart: '重启' }[action];
    if (action !== 'start') {
      const ok = await confirmDialog({
        title: `确认${label}容器`, danger: action === 'stop', confirmText: label,
        message: `确定要${label}容器 <b class="mono">${esc(id)}</b> 吗？`,
      });
      if (!ok) return;
    }
    try {
      const res = await api.post(`/api/panel/infra/docker/containers/${encodeURIComponent(id)}/action`,
        { action }, 180000);
      toast(res.message);
      await ctx.open('docker');
    } catch (err) { toast(err.message, 'err'); }
  };

  host.onclick = async (event) => {
    const btn = event.target.closest('[data-act]');
    if (!btn) return;
    const id = btn.dataset.id;
    switch (btn.dataset.act) {
      case 'dk-reload': await ctx.open('docker'); break;
      case 'dk-logs': await opsDockerLogs(id); break;
      case 'dk-start': await act(id, 'start'); break;
      case 'dk-stop': await act(id, 'stop'); break;
      case 'dk-restart': await act(id, 'restart'); break;
      case 'dk-remove': {
        const ok = await confirmDialog({
          title: '删除容器', danger: true, confirmText: '删除',
          message: `将强制删除容器 <b class="mono">${esc(id)}</b>（数据卷不会被删除）。此操作不可恢复。`,
        });
        if (!ok) return;
        try {
          const res = await api.delConfirmed(`/api/panel/infra/docker/containers/${encodeURIComponent(id)}?force=true`,
            'docker', 180000);
          toast(res.message);
          await ctx.open('docker');
        } catch (err) { toast(err.message, 'err'); }
        break;
      }
      default: break;
    }
  };
  return null;
}

/* ---------- 防火墙 ---------- */

async function opsFirewall(host, ctx) {
  const data = await api.get('/api/panel/infra/firewall');
  const backend = data.backend ? data.backend.toUpperCase() : '';
  host.innerHTML = `
    <div class="card">
      <div class="toolbar" style="margin-bottom:10px">
        <span class="badge ${backend ? 'info' : 'warn'}">${backend ? `${esc(backend)} 后端` : '未检测到防火墙'}</span>
        <span class="badge">${data.rules.length} 条规则</span>
        ${data.writable ? '' : '<span class="dim">当前后端仅支持只读查看</span>'}
        <div class="spacer"></div>
        <button class="btn sm" data-act="fw-reload">刷新</button>
      </div>
      ${data.writable && isInternal() ? `<div class="row" style="margin-bottom:8px">
        <input class="input" id="fw-port" placeholder="端口，如 8080" style="width:150px">
        <select class="input" id="fw-proto" style="width:90px">
          <option value="tcp">tcp</option><option value="udp">udp</option></select>
        <button class="btn sm primary" data-act="fw-allow">放行</button>
        <button class="btn sm danger" data-act="fw-deny">拒绝</button>
      </div>` : ''}
      ${data.error ? `<div class="dim">${esc(data.error)}</div>` : ''}
    </div>
    <div class="card flush"><div class="table-wrap">
      ${data.rules.length ? `<table class="data"><thead><tr>
          <th>#</th><th>端口</th><th>协议</th><th>动作</th><th>来源</th><th>备注</th></tr></thead><tbody>
        ${data.rules.map((rule) => `<tr>
          <td class="cell-sub">${rule.index}</td>
          <td class="cell-main mono">${esc(rule.port || '全部')}</td>
          <td class="cell-sub">${esc(rule.proto || '-')}</td>
          <td><span class="badge ${String(rule.action).startsWith('ALLOW') || rule.action === 'ACCEPT' ? 'ok' : 'danger'}">${esc(rule.action)}</span></td>
          <td class="cell-sub mono">${esc(rule.from)}${rule.v6 ? ' (v6)' : ''}</td>
          <td>${rule.risky ? '<span class="badge danger">对全网放行</span>' : ''}</td>
        </tr>`).join('')}</tbody></table>` : '<div class="empty">没有可展示的规则</div>'}
    </div></div>`;

  host.onclick = async (event) => {
    const btn = event.target.closest('[data-act]');
    if (!btn) return;
    if (btn.dataset.act === 'fw-reload') { await ctx.open('firewall'); return; }
    const action = btn.dataset.act === 'fw-allow' ? 'allow' : 'deny';
    const port = ($('#fw-port', host)?.value || '').trim();
    const proto = $('#fw-proto', host)?.value || 'tcp';
    if (!/^\d{1,5}$/.test(port)) { toast('端口需要是 1-65535 的数字', 'err'); return; }
    const ok = await confirmDialog({
      title: action === 'allow' ? '放行端口' : '拒绝端口', danger: action === 'deny',
      confirmText: action === 'allow' ? '放行' : '拒绝',
      message: `将对 <b class="mono">${esc(port)}/${esc(proto)}</b> 执行 ufw ${action}。确定继续？`,
    });
    if (!ok) return;
    try {
      const res = await api.postConfirmed(`/api/panel/infra/firewall/${action}`,
        { port: Number(port), proto }, 'firewall');
      toast(res.message);
      await ctx.open('firewall');
    } catch (err) { toast(err.message, 'err'); }
  };
  return null;
}

/* ---------- 反代 / 证书 ---------- */

function opsProxyBlock(data) {
  if (!data.nginx) {
    return `<div class="card"><h2>nginx</h2><div class="dim">未检测到 nginx。</div></div>`;
  }
  const test = data.nginx.config_test || {};
  return `<div class="card">
    <div class="toolbar" style="margin-bottom:10px">
      <span class="badge info">${esc(data.nginx.version || 'nginx')}</span>
      <span class="badge ${test.ok ? 'ok' : 'danger'}">nginx -t ${test.ok ? '通过' : '未通过'}</span>
      <span class="badge">${(data.nginx.sites || []).length} 个站点</span>
      <div class="spacer"></div>
      <button class="btn sm primary" data-act="px-reload">重载配置</button>
    </div>
    <div class="dim mono" style="margin-bottom:6px">${esc(data.nginx.dir || '')}</div>
    <div class="dim mono">${(data.nginx.sites || []).join(' · ') || '（站点目录为空或不存在）'}</div>
    ${test.output ? `<div class="log-output" style="max-height:180px;margin-top:10px">${esc(test.output)}</div>` : ''}
  </div>`;
}

function opsCertTable(certs) {
  if (!certs.length) return '<div class="empty">没有找到 Let\'s Encrypt 证书</div>';
  return `<table class="data"><thead><tr>
      <th>域名</th><th>到期时间</th><th>剩余</th></tr></thead><tbody>
    ${certs.map((cert) => `<tr>
      <td class="cell-main mono">${esc(cert.name)}</td>
      <td class="cell-sub">${esc(cert.not_after || '未读取到（缺少 openssl）')}</td>
      <td>${cert.days_left === null ? '-' : (cert.expiring
    ? `<span class="badge danger">${cert.days_left} 天</span>`
    : `<span class="badge ok">${cert.days_left} 天</span>`)}</td>
    </tr>`).join('')}</tbody></table>`;
}

async function opsProxy(host, ctx) {
  const data = await api.get('/api/panel/infra/proxy');
  const certs = await api.get('/api/panel/infra/proxy/certificates')
    .catch(() => ({ certificates: [], capabilities: {} }));
  host.innerHTML = `
    ${opsProxyBlock(data)}
    <div class="card" style="margin-top:14px">
      <h2>Caddy</h2>
      <div class="dim">${data.caddy ? esc(data.caddy.version || '已安装') : '未检测到 caddy。'}</div>
    </div>
    <div class="card flush" style="margin-top:14px">
      <div class="toolbar" style="padding:12px 14px 0;margin-bottom:8px">
        <h2 style="margin:0">证书（${esc(certs.dir || '/etc/letsencrypt/live')}）</h2>
        <div class="spacer"></div>
        <span class="dim">剩余不足 ${certs.warn_days || 30} 天标记为告警</span>
      </div>
      <div class="table-wrap">${opsCertTable(certs.certificates || [])}</div>
    </div>`;

  host.onclick = async (event) => {
    const btn = event.target.closest('[data-act]');
    if (!btn || btn.dataset.act !== 'px-reload') return;
    const ok = await confirmDialog({
      title: '重载 nginx', confirmText: '重载',
      message: '将先执行 <span class="mono">nginx -t</span> 校验，通过后重载配置。确定继续？',
    });
    if (!ok) return;
    try {
      const res = await api.postConfirmed('/api/panel/infra/proxy/reload', {}, 'proxy');
      toast(res.message);
      await ctx.open('proxy');
    } catch (err) { toast(err.message, 'err'); }
  };
  return null;
}

/* ---------- 数据库 ---------- */

async function opsDb(host) {
  const data = await api.get('/api/panel/infra/databases');
  const usable = data.engines.filter((engine) => engine.available);
  if (!usable.length) {
    host.innerHTML = opsHint('数据库探测不可用',
      '本机没有 <span class="mono">mysql</span> / <span class="mono">psql</span> / '
      + '<span class="mono">redis-cli</span> 客户端，无法连接数据库。<br>'
      + '只做只读探测（<span class="mono">SHOW STATUS</span> / '
      + '<span class="mono">SELECT version()</span> / <span class="mono">INFO</span>），不支持执行自定义 SQL。');
    return null;
  }
  host.innerHTML = `
    <div class="card">
      <div class="toolbar" style="margin-bottom:10px">
        ${data.engines.map((engine) => `<span class="badge ${engine.available ? 'ok' : ''}">${esc(engine.label)}${engine.available ? '' : '（未安装）'}</span>`).join('')}
        <div class="spacer"></div>
        <span class="dim">只读探测，禁止自定义 SQL</span>
      </div>
      <div class="row" style="margin-bottom:8px">
        <select class="input" id="db-kind" style="width:170px">
          ${usable.map((engine) => `<option value="${esc(engine.kind)}">${esc(engine.label)}</option>`).join('')}
        </select>
        <input class="input" id="db-host" value="127.0.0.1" placeholder="主机" style="width:150px">
        <input class="input" id="db-port" placeholder="端口（默认）" style="width:130px">
      </div>
      <div class="row" style="margin-bottom:8px">
        <input class="input" id="db-user" placeholder="用户名（可选）" style="width:170px">
        <input class="input" id="db-name" placeholder="库名（可选）" style="width:170px">
        <input class="input" id="db-pass" type="password" placeholder="密码（可选，不会写审计）" style="width:220px">
        <button class="btn sm primary" data-act="db-probe">探测</button>
      </div>
      <div id="db-output" class="log-output" style="max-height:320px">点击「探测」执行固定的只读命令</div>
    </div>`;

  host.onclick = async (event) => {
    const btn = event.target.closest('[data-act]');
    if (!btn || btn.dataset.act !== 'db-probe') return;
    const body = {
      kind: $('#db-kind', host).value,
      host: $('#db-host', host).value.trim() || '127.0.0.1',
      user: $('#db-user', host).value.trim(),
      database: $('#db-name', host).value.trim(),
      password: $('#db-pass', host).value,
    };
    const port = $('#db-port', host).value.trim();
    if (port) body.port = Number(port);
    const out = $('#db-output', host);
    out.textContent = '探测中…';
    btn.disabled = true;
    try {
      const res = await api.post('/api/panel/infra/databases/probe', body, 60000);
      out.textContent = res.output || '（无输出）';
      toast('探测成功');
    } catch (err) {
      out.textContent = err.message;
      toast(err.message, 'err');
    } finally { btn.disabled = false; }
  };
  return null;
}

/* ---------- SSH 公钥 ---------- */

async function opsSsh(host, ctx) {
  const data = await api.get('/api/panel/infra/ssh/keys');
  host.innerHTML = `
    <div class="card">
      <div class="toolbar" style="margin-bottom:10px">
        <span class="badge">${data.keys.length} 把公钥</span>
        <span class="dim mono">${esc(data.path)}</span>
        <div class="spacer"></div>
        ${data.capabilities.ssh_keygen ? '' : '<span class="badge warn">缺少 ssh-keygen，无法计算指纹</span>'}
        <button class="btn sm" data-act="ss-reload">刷新</button>
      </div>
      <label class="field"><span>追加公钥（整行粘贴，支持 ssh-rsa / ssh-ed25519 / ecdsa / sk-）</span>
        <textarea class="input mono" id="ss-line" spellcheck="false" style="height:70px"
          placeholder="ssh-ed25519 AAAA... me@laptop"></textarea></label>
      <button class="btn sm primary" data-act="ss-add">追加</button>
    </div>
    <div class="card flush"><div class="table-wrap">
      ${data.keys.length ? `<table class="data"><thead><tr>
          <th>类型</th><th>注释</th><th>指纹</th><th></th></tr></thead><tbody>
        ${data.keys.map((key, index) => `<tr>
          <td class="cell-main mono">${esc(key.type)}</td>
          <td class="cell-sub">${esc(key.comment || '-')}</td>
          <td class="cell-sub mono">${esc(key.fingerprint || '-')}</td>
          <td class="actions"><button class="btn sm danger" data-act="ss-del" data-index="${index}">删除</button></td>
        </tr>`).join('')}</tbody></table>` : '<div class="empty">authorized_keys 里还没有公钥</div>'}
    </div></div>`;

  host.onclick = async (event) => {
    const btn = event.target.closest('[data-act]');
    if (!btn) return;
    if (btn.dataset.act === 'ss-reload') { await ctx.open('ssh'); return; }
    if (btn.dataset.act === 'ss-add') {
      const line = $('#ss-line', host).value.trim();
      if (!line) { toast('请先粘贴公钥', 'err'); return; }
      try {
        const res = await api.post('/api/panel/infra/ssh/keys', { line });
        toast(res.message);
        await ctx.open('ssh');
      } catch (err) { toast(err.message, 'err'); }
      return;
    }
    if (btn.dataset.act === 'ss-del') {
      const key = data.keys[Number(btn.dataset.index)];
      const ok = await confirmDialog({
        title: '删除公钥', danger: true, confirmText: '删除',
        message: `将精确删除这一行公钥（${esc(key.comment || key.type)}），之后用该私钥将无法登录。`,
      });
      if (!ok) return;
      try {
        const res = await api.delBody('/api/panel/infra/ssh/keys', { line: key.line });
        toast(res.message);
        await ctx.open('ssh');
      } catch (err) { toast(err.message, 'err'); }
    }
  };
  return null;
}

/* ---------- 网络工具 ---------- */

async function opsNet(host) {
  host.innerHTML = `
    <div class="card">
      <div class="toolbar" style="margin-bottom:10px">
        <select class="input" id="net-tool" style="width:150px">
          <option value="ping">ping</option><option value="traceroute">traceroute</option>
          <option value="mtr">mtr</option><option value="curl">curl -I</option>
        </select>
        <input class="input mono" id="net-target" placeholder="目标：域名 / IP / IPv6" style="width:240px">
        <button class="btn sm primary" data-act="net-run">执行</button>
        <div class="spacer"></div>
        <span class="dim">只允许字母、数字、. : - [ ]，禁止管道与重定向</span>
      </div>
      <div class="log-output" id="net-output" style="max-height:420px">选择工具并输入目标后执行</div>
    </div>`;

  host.onclick = async (event) => {
    const btn = event.target.closest('[data-act]');
    if (!btn || btn.dataset.act !== 'net-run') return;
    const tool = $('#net-tool', host).value;
    const target = $('#net-target', host).value.trim();
    const out = $('#net-output', host);
    if (!target) { toast('请填写目标地址', 'err'); return; }
    out.textContent = `${tool} ${target} …`;
    btn.disabled = true;
    try {
      const res = await api.post('/api/panel/infra/net/tool', { tool, target }, 60000);
      out.textContent = res.output || '（无输出）';
      if (!res.ok) toast(res.error || '命令返回非 0', 'err');
    } catch (err) {
      out.textContent = err.message;
      toast(err.message, 'err');
    } finally { btn.disabled = false; }
  };
  return null;
}

async function opsRecording(root) {
  let timer = null;

  const playRecording = async (name) => {
    const data = await api.get(`/api/panel/recordings/${encodeURIComponent(name)}`);
    const pre = document.createElement('pre');
    pre.className = 'mono';
    pre.style.cssText = 'margin:0;white-space:pre-wrap;word-break:break-all;max-height:60vh;'
      + 'overflow:auto;background:#0b0d0f;color:#d7e0e6;padding:12px;border-radius:8px;font-size:12.5px;line-height:1.45';
    pre.textContent = '（开始回放…）';
    const handle = openModal({
      title: `回放 · ${name}`,
      body: pre,
      size: 'wide',
      // 无论点 ✕、点遮罩还是 Esc 关闭都要停掉回放定时器（以前只有 Esc 会清）
      onClose: () => { if (timer) clearTimeout(timer); timer = null; },
    });
    const events = (data.events || []).filter((ev) => ev.kind === 'o');
    if (!events.length) { pre.textContent = '（这段录制没有输出）'; return; }
    pre.textContent = '';
    let index = 0;
    let text = '';
    const tick = () => {
      timer = null;
      if (index >= events.length) { pre.textContent = text; pre.scrollTop = pre.scrollHeight; return; }
      const current = events[index];
      text += current.data;
      // 单段过长时截掉头部，避免回放把内存吃满
      if (text.length > 400000) text = text.slice(-300000);
      pre.textContent = text;
      pre.scrollTop = pre.scrollHeight;
      index += 1;
      if (index >= events.length) return;
      // 间隔压缩到最多 0.6 秒，长停顿（装包、编译）不会让回放看着像卡死
      const gap = Math.min(0.6, Math.max(0, events[index].time - current.time));
      timer = setTimeout(tick, gap * 1000);
    };
    tick();
  };

  const render = async () => {
    const data = await api.get('/api/panel/recordings');
    const rows = data.items.length ? data.items.map((item) => `
      <tr>
        <td class="mono">${esc(item.name)}</td>
        <td class="num">${bytes(item.size)}</td>
        <td>${esc(new Date(item.time * 1000).toLocaleString())}</td>
        <td class="row" style="justify-content:flex-end;gap:6px">
          <button class="btn sm" data-play="${esc(item.name)}">回放</button>
          <button class="btn sm danger" data-del="${esc(item.name)}">删除</button>
        </td>
      </tr>`).join('')
      : '<tr><td colspan="4"><div class="empty">还没有录制。打开上面的开关后，新开的终端会话才会被记录。</div></td></tr>';
    root.innerHTML = `
      <div class="card">
        <div class="row" style="justify-content:space-between;align-items:flex-start;gap:16px">
          <div>
            <h2 style="margin:0">会话录制</h2>
            <div class="dim" style="margin-top:6px;line-height:1.7">
              格式为 asciinema v2（JSONL），同一文件也能用 <span class="mono">asciinema play &lt;文件&gt;</span> 在命令行回放。
              录制只对新开的终端会话生效；单文件超过设置里的体积上限会自动停止。<br>
              目录：<span class="mono">${esc(data.dir)}</span>
            </div>
          </div>
          <label class="row" style="gap:8px;align-items:center;white-space:nowrap">
            <input type="checkbox" id="rec-enabled" ${data.enabled ? 'checked' : ''}>
            <span>录制新会话</span>
          </label>
        </div>
      </div>
      <div class="card">
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>文件</th><th class="num">大小</th><th>时间</th><th></th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>`;

    const toggle = $('#rec-enabled', root);
    toggle.addEventListener('change', async () => {
      try {
        await api.put('/api/panel/prefs', {
          values: { 'terminal.record_sessions': toggle.checked },
        });
        toast(toggle.checked ? '已开启会话录制' : '已关闭会话录制');
      } catch (err) {
        toggle.checked = !toggle.checked;
        toast(err.message, 'danger');
      }
    });
    $$('[data-play]', root).forEach((button) => {
      button.addEventListener('click', () => {
        playRecording(button.dataset.play).catch((err) => toast(err.message, 'danger'));
      });
    });
    $$('[data-del]', root).forEach((button) => {
      button.addEventListener('click', async () => {
        const name = button.dataset.del;
        const ok = await confirmDialog({
          title: '删除录制',
          message: `确定删除 <span class="mono">${esc(name)}</span>？删除后不可恢复。`,
          confirmText: '删除',
          danger: true,
        });
        if (!ok) return;
        try {
          await api.del(`/api/panel/recordings/${encodeURIComponent(name)}`);
          toast('已删除');
          await render();
        } catch (err) {
          toast(err.message, 'danger');
        }
      });
    });
  };

  await render();
  return () => { if (timer) clearTimeout(timer); timer = null; };
}

const OPS_PANELS = {
  cron: opsCron,
  backup: opsBackup,
  update: opsUpdate,
  docker: opsDocker,
  firewall: opsFirewall,
  proxy: opsProxy,
  db: opsDb,
  ssh: opsSsh,
  net: opsNet,
  recording: opsRecording,
};

registerView('ops', {
  title: '运维',
  async render(root, res) {
    root.innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <div class="toolbar" id="ops-tabs" style="margin-bottom:0">
          ${OPS_TABS.map((tab, index) => `<button class="btn sm${index === 0 ? ' primary' : ''}"
            data-tab-id="${tab.id}">${tab.label}</button>`).join('')}
        </div>
      </div>
      <div id="ops-body"><div class="empty">加载中…</div></div>`;

    const body = $('#ops-body', root);
    let cleanup = null;
    let seq = 0;

    const open = async (id) => {
      const current = (seq += 1);
      if (cleanup) {
        try { cleanup(); } catch (err) { console.error(err); }
        cleanup = null;
      }
      $$('#ops-tabs .btn', root).forEach((el) => {
        el.classList.toggle('primary', el.dataset.tabId === id);
      });
      body.innerHTML = '<div class="empty">加载中…</div>';
      let result = null;
      try {
        result = await OPS_PANELS[id](body, { open });
      } catch (err) {
        body.innerHTML = opsFail(err);
      }
      if (current !== seq) { if (typeof result === 'function') result(); return; }
      // 登记到视图资源表：切换/离开视图时由路由统一回收（定时器/订阅同理）
      cleanup = res.own(typeof result === 'function' ? result : null);
    };

    $('#ops-tabs', root).onclick = (event) => {
      const btn = event.target.closest('[data-tab-id]');
      if (btn) open(btn.dataset.tabId);
    };
    await open('cron');
    return () => {
      seq += 1;
      if (cleanup) { try { cleanup(); } catch (err) { console.error(err); } cleanup = null; }
    };
  },
});

registerView('settings', {
  title: '设置',
  async render(root) {
    const canQuick = isInternal();
    let tab = localStorage.getItem('sp-settings-tab') === 'quick' && canQuick ? 'quick' : 'general';
    const caps = live.capabilities || {};
    const info = await api.get('/api/system/info').catch(() => ({}));
    const hz = await api.get('/api/system/version').catch(() => null);

    // ---- 快捷设置状态 ----
    let prefsFields = [];
    let prefsValues = {};
    let bootInfo = null;
    let guardian = null;
    let listen = {};
    let tz = {};
    let backups = [];
    let busy = false;
    // 用户管理（2.0 M4）：仅内网模式 + admin 才拉取；其他人拿到空表也不会报错
    let usersData = [];
    let multiUser = false;
    if (isInternal() && isAdmin()) {
      try {
        const res = await api.get('/api/panel/users');
        usersData = res.users || [];
        multiUser = !!res.multi_user;
      } catch (err) { usersData = []; }
    }

    async function loadQuick() {
      const [p, b, g] = await Promise.all([
        api.get('/api/panel/prefs'),
        api.get('/api/panel/boot'),
        api.get('/api/panel/boot/guardian'),
      ]);
      prefsFields = p.fields;
      prefsValues = p.values;
      listen = p.listen;
      tz = p.timezone;
      bootInfo = b;
      guardian = g;
      try { backups = (await api.get('/api/panel/config/backups')).items; }
      catch (err) { backups = []; }
    }

    const STATE_META = {
      ok: ['ok', '通'], broken: ['danger', '断'], manual: ['warn', '需手工'], unknown: ['', '未知'],
    };

    const EFFECT_LABEL = {
      immediate: '<span class="badge ok">立即生效</span>',
      'new-session': '<span class="badge info">新会话生效</span>',
      restart: '<span class="badge warn">需重启面板</span>',
    };

    function fieldOf(key) {
      return prefsFields.find((f) => f.key === key) || { key, value: '', note: '', effect: 'immediate' };
    }

    function numField(key, label, unit, hint) {
      const field = fieldOf(key);
      return `<label class="field"><span>${esc(label)} <span class="dim">（${esc(unit)}）</span></span>
        <input class="input" type="number" data-pref="${esc(key)}" value="${esc(field.value)}"
          data-original="${esc(field.value)}">
        <span class="dim" style="font-size:11px">${esc(hint || field.note)}</span></label>`;
    }

    function switchField(key, label, hint, danger) {
      const field = fieldOf(key);
      return `<label class="switch-row">
        <input type="checkbox" data-pref-bool="${esc(key)}" ${field.value ? 'checked' : ''}
          data-original="${field.value ? '1' : '0'}">
        <span><b>${esc(label)}</b>${danger ? ' <span class="badge danger">谨慎</span>' : ''}
          <div class="dim" style="font-size:11.5px;line-height:1.6">${esc(hint || field.note)}</div></span>
      </label>`;
    }

    function roleBadge(role) {
      const meta = {
        admin: ['danger', 'admin · 管理员'],
        operator: ['warn', 'operator · 运维'],
        viewer: ['info', 'viewer · 只读'],
      };
      const [cls, label] = meta[role] || ['', role];
      return `<span class="badge ${cls}">${esc(label)}</span>`;
    }

    async function reloadUsers() {
      try {
        const res = await api.get('/api/panel/users');
        usersData = res.users || [];
        multiUser = !!res.multi_user;
      } catch (err) { usersData = []; }
      paint();
    }

    async function runUserAction(btn) {
      const id = btn.dataset.userRole || btn.dataset.userReset
        || btn.dataset.userToggle || btn.dataset.userDelete;
      const user = usersData.find((u) => u.id === id);
      if (!user) return;
      try {
        if (btn.dataset.userRole) {
          const role = await promptRole(user.role);
          if (!role || role === user.role) return;
          const res = await api.put(`/api/panel/users/${id}`, { role });
          toast(res.message || '角色已更新');
        } else if (btn.dataset.userReset) {
          const password = await promptDialog({
            title: `重置 ${user.username} 的密码`,
            label: '新密码（至少 12 位，不要用弱口令）', confirmText: '重置',
          });
          if (!password) return;
          const res = await api.put(`/api/panel/users/${id}`, { password });
          toast(res.message || '密码已重置');
        } else if (btn.dataset.userToggle) {
          const disabled = btn.dataset.disabled !== '1';
          const ok = await confirmDialog({
            title: disabled ? '禁用账号' : '启用账号', danger: disabled,
            confirmText: disabled ? '禁用' : '启用',
            message: `${disabled ? '禁用' : '启用'} <b>${esc(user.username)}</b>？${disabled
              ? '<br><span class="dim">该账号的会话会立即失效，无法再登录。</span>' : ''}`,
          });
          if (!ok) return;
          const res = await api.put(`/api/panel/users/${id}`, { disabled });
          toast(res.message || '已更新');
        } else if (btn.dataset.userDelete) {
          const ok = await confirmDialog({
            title: '删除用户', danger: true, confirmText: '删除', phrase: 'DELETE',
            message: `将永久删除 <b>${esc(user.username)}</b>，其会话立即失效。`,
          });
          if (!ok) return;
          const res = await api.del(`/api/panel/users/${id}`);
          toast(res.message || '已删除');
        }
        await reloadUsers();
      } catch (err) { toast(err.message, 'err'); }
    }

    function promptRole(current) {
      return new Promise((resolve) => {
        const body = document.createElement('div');
        body.innerHTML = `<label class="field"><span>角色</span>
          <select class="input" id="role-select">
            ${[['viewer', 'viewer（只读）'], ['operator', 'operator（运维）'],
              ['admin', 'admin（管理员）']]
              .map(([value, label]) => `<option value="${value}"${value === current ? ' selected' : ''}>${label}</option>`)
              .join('')}
          </select></label>`;
        const foot = document.createElement('div');
        foot.className = 'row';
        foot.innerHTML = '<button class="btn" data-cancel>取消</button>'
          + '<button class="btn primary" data-ok>保存</button>';
        const finish = (value) => { modal.close(); resolve(value); };
        const modal = openModal({
          title: '修改角色', body, footer: foot, size: 'narrow',
          onEscape: () => finish(null),
        });
        $('[data-cancel]', foot).onclick = () => finish(null);
        $('[data-ok]', foot).onclick = () => finish($('#role-select', modal.body).value);
      });
    }

    function usersCard() {
      if (!isInternal() || !isAdmin()) return '';
      const rows = usersData.map((user) => `<tr>
        <td class="cell-main">${esc(user.username)}</td>
        <td>${roleBadge(user.role)}</td>
        <td>${user.disabled ? '<span class="badge danger">已禁用</span>'
          : '<span class="badge ok">启用</span>'}</td>
        <td>${user.totp_enabled ? '<span class="badge ok">已开启</span>' : '<span class="dim">-</span>'}</td>
        <td class="cell-sub">${datetime(user.created_at)}</td>
        <td><div class="row" style="gap:6px;flex-wrap:wrap">
          <button class="btn sm ghost" data-user-role="${esc(user.id)}">改角色</button>
          <button class="btn sm ghost" data-user-reset="${esc(user.id)}">重置密码</button>
          <button class="btn sm ghost" data-user-toggle="${esc(user.id)}"
            data-disabled="${user.disabled ? '1' : '0'}">${user.disabled ? '启用' : '禁用'}</button>
          <button class="btn sm danger" data-user-delete="${esc(user.id)}">删除</button>
        </div></td></tr>`).join('');
      return `<div class="card" style="grid-column:1/-1">
        <h2>用户管理 <span class="spacer"></span>
          <span class="dim" style="font-size:12px">${usersData.length} 个账号 ·
            多用户模式${multiUser ? '已启用' : '未启用'}</span></h2>
        <div class="dim" style="font-size:12px;line-height:1.7;margin:4px 0 12px">
          角色：<b>viewer</b> 只读（GET）· <b>operator</b> 有界运维（服务启停、任务触发、
          容器启停、网络工具、只读浏览；文件写入需管理员在「快捷设置 → 文件管理写权限」里配置可写根）·
          <b>admin</b> 全部权限。凡是能拿到命令执行 / root 持久化 / 备份外带 /
          系统级变更的能力（网页终端、常驻应用、市场安装、SSH 公钥、开机任务、
          备份、挂载、防火墙、反代）都仅限 admin。
          ${multiUser ? '' : '当前仍是<b>单密码模式</b>：创建第一个用户后，原密码会自动迁移成'
            + ' <span class="mono">admin</span> 账号，仍可用原密码登录。'}
        </div>
        <div class="table-wrap"><table class="data">
          <thead><tr><th>用户名</th><th>角色</th><th>状态</th><th>二次认证</th>
            <th>创建时间</th><th>操作</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="6"><div class="empty">还没有额外用户</div></td></tr>'}</tbody>
        </table></div>
        <form id="user-create-form" class="row" style="margin-top:14px;gap:10px;flex-wrap:wrap">
          <input class="input" id="user-name" placeholder="用户名（3~32 位字母数字 . _ -）"
            autocomplete="off" style="max-width:240px">
          <input class="input" id="user-password" type="password" autocomplete="new-password"
            placeholder="初始密码（至少 12 位）" style="max-width:240px">
          <select class="input" id="user-role" style="max-width:180px">
            <option value="viewer">viewer（只读）</option>
            <option value="operator">operator（运维）</option>
            <option value="admin">admin（管理员）</option>
          </select>
          <button class="btn primary" type="submit">新建用户</button>
        </form>
      </div>`;
    }

    function localeCard() {
      const option = (value, label) => `<option value="${value}"${
        I18N.locale === value ? ' selected' : ''}>${label}</option>`;
      return `<div class="card">
        <h2>界面语言</h2>
        <label class="field" style="max-width:300px"><span>语言 / Language</span>
          <select class="input" id="locale-select">
            ${option('zh-CN', '简体中文（zh-CN）')}${option('en-US', 'English (en-US)')}
          </select></label>
        <div class="dim" style="font-size:12px;margin-top:10px">
          切换后立即生效：只重绘导航、标题与静态标签，不整页刷新。
          未翻译的业务文案回退中文。
        </div>
      </div>`;
    }

    function platformCard() {
      if (!isInternal()) return '';
      return `<div class="card">
        <h2>自诊断与接口文档</h2>
        <div class="row" style="flex-wrap:wrap">
          <button class="btn" data-act="diagnostics">下载自诊断包</button>
          <a class="btn ghost" href="/api/docs" target="_blank" rel="noopener noreferrer">接口文档</a>
          <a class="btn ghost" href="/api/openapi.json" target="_blank"
             rel="noopener noreferrer">OpenAPI</a>
        </div>
        <div class="dim" style="font-size:12px;margin-top:10px;line-height:1.7">
          诊断包含版本/脱敏配置/能力探测/最近指标与审计，
          <b>不含密码哈希、TOTP 密钥与 Agent 令牌</b>。
          接口文档为自包含页面（内联样式，不依赖 CDN），离线内网也能打开。
        </div>
      </div>`;
    }

    function bootCard() {
      if (!bootInfo) return '<div class="card"><div class="empty">加载中…</div></div>';
      const verdictMap = {
        ok: ['ok', '自启链路完整'], warn: ['warn', '可自动的部分已就绪，仍有需手工的环节'],
        broken: ['danger', '自启链路存在断点'],
      };
      const [vcls, vtext] = verdictMap[bootInfo.verdict] || ['', bootInfo.verdict];
      return `<div class="card" style="grid-column:1/-1">
        <h2>开机自启体检 <span class="spacer"></span>
          <span class="badge ${vcls}">${esc(vtext)}</span>
          <button class="btn sm ghost" data-act="boot-refresh">重新检测</button></h2>
        <div class="boot-chain">
          ${bootInfo.links.map((link, index) => {
            const [cls, label] = STATE_META[link.state] || ['', link.state];
            return `<div class="boot-link ${cls}">
              <div class="bl-head"><span class="bl-no">${index + 1}</span>
                <b>${esc(link.title)}</b><span class="badge ${cls}">${esc(label)}</span></div>
              <div class="bl-detail">${esc(link.detail)}</div>
              ${link.evidence ? `<div class="dim mono bl-evidence">${esc(link.evidence)}</div>` : ''}
              ${link.actions.length ? `<div class="row" style="margin-top:8px">${link.actions.map((a) => `
                <button class="btn sm ${a.needs_confirm ? 'primary' : 'ghost'}"
                  data-boot-action="${esc(a.id)}">${esc(a.label)}</button>`).join('')}</div>` : ''}
            </div>`;
          }).join('')}
        </div>
        <div class="dim" style="font-size:12px;margin-top:12px;line-height:1.7">
          链路：设备/容器 → 守护 → 面板 → 常驻应用 → 设备保活。
          标「需手工」的环节在 Android 宿主侧，容器内无法修改，按提示在手机上操作即可。
          平台：<span class="mono">${esc(bootInfo.platform.init)}</span>
          ${bootInfo.platform.proot ? '· PRoot 容器' : ''}
          ${bootInfo.cron.available ? `· crontab ${bootInfo.cron.configured ? '已配置' : '未配置'}`
            : '· 无 crontab'}
        </div>
        <details style="margin-top:10px">
          <summary class="dim" style="cursor:pointer;font-size:12px">查看 Termux:Boot 启动脚本（手机侧使用）</summary>
          <pre class="snippet-body" style="margin-top:8px">${esc(bootInfo.termux_script)}</pre>
          <button class="btn sm ghost" data-act="copy-termux">复制脚本</button>
        </details>
      </div>`;
    }

    function guardianCard() {
      if (!guardian) return '';
      const health = guardian.health || {};
      return `<div class="card">
        <h2>守护进程</h2>
        <dl class="kv" style="grid-template-columns:110px 1fr">
          <dt>托管方式</dt><dd>${guardian.systemd ? 'systemd（Restart=always）' : 'panel-supervisor.sh'}</dd>
          <dt>守护 PID</dt><dd>${guardian.alive ? guardian.pid : '未运行'}</dd>
          <dt>健康检查</dt><dd>${health.ok ? `正常 · ${esc(health.version || '')}` : '<span class="badge danger">无响应</span>'}</dd>
          <dt>应用目录</dt><dd class="mono">${esc(guardian.app_dir)}</dd>
        </dl>
        <div class="row" style="margin-top:12px">
          <button class="btn primary" data-act="guardian-restart">重启面板</button>
          <button class="btn" data-act="guardian-repair">重装守护</button>
        </div>
        <div class="dim" style="font-size:12px;margin-top:10px;line-height:1.7">
          重启约 3~10 秒，登录态保持；重装守护会按当前配置重新生成启动脚本与开机自启项。
        </div>
        ${bootInfo && bootInfo.cron.available ? `
        <div class="row" style="margin-top:12px">
          ${bootInfo.cron.configured
            ? '<button class="btn danger" data-act="cron-remove">移除容器 @reboot 兜底</button>'
            : '<button class="btn" data-act="cron-install">写入容器 @reboot 兜底</button>'}
          <span class="dim" style="font-size:12px">
            crontab 现有 ${bootInfo.cron.total_lines} 行定时任务，写入前会自动备份、去重并读回校验</span>
        </div>` : ''}
      </div>`;
    }

    function prefsCards() {
      const sessionCard = `<div class="card">
        <h2>会话与登录防护</h2>
        ${numField('session.ttl_hours', '登录会话有效期', '小时', '滑动续期；已签发的会话保留原到期时间')}
        ${numField('security.max_failures', '连续失败锁定阈值', '次', '同一来源 IP 连续失败多少次后锁定')}
        ${numField('security.lockout_seconds', '锁定时长', '秒', '锁定期间该来源的登录请求一律拒绝')}
        <div class="dim" style="font-size:11.5px">${EFFECT_LABEL['new-session']} ${EFFECT_LABEL.immediate}</div>
      </div>`;

      const logCard = `<div class="card">
        <h2>日志与保留</h2>
        ${numField('logs.app_max_bytes', '单个应用日志上限', '字节', '超过后轮转为 .log.1')}
        ${numField('logs.panel_max_bytes', '面板日志上限', '字节', '守护脚本按此上限轮转 panel.log')}
        <div class="row" style="margin-top:4px">
          <button class="btn primary" data-act="logs-trim">立即清理到上限</button>
          <span class="dim" style="font-size:12px">面板与全部应用日志一次性截断</span>
        </div>
      </div>`;

      const autostartCard = `<div class="card">
        <h2>常驻应用自启</h2>
        ${switchField('autostart.apps_enabled', '面板启动时自动拉起自启应用',
          '关闭后，标记了自启的应用不会被自动拉起（手动「启动」仍然生效）')}
        <div class="dim" style="font-size:12px;margin-top:8px;line-height:1.7">
          单个应用的自启开关在「常驻应用」页面按应用配置。
        </div>
      </div>`;

      const tzCard = `<div class="card">
        <h2>时间与时区</h2>
        <div class="row">
          <span class="badge">当前 ${esc(tz.current || '-')}</span>
          ${tz.supported ? '' : '<span class="badge danger">本机不支持切换</span>'}
        </div>
        <label class="field"><span>切换到</span>
          <input class="input" id="tz-input" list="tz-options" value="${esc(tz.current || '')}"
            ${tz.supported ? '' : 'disabled'} placeholder="Asia/Shanghai">
          <datalist id="tz-options">${(tz.common || []).map((z) => `<option value="${esc(z)}"></option>`).join('')}</datalist>
        </label>
        <label class="switch-row">
          <input type="checkbox" id="tz-ntp" ${tz.ntp_enabled ? 'checked' : ''}
            ${tz.ntp_supported ? '' : 'disabled'}>
          <span><b>开启 NTP 自动对时</b>
            <div class="dim" style="font-size:11.5px;line-height:1.6">
              ${tz.ntp_supported ? '由 systemd-timedated 负责对时'
                : '本环境无 systemd：容器时钟由 Android 宿主控制，无法在容器内对时'}</div></span>
        </label>
        <button class="btn primary" data-act="tz-apply" ${tz.supported ? '' : 'disabled'}>应用时区</button>
      </div>`;

      const proxyCard = `<div class="card">
        <h2>反向代理与来源白名单</h2>
        ${switchField('security.trust_proxy', '信任反向代理的 X-Forwarded-For', 
          '只有在面板确实位于可信反向代理之后才可开启：否则攻击者可伪造 XFF 绕过登录失败锁定', true)}
        <label class="field"><span>额外放行来源（每行一个，用于反代换域名时的 WebSocket 握手）</span>
          <textarea class="input" rows="3" data-pref-list="security.allowed_origins"
            data-original="${esc((prefsValues['security.allowed_origins'] || []).join('\n'))}"
            placeholder="https://panel.example.com">${esc((prefsValues['security.allowed_origins'] || []).join('\n'))}</textarea></label>
      </div>`;

      const logDirsCard = `<div class="card">
        <h2>日志白名单目录</h2>
        <label class="field"><span>日志接口允许读取的目录（每行一个绝对路径）</span>
          <textarea class="input" rows="3" data-pref-list="security.log_dirs"
            data-original="${esc((prefsValues['security.log_dirs'] || []).join('\n'))}">${esc((prefsValues['security.log_dirs'] || []).join('\n'))}</textarea></label>
        <div class="dim" style="font-size:11.5px;line-height:1.7">
          保存前会自检：若该目录会让 <span class="mono">/etc/shadow</span> 之类敏感文件进入可读范围，
          或包含系统关键目录，会被拒绝。
        </div>
      </div>`;

      const writeRootsCard = `<div class="card">
        <h2>文件管理写权限（operator）</h2>
        <label class="field"><span>operator 可写入的根目录（每行一个绝对路径，留空 = 只有管理员能写文件）</span>
          <textarea class="input" rows="3" data-pref-list="files.write_roots"
            data-original="${esc((prefsValues['files.write_roots'] || []).join('\n'))}"
            placeholder="/srv/website">${esc((prefsValues['files.write_roots'] || []).join('\n'))}</textarea></label>
        <div class="dim" style="font-size:11.5px;line-height:1.7">
          只对 operator 角色生效（viewer 与单密码模式不受影响）。面板配置目录、代码根目录、
          以及路径里含 <span class="mono">.ssh</span> / <span class="mono">.gnupg</span> 的位置
          对任何角色都禁止写入——写进去就等于 root。
        </div>
      </div>`;

      const listenCard = `<div class="card">
        <h2>监听地址 <span class="spacer"></span><span class="badge warn">改完需重启面板</span></h2>
        <div class="row">
          <label class="field" style="flex:1;min-width:140px"><span>地址</span>
            <input class="input" id="listen-host" value="${esc(listen.host || '')}"></label>
          <label class="field" style="width:120px"><span>端口</span>
            <input class="input" type="number" id="listen-port" value="${esc(listen.port || '')}"></label>
        </div>
        <button class="btn danger" data-act="listen-apply">应用并重启面板</button>
        <div class="dim" style="font-size:12px;margin-top:10px;line-height:1.7">
          当前 <span class="mono">${esc(listen.host)}:${esc(listen.port)}</span>。
          变更会重建守护脚本并重启面板，本页面会断连数十秒后自动跳转到新地址；
          失败会回滚到原配置。
        </div>
      </div>`;

      const backupCard = `<div class="card" style="grid-column:1/-1">
        <h2>备份与迁移</h2>
        <div class="row">
          <a class="btn primary" href="/api/panel/config/export" download>导出配置（不含凭据）</a>
          <a class="btn" href="/api/panel/config/export?include_secrets=1" download>导出（含密码与令牌）</a>
          <button class="btn ghost" data-act="backup-now">就地备份</button>
          <input type="file" id="import-file" accept=".zip" class="hidden">
          <button class="btn ghost" data-act="import-pick">导入配置…</button>
        </div>
        <div class="dim" style="font-size:12px;margin-top:10px;line-height:1.7">
          默认导出会剔除密码哈希与 Agent 令牌，导入时这两项<b>始终以本机为准</b>；
          「含密码与令牌」的导出文件请妥善保管。就地备份保存在服务器
          <span class="mono">/etc/serverpanel/backups/</span>，最多保留 10 份。
        </div>
        ${backups.length ? `<div class="table-wrap" style="margin-top:10px"><table class="data">
          <thead><tr><th>备份文件</th><th class="num">大小</th><th>时间</th></tr></thead>
          <tbody>${backups.map((b) => `<tr>
            <td class="cell-main">${esc(b.name)}</td>
            <td class="num">${bytes(b.size)}</td>
            <td class="cell-sub">${datetime(b.time)}</td></tr>`).join('')}</tbody></table></div>` : ''}
      </div>`;

      return autostartCard + sessionCard + logCard + tzCard + proxyCard + logDirsCard
        + (isAdmin() ? writeRootsCard : '') + listenCard + backupCard;
    }

    function generalTab() {
      return `
      <div class="grid c2">
        <div class="card">
          <h2>修改面板密码</h2>
          <form id="pwd-form" style="display:flex;flex-direction:column;gap:12px;max-width:360px">
            <label class="field"><span>当前密码</span>
              <input class="input" type="password" id="pwd-current" autocomplete="current-password" required></label>
            <label class="field"><span>新密码（至少 12 位）</span>
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
          <h2>安全中心</h2>
          <div class="dim" style="font-size:12px;line-height:1.7;margin:4px 0 12px">
            二次认证（TOTP）、Agent 令牌作用域、活跃会话管理与统一审计日志，
            集中在一个页面。需要内网模式。
          </div>
          <button class="btn" data-act="goto-security">打开安全中心</button>
        </div>

        ${localeCard()}

        ${usersCard()}

        ${platformCard()}

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
            <li>连续 5 次密码错误后，该来源 IP 会被锁定 60 秒（可在「快捷设置」调整）。</li>
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
            ${isInternal() && isAdmin() ? '<button class="btn" data-act="terminal">打开终端</button>' : ''}
            ${isInternal() ? `<button class="btn danger" data-act="reboot">重启系统</button>
            <button class="btn danger" data-act="shutdown">关机</button>` : ''}
            <button class="btn ghost" data-act="logout">退出登录</button>
          </div>
          <div class="dim" style="font-size:12px;margin-top:14px">
            重启与关机需要输入确认词，且仅在主机以 systemd 启动时可用。
          </div>
        </div>
      </div>`;
    }

    function quickTab() {
      if (!bootInfo) return '<div class="card"><div class="empty">加载中…</div></div>';
      return `<div class="row" style="margin-bottom:12px">
          <span class="dim" style="font-size:12px">开关类改动即时保存；输入框改动需点「保存设置」。</span>
          <div class="spacer"></div>
          <button class="btn primary" data-act="prefs-save">保存设置</button>
        </div>
        <div class="grid c2">${bootCard()}${guardianCard()}${prefsCards()}</div>`;
    }

    function paint() {
      root.innerHTML = `
        <div class="tabs-head">
          <button class="tab-btn ${tab === 'general' ? 'active' : ''}" data-settings-tab="general">常规</button>
          ${canQuick ? `<button class="tab-btn ${tab === 'quick' ? 'active' : ''}" data-settings-tab="quick">快捷设置</button>` : ''}
        </div>
        <div id="settings-panel">${tab === 'general' ? generalTab() : quickTab()}</div>`;
      if (tab === 'general') bindGeneral();
    }

    // ---- 常规 tab 的绑定 ----
    function bindGeneral() {
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

      const localeSelect = $('#locale-select');
      if (localeSelect) {
        localeSelect.onchange = async (event) => {
          await applyLocale(event.target.value);
          toast(`界面语言已切换：${I18N.locale}`);
        };
      }

      const userForm = $('#user-create-form');
      if (userForm) {
        userForm.onsubmit = async (event) => {
          event.preventDefault();
          const username = $('#user-name').value.trim();
          const password = $('#user-password').value;
          const role = $('#user-role').value;
          if (!username || !password) { toast('用户名和密码都要填', 'err'); return; }
          try {
            const res = await api.post('/api/panel/users', { username, password, role });
            toast(res.message || '用户已创建', 'ok');
            userForm.reset();
            await reloadUsers();
          } catch (err) { toast(err.message, 'err'); }
        };
      }

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
          await api.postConfirmed('/api/system/self-update', {}, 'update');
        } catch (err) {
          toast(err.message, 'err');
          btn.disabled = false;
          btn.textContent = '一键升级（git 拉取最新代码）';
          return;
        }
        toast('升级已在后台启动，等待面板重启…');
        const result = await waitForPanelRestart({
          before, onProgress: (text) => { btn.textContent = text; },
        });
        if (result.ok) {
          if (result.relogin) {
            toast('面板已恢复，但登录态已过期，请重新登录', 'warn', 6000);
          } else {
            toast(`升级完成：${result.health.version}（${result.health.build || '无部署标记'}）`, 'ok');
          }
          setTimeout(() => location.reload(), 1200);
        } else {
          toast('升级未在预期时间内完成，请通过终端查看 panel.log', 'err');
          btn.disabled = false;
          btn.textContent = '一键升级（git 拉取最新代码）';
        }
      };
    }

    // ---- 快捷设置 tab 的动作 ----
    function collectPrefs() {
      const patch = {};
      $$('[data-pref]').forEach((input) => {
        const original = input.dataset.original;
        if (input.value.trim() !== original) patch[input.dataset.pref] = Number(input.value.trim());
      });
      $$('[data-pref-bool]').forEach((input) => {
        const now = input.checked ? '1' : '0';
        if (now !== input.dataset.original) patch[input.dataset.prefBool] = input.checked;
      });
      $$('[data-pref-list]').forEach((area) => {
        if (area.value.trim() !== area.dataset.original) {
          patch[area.dataset.prefList] = area.value.split('\n').map((s) => s.trim()).filter(Boolean);
        }
      });
      return patch;
    }

    async function savePrefs(patch, confirmText = '保存') {
      if (!patch || !Object.keys(patch).length) { toast('没有需要保存的改动'); return false; }
      const needConfirm = 'security.trust_proxy' in patch || 'security.log_dirs' in patch;
      if (needConfirm) {
        const ok = await confirmDialog({
          title: '确认修改安全相关设置', danger: 'security.log_dirs' in patch,
          confirmText, phrase: 'security.trust_proxy' in patch ? 'PROXY' : '',
          message: `将修改：<b class="mono">${esc(Object.keys(patch).join('、'))}</b><br>
            <span class="dim">开启信任代理会让来源判定改为读取 X-Forwarded-For；
            扩展日志白名单会放宽可读范围。请确认当前部署确实需要。</span>`,
        });
        if (!ok) return false;
      }
      try {
        const res = await api.put('/api/panel/prefs', { values: patch });
        toast(res.message || '已保存');
        await loadQuick();
        paint();
        return true;
      } catch (err) {
        toast(err.message, 'err');
        return false;
      }
    }

    async function runBootAction(actionId) {
      if (busy) return;
      busy = true;
      try {
      const actions = {};
      (bootInfo?.links || []).forEach((link) => link.actions.forEach((a) => { actions[a.id] = a; }));
      const action = actions[actionId] || {};
      if (actionId === 'copy-termux-script') {
        copyText(bootInfo.termux_script, 'Termux:Boot 脚本已复制');
        return;
      }
      if (actionId === 'cron-install') {
        const ok = await confirmDialog({
          title: '写入容器 @reboot 兜底', confirmText: '写入',
          message: `将在容器 crontab 追加一行，让守护在开机时自动拉起。<br>
            <span class="dim">写入前会备份现有 crontab（共 ${bootInfo.cron.total_lines} 行），
            自动去重并读回校验；失败会回滚。</span>`,
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/panel/boot/cron', {});
          toast(res.message);
          await loadQuick();
          paint();
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      if (actionId === 'cron-remove') {
        const ok = await confirmDialog({
          title: '移除 crontab 兜底', danger: true, confirmText: '移除',
          message: '移除后容器重启将不再自动拉起守护（systemd 单元不受影响）。',
        });
        if (!ok) return;
        try {
          const res = await api.del('/api/panel/boot/cron');
          toast(res.message);
          await loadQuick();
          paint();
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      if (actionId === 'guardian-repair') {
        const ok = await confirmDialog({
          title: '重装面板守护', confirmText: '重装',
          message: `将按 <span class="mono">${esc(listen.host)}:${esc(listen.port)}</span>
            重新生成启动脚本与开机自启项，并重启面板。`,
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/panel/boot/guardian/repair', {});
          toast(res.message);
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      busy = false;  // 未识别的面板动作交给 runPanelAction，由它自己重新持锁
      await runPanelAction(actionId);
      } finally {
        busy = false;
      }
    }

    /** 守护 / 备份 / 日志 / 时区 / 监听 等面板级动作（体检卡片与卡片按钮共用）。 */
    async function runPanelAction(action) {
      if (busy) return;
      busy = true;
      try {
      if (action === 'boot-refresh') {
        await loadQuick();
        paint();
        toast('已重新检测');
        return;
      }
      if (action === 'guardian-restart') {
        const ok = await confirmDialog({
          title: '重启面板服务', confirmText: '重启',
          message: '面板将在数秒内重启，登录态保持。当前页面会自动重连。',
        });
        if (!ok) return;
        const before = hz?.build || hz?.version || '';
        try {
          await api.post('/api/panel/boot/guardian/restart', {});
        } catch (err) { toast(err.message, 'err'); return; }
        toast('重启指令已下发，等待恢复…');
        const result = await waitForPanelRestart({ before });
        if (result.ok) { toast('面板已恢复', 'ok'); location.reload(); }
        else toast('面板未在预期时间内恢复，请查看 panel.log', 'err');
        return;
      }
      if (action === 'cron-install' || action === 'cron-remove' || action === 'guardian-repair'
          || action === 'copy-termux-script') {
        await runBootAction(action);
        return;
      }
      if (action === 'logs-trim') {
        const ok = await confirmDialog({
          title: '清理日志到上限', confirmText: '清理',
          message: '面板日志与全部应用日志会被截断到各自上限的一半，历史输出不可恢复。',
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/panel/logs/trim', {});
          toast(res.message);
          await loadQuick();
          paint();
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      if (action === 'tz-apply') {
        const zone = $('#tz-input').value.trim();
        if (!zone) { toast('请填写时区', 'err'); return; }
        const ntp = tz.ntp_supported ? $('#tz-ntp').checked : undefined;
        const ok = await confirmDialog({
          title: '切换时区', confirmText: '应用',
          message: `将把服务器时区切换为 <b class="mono">${esc(zone)}</b>。
            <span class="dim">日志时间戳口径会随之改变。</span>`,
        });
        if (!ok) return;
        try {
          const res = await api.post('/api/panel/timezone', { zone, enable_ntp: ntp });
          toast(res.message);
          tz = res.status;
          await loadQuick();
          paint();
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      if (action === 'listen-apply') {
        const host = $('#listen-host').value.trim();
        const port = Number($('#listen-port').value.trim());
        if (!host || !port) { toast('地址与端口都不能为空', 'err'); return; }
        const ok = await confirmDialog({
          title: '变更监听地址并重启', danger: true, confirmText: '应用并重启',
          phrase: 'RESTART',
          message: `面板将改为监听 <b class="mono">${esc(host)}:${esc(port)}</b> 并立即重启。<br>
            <span class="dim">本页面会断连数十秒，然后自动跳转到新地址；失败会自动回滚。</span>`,
        });
        if (!ok) return;
        const ok2 = await applyListen(host, port, false);
        if (!ok2) return;
        return;
      }
      if (action === 'backup-now') {
        try {
          const res = await api.post('/api/panel/config/backup', {});
          toast(res.message);
          await loadQuick();
          paint();
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      if (action === 'prefs-save') {
        await savePrefs(collectPrefs(), '保存');
        return;
      }
      if (action === 'import-pick') { $('#import-file').click(); }
      } finally {
        busy = false;  // 面板级动作期间防重入（重启/清理/切地址都不该能连点）
      }
    }

    async function applyListen(host, port, force) {
      const before = hz?.build || hz?.version || '';
      let res;
      try {
        res = await api.post('/api/panel/listen', { host, port, force });
      } catch (err) {
        if (err.status === 409) {
          const ok = await confirmDialog({
            title: '确认强制切换', danger: true, confirmText: '仍然切换',
            message: `${esc(err.message)}<br><span class="dim">切换后请确保新地址可访问，否则将无法再进入面板。</span>`,
          });
          if (!ok) return false;
          return applyListen(host, port, true);
        }
        toast(err.message, 'err');
        return false;
      }
      if (!res.changed) { toast(res.message); return true; }
      toast(`正在切换到 ${res.host}:${res.port}，等待面板恢复…`, 'warn');
      const target = `http://${location.hostname}:${res.port}/api/system/version`;
      const result = await waitForPanelRestart({ before, probeUrl: target, timeoutMs: 120000 });
      if (result.ok) {
        toast('新地址已就绪，正在跳转…', 'ok');
        const scheme = location.protocol;
        setTimeout(() => { location.href = `${scheme}//${location.hostname}:${res.port}/`; }, 1200);
        return true;
      }
      toast(`面板未在新地址就绪，请手动访问 http://<服务器IP>:${res.port}/ 或按备份回滚`, 'err', 12000);
      return false;
    }

    async function importConfig(file) {
      const ok = await confirmDialog({
        title: '导入配置', danger: true, confirmText: '导入',
        message: `将用 <b class="mono">${esc(file.name)}</b> 覆盖当前配置（<b>密码与 Agent 令牌保持本机不变</b>）。
          <span class="dim">导入前会自动生成一份就地备份。</span>`,
      });
      if (!ok) return;
      const form = new FormData();
      form.append('file', file);
      try {
        const res = await api.uploadConfirmed('/api/panel/config/import', form, 'config');
        toast(res.message, 'ok', 8000);
        await loadQuick();
        paint();
      } catch (err) { toast(err.message, 'err'); }
    }

    root.onclick = async (event) => {
      const tabBtn = event.target.closest('[data-settings-tab]');
      if (tabBtn) {
        tab = tabBtn.dataset.settingsTab;
        localStorage.setItem('sp-settings-tab', tab);
        if (tab === 'quick') {
          try { await loadQuick(); } catch (err) { toast(err.message, 'err'); }
        }
        paint();
        return;
      }
      const bootBtn = event.target.closest('[data-boot-action]');
      if (bootBtn) { await runBootAction(bootBtn.dataset.bootAction); return; }

      const userBtn = event.target.closest(
        '[data-user-role],[data-user-reset],[data-user-toggle],[data-user-delete]');
      if (userBtn) { await runUserAction(userBtn); return; }

      const action = event.target.dataset?.act || event.target.closest('[data-act]')?.dataset.act;
      if (!action) return;
      if (action === 'diagnostics') {
        location.href = '/api/panel/diagnostics';
        return;
      }
      if (action === 'mode-help') { showModeHelp(); return; }
      if (action === 'terminal') { if (!isAdmin()) return; navigate('terminal'); return; }
      if (action === 'goto-security') { navigate('security'); return; }
      if (action === 'logout') { await api.post('/api/auth/logout', {}); location.reload(); return; }
      if (action === 'copy-termux') { copyText(bootInfo.termux_script, '已复制'); return; }
      if (action === 'reboot' || action === 'shutdown') {
        const label = action === 'reboot' ? '重启' : '关机';
        const ok = await confirmDialog({
          title: `${label}系统`, danger: true, confirmText: label,
          message: `确定要${label}主机 <b>${esc(info.hostname || '')}</b> 吗？`,
          phrase: action.toUpperCase(),
        });
        if (!ok) return;
        try {
          const res = await api.postConfirmed('/api/system/power', { action, confirm: 'CONFIRM' }, 'power');
          toast(res.message, 'warn');
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      // 下面的动作会整页重绘，先收集未保存的表单改动
      const patch = collectPrefs();
      if (['boot-refresh', 'guardian-restart', 'guardian-repair', 'cron-install', 'cron-remove',
           'logs-trim', 'backup-now', 'import-pick', 'tz-apply', 'listen-apply'].includes(action)
          && Object.keys(patch).length) {
        const ok = await confirmDialog({
          title: '有未保存的改动', confirmText: '先保存再继续',
          message: `检测到 <b class="mono">${esc(Object.keys(patch).join('、'))}</b> 有改动尚未保存，
            是否先保存？（选「取消」则放弃这些改动并继续当前操作）`,
        });
        if (ok) {
          const saved = await savePrefs(patch);
          if (!saved) return;
        }
      }
      await runPanelAction(action);
    };

    root.onchange = async (event) => {
      if (event.target.id === 'import-file' && event.target.files?.[0]) {
        const file = event.target.files[0];
        event.target.value = '';
        await importConfig(file);
      }
      // 开关类即时保存：勾选后立刻落盘，避免"以为改了其实没提交"
      if (event.target.dataset?.prefBool) {
        const key = event.target.dataset.prefBool;
        await savePrefs({ [key]: event.target.checked }, '保存');
      }
    };

    if (tab === 'quick') {
      try {
        await loadQuick();
      } catch (err) {
        root.innerHTML = `<div class="card"><div class="empty">读取设置失败：${esc(err.message)}</div></div>`;
        return null;
      }
    }
    paint();
  },
});


/* ============================ 账号 / 语言 / PWA ============================ */

const ROLE_LABEL = { admin: '管理员', operator: '运维', viewer: '只读' };

function renderUserBadge() {
  const badge = $('#user-badge');
  if (!badge) return;
  const role = ROLE_LABEL[authUser.role] || authUser.role;
  badge.textContent = `${authUser.username} · ${role}`;
  badge.className = `badge user-badge ${authUser.role}`;
  badge.title = authUser.multiUser
    ? `当前登录：${authUser.username}（${role}）`
    : '单密码模式：内置管理员';
}

/** 切换界面语言：只刷新导航/标题/静态标签，不整页 reload。 */
async function applyLocale(locale) {
  await I18N.load(locale);
  I18N.apply();
  buildNav();
  renderTabs();
  if (currentView && views[currentView]) {
    $('#page-title').textContent = I18N.t(`view.${currentView}`, views[currentView].title);
  }
  if (isInternal() && isAdmin()) {
    try {
      await api.put('/api/panel/prefs', { values: { 'ui.locale': I18N.locale } });
    } catch (err) {
      toast(`界面语言已切换，但未能保存到服务端：${err.message}`, 'warn');
    }
  }
}

/** 内网模式下把服务端的 ui.locale 同步到本地（公网模式读不到 prefs，用本地缓存）。 */
async function syncLocale() {
  if (!isInternal()) return;
  try {
    const data = await api.get('/api/panel/prefs', 8000);
    const locale = data.values ? data.values['ui.locale'] : '';
    if (locale && locale !== I18N.locale) await applyLocale(locale);
  } catch (err) { /* 无权限 / 公网模式：保持本地语言 */ }
}

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  // 新版 SW 接管后自动刷新一次（仅在页面原本已受 SW 控制时）：
  // 否则升级面板后用户可能一直停留在旧壳上，需要手动清缓存
  const hadController = !!navigator.serviceWorker.controller;
  let reloaded = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (!hadController || reloaded) return;
    reloaded = true;
    location.reload();
  });
  // 失败静默：http 内网地址、隐私模式、部分 WebView 都会注册失败，
  // 那只是"少一层离线壳"，不影响在线使用。
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/static/sw.js').catch(() => {});
  });
}

/* ============================ 命令面板（Ctrl / ⌘ + K）============================ */

let paletteOpen = false;

function paletteActions() {
  const actions = visibleNav().map((item) => ({
    id: `nav-${item.id}`,
    label: `前往 · ${item.label}`,
    hint: I18N.t(`view.${item.id}`, item.label),
    run: () => navigate(item.id),
  }));
  actions.push({
    id: 'toggle-save-mode',
    label: '切换低功耗模式',
    hint: '性能采样 2s ↔ 10s',
    run: () => toggleSaveMode(),
  });
  if (isInternal()) {
    actions.push({
      id: 'open-trash',
      label: '打开回收站',
      hint: '文件管理 → 回收站',
      run: async () => {
        await navigate('files');
        setTimeout(() => $('[data-act="trash"]')?.click(), 400);
      },
    });
  }
  return actions;
}

/** 常用任务（按需拉取，失败不影响其它命令）。 */
async function paletteTaskActions() {
  if (!isInternal()) return [];
  try {
    const data = await api.get('/api/panel/tasks', 8000);
    return (data.tasks || []).map((task) => ({
      id: `task-${task.id}`,
      label: `执行任务 · ${task.title}`,
      hint: (task.description || '常用任务').slice(0, 40),
      run: async () => {
        try {
          const res = await api.post(`/api/panel/tasks/${task.id}/run`, {});
          toast(`${task.title}：${res.ok ? '成功' : `失败（退出码 ${res.code}）`}`,
                res.ok ? 'ok' : 'err');
        } catch (err) { toast(err.message, 'err'); }
      },
    }));
  } catch (err) {
    return [];
  }
}

async function toggleSaveMode() {
  try {
    const data = await api.get('/api/panel/prefs', 8000);
    const next = !(data.values && data.values['power.save_mode']);
    const res = await api.put('/api/panel/prefs', { values: { 'power.save_mode': next } });
    toast(res.message || `低功耗模式已${next ? '开启' : '关闭'}`, 'ok');
  } catch (err) { toast(err.message, 'err'); }
}

function runPaletteTarget(target) {
  if (!target) return;
  // 命令的 run() 几乎都是 async（导航、请求）：不 catch 会变成未捕获的
  // Promise rejection，用户点完看不到任何反馈
  Promise.resolve()
    .then(() => target.run())
    .catch((err) => toast(err.message || '命令执行失败', 'err'));
}

function openPalette() {
  if (paletteOpen) return;
  paletteOpen = true;
  const overlay = document.createElement('div');
  overlay.className = 'palette-overlay';
  overlay.innerHTML = `
    <div class="palette" role="dialog" aria-label="命令面板">
      <input class="input palette-input" id="palette-input"
        placeholder="搜索视图、任务或操作…" autocomplete="off">
      <div class="palette-list" id="palette-list"></div>
      <div class="dim palette-hint">↑↓ 选择 · Enter 执行 · Esc 关闭</div>
    </div>`;
  document.body.appendChild(overlay);
  const input = $('#palette-input', overlay);
  const list = $('#palette-list', overlay);
  let items = paletteActions();
  let matched = items;
  let index = 0;

  function close() {
    overlay.remove();
    paletteOpen = false;
    document.removeEventListener('keydown', onKey, true);
  }

  function paint() {
    index = Math.max(0, Math.min(index, matched.length - 1));
    list.innerHTML = matched.length ? matched.map((item, i) => `
      <button class="palette-item${i === index ? ' active' : ''}" data-index="${i}">
        <span>${esc(item.label)}</span><span class="dim">${esc(item.hint || '')}</span>
      </button>`).join('') : '<div class="dim" style="padding:14px">没有匹配的命令</div>';
    $$('.palette-item', list).forEach((el) => {
      el.onclick = () => {
        const target = matched[Number(el.dataset.index)];
        close();
        runPaletteTarget(target);
      };
    });
  }

  function filter() {
    const q = input.value.trim().toLowerCase();
    matched = items.filter((item) => !q
      || `${item.label} ${item.hint || ''}`.toLowerCase().includes(q));
    index = 0;
    paint();
  }

  function onKey(event) {
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      close();
      return;
    }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (!matched.length) return;
      index = (index + (event.key === 'ArrowDown' ? 1 : -1) + matched.length) % matched.length;
      paint();
      return;
    }
    if (event.key === 'Enter') {
      event.preventDefault();
      const target = matched[index];
      close();
      runPaletteTarget(target);
    }
  }

  document.addEventListener('keydown', onKey, true);
  input.addEventListener('input', filter);
  paint();
  setTimeout(() => input.focus(), 10);
  paletteTaskActions().then((extra) => {
    if (!paletteOpen) return;
    items = items.concat(extra);
    filter();
  });
}

document.addEventListener('keydown', (event) => {
  if (!(event.ctrlKey || event.metaKey) || (event.key !== 'k' && event.key !== 'K')) return;
  event.preventDefault();
  openPalette();
});
$('#btn-palette')?.addEventListener('click', openPalette);

/* ============================ 视图：应用市场 ============================ */

registerView('market', {
  title: '应用市场',
  async render(root) {
    const data = await api.get('/api/panel/market');
    const cards = data.apps.map((item) => `
      <div class="card market-card">
        <div class="row" style="align-items:baseline;gap:8px">
          <h2 style="margin:0">${esc(item.name)}</h2>
          <span class="badge ${item.installed ? 'ok' : ''}">${item.installed ? '已注册' : '未注册'}</span>
          <div class="spacer"></div>
          <span class="badge info">:${esc(item.port)}</span>
        </div>
        <p class="dim" style="font-size:12.5px;line-height:1.7;margin:8px 0">
          ${esc(item.description)}</p>
        <div class="market-cmd mono">${esc(item.command)}</div>
        <div class="row" style="margin-top:12px">
          ${item.installed
            ? `<button class="btn sm ghost" data-goto-app>查看应用</button>`
            : `<button class="btn sm primary" data-install="${esc(item.id)}">一键注册</button>`}
          <button class="btn sm ghost" data-copy="${esc(item.id)}">复制命令</button>
          <a class="btn sm ghost" href="${esc(item.docs)}" target="_blank"
             rel="noopener noreferrer">文档</a>
        </div>
        ${(item.requires || []).length
          ? `<div class="dim" style="font-size:11.5px;margin-top:8px">依赖：${
            item.requires.map((r) => `<span class="mono">${esc(r)}</span>`).join('、')}</div>`
          : ''}
      </div>`).join('');
    root.innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <h2>应用市场 <span class="spacer"></span>
          <span class="dim" style="font-size:12px">已注册 ${data.installed} / ${data.total}</span></h2>
        <div class="dim" style="font-size:12px;line-height:1.8">
          这里只做<b>提示与注册</b>：命令来自仓库内置清单（不接受手工输入），
          注册后与「常驻应用」同构——<b>不会自动下载、也不会自动启动</b>。
          先在服务器上装好依赖，再到「常驻应用」试运行即可。
        </div>
      </div>
      <div class="grid c2">${cards || '<div class="card"><div class="empty">清单为空</div></div>'}</div>`;

    root.onclick = async (event) => {
      const installBtn = event.target.closest('[data-install]');
      if (installBtn) {
        const item = data.apps.find((a) => a.id === installBtn.dataset.install);
        if (!item) return;
        const ok = await confirmDialog({
          title: '注册常驻应用', confirmText: '注册',
          message: `将把 <b>${esc(item.name)}</b> 注册为常驻应用（不立即启动）。<br>
            <span class="dim mono">${esc(item.command)}</span>`,
        });
        if (!ok) return;
        try {
          const res = await api.post(`/api/panel/market/${item.id}/install`, {});
          toast(res.message || '已注册', 'ok', 6000);
          await navigate('market');
        } catch (err) { toast(err.message, 'err'); }
        return;
      }
      const copyBtn = event.target.closest('[data-copy]');
      if (copyBtn) {
        const item = data.apps.find((a) => a.id === copyBtn.dataset.copy);
        if (item) copyText(item.command, '命令已复制');
        return;
      }
      if (event.target.closest('[data-goto-app]')) navigate('apps');
    };
  },
});


boot();
