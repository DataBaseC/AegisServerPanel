/**
 * 窗口管理器（M0）：创建、焦点/层级、拖动、八向缩放、最小化/最大化/关闭。
 *
 * 只做 DOM 与几何，不认识"应用"。应用通过 onMount 往 win.body 里挂内容，
 * 关闭时由外部设置的 win.dispose 负责清理（例如断开终端 WebSocket）。
 */

const MIN_W = 340;
const MIN_H = 200;
const EDGE = 8; // 窗口至少保留在可视区内的边距

export class WindowManager {
  constructor({ layer, workspace, onChange }) {
    this.layer = layer;
    this.workspace = workspace;
    this.onChange = onChange || (() => {});
    this.windows = new Map();
    this.z = 10;
    this.seq = 0;
    this.activeId = null;
    this._onViewportResize = () => this._reflow();
    window.addEventListener("resize", this._onViewportResize);
  }

  get workspaceSize() {
    return { w: this.workspace.clientWidth, h: this.workspace.clientHeight };
  }

  _clampRect(rect) {
    const { w: W, h: H } = this.workspaceSize;
    const maxW = Math.max(MIN_W, W - EDGE * 2);
    const maxH = Math.max(MIN_H, H - EDGE * 2);
    const w = Math.max(MIN_W, Math.min(Math.round(rect.w), maxW));
    const h = Math.max(MIN_H, Math.min(Math.round(rect.h), maxH));
    const x = Math.max(0, Math.min(Math.round(rect.x), Math.max(0, W - w)));
    const y = Math.max(0, Math.min(Math.round(rect.y), Math.max(0, H - h)));
    return { x, y, w, h };
  }

  _applyRect(win) {
    const { w: W, h: H } = this.workspaceSize;
    const maxed = win.state === "maximized";
    const r = maxed ? { x: 0, y: 0, w: W, h: H } : win.rect;
    win.el.style.transform = `translate3d(${r.x}px, ${r.y}px, 0)`;
    win.el.style.width = `${r.w}px`;
    win.el.style.height = `${r.h}px`;
    win.el.classList.toggle("maximized", maxed);
    win.el.style.display = win.minimized ? "none" : "";
  }

  create({ id, appId, title, x = 80, y = 60, w = 820, h = 500, state, minimized } = {}) {
    const winId = id || `win-${Date.now().toString(36)}-${(this.seq++).toString(36)}`;
    if (this.windows.has(winId)) return this.windows.get(winId);

    const rect = this._clampRect({ x, y, w, h });
    const el = document.createElement("section");
    el.className = "win";
    el.dataset.id = winId;
    el.tabIndex = -1;
    el.innerHTML = `
      <header class="win-titlebar">
        <span class="win-icon" aria-hidden="true"></span>
        <span class="win-title"></span>
        <div class="win-controls">
          <button type="button" class="win-btn" data-act="min" title="最小化" aria-label="最小化">–</button>
          <button type="button" class="win-btn" data-act="max" title="最大化" aria-label="最大化">□</button>
          <button type="button" class="win-btn win-close" data-act="close" title="关闭" aria-label="关闭">×</button>
        </div>
      </header>
      <div class="win-body"></div>
      ${["n", "s", "e", "w", "ne", "nw", "se", "sw"]
        .map((dir) => `<div class="win-handle" data-dir="${dir}"></div>`)
        .join("")}
    `;
    el.querySelector(".win-title").textContent = title || appId || "窗口";

    const win = {
      id: winId,
      appId: appId || "app",
      title: title || appId || "窗口",
      el,
      body: el.querySelector(".win-body"),
      rect,
      state: state === "maximized" ? "maximized" : "normal",
      minimized: Boolean(minimized),
      dispose: null,
    };

    this.layer.append(el);
    this.windows.set(winId, win);
    this._applyRect(win);
    this._bind(win);

    this.focus(winId);
    this.onChange({ reason: "create", win });
    return win;
  }

  _bind(win) {
    const el = win.el;

    el.addEventListener("pointerdown", () => {
      if (!win.minimized) this.focus(win.id);
    }, { capture: true });

    const controls = el.querySelector(".win-controls");
    controls.addEventListener("click", (event) => {
      const button = event.target.closest("button");
      if (!button) return;
      event.stopPropagation();
      const act = button.dataset.act;
      if (act === "close") this.close(win.id);
      else if (act === "min") this.minimize(win.id);
      else if (act === "max") this.toggleMaximize(win.id);
    });

    const bar = el.querySelector(".win-titlebar");
    bar.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      if (event.target.closest("button")) return;
      if (win.state === "maximized") return;
      this._startDrag(win, event, bar);
    });
    bar.addEventListener("dblclick", (event) => {
      if (event.target.closest("button")) return;
      this.toggleMaximize(win.id);
    });

    el.querySelectorAll(".win-handle").forEach((handle) => {
      handle.addEventListener("pointerdown", (event) => {
        if (event.button !== 0 || win.state === "maximized") return;
        this._startResize(win, handle.dataset.dir, event, handle);
      });
    });
  }

  _track(handle, event, onMove, onEnd) {
    const finish = () => {
      handle.removeEventListener("pointermove", onMove);
      handle.removeEventListener("pointerup", finish);
      handle.removeEventListener("pointercancel", finish);
      onEnd();
    };
    handle.addEventListener("pointermove", onMove);
    handle.addEventListener("pointerup", finish);
    handle.addEventListener("pointercancel", finish);
    if (handle.setPointerCapture) handle.setPointerCapture(event.pointerId);
    event.preventDefault();
  }

  _startDrag(win, event, handle) {
    const startX = event.clientX;
    const startY = event.clientY;
    const origin = { ...win.rect };
    const move = (e) => {
      win.rect = this._clampRect({
        x: origin.x + e.clientX - startX,
        y: origin.y + e.clientY - startY,
        w: origin.w,
        h: origin.h,
      });
      this._applyRect(win);
    };
    this._track(handle, event, move, () => this.onChange({ reason: "move", win }));
  }

  _startResize(win, dir, event, handle) {
    const startX = event.clientX;
    const startY = event.clientY;
    const origin = { ...win.rect };
    const { w: W, h: H } = this.workspaceSize;
    const move = (e) => {
      const dx = e.clientX - startX;
      const dy = e.clientY - startY;
      let { x, y, w, h } = origin;

      if (dir.includes("e")) w = origin.w + dx;
      if (dir.includes("s")) h = origin.h + dy;
      if (dir.includes("w")) { w = origin.w - dx; x = origin.x + dx; }
      if (dir.includes("n")) { h = origin.h - dy; y = origin.y + dy; }

      // 最小尺寸：西/北拖动时同步修正 x/y，避免窗口"反向跳"
      if (w < MIN_W) {
        if (dir.includes("w")) x = origin.x + origin.w - MIN_W;
        w = MIN_W;
      }
      if (h < MIN_H) {
        if (dir.includes("n")) y = origin.y + origin.h - MIN_H;
        h = MIN_H;
      }
      // 不越出工作区
      if (x < 0) { w += x; x = 0; }
      if (y < 0) { h += y; y = 0; }
      if (x + w > W) w = W - x;
      if (y + h > H) h = H - y;
      w = Math.max(1, w);
      h = Math.max(1, h);

      win.rect = {
        x: Math.round(x), y: Math.round(y),
        w: Math.round(w), h: Math.round(h),
      };
      this._applyRect(win);
    };
    this._track(handle, event, move, () => this.onChange({ reason: "resize", win }));
  }

  focus(id) {
    const win = this.windows.get(id);
    if (!win) return;
    win.el.style.zIndex = String(++this.z);
    this.activeId = id;
    this.windows.forEach((item) => item.el.classList.toggle("active", item.id === id));
    if (this._focusHandler) this._focusHandler(win);
    this.onChange({ reason: "focus", win });
  }

  /** 终端等应用可以在拿到焦点时把光标还给自己的输入区。 */
  setFocusHandler(handler) {
    this._focusHandler = handler;
  }

  minimize(id) {
    const win = this.windows.get(id);
    if (!win) return;
    win.minimized = true;
    this._applyRect(win);
    if (this.activeId === id) this.activeId = null;
    this.onChange({ reason: "minimize", win });
  }

  show(id) {
    const win = this.windows.get(id);
    if (!win) return;
    win.minimized = false;
    this._applyRect(win);
    this.focus(id);
    this.onChange({ reason: "show", win });
  }

  toggleMaximize(id) {
    const win = this.windows.get(id);
    if (!win) return;
    win.state = win.state === "maximized" ? "normal" : "maximized";
    this._applyRect(win);
    this.focus(id);
    this.onChange({ reason: "maximize", win });
  }

  close(id) {
    const win = this.windows.get(id);
    if (!win) return;
    try {
      if (win.dispose) win.dispose();
    } catch (err) {
      // 应用清理失败不应该阻止窗口关闭
      console.error("窗口清理失败", err);
    }
    win.el.remove();
    this.windows.delete(id);
    if (this.activeId === id) this.activeId = null;
    this.onChange({ reason: "close", win });
  }

  toLayout() {
    return [...this.windows.values()].map((win) => ({
      id: win.id,
      appId: win.appId,
      title: win.title,
      x: Math.round(win.rect.x),
      y: Math.round(win.rect.y),
      w: Math.round(win.rect.w),
      h: Math.round(win.rect.h),
      state: win.state,
      minimized: win.minimized,
    }));
  }

  /** 视口变化（窗口/屏幕尺寸）后把窗口重新约束回可视区。 */
  _reflow() {
    this.windows.forEach((win) => {
      win.rect = this._clampRect(win.rect);
      this._applyRect(win);
    });
    this.onChange({ reason: "reflow" });
  }

  destroy() {
    window.removeEventListener("resize", this._onViewportResize);
    [...this.windows.keys()].forEach((id) => this.close(id));
  }
}
