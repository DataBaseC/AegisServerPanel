/**
 * 桌面终端应用：一个窗口 = 一个独立 xterm + 一条独立的 PTY WebSocket。
 *
 * 断线重连沿用控制台的做法：1.5s 起步指数退避、封顶 30s；
 * 服务端用 4401/4403 关闭表示"认证/权限已失效"，此时停止重连并提示。
 */

const AUTH_CLOSE_CODES = new Set([1008, 4401, 4403]);

export function mountTerminal(container) {
  if (typeof Terminal === "undefined" || typeof FitAddon === "undefined") {
    container.innerHTML =
      '<div class="term-root"><div class="term-status err">终端组件未加载（/static/vendor/xterm.js 缺失）</div></div>';
    return { dispose() {}, focus() {} };
  }

  const root = document.createElement("div");
  root.className = "term-root";
  const mount = document.createElement("div");
  mount.className = "term-mount";
  const status = document.createElement("div");
  status.className = "term-status";
  status.textContent = "连接中…";
  root.append(mount, status);
  container.append(root);

  const term = new Terminal({
    cursorBlink: true,
    fontSize: 13,
    fontFamily: '"JetBrains Mono", Menlo, Consolas, "Noto Sans Mono CJK SC", monospace',
    scrollback: 5000,
    allowProposedApi: true,
    theme: {
      background: "#08090b", foreground: "#e9ebee", cursor: "#ffd802",
      selectionBackground: "rgba(255,216,2,.24)",
      black: "#1b1f24", red: "#ff4d4d", green: "#b8e619", yellow: "#ffd802",
      blue: "#4aa3ff", magenta: "#b26bff", cyan: "#58c8c8", white: "#e9ebee",
    },
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(mount);

  let socket = null;
  let disposed = false;
  let reconnectTimer = null;
  let reconnectDelay = 1500;
  let everConnected = false;

  const setStatus = (text, kind = "") => {
    status.textContent = text;
    status.className = `term-status ${kind}`.trim();
  };

  const doFit = () => {
    // 窗口最小化/被隐藏时容器尺寸为 0，fit 会算出 1x1，必须跳过
    if (root.clientWidth < 40 || root.clientHeight < 30) return;
    try {
      fit.fit();
    } catch (err) {
      return;
    }
    if (socket && socket.readyState === WebSocket.OPEN && term.cols && term.rows) {
      socket.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
    }
  };

  const connect = () => {
    if (disposed) return;
    setStatus("连接中…");
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    socket = new WebSocket(`${scheme}://${location.host}/api/terminal/ws`);
    socket.binaryType = "arraybuffer";

    socket.onopen = () => {
      everConnected = true;
      reconnectDelay = 1500;
      setStatus("已连接", "ok");
      requestAnimationFrame(() => {
        doFit();
        term.focus();
      });
    };

    socket.onmessage = (event) => {
      if (typeof event.data === "string") term.write(event.data);
      else term.write(new Uint8Array(event.data));
    };

    socket.onclose = (event) => {
      socket = null;
      if (disposed) return;
      if (AUTH_CLOSE_CODES.has(event.code)) {
        setStatus("会话已失效，请刷新页面重新登录", "err");
        return;
      }
      const seconds = Math.round(reconnectDelay / 1000);
      setStatus(`已断开，${seconds} 秒后重连`, "warn");
      if (everConnected && reconnectDelay <= 1500) {
        term.write("\r\n\x1b[33m[连接已断开，正在自动重连]\x1b[0m\r\n");
      }
      reconnectTimer = setTimeout(connect, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, 30000);
    };

    socket.onerror = () => setStatus("连接错误", "err");
  };

  term.onData((data) => {
    if (socket && socket.readyState === WebSocket.OPEN) socket.send(data);
  });

  // 窗口拖动/缩放、浏览器尺寸变化都会改变容器尺寸；ResizeObserver 统一兜住
  const observer = new ResizeObserver(() => {
    if (disposed) return;
    requestAnimationFrame(doFit);
  });
  observer.observe(root);

  connect();
  requestAnimationFrame(() => {
    doFit();
    term.focus();
  });

  return {
    focus() {
      if (!disposed) term.focus();
    },
    fit: doFit,
    dispose() {
      disposed = true;
      clearTimeout(reconnectTimer);
      observer.disconnect();
      if (socket) {
        try { socket.close(); } catch (err) { /* 已断开 */ }
        socket = null;
      }
      term.dispose();
      root.remove();
    },
  };
}
