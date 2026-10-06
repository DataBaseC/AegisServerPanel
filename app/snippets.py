"""代码 / 命令片段库：AI Agent 与本地脚本接入时反复要用的代码，一次给全。

与「Agent 接入」页原有的三段写死示例相比，这里做了两件事：

1. **模板按当前环境渲染**：``{{base_url}}`` / ``{{endpoint}}`` / ``{{host}}`` /
   ``{{shell}}`` 等占位符由服务端用当前请求与配置填充，复制出来即可直接粘进终端跑通，
   不再是 ``192.168.1.10`` 这类需要手工替换的占位符。
2. **令牌默认不回显**：``{{token}}`` 渲染为 ``YOUR_TOKEN``，只有显式
   ``?reveal_token=1`` 时才填入真实令牌（前端「显示令牌」按钮才这么做）。

标记 ``exec`` 的片段（``bash`` 语言 + 非破坏性）可以在面板内一键运行，运行通道仍是
``/api/terminal/exec``，门禁与审计完全一致。
"""

from __future__ import annotations

from dataclasses import dataclass, field

TOKEN_PLACEHOLDER = "YOUR_TOKEN"


@dataclass(frozen=True)
class Snippet:
    id: str
    category: str
    title: str
    language: str
    code: str
    note: str = ""
    requires: tuple[str, ...] = ()
    exec: bool = False          # 是否允许在面板内直接运行（仅 bash 且非破坏性）
    platforms: tuple[str, ...] = ()   # 为空表示通用；("posix",) 表示仅 Linux/macOS


SNIPPETS: tuple[Snippet, ...] = (
    # ---------------- Agent 接入 ----------------
    Snippet(
        id="agent-curl", category="Agent 接入", title="curl —— 执行一条命令",
        language="bash", exec=True,
        code="""curl -sS -X POST '{{endpoint}}' \\
  -H 'X-Agent-Token: {{token}}' \\
  -H 'Content-Type: application/json' \\
  -d '{"command":"uname -a && df -h","timeout":30}'""",
        note="返回 {\"code\":0,\"stdout\":\"...\",\"stderr\":\"...\"}",
    ),
    Snippet(
        id="agent-bash", category="Agent 接入", title="bash —— 像 SSH 一样用服务器",
        language="bash",
        code="""export SP_URL='{{endpoint}}'
export SP_TOKEN='{{token}}'

# 依赖 jq：sudo apt install -y jq
sp() {
  jq -n --arg c "$*" '{command:$c, timeout:600}' \\
    | curl -sS -X POST "$SP_URL" -H "X-Agent-Token: $SP_TOKEN" \\
        -H 'Content-Type: application/json' --data @- \\
    | jq -r '.stdout, .stderr'
}

# 用法：sp systemctl restart nginx""",
        requires=("jq",),
    ),
    Snippet(
        id="agent-python", category="Agent 接入", title="python —— 供 AI Agent 工具调用",
        language="python",
        code="""import json
import urllib.request

ENDPOINT = "{{endpoint}}"
TOKEN = "{{token}}"


def server(cmd: str, timeout: int = 600, cwd: str | None = None) -> str:
    \"\"\"在服务器上执行一条命令，返回 stdout；失败抛 RuntimeError。\"\"\"
    payload = {"command": cmd, "timeout": timeout}
    if cwd:
        payload["cwd"] = cwd
    req = urllib.request.Request(
        ENDPOINT,
        data=json.dumps(payload).encode(),
        headers={"X-Agent-Token": TOKEN, "Content-Type": "application/json"},
    )
    res = json.load(urllib.request.urlopen(req, timeout=timeout + 10))
    if res["code"] != 0:
        raise RuntimeError(res["stderr"] or f"exit {res['code']}")
    return res["stdout"]


if __name__ == "__main__":
    print(server("uptime"))""",
    ),
    Snippet(
        id="agent-powershell", category="Agent 接入", title="PowerShell —— Windows 侧调用",
        language="powershell",
        note="在 Windows 本机运行，访问服务器上的面板",
        code="""$Url   = '{{endpoint}}'
$Token = '{{token}}'

function Invoke-Server {
    param([string]$Command, [int]$Timeout = 600)
    $body = @{ command = $Command; timeout = $Timeout } | ConvertTo-Json -Compress
    $res = Invoke-RestMethod -Method Post -Uri $Url -Body $body -ContentType 'application/json' `
        -Headers @{ 'X-Agent-Token' = $Token }
    if ($res.code -ne 0) { throw $res.stderr }
    $res.stdout
}

# 用法：Invoke-Server 'systemctl status nginx'""",
    ),
    Snippet(
        id="agent-panel-cli", category="Agent 接入", title="服务器本机管理命令",
        language="bash",
        code="""# 全部在服务器本机执行（面板界面不提供这些入口）
serverpanel --show-mode              # 当前模式
serverpanel --enable-internal        # 解锁终端 / 文件 / 电源（Agent 令牌同时生效）
serverpanel --disable-internal       # 回到只读
serverpanel --agent-token            # 生成 / 轮换 Agent 令牌
serverpanel --status                 # 运行状态 + 健康检查
serverpanel --restart                # 重启面板（登录态保持）
serverpanel --set-password '新密码'   # 忘记密码时重置""",
    ),

    # ---------------- 终端常用 ----------------
    Snippet(
        id="sh-port", category="终端常用", title="查端口被谁占用", language="bash", exec=True,
        requires=("ss",),
        code="""# 方案一：ss（推荐）
ss -tulnp | grep -w 8787

# 方案二：没有 ss 时用 lsof / fuser
lsof -i :8787
fuser -n tcp 8787""",
    ),
    Snippet(
        id="sh-kill", category="终端常用", title="按名字结束进程", language="bash",
        code="""pkill -f 'uvicorn app.main'      # 按命令行匹配
pkill -x nginx                   # 精确匹配进程名
ps aux | grep -v grep | grep uvicorn   # 先看清楚再动手""",
    ),
    Snippet(
        id="sh-tar", category="终端常用", title="打包 / 解包", language="bash",
        code="""tar czf backup-$(date +%F).tar.gz -C /opt myapp      # 打包
tar xzf backup.tar.gz -C /tmp                        # 解包
tar tzf backup.tar.gz | head                         # 只看内容
rsync -av --delete /opt/myapp/ root@主机:/opt/myapp/  # 增量同步""",
    ),
    Snippet(
        id="sh-log-journal", category="终端常用", title="journal 日志检索", language="bash",
        code="""journalctl -u nginx -n 200 --no-pager          # 某服务最近 200 行
journalctl -p err --since '1 hour ago'          # 一小时内错误
journalctl -f -u nginx                          # 实时跟随
journalctl --disk-usage && journalctl --vacuum-size=200M   # 清理日志占用""",
        requires=("journalctl",),
    ),
    Snippet(
        id="sh-disk", category="终端常用", title="磁盘排查三连", language="bash", exec=True,
        code="""df -h                    # 分区占用
df -i                    # inode（"没满却写不进"多半是它）
du -x -h -d1 / | sort -h | tail -15    # 一级目录排行""",
    ),

    # ---------------- Docker ----------------
    Snippet(
        id="docker-in", category="Docker", title="进入容器 / 看日志", language="bash",
        requires=("docker",),
        code="""docker ps --format 'table {{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}'
docker exec -it 容器名 /bin/bash
docker logs -f --tail 200 容器名
docker inspect -f '{{.State.Status}}' 容器名""",
    ),
    Snippet(
        id="docker-clean", category="Docker", title="清理未使用资源", language="bash",
        requires=("docker",),
        code="""docker system df                 # 先看占用
docker image prune -f            # 悬空镜像
docker container prune -f        # 已停止容器
docker builder prune -f          # 构建缓存
docker system prune -a --volumes # 彻底清理（会删未使用卷，慎用）""",
    ),

    # ---------------- 面板运维 ----------------
    Snippet(
        id="panel-offline-update", category="面板运维", title="离线升级（无外网机器）",
        language="bash",
        code="""# 1) 联网机器上打离线包（代码 + 依赖 wheel）
git clone https://github.com/DataBaseC/AegisServerPanel.git
cd AegisServerPanel && scripts/make-offline-bundle.sh
# 交叉架构打包：--platform manylinux2014_aarch64 --python-version 3.12 --implementation cp --abi cp312

# 2) 传到目标机后覆盖代码目录（配置在 /etc/serverpanel/，不受影响）
tar xzf AegisServerPanel-offline.tar.gz -C /root/aegis --strip-components=1

# 3) 重启
serverpanel --restart && serverpanel --status""",
    ),
    Snippet(
        id="panel-transfer", category="面板运维", title="代码分块传输（GitHub 不可达时）",
        language="bash",
        note="SERVER_ACCESS.md 记录的可靠通道：本地 base64 → 分块走 exec API → 服务器校验后落盘",
        code="""# 本地（PowerShell）：把 tar.gz 切成 20KB 的 base64 分块
$b = [Convert]::ToBase64String([IO.File]::ReadAllBytes('bundle.tar.gz'))
$i = 0; $n = 20000
while ($i -lt $b.Length) {
    $chunk = $b.Substring($i, [Math]::Min($n, $b.Length - $i))
    # 逐块 POST /api/terminal/exec，服务器端 >> /tmp/bundle.b64
    $i += $n
}

# 服务器：解码并校验
base64 -d /tmp/bundle.b64 > /tmp/bundle.tar.gz
md5sum /tmp/bundle.tar.gz""",
    ),
    Snippet(
        id="panel-supervisor", category="面板运维", title="无 systemd 环境的守护与自启",
        language="bash",
        code="""# 守护脚本由 install 生成：flock 单实例 + 崩溃 1 秒拉起 + 日志轮转
/root/aegis/AegisServerPanel/panel-supervisor.sh          # 前台观察
setsid nohup /root/aegis/AegisServerPanel/panel-supervisor.sh >/dev/null 2>&1 &   # 后台

# 容器内 crontab 兜底
crontab -l ; echo '@reboot /root/aegis/AegisServerPanel/panel-supervisor.sh &' | crontab -

# Termux 侧（安装 Termux:Boot 后）~/.termux/boot/start-panel.sh
# termux-wake-lock
# proot-distro login ubuntu -- bash -c "service cron start; setsid nohup /root/aegis/AegisServerPanel/panel-supervisor.sh >/dev/null 2>&1 &"
""",
    ),

    # ---------------- 开发片段（本机运行） ----------------
    Snippet(
        id="dev-run", category="开发调试", title="本机前台调试面板", language="bash",
        platforms=("posix",), exec=True,
        code="""# 在服务器上直接前台启动，日志打到终端（不经守护）
cd /root/aegis/AegisServerPanel
./.venv/bin/python -m app.main --host 0.0.0.0 --port 8788

# 或者只跑测试
./.venv/bin/python -m pytest tests -q""",
    ),
    Snippet(
        id="dev-log-reload", category="开发调试", title="配置热加载与模式切换", language="bash",
        platforms=("posix",),
        code="""# 配置文件按 mtime 热加载：本机命令改完，运行中的面板数秒内自动生效
serverpanel --enable-internal
watch -n1 'cat /etc/serverpanel/config.json | head -20'   # 观察变化

# 托管应用注册表
cat /etc/serverpanel/apps.json""",
    ),
)


def snippet_by_id(snippet_id: str) -> Snippet | None:
    for snippet in SNIPPETS:
        if snippet.id == snippet_id:
            return snippet
    return None


def render_text(text: str, context: dict[str, str]) -> str:
    out = text
    for key, value in context.items():
        out = out.replace("{{" + key + "}}", value)
    return out


def public_snippets(context: dict[str, str], platform: str = "posix") -> list[dict]:
    result = []
    for snippet in SNIPPETS:
        if snippet.platforms and platform not in snippet.platforms:
            continue
        result.append({
            "id": snippet.id,
            "category": snippet.category,
            "title": snippet.title,
            "language": snippet.language,
            "note": snippet.note,
            "requires": list(snippet.requires),
            "exec": snippet.exec and snippet.language == "bash",
            "code": render_text(snippet.code, context),
            "raw": snippet.code,
        })
    return result
