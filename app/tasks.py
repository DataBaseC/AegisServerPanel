"""常用操作（任务快照）：把经常要敲的一长串命令收敛成一次点击。

设计原则：

- **声明式，不是"命令输入框"**。每个任务是一段写死的命令模板，只有声明了
  ``params`` 的任务才接受输入，且输入必须匹配正则（默认只允许 ``[\\w./:@=-]{0,200}``）。
  这样"常用操作"不会退化成终端的马甲，也不会多出一层伪安全感。
- **输出即审计**。所有执行都走 ``shell.run``（超时 + 512KB 截断），并记入
  ``routes.tasks_routes`` 的执行记录，与 Agent 审计同源可查。
- **能力自适应**。标记了 ``requires`` 的任务在前端按 ``/api/system/capabilities``
  的探测结果自动置灰（例如无 systemd 环境下的 journal 相关任务）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

DEFAULT_PARAM_RE = r"[\w./:@=,\- ]{0,200}"


@dataclass(frozen=True)
class Param:
    name: str
    label: str
    default: str = ""
    pattern: str = DEFAULT_PARAM_RE
    placeholder: str = ""


@dataclass(frozen=True)
class Task:
    id: str
    group: str
    title: str
    command: str
    description: str = ""
    timeout: int = 60
    danger: bool = False
    requires: tuple[str, ...] = ()
    params: tuple[Param, ...] = ()
    readonly: bool = True       # 只读任务在公网模式下也允许运行（本模块整体要求内网，此项供未来放宽）
    kind: str = "cmd"           # cmd = 交给 shell；panel = 面板自身动作


TASKS: tuple[Task, ...] = (
    # ---------------- 系统快照 ----------------
    Task(
        id="sys-snapshot", group="系统快照", title="资源总览",
        description="负载、内存、磁盘、温度一次看全",
        command=(
            "echo '== 负载 / 运行时长 =='; uptime; "
            "echo; echo '== 内存 =='; head -3 /proc/meminfo; "
            "echo; echo '== 磁盘 =='; df -h -x tmpfs -x devtmpfs 2>/dev/null || df -h; "
            "echo; echo '== 温度 =='; for z in /sys/class/thermal/thermal_zone*/temp; do "
            "[ -f \"$z\" ] && echo \"$(dirname $z | xargs basename): $(cat $z)\"; done"
        ),
    ),
    Task(
        id="sys-top", group="系统快照", title="资源占用 Top 10",
        description="按内存排序的进程前 10",
        command="ps aux --sort=-%mem 2>/dev/null | head -11 || ps aux | head -11",
    ),
    Task(
        id="sys-ports", group="系统快照", title="监听端口一览",
        description="所有 TCP/UDP 监听端口与所属进程",
        command="(ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null) | head -60",
        requires=("ss",),
    ),
    Task(
        id="sys-boot", group="系统快照", title="开机自启项",
        description="cron 任务、rc.local、systemd 启用的服务",
        command=(
            "echo '== crontab (root) =='; crontab -l 2>/dev/null || echo '（无）'; "
            "echo; echo '== /etc/cron.d =='; ls -1 /etc/cron.d 2>/dev/null || echo '（无）'; "
            "echo; echo '== rc.local =='; [ -f /etc/rc.local ] && cat /etc/rc.local || echo '（无）'; "
            "echo; echo '== 已启用的 systemd 服务 =='; "
            "systemctl list-unit-files --state=enabled --no-pager 2>/dev/null || echo '（无 systemd）'"
        ),
    ),

    # ---------------- 磁盘 ----------------
    Task(
        id="disk-usage", group="磁盘", title="根分区占用明细",
        description="根目录下各一级目录的体积排行",
        command="du -x -h -d1 / 2>/dev/null | sort -h | tail -20",
        timeout=180,
    ),
    Task(
        id="disk-big-files", group="磁盘", title="大文件 Top 20",
        description="根文件系统内大于 100MB 的文件",
        command="find / -xdev -type f -size +100M -printf '%s\\t%p\\n' 2>/dev/null "
                "| sort -rn | head -20 | awk -F'\\t' '{printf \"%.1f MB\\t%s\\n\", $1/1048576, $2}'",
        timeout=300,
    ),
    Task(
        id="disk-inodes", group="磁盘", title="inode 占用",
        description="排查「磁盘没满却写不进文件」",
        command="df -i",
    ),
    Task(
        id="disk-tmp-clean", group="磁盘", title="清理 /tmp 中 7 天前的文件",
        description="删除 /tmp 下超过 7 天未修改的普通文件（不算子目录内容）",
        command="find /tmp -xdev -type f -mtime +7 -print -delete 2>/dev/null | head -50; "
                "echo '--- 完成，/tmp 现状 ---'; du -sh /tmp 2>/dev/null",
        danger=True, timeout=180,
    ),

    # ---------------- 日志 ----------------
    Task(
        id="log-errors", group="日志", title="最近的错误日志",
        description="journal 中 priority<=err 的记录（无 systemd 时自动跳过）",
        command="journalctl -p err -n 60 --no-pager 2>/dev/null "
                "|| { echo '无 systemd/journalctl，改为查看 /var/log 下最近修改的日志尾部'; "
                "ls -t /var/log/*.log 2>/dev/null | head -3 | while read f; do "
                "echo \"== $f ==\"; tail -20 \"$f\"; done; }",
        timeout=60,
    ),
    Task(
        id="log-dmesg", group="日志", title="内核环形缓冲最后 50 行",
        command="dmesg 2>/dev/null | tail -50 || echo 'dmesg 不可用（容器环境常见）'",
        requires=("dmesg",),
    ),
    Task(
        id="log-auth", group="日志", title="登录失败记录",
        description="最近 40 条认证失败（暴力破解排查）",
        command="(grep -iE 'failed|invalid' /var/log/auth.log 2>/dev/null || "
                "journalctl -u ssh -n 40 --no-pager 2>/dev/null || "
                "grep -iE 'failed|invalid' /var/log/secure 2>/dev/null) | tail -40 "
                "|| echo '未找到认证日志'",
    ),
    Task(
        id="log-panel", group="日志", title="面板自身日志尾部",
        description="panel.log 最后 80 行（升级 / 重启排查）",
        command="tail -80 \"$(dirname \"$(readlink -f /usr/local/bin/serverpanel 2>/dev/null)\" 2>/dev/null)/panel.log\" "
                "2>/dev/null || tail -80 ./panel.log 2>/dev/null || echo '未找到 panel.log'",
    ),

    # ---------------- 网络 ----------------
    Task(
        id="net-listen", group="网络", title="谁占用了端口",
        description="查询指定端口被哪个进程占用",
        command="(ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null) | grep -w '{{port}}' "
                "|| echo '端口 {{port}} 没有监听进程'",
        params=(Param("port", "端口号", "8787", r"\d{1,5}", "例如 8787"),),
        requires=("ss",),
    ),
    Task(
        id="net-ping", group="网络", title="连通性测试",
        description="ping 目标地址 4 次",
        command="ping -c 4 -W 2 '{{target}}' 2>&1 | tail -8",
        params=(Param("target", "目标地址", "223.5.5.5", r"[\w.\-:]{1,64}", "IP 或域名"),),
        timeout=30,
    ),
    Task(
        id="net-http", group="网络", title="HTTP 探测",
        description="查看状态码、耗时与关键响应头",
        command="curl -sS -o /dev/null -D - --max-time 15 '{{url}}' 2>&1 | head -20",
        params=(Param("url", "URL", "https://www.baidu.com", r"https?://[\w.\-:/?&=#%+~]{1,180}", "https://…"),),
        timeout=30,
    ),
    Task(
        id="net-dns", group="网络", title="DNS 解析",
        command="(getent hosts '{{domain}}' || nslookup '{{domain}}' 2>/dev/null || "
                "echo '解析失败') | head -10",
        params=(Param("domain", "域名", "github.com", r"[\w.\-]{1,128}", "例如 github.com"),),
        timeout=30,
    ),
    Task(
        id="net-speed", group="网络", title="网卡流量统计",
        command="cat /proc/net/dev | awk 'NR>2 {printf \"%-12s 收 %.1f MB  发 %.1f MB\\n\", $1, $2/1048576, $10/1048576}'",
    ),

    # ---------------- 面板自身 ----------------
    Task(
        id="panel-status", group="面板", title="面板运行状态",
        description="版本、模式、健康检查、守护进程",
        command="serverpanel --status 2>&1 | head -40; "
                "echo; echo '== healthz =='; curl -sS --max-time 5 http://127.0.0.1:8787/healthz; echo",
        timeout=60,
    ),
    Task(
        id="panel-log-errors", group="面板", title="面板日志中的异常",
        command="tail -400 ./panel.log 2>/dev/null | grep -iE 'error|exception|traceback|失败' | tail -30 "
                "|| echo '未发现异常记录'",
    ),
    Task(
        id="panel-restart", group="面板", title="重启面板服务",
        description="升级或配置变更后重启；登录态保持，页面会自动重连",
        command="nohup serverpanel --restart >/dev/null 2>&1 & echo '重启指令已下发，数秒后本页面自动恢复'",
        danger=True, timeout=20, kind="panel",
    ),
)


def task_by_id(task_id: str) -> Task | None:
    for task in TASKS:
        if task.id == task_id:
            return task
    return None


def render(task: Task, values: dict[str, str]) -> str:
    """把参数带入命令模板。

    每个参数值都必须完整匹配 ``Param.pattern``（默认只允许 ``[\\w./:@=,\\- ]``），
    因此不能注入 ``;``、``|``、``$()``、反引号与引号；校验不通过直接报错，不做静默兜底。
    """
    command = task.command
    for param in task.params:
        raw = str(values.get(param.name, "") or param.default)
        if not re.fullmatch(param.pattern, raw):
            raise ValueError(f"参数「{param.label}」不合法：{raw[:40]}")
        command = command.replace("{{" + param.name + "}}", raw)
    return command


def public_tasks() -> list[dict]:
    return [{
        "id": t.id,
        "group": t.group,
        "title": t.title,
        "description": t.description,
        "danger": t.danger,
        "requires": list(t.requires),
        "readonly": t.readonly,
        "kind": t.kind,
        "params": [
            {"name": p.name, "label": p.label, "default": p.default,
             "placeholder": p.placeholder}
            for p in t.params
        ],
    } for t in TASKS]
