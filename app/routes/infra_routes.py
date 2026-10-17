"""基础设施运维：Docker、防火墙、反向代理 / 证书、数据库探测、SSH 公钥、网络工具。

2.0 M3 的定位是"**只看 + 少量受控写**"：能力全部来自系统 CLI，缺工具就降级
（端点返回 ``capabilities`` 为 false，前端隐藏对应面板），绝不让面板起不来。

安全约定：

- 所有端点挂 ``require_internal``；删除容器、防火墙写、nginx 重载还额外要求
  M1 的服务端确认令牌（``app/confirm.py`` 新增 docker / firewall / proxy 动作）。
- 用户输入（容器 id、端口、协议、主机、库名、工具目标）逐项白名单校验，
  命令行一律以参数列表交给 ``shell.run``，不做任何字符串拼接。
- 数据库探测只执行**固定只读语句**，密码走环境变量传递，不写审计、
  并且会从输出里抹掉。
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .. import boot as boot_mod
from .. import ops, shell
from ..audit import AuditEvent, audit
from ..auth import client_ip, require_internal

router = APIRouter(prefix="/api/panel/infra", tags=["infra"],
                   dependencies=[Depends(require_internal)])

DOCKER_TIMEOUT = 30
DOCKER_ACTION_TIMEOUT = 120
FIREWALL_TIMEOUT = 30
PROXY_TIMEOUT = 30
DB_TIMEOUT = 10
NET_TIMEOUT = 30
NET_MAX_OUTPUT = 64 * 1024      # 网络工具输出截断 64KB
LOG_MAX_LINES = 2000
CERT_WARN_DAYS = 30
NGINX_SITES = "/etc/nginx/sites-enabled"
LETSENCRYPT_LIVE = "/etc/letsencrypt/live"


def _guard(fn, *args, **kwargs):
    """把 OpsError（用户输入问题）翻译成 400，而不是 500。"""
    try:
        return fn(*args, **kwargs)
    except ops.OpsError as exc:
        raise HTTPException(400, str(exc)) from exc


# ---------------------------------------------------------------- Docker


def _docker_required() -> None:
    if not shell.available("docker"):
        raise HTTPException(400, "本机没有 docker 命令，无法管理容器")


async def _docker_json(args: list[str]) -> tuple[list[dict], str]:
    result = await shell.run(["docker"] + args, timeout=DOCKER_TIMEOUT)
    if not result.ok:
        return [], (result.text or "docker 命令执行失败").strip()[:400]
    return ops.parse_docker_json(result.out), ""


def _container(item: dict) -> dict:
    return {
        "id": item.get("id", ""),
        "name": item.get("names", ""),
        "image": item.get("image", ""),
        "state": str(item.get("state") or "").lower(),
        "status": item.get("status", ""),
        "ports": item.get("ports", ""),
        "created": item.get("createdat", ""),
    }


def _image(item: dict) -> dict:
    return {
        "id": item.get("id", ""),
        "repository": item.get("repository", ""),
        "tag": item.get("tag", ""),
        "size": item.get("size", ""),
        "created": item.get("createdat", "") or item.get("createdsince", ""),
    }


@router.get("/docker/containers")
async def docker_containers():
    if not shell.available("docker"):
        return {"capabilities": {"docker": False}, "containers": [],
                "error": "本机没有 docker 命令"}
    items, error = await _docker_json(["ps", "-a", "--format", "{{json .}}"])
    return {"capabilities": {"docker": True},
            "containers": [_container(item) for item in items], "error": error}


@router.get("/docker/images")
async def docker_images():
    if not shell.available("docker"):
        return {"capabilities": {"docker": False}, "images": [],
                "error": "本机没有 docker 命令"}
    items, error = await _docker_json(["images", "--format", "{{json .}}"])
    return {"capabilities": {"docker": True}, "images": [_image(item) for item in items],
            "error": error}


@router.get("/docker/containers/{cid}/logs")
async def docker_logs(cid: str, tail: int = 200):
    _docker_required()
    ident = _guard(ops.check_container_id, cid)
    lines = max(1, min(int(tail or 200), LOG_MAX_LINES))
    result = await shell.run(["docker", "logs", "--tail", str(lines), ident],
                             timeout=DOCKER_TIMEOUT)
    # docker logs 把容器 stdout/stderr 分别写到两者的 stderr/stdout，这里合并展示
    output = (result.out or "") + (result.err or "")
    return {"id": ident, "lines": output.splitlines()[:LOG_MAX_LINES],
            "ok": result.ok,
            "error": None if result.ok else (result.err or "读取日志失败").strip()[:400]}


DOCKER_ACTIONS = {"start": "启动", "stop": "停止", "restart": "重启"}


class DockerActionBody(BaseModel):
    action: str


@router.post("/docker/containers/{cid}/action")
async def docker_action(cid: str, body: DockerActionBody, request: Request):
    _docker_required()
    ident = _guard(ops.check_container_id, cid)
    if body.action == "remove":
        # 删除不可逆，必须走下面带确认令牌的 DELETE 路径
        raise HTTPException(400, "删除容器请使用 DELETE /api/panel/infra/docker/containers/{id}"
                                 "（需要服务端确认令牌）")
    if body.action not in DOCKER_ACTIONS:
        raise HTTPException(400, "不支持的操作，可选：start / stop / restart / remove")
    result = await shell.run(["docker", body.action, ident], timeout=DOCKER_ACTION_TIMEOUT)
    audit.record(AuditEvent(action="docker_action", target=ident,
                            summary=DOCKER_ACTIONS[body.action], source="web",
                            ip=client_ip(request), ok=result.ok, code=result.code))
    if not result.ok:
        raise HTTPException(500, (result.text or "docker 操作失败").strip()[-600:])
    return {"ok": True, "message": f"{ident} {DOCKER_ACTIONS[body.action]}成功"}


@router.delete("/docker/containers/{cid}")
async def docker_remove(cid: str, request: Request, force: bool = False):
    _docker_required()
    ident = _guard(ops.check_container_id, cid)
    command = ["docker", "rm"] + (["-f"] if force else []) + [ident]
    result = await shell.run(command, timeout=DOCKER_ACTION_TIMEOUT)
    audit.record(AuditEvent(action="docker_action", target=ident,
                            summary="删除容器" + ("（强制）" if force else ""), source="web",
                            ip=client_ip(request), ok=result.ok, code=result.code))
    if not result.ok:
        raise HTTPException(500, (result.text or "删除容器失败").strip()[-600:])
    return {"ok": True, "message": f"已删除容器 {ident}"}


# ---------------------------------------------------------------- 防火墙


def _watch_ports() -> set[str]:
    """危险规则判定的关注端口：22 与面板自身的监听端口。"""
    ports = {"22"}
    with contextlib.suppress(Exception):
        port = int(boot_mod.listen_status().get("port") or 0)
        if port:
            ports.add(str(port))
    return ports


@router.get("/firewall")
async def firewall_status():
    """只读：ufw 优先（含规则编号），否则退到 iptables -S。"""
    ufw = shell.available("ufw")
    iptables = shell.available("iptables")
    capabilities = {"ufw": ufw, "iptables": iptables}
    if ufw:
        result = await shell.run(["ufw", "status", "numbered"], timeout=FIREWALL_TIMEOUT)
        return {"backend": "ufw", "capabilities": capabilities, "writable": True,
                "rules": ops.parse_ufw_status(result.out, _watch_ports()),
                "error": "" if result.ok else (result.text or "").strip()[:400]}
    if iptables:
        result = await shell.run(["iptables", "-S"], timeout=FIREWALL_TIMEOUT)
        return {"backend": "iptables", "capabilities": capabilities, "writable": False,
                "rules": ops.parse_iptables(result.out, _watch_ports()),
                "error": "" if result.ok else (result.text or "").strip()[:400]}
    return {"backend": "", "capabilities": capabilities, "writable": False, "rules": [],
            "error": "本机没有 ufw / iptables，无法查看防火墙"}


class FirewallBody(BaseModel):
    port: int | str
    proto: str = "tcp"


@router.post("/firewall/{action}")
async def firewall_change(action: str, body: FirewallBody, request: Request):
    """放行 / 拒绝端口：只支持 ufw 后端（iptables 只读展示，避免误伤已有规则）。"""
    if action not in ("allow", "deny"):
        raise HTTPException(404, "不支持的操作")
    if not shell.available("ufw"):
        raise HTTPException(400, "本机没有 ufw；iptables 后端仅支持只读查看，请手工维护规则")
    port = _guard(ops.check_port, body.port)
    proto = _guard(ops.check_proto, body.proto)
    rule = f"{port}/{proto}"
    result = await shell.run(["ufw", action, rule], timeout=FIREWALL_TIMEOUT)
    audit.record(AuditEvent(action="firewall_rule", target=rule,
                            summary="放行" if action == "allow" else "拒绝", source="web",
                            ip=client_ip(request), ok=result.ok, code=result.code))
    if not result.ok:
        raise HTTPException(500, (result.text or "ufw 执行失败").strip()[-600:])
    return {"ok": True, "message": f"已{'放行' if action == 'allow' else '拒绝'} {rule}"}


# ---------------------------------------------------------------- 反向代理


def _nginx_sites() -> list[str]:
    try:
        return ops.parse_nginx_sites(os.listdir(NGINX_SITES))
    except OSError:
        return []


def _first_line(text: str) -> str:
    lines = (text or "").strip().splitlines()
    return lines[0][:160] if lines else ""


async def _nginx_info() -> dict:
    version = await shell.run(["nginx", "-v"], timeout=PROXY_TIMEOUT)
    tested = await shell.run(["nginx", "-t"], timeout=PROXY_TIMEOUT)
    output = (tested.err or "") + (tested.out or "")
    return {
        "version": _first_line(version.err or version.out),
        "dir": NGINX_SITES,
        "sites": await asyncio.to_thread(_nginx_sites),
        "config_test": {"ok": tested.ok, "output": output.strip()[-2000:]},
    }


async def _caddy_info() -> dict:
    result = await shell.run(["caddy", "version"], timeout=PROXY_TIMEOUT)
    return {"version": _first_line(result.out or result.err)}


@router.get("/proxy")
async def proxy_status():
    nginx = shell.available("nginx")
    caddy = shell.available("caddy")
    return {
        "capabilities": {"nginx": nginx, "caddy": caddy,
                         "systemd": os.path.isdir("/run/systemd/system")},
        "nginx": await _nginx_info() if nginx else None,
        "caddy": await _caddy_info() if caddy else None,
    }


@router.post("/proxy/reload")
async def proxy_reload(request: Request):
    """先 nginx -t 再 reload：配置有语法错误时拒绝执行，不影响线上服务。"""
    if not shell.available("nginx"):
        raise HTTPException(400, "本机没有 nginx，无法重载配置")
    tested = await shell.run(["nginx", "-t"], timeout=PROXY_TIMEOUT)
    if not tested.ok:
        audit.record(AuditEvent(action="proxy_reload", target="nginx", summary="nginx -t 未通过",
                                source="web", ip=client_ip(request), ok=False))
        raise HTTPException(400, "nginx -t 未通过，未执行重载："
                                 + ((tested.err or tested.out).strip()[-400:] or "配置有误"))
    if os.path.isdir("/run/systemd/system") and shell.available("systemctl"):
        command = ["systemctl", "reload", "nginx"]
    else:
        command = ["nginx", "-s", "reload"]
    result = await shell.run(command, timeout=PROXY_TIMEOUT)
    audit.record(AuditEvent(action="proxy_reload", target="nginx",
                            summary=" ".join(command), source="web", ip=client_ip(request),
                            ok=result.ok, code=result.code))
    if not result.ok:
        raise HTTPException(500, (result.text or "重载失败").strip()[-600:])
    return {"ok": True, "message": "nginx 已重载配置"}


def _certificate_files() -> list[dict]:
    try:
        names = sorted(os.listdir(LETSENCRYPT_LIVE))
    except OSError:
        return []
    entries = []
    for name in names:
        base = os.path.join(LETSENCRYPT_LIVE, name)
        if not os.path.isdir(base):
            continue
        path = ""
        for candidate in ("cert.pem", "fullchain.pem"):
            full = os.path.join(base, candidate)
            if os.path.isfile(full):
                path = full
                break
        entries.append({"name": name, "path": path})
    return entries


async def _certificate_entry(entry: dict, openssl: bool) -> dict:
    item = {"name": entry["name"], "path": entry["path"], "not_after": "",
            "days_left": None, "expiring": False}
    if not openssl or not entry["path"]:
        return item
    result = await shell.run(["openssl", "x509", "-enddate", "-noout", "-in", entry["path"]],
                             timeout=PROXY_TIMEOUT)
    parsed = ops.parse_not_after(result.out or result.err)
    if parsed:
        item.update(parsed)
        item["expiring"] = parsed["days_left"] <= CERT_WARN_DAYS
    return item


@router.get("/proxy/certificates")
async def proxy_certificates():
    openssl = shell.available("openssl")
    entries = await asyncio.to_thread(_certificate_files)
    certificates = [await _certificate_entry(entry, openssl) for entry in entries]
    return {"dir": LETSENCRYPT_LIVE, "capabilities": {"openssl": openssl},
            "warn_days": CERT_WARN_DAYS, "certificates": certificates}


# ---------------------------------------------------------------- 数据库

DB_ENGINES = (("mysql", "MySQL / MariaDB"), ("psql", "PostgreSQL"), ("redis-cli", "Redis"))
DB_DEFAULT_PORTS = {"mysql": 3306, "psql": 5432, "redis-cli": 6379}
# 只读探测语句固定在这里，不接受任何用户自定义 SQL
DB_READONLY = {"mysql": "SHOW STATUS", "psql": "SELECT version()", "redis-cli": "INFO"}
DB_OUTPUT_LIMIT = 16 * 1024


class DbProbeBody(BaseModel):
    kind: str
    host: str = "127.0.0.1"
    port: int | None = None
    user: str = ""
    database: str = ""
    password: str = ""


@router.get("/databases")
async def database_status():
    engines = []
    for binary, label in DB_ENGINES:
        path = shell.which(binary)
        engines.append({"kind": binary, "label": label, "available": bool(path),
                        "path": path or "", "default_port": DB_DEFAULT_PORTS[binary],
                        "command": DB_READONLY[binary]})
    return {"engines": engines, "readonly": True}


def _mysql_probe(host: str, port: int, user: str, database: str,
                 password: str) -> tuple[list[str], dict]:
    args = ["mysql", "-h", host]
    if port:
        args += ["-P", str(port)]
    if user:
        args += ["-u", user]
    if database:
        args.append(database)
    env = {"MYSQL_PWD": password} if password else {}
    return args + ["-e", DB_READONLY["mysql"]], env


def _psql_probe(host: str, port: int, user: str, database: str,
                password: str) -> tuple[list[str], dict]:
    args = ["psql", "-h", host]
    if port:
        args += ["-p", str(port)]
    if user:
        args += ["-U", user]
    if database:
        args += ["-d", database]
    env = {"PGPASSWORD": password} if password else {}
    return args + ["-c", DB_READONLY["psql"]], env


def _redis_probe(host: str, port: int, user: str, database: str,
                 password: str) -> tuple[list[str], dict]:
    args = ["redis-cli", "-h", host]
    if port:
        args += ["-p", str(port)]
    env = {"REDISCLI_AUTH": password} if password else {}
    return args + [DB_READONLY["redis-cli"]], env


DB_BUILDERS = {"mysql": _mysql_probe, "psql": _psql_probe, "redis-cli": _redis_probe}


def _build_probe(kind: str, host: str, port: int, user: str, database: str,
                 password: str) -> tuple[list[str], dict]:
    """拼出**固定只读命令**；密码走环境变量，不出现在 argv 里（ps 看不到）。

    ``user`` / ``database`` 参数在 redis 下被忽略（redis 没有这两项）。
    """
    return DB_BUILDERS[kind](host, port, user, database, password)


def _scrub(text: str, password: str) -> str:
    """输出里若回显了密码（某些客户端会），替换掉再返回。"""
    if password:
        return text.replace(password, "***")
    return text


@router.post("/databases/probe")
async def database_probe(body: DbProbeBody, request: Request):
    kind = (body.kind or "").strip()
    if kind not in DB_DEFAULT_PORTS:
        raise HTTPException(400, "只支持 mysql / psql / redis-cli 三种客户端")
    if not shell.available(kind):
        raise HTTPException(400, f"本机没有 {kind} 命令")
    host = _guard(ops.check_db_host, body.host)
    port = _guard(ops.check_port, body.port) if body.port else 0
    user = _guard(ops.check_ident, body.user, "用户名") if (body.user or "").strip() else ""
    database = (_guard(ops.check_ident, body.database, "库名")
                if (body.database or "").strip() else "")
    command, env = _build_probe(kind, host, port, user, database, body.password or "")
    started = time.perf_counter()
    result = await shell.run(command, timeout=DB_TIMEOUT, env=env or None)
    output = _scrub((result.out or "") + (result.err or ""), body.password or "")
    audit.record(AuditEvent(action="db_probe",
                            target=f"{kind}@{host}:{port or DB_DEFAULT_PORTS[kind]}",
                            summary=f"user={user or '-'} db={database or '-'}",
                            source="web", ip=client_ip(request), ok=result.ok,
                            code=result.code,
                            duration=round(time.perf_counter() - started, 3)))
    if not result.ok:
        raise HTTPException(502, (output.strip() or "连接失败")[-600:])
    return {"ok": True, "kind": kind, "output": output[:DB_OUTPUT_LIMIT],
            "command": DB_READONLY[kind]}


# ---------------------------------------------------------------- SSH 公钥


def _keys_path() -> Path:
    return Path(os.path.expanduser("~")) / ".ssh" / "authorized_keys"


def _read_key_lines(path: Path) -> list[str]:
    try:
        text = path.read_text("utf-8", "replace")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")]


def _append_key(path: Path, line: str) -> None:
    """追加一行公钥：目录 0700、文件 0600（ssh 对权限很严格）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path.parent, 0o700)
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line + "\n")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def _remove_key(path: Path, line: str) -> bool:
    """精确匹配删除一行（不做子串匹配，避免误删别的公钥）。"""
    lines = _read_key_lines(path)
    kept = [item for item in lines if item != line]
    if len(kept) == len(lines):
        return False
    path.write_text("".join(item + "\n" for item in kept), "utf-8")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return True


async def _fingerprint(line: str) -> str:
    if not shell.available("ssh-keygen"):
        return ""
    result = await shell.run(["ssh-keygen", "-lf", "-"], timeout=10,
                             stdin=(line + "\n").encode())
    return ops.parse_fingerprint(result.out or result.err) if result.ok else ""


@router.get("/ssh/keys")
async def ssh_keys():
    path = _keys_path()
    lines = await asyncio.to_thread(_read_key_lines, path)
    available = shell.available("ssh-keygen")
    keys = []
    for line in lines[:200]:
        parsed = ops.parse_key_line(line)
        parsed["fingerprint"] = await _fingerprint(line) if available else ""
        keys.append(parsed)
    return {"path": str(path), "capabilities": {"ssh_keygen": available}, "keys": keys}


class KeyBody(BaseModel):
    line: str


@router.post("/ssh/keys")
async def add_ssh_key(body: KeyBody, request: Request):
    line = _guard(ops.validate_public_key, body.line)
    path = _keys_path()
    existing = await asyncio.to_thread(_read_key_lines, path)
    if line in existing:
        raise HTTPException(409, "该公钥已存在")
    await asyncio.to_thread(_append_key, path, line)
    parsed = ops.parse_key_line(line)
    audit.record(AuditEvent(action="ssh_key_add", target=str(path),
                            summary=f"{parsed['type']} {parsed['comment'][:60]}",
                            source="web", ip=client_ip(request)))
    return {"ok": True, "message": "公钥已追加到 authorized_keys"}


@router.delete("/ssh/keys")
async def remove_ssh_key(body: KeyBody, request: Request):
    line = _guard(ops.validate_public_key, body.line)
    path = _keys_path()
    removed = await asyncio.to_thread(_remove_key, path, line)
    if not removed:
        raise HTTPException(404, "authorized_keys 里没有这一行")
    parsed = ops.parse_key_line(line)
    audit.record(AuditEvent(action="ssh_key_remove", target=str(path),
                            summary=f"{parsed['type']} {parsed['comment'][:60]}",
                            source="web", ip=client_ip(request)))
    return {"ok": True, "message": "公钥已移除"}


# ---------------------------------------------------------------- 网络工具

NET_COMMANDS = {
    "ping": lambda target: ["ping", "-c", "4", "-W", "2", target],
    "traceroute": lambda target: ["traceroute", "-n", "-m", "15", target],
    "mtr": lambda target: ["mtr", "-r", "-c", "5", target],
    "curl": lambda target: ["curl", "-sS", "-I", "--max-time", "8", target],
}


class NetBody(BaseModel):
    tool: str
    target: str


@router.post("/net/tool")
async def net_tool(body: NetBody, request: Request):
    """固定命令 + 白名单目标：用户只能选工具和填主机，无法注入额外参数。"""
    tool = _guard(ops.check_net_tool, body.tool)
    target = _guard(ops.check_target, body.target)
    if not shell.available(tool):
        raise HTTPException(400, f"本机没有 {tool} 命令")
    command = NET_COMMANDS[tool](target)
    started = time.perf_counter()
    result = await shell.run(command, timeout=NET_TIMEOUT)
    output = ((result.out or "") + (result.err or ""))[:NET_MAX_OUTPUT]
    audit.record(AuditEvent(action="net_tool", target=target,
                            summary=f"{tool}（{len(output)} 字节）", source="web",
                            ip=client_ip(request), ok=result.ok, code=result.code,
                            duration=round(time.perf_counter() - started, 3)))
    return {"ok": result.ok, "code": result.code, "tool": tool, "target": target,
            "output": output,
            "error": None if result.ok else (result.err or "命令执行失败").strip()[-400:]}
