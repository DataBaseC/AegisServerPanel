"""文件写根白名单（2.0.1 P0）：operator 只能写 ``files.write_roots`` 之内的路径。

修复前的缺口：多用户模式下 ``/api/files/*`` 的写接口只有 ``require_internal``
（内网模式 + 已登录），没有角色/路径限制，operator 能把任意路径写成
``/etc/cron.d/*``、``/root/.ssh/authorized_keys`` 甚至面板自己的 ``config.json``
（改自己的 role 为 admin）。面板以 root 运行，等于 root shell。

本文件覆盖（与 test_platform.py 同款的配置隔离/身份切换写法）：

- 单密码模式回归：admin 写临时路径不受写根限制（不能把现网部署改坏）；
- 多用户模式：operator 越界 403；把 ``files.write_roots`` 配成 ``[tmp_path]``
  后根内 200、根外 403；admin 不受根限制；
- 固定禁区（仓库根 / 面板配置目录 / 路径里的 ``.ssh``）：**任何角色**都 403，
  即使这些目录已被配进 ``files.write_roots``；
- mkdir / delete / rename 的目标越界同样 403，且拒绝时不产生任何副作用。

注意：写操作会真的落盘，全部使用 pytest 的 ``tmp_path``；不依赖网络。
"""

from __future__ import annotations

import copy
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth import sessions
from app.config import MODE_INTERNAL, MODE_PUBLIC, config
from app.main import app
from app.prefs import prefs

PASSWORD = "test-password-123"
OPERATOR_PASSWORD = "operator-password-123"

# 面板代码根（与 file_routes 里 Path(__file__).resolve().parents[2] 同义）
REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- 身份 / 隔离

def _login(client: TestClient, username: str, password: str):
    payload = {"password": password}
    if username:
        payload["username"] = username
    return client.post("/api/auth/login", json=payload)


def _identity(username: str, password: str) -> TestClient:
    """按某个账号登录，返回**独立的** TestClient（各自持一份会话 Cookie）。

    与 test_platform._identity 一致：TestClient 的 per-request cookies 不会覆盖
    实例上的 Cookie，切换身份必须换客户端实例。
    """
    client = TestClient(app)
    res = _login(client, username, password)
    assert res.status_code == 200, res.text
    return client


@pytest.fixture(scope="module", autouse=True)
def _isolated_config():
    """本文件会写入 users / prefs / 模式：模块结束整体还原，不污染其它测试。"""
    snapshot = copy.deepcopy(config.data)
    yield
    config.data = snapshot
    config.save()
    prefs._invalidate()
    sessions.revoke_all()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin(client):
    """确保已初始化密码、处于内网模式，并以管理员身份登录（单密码模式）。"""
    config.disable_totp()  # 前面的测试文件可能启用了 2FA
    if not config.initialized:
        assert client.post("/api/auth/setup",
                           json={"password": PASSWORD}).status_code == 200
    config.set_mode(MODE_INTERNAL)
    if _login(client, "", PASSWORD).status_code != 200:
        # 救援通道：前面用例可能改过密码/TOTP，按 CLI 的方式重置
        config.set_password(PASSWORD)
        config.set_mode(MODE_INTERNAL)
        assert _login(client, "", PASSWORD).status_code == 200
    return client


@pytest.fixture()
def internal_mode():
    config.set_mode(MODE_INTERNAL)
    yield
    config.set_mode(MODE_PUBLIC)


@pytest.fixture(scope="module")
def multi_user(admin):
    """进入多用户模式并建好 operator（模块内只建一次）。"""
    config.set_mode(MODE_INTERNAL)
    if not any(u.get("username") == "bob" for u in config.users):
        res = admin.post("/api/panel/users", json={
            "username": "bob", "password": OPERATOR_PASSWORD,
            "role": "operator"})
        assert res.status_code == 200, res.text
    assert config.has_users is True
    return admin


@pytest.fixture()
def outside(tmp_path):
    """tmp_path 之外、且不在任何写根里的目录。

    名字特意带 ``<tmp_path.name>-`` 前缀：它验证的是 ``/root`` 与 ``/root2``
    这类**前缀边界**（字符串 startswith 会误判成在根内，commonpath 不会）。
    """
    path = tmp_path.parent / f"{tmp_path.name}-outside"
    path.mkdir(exist_ok=True)
    return path


@pytest.fixture()
def write_roots():
    """按需配置 ``files.write_roots``，用例结束恢复默认空列表。"""
    def apply(roots):
        prefs.update({"files.write_roots": roots})

    yield apply
    prefs.update({"files.write_roots": []})


def _write(client, path, content="x"):
    return client.post("/api/files/write",
                       json={"path": str(path), "content": content})


# ---------------------------------------------------------------- 单密码模式回归

def test_single_password_mode_admin_write_unrestricted(admin, internal_mode, tmp_path):
    """回归：users 为空（单密码）时 RBAC 完全旁路，任意临时路径仍可写。"""
    assert config.has_users is False
    target = tmp_path / "single-mode.txt"
    res = _write(admin, target, "ok")
    assert res.status_code == 200, res.text
    assert target.read_text(encoding="utf-8") == "ok"


# ---------------------------------------------------------------- operator 写根

def test_operator_write_requires_configured_roots(
        multi_user, internal_mode, tmp_path, outside, write_roots):
    """默认空写根 = operator 全拒；配置根后根内放行、根外仍拒；admin 不受限。"""
    operator = _identity("bob", OPERATOR_PASSWORD)

    # 1) 默认 files.write_roots 为空：operator 没有任何可写根，tmp_path 也写不了
    write_roots([])
    blocked = tmp_path / "blocked.txt"
    res = _write(operator, blocked)
    assert res.status_code == 403, res.text
    assert "可写范围" in res.json()["detail"], res.text
    assert not blocked.exists(), "被拒绝的写入不能落盘"

    # 2) 只把 tmp_path 配成写根：根内 200
    write_roots([str(tmp_path)])
    allowed = tmp_path / "allowed.txt"
    res = _write(operator, allowed, "ok")
    assert res.status_code == 200, res.text
    assert allowed.read_text(encoding="utf-8") == "ok"

    # 3) 根外（前缀相同但其实是兄弟目录）→ 403
    deeper = tmp_path / "sub" / "nested.txt"
    deeper.parent.mkdir(exist_ok=True)
    assert _write(operator, deeper, "ok").status_code == 200, "根内子目录应放行"
    res = _write(operator, outside / "nope.txt")
    assert res.status_code == 403, res.text
    assert not (outside / "nope.txt").exists()

    # 4) admin 不受写根限制（即使是 operator 被拒的同一路径）
    admin_target = outside / "admin.txt"
    res = _write(multi_user, admin_target, "admin")
    assert res.status_code == 200, res.text
    assert admin_target.read_text(encoding="utf-8") == "admin"


# ---------------------------------------------------------------- 固定禁区

def test_forbidden_zones_denied_even_when_configured(
        multi_user, internal_mode, tmp_path, write_roots):
    """写进去等于 root 的固定禁区：任何角色（含 admin）都拒绝，配置写根也绕不过。"""
    operator = _identity("bob", OPERATOR_PASSWORD)
    config_dir = Path(config.path).resolve().parent

    # 故意把「代码根 + 配置目录」都配进写根，证明固定禁区不是靠写根兜住的
    write_roots([str(REPO_ROOT), str(config_dir), str(tmp_path)])

    # 1) 面板代码根（写入 = 下次启动/自更新时以 root 执行任意 Python）
    evil = REPO_ROOT / "evil_rbac_probe.py"
    res = _write(operator, evil, "print('pwn')")
    assert res.status_code == 403, res.text
    assert not evil.exists()

    # 2) 面板配置目录（写入 config.json = 改自己 role 为 admin）
    cfg_target = config_dir / "evil_rbac_probe.json"
    res = _write(operator, cfg_target, "{}")
    assert res.status_code == 403, res.text
    assert not cfg_target.exists()

    # 3) 路径里含 .ssh 目录（authorized_keys = root 持久化）——此处 tmp_path 已在写根内
    key = tmp_path / ".ssh" / "authorized_keys"
    res = _write(operator, key, "ssh-ed25519 AAAA rbac-probe")
    assert res.status_code == 403, res.text
    assert not key.exists()

    # 4) 含 .gnupg 同理
    gpg = tmp_path / ".gnupg" / "gpg.conf"
    res = _write(operator, gpg, "keyserver evil")
    assert res.status_code == 403, res.text
    assert not gpg.exists()

    # 5) admin 同样被固定禁区拦下（不是只拦 operator）
    res = _write(multi_user, evil, "print('pwn')")
    assert res.status_code == 403, res.text
    assert not evil.exists()


def test_operator_upload_cannot_escape_target_dir(
        multi_user, internal_mode, tmp_path, outside, write_roots):
    """上传除目标目录外，还要逐个文件校验实际落点（.ssh 子路径 / Windows 换盘）。"""
    operator = _identity("bob", OPERATOR_PASSWORD)
    write_roots([str(tmp_path)])

    # 1) 上传目标目录本身越界 → 403
    res = operator.post("/api/files/upload",
                        data={"path": str(outside)},
                        files={"files": ("a.txt", b"x", "text/plain")})
    assert res.status_code == 403, res.text
    assert not (outside / "a.txt").exists()

    # 2) 目标目录合法，但文件名解析出的子路径落在 .ssh（固定禁区）→ 该文件被拒
    res = operator.post("/api/files/upload",
                        data={"path": str(tmp_path)},
                        files={"files": (".ssh/authorized_keys",
                                         b"ssh-ed25519 AAAA upload-probe", "text/plain")})
    assert res.status_code == 200, res.text
    assert res.json()["failed"], res.text
    assert res.json()["saved"] == []
    assert not (tmp_path / ".ssh" / "authorized_keys").exists()

    # 3) Windows：drive-relative 文件名会让 os.path.join 换盘，必须按越界拒绝
    if os.name == "nt":
        res = operator.post("/api/files/upload",
                            data={"path": str(tmp_path)},
                            files={"files": ("D:/evil_upload_probe.txt", b"x", "text/plain")})
        assert res.status_code == 200, res.text
        assert res.json()["failed"], res.text


# ---------------------------------------------------------------- mkdir / delete / rename

def test_operator_mkdir_and_delete_out_of_scope(
        multi_user, internal_mode, tmp_path, outside, write_roots):
    """mkdir / delete 的目标越界 → 403；越界删除不能真的动到文件。"""
    operator = _identity("bob", OPERATOR_PASSWORD)
    write_roots([str(tmp_path)])

    # mkdir 越界
    newdir = outside / "newdir"
    res = operator.post("/api/files/mkdir", json={"path": str(newdir)})
    assert res.status_code == 403, res.text
    assert not newdir.exists()

    # mkdir 根内放行（守卫不能把正常功能一起堵死）
    inside = tmp_path / "newdir"
    res = operator.post("/api/files/mkdir", json={"path": str(inside)})
    assert res.status_code == 200, res.text
    assert inside.is_dir()

    # delete 越界：根外的文件（先由 admin 建好）operator 删不掉
    victim = outside / "victim.txt"
    assert _write(multi_user, victim, "keep").status_code == 200
    res = operator.post("/api/files/delete", json={"paths": [str(victim)]})
    assert res.status_code == 403, res.text
    assert victim.exists(), "越界删除必须整体被拒，不能动到文件"

    # delete 根内放行（进回收站 = 从原位置消失）
    trash_me = tmp_path / "trash-me.txt"
    assert _write(operator, trash_me, "bye").status_code == 200
    res = operator.post("/api/files/delete", json={"paths": [str(trash_me)]})
    assert res.status_code == 200, res.text
    assert not trash_me.exists()

    # move 的源在根外同样不行：否则等于绕过 delete 守卫把根外文件搬走
    mover = outside / "mover.txt"
    assert _write(multi_user, mover, "keep").status_code == 200
    res = operator.post("/api/files/move",
                        json={"paths": [str(mover)], "dest": str(tmp_path)})
    assert res.status_code == 200, res.text
    assert res.json()["ok"] is False and res.json()["failed"], res.text
    assert mover.exists()


def test_operator_rename_target_out_of_scope(
        multi_user, internal_mode, tmp_path, outside, write_roots):
    """rename 判断的是目标路径：不得把根内文件搬到根外。"""
    operator = _identity("bob", OPERATOR_PASSWORD)
    write_roots([str(tmp_path)])

    source = tmp_path / "move-me.txt"
    source.write_text("data", encoding="utf-8")

    stolen = outside / "stolen.txt"
    res = operator.post("/api/files/rename",
                        json={"path": str(source), "target": str(stolen)})
    assert res.status_code == 403, res.text
    assert source.exists(), "被拒绝的重命名不能动到源文件"
    assert not stolen.exists()

    # 根内重命名放行
    renamed = tmp_path / "renamed.txt"
    res = operator.post("/api/files/rename",
                        json={"path": str(source), "target": str(renamed)})
    assert res.status_code == 200, res.text
    assert renamed.read_text(encoding="utf-8") == "data"

    # 反向同样要拦：根外文件不得借「改名搬进根内」绕过 delete 守卫
    outside_file = outside / "outside-keep.txt"
    assert _write(multi_user, outside_file, "keep").status_code == 200
    grabbed = tmp_path / "grabbed.txt"
    res = operator.post("/api/files/rename",
                        json={"path": str(outside_file), "target": str(grabbed)})
    assert res.status_code == 403, res.text
    assert outside_file.exists() and not grabbed.exists()
