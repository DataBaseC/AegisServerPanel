#!/usr/bin/env python3
"""端到端冒烟：验证本轮深度修复真的生效（不是只看测试全绿）。"""
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error

BASE = "/sandbox/workspace/AegisServerPanel"
WORK = "/tmp/sp-smoke"
PORT = 8899
URL = f"http://127.0.0.1:{PORT}"
COOKIE = os.path.join(WORK, "cookies.txt")

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ->  {detail}" if detail else ""))


def req(path, method="GET", body=None, raw_query=False):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(URL + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if os.path.exists(COOKIE):
        r.add_header("Cookie", open(COOKIE).read().strip())
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def save_cookie(resp_headers):
    pass  # urllib 不方便拿 Set-Cookie，改用 http.client


def main():
    import http.client
    os.makedirs(WORK, exist_ok=True)
    cfg = os.path.join(WORK, "config.json")
    import shutil
    for f in os.listdir(WORK):
        p = os.path.join(WORK, f)
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
        else:
            os.unlink(p)
    env = dict(os.environ, SERVERPANEL_CONFIG=cfg)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=BASE, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(40):
            time.sleep(0.5)
            try:
                urllib.request.urlopen(f"{URL}/healthz", timeout=2)
                break
            except Exception:
                continue

        def call(method, path, body=None):
            conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
            headers = {"Content-Type": "application/json"}
            token = None
            if os.path.exists(COOKIE):
                token = open(COOKIE).read().strip()
            if token:
                headers["Cookie"] = f"sp_session={token}"
            conn.request(method, path, json.dumps(body) if body is not None else None, headers)
            resp = conn.getresponse()
            raw = resp.read().decode()
            try:
                data = json.loads(raw) if raw else {}
            except Exception:
                data = {"_raw": raw[:200]}
            # 记录 Set-Cookie
            sc = resp.getheader("Set-Cookie")
            if sc and "sp_session=" in sc:
                val = sc.split("sp_session=")[1].split(";")[0]
                with open(COOKIE, "w") as fh:
                    fh.write(val)
            conn.close()
            return resp.status, data

        st, d = call("GET", "/healthz")
        check("1. /healthz 可用", st == 200 and d.get("ok"), f"status={st}")

        st, d = call("GET", "/api/auth/status")
        check("2. auth/status 无副作用可查", st == 200 and d.get("initialized") is False and "active_sessions" not in d,
              f"initialized={d.get('initialized')} active_sessions_in_resp={'active_sessions' in d}")

        st, d = call("POST", "/api/auth/setup", {"password": "smoke-pass-123"})
        check("3. 首次设置密码", st == 200 and d.get("ok"), f"status={st} {d.get('detail','')}")

        # 并发 setup 竞态防护：已初始化后拒绝
        st, d = call("POST", "/api/auth/setup", {"password": "another-pass-456"})
        check("4. 重复 setup 被拒（防抢注）", st == 400, f"status={st}")

        # dirsize：空子目录场景（原 bug：entries 为空时 IndexError 500）
        os.makedirs(f"{WORK}/empty-dir", exist_ok=True)
        st, d = call("GET", "/api/storage/dirsize?path=" + f"{WORK}/empty-dir")
        check("5. dirsize 空目录不再 500（total=目录自身占用）", st == 200 and isinstance(d.get("total"), int),
              f"status={st} total={d.get('total')}")

        # dirsize：有子项时 total 应为目录总占用（原来恒为 None）
        os.makedirs(f"{WORK}/data/sub", exist_ok=True)
        with open(f"{WORK}/data/sub/f.bin", "wb") as fh:
            fh.write(b"x" * 4096)
        st, d = call("GET", "/api/storage/dirsize?path=" + f"{WORK}/data")
        check("6. dirsize total 有值（du 自身行）", st == 200 and isinstance(d.get("total"), int) and d["total"] >= 4096,
              f"status={st} total={d.get('total')}")

        # 公网模式：进程详情不得泄露 environ
        st, d = call("GET", f"/api/processes/{os.getpid()}")
        check("7. 公网模式进程详情无 environ", st == 200 and "environ" not in d,
              f"status={st} keys={sorted(d)[:8]}")

        # 公网模式：文件接口应 403
        st, d = call("POST", "/api/files/write", {"path": f"{WORK}/x.txt", "content": "hi"})
        check("8. 公网模式文件写入被拒", st == 403, f"status={st}")

        # 切内网模式：直接改配置文件，验证热加载（本轮修复的 mtime_ns 指纹）
        cfg_data = json.load(open(cfg))
        cfg_data["mode"] = "internal"
        with open(cfg, "w") as fh:
            json.dump(cfg_data, fh)
        os.utime(cfg, (time.time(), time.time()))
        time.sleep(0.2)
        st, d = call("GET", "/api/auth/status")
        check("9. 模式热加载立即生效（指纹修复）", st == 200 and d.get("mode") == "internal",
              f"mode={d.get('mode')}")

        # 内网：files/read 的 max_bytes 超大参数必须被钳制（原 bug：可 OOM）
        with open(f"{WORK}/big.txt", "w") as fh:
            fh.write("y" * (3 * 1024 * 1024))  # 3MB > EDIT_LIMIT 2MB
        st, d = call("GET", f"/api/files/read?path={WORK}/big.txt&max_bytes=999999999999")
        check("10. max_bytes 超大参数被钳制（413 拒绝大文件）", st == 413, f"status={st} {d.get('detail','')[:60]}")

        # 内网：read/write 乐观锁纳秒精度
        with open(f"{WORK}/edit.txt", "w") as fh:
            fh.write("v1")
        st, d = call("GET", f"/api/files/read?path={WORK}/edit.txt")
        mtime_ns = d.get("mtime", 0)
        check("11. read 返回纳秒 mtime", st == 200 and mtime_ns > 10**15, f"mtime={mtime_ns}")
        st, d = call("POST", "/api/files/write", {"path": f"{WORK}/edit.txt", "content": "v2", "expected_mtime": mtime_ns})
        check("12. 乐观锁正确放行（未改过）", st == 200, f"status={st}")
        with open(f"{WORK}/edit.txt", "w") as fh:
            fh.write("v3-external")
        st, d = call("POST", "/api/files/write", {"path": f"{WORK}/edit.txt", "content": "v4", "expected_mtime": mtime_ns})
        check("13. 乐观锁检测到外部修改（409）", st == 409, f"status={st}")

        # exec timeout NaN 拒绝
        st, d = call("POST", "/api/terminal/exec", {"command": "echo hi", "timeout": None})
        check("14a. exec timeout=null 被拒", st in (400, 422), f"status={st}")

        # 解压逃逸：恶意 tar（符号链接指针逃逸）应被拦截
        import tarfile, io
        evil = f"{WORK}/evil.tar"
        with tarfile.open(evil, "w") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc"
            tf.addfile(info)
            data = b"pwned"
            info2 = tarfile.TarInfo("link/shadow")
            info2.size = len(data)
            tf.addfile(info2, io.BytesIO(data))
        st, d = call("POST", "/api/files/extract", {"path": evil})
        # 400=整包拒绝（更严格），200=跳过越界条目后解压；两者都算逃逸被拦
        check("15. 恶意 tar 符号链接逃逸被拦", st in (200, 400),
              f"status={st}（400=整包拒绝 / 200=跳过越界条目）")
        # 逃逸成功的判定：/etc/shadow 不可写是自然的，改为检查解压产物里 link 不是符号链接
        link_path = os.path.join(WORK, "evil", "link")
        link_is_symlink = os.path.islink(link_path)
        check("16. 解出的 link 不是符号链接（已丢弃）", not link_is_symlink,
              f"link is symlink={link_is_symlink}")

        # exec 命令长度限制
        st, d = call("POST", "/api/terminal/exec", {"command": "x" * (64 * 1024 + 1), "timeout": 5})
        check("17. 超长命令被拒（64KB 上限）", st == 400, f"status={st}")

    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    failed = [r for r in results if not r[1]]
    print(f"\n=== 冒烟结果：{len(results) - len(failed)}/{len(results)} 通过 ===")
    for name, ok, detail in failed:
        print(f"  FAIL: {name}  {detail}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
