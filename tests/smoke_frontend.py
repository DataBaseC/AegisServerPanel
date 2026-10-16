"""前端冒烟测试：登录 → 安全中心渲染 → TOTP 全流程 → 回收站 UI。"""
import hmac
import hashlib
import base64
import struct
import time
import sys

from playwright.sync_api import sync_playwright

BASE = "http://localhost:8899"
PASSWORD = "smoke-test-password-1234"
errors = []


def totp_code(secret: str) -> str:
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    counter = int(time.time()) // 30
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)


with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.on("console", lambda m: errors.append(m.text)
            if m.type == "error" and "401" not in m.text else None)
    page.on("pageerror", lambda e: errors.append(str(e)))

    # 1. 登录页
    page.goto(BASE, wait_until="networkidle")
    page.fill("#login-password", PASSWORD)
    page.click("#login-submit")
    page.wait_for_selector("#app:not(.hidden)", timeout=10000)
    print("PASS 登录进入主界面")

    # 2. 侧边栏应有安全中心
    nav_text = page.inner_text("#nav")
    assert "安全中心" in nav_text, "侧边栏缺少安全中心"
    print("PASS 侧边栏包含安全中心入口")

    # 3. 打开安全中心
    page.click('#nav .nav-item[data-id="security"]')
    page.wait_for_selector("#sec-audit-body table", timeout=10000)
    body = page.inner_text("#view")
    for key in ("二次认证", "活跃会话", "Agent 令牌", "审计日志", "登录防爆破", "回收站"):
        assert key in body, f"安全中心缺少 {key}"
    print("PASS 安全中心渲染完整（摘要 + TOTP + 会话 + 令牌 + 审计）")

    # 4. TOTP 全流程：setup → 计算动态码 → enable → 拿到恢复码
    page.request.post(f"{BASE}/api/auth/logout")
    page.evaluate("document.cookie = 'sp_session=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'")
    page.goto(BASE, wait_until="networkidle")
    page.fill("#login-password", PASSWORD)
    page.click("#login-submit")
    page.wait_for_selector("#app:not(.hidden)", timeout=10000)

    page.click('#nav .nav-item[data-id="security"]')
    page.wait_for_selector("#sec-totp-enable", timeout=10000)
    page.click("#sec-totp-enable")
    page.wait_for_selector("#totp-code", timeout=10000)
    secret = page.inner_text("#totp-secret")
    # 动态码有 30 秒步长，跨边界时首试可能失败：见到错误 toast 就换新码重试
    enabled = False
    for attempt in range(3):
        page.fill("#totp-code", totp_code(secret))
        page.click('[data-ok]')
        try:
            page.wait_for_selector(".modal h3:has-text('二次认证已启用')", timeout=4000)
            enabled = True
            break
        except Exception:
            page.wait_for_timeout(1000)
    assert enabled, "TOTP 启用失败（动态码可能跨步长边界）"
    recovery = page.inner_text(".modal-body")
    assert "-" in recovery, "未展示恢复码"
    print(f"PASS TOTP 启用成功，secret={secret[:8]}…，恢复码已展示")
    page.click(".modal [data-cancel]")  # 关闭恢复码弹窗
    page.wait_for_selector(".modal", state="detached", timeout=5000)

    # 5. 退出后用「密码 + 动态码」重新登录
    page.click("#btn-logout")
    page.wait_for_selector("#login-screen:not(.hidden)", timeout=10000)
    page.fill("#login-password", PASSWORD)
    page.click("#login-submit")
    # 应出现「请输入二次验证码」并展开输入框
    page.wait_for_selector("#totp-field:not(.hidden)", timeout=10000)
    print("PASS 未带动态码登录被引导至二次验证输入框")
    page.fill("#login-totp", totp_code(secret))
    page.click("#login-submit")
    page.wait_for_selector("#app:not(.hidden)", timeout=10000)
    print("PASS 密码 + TOTP 动态码登录成功")

    # 6. 安全中心摘要应显示已启用
    page.click('#nav .nav-item[data-id="security"]')
    page.wait_for_selector("#sec-totp-recovery", timeout=10000)
    assert "已启用" in page.inner_text("#view")
    print("PASS 安全中心显示二次认证已启用")

    # 7. 回收站 UI
    page.click('#nav .nav-item[data-id="files"]')
    page.wait_for_selector('[data-act="trash"]', timeout=10000)
    page.click('[data-act="trash"]')
    page.wait_for_selector(".modal .modal-body table", timeout=10000)
    assert "回收站" in page.inner_text(".modal")
    print("PASS 文件管理器回收站面板打开")
    page.click(".modal [data-close]")  # 关闭回收站弹窗
    page.wait_for_selector(".modal", state="detached", timeout=5000)

    # 8. 令牌创建 UI
    page.click('#nav .nav-item[data-id="security"]')
    page.wait_for_selector("#sec-token-create", timeout=10000)
    page.click("#sec-token-create")
    page.wait_for_selector("#tk-scope", timeout=10000)
    page.select_option("#tk-scope", "readonly")
    page.fill("#tk-name", "smoke-readonly")
    page.click('[data-ok]')
    page.wait_for_selector(".token-box", timeout=10000)
    token = page.inner_text(".token-box")
    assert len(token) >= 16, f"令牌过短: {token}"
    print(f"PASS 只读令牌创建成功（明文一次性展示 {len(token)} 位）")

    # 9. 用只读令牌调 exec：只读命令放行，危险命令被拒（独立请求上下文，不带会话 Cookie）
    api_ctx = p.request.new_context()
    r = api_ctx.post(f"{BASE}/api/terminal/exec",
                     headers={"X-Agent-Token": token},
                     data={"command": "df -h"})
    assert r.status == 200, f"只读命令应放行: {r.status} {r.text()}"
    r2 = api_ctx.post(f"{BASE}/api/terminal/exec",
                      headers={"X-Agent-Token": token},
                      data={"command": "systemctl restart nginx"})
    assert r2.status == 403, f"危险命令应被拒: {r2.status} {r2.text()}"
    print("PASS 只读令牌：df -h 放行 / systemctl restart 拒绝")

    browser.close()

if errors:
    print("\n控制台错误:")
    for e in errors:
        print(" -", repr(e))
    sys.exit(1)
print("\n全部冒烟测试通过，无控制台错误")
