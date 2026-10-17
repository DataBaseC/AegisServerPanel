"""会话录制测试（2.0 M5）：asciinema v2 格式、体积上限、路径校验与 API。"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import config as config_mod
from app import recording
from app.auth import sessions
from app.config import COOKIE_NAME
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def authed(client):
    token = sessions.create("127.0.0.1", "pytest-recording")
    client.cookies.set(COOKIE_NAME, token)
    yield client
    client.cookies.clear()


@pytest.fixture()
def internal_mode():
    config_mod.config.set_mode(config_mod.MODE_INTERNAL)
    yield
    config_mod.config.set_mode(config_mod.MODE_PUBLIC)


def _make(name: str = None) -> recording.Recorder:
    rec = recording.Recorder(1024 * 1024).start(width=120, height=30)
    assert rec is not None and rec.path is not None
    return rec


# ================================================================ 录制器


def test_recorder_writes_asciinema_v2():
    rec = _make()
    rec.output("hello")
    rec.input("ls\r")
    rec.close()
    lines = rec.path.read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    assert header["version"] == 2
    assert (header["width"], header["height"]) == (120, 30)
    assert isinstance(header["timestamp"], int)
    events = [json.loads(line) for line in lines[1:]]
    assert [ev[1] for ev in events] == ["o", "i"]
    assert events[0][2] == "hello" and events[1][2] == "ls\r"
    assert all(isinstance(ev[0], (int, float)) and ev[0] >= 0 for ev in events)


def test_recorder_stops_at_size_limit():
    rec = recording.Recorder(max_bytes=120).start()
    for _ in range(50):
        rec.output("x" * 20)
    assert rec._fh is None                     # 超限后自动收尾
    size = rec.path.stat().st_size
    assert size <= 120 + 200                   # 停止前最多再写一条


def test_recorder_ignores_after_close():
    rec = _make()
    rec.close()
    rec.output("late")                        # 不应抛异常
    assert "late" not in rec.path.read_text(encoding="utf-8")


def test_recorder_records_resize():
    rec = _make()
    rec.resize(132, 43)
    rec.close()
    events = [json.loads(line) for line in
              rec.path.read_text(encoding="utf-8").splitlines()[1:]]
    assert events[0][1] == "r" and events[0][2] == "132x43"


def test_load_events_roundtrip():
    rec = _make()
    rec.output("hi")
    rec.close()
    events = recording.load_events(rec.path.name)
    assert events[0]["header"]["version"] == 2
    assert {"time", "kind", "data"} <= set(events[1])
    assert events[1]["data"] == "hi"


BAD_NAMES = ["../../etc/passwd", "abc.cast", "", "20260101-000000-zzzzzz.cast"]


@pytest.mark.parametrize("name", BAD_NAMES)
def test_load_events_rejects_bad_names(name):
    assert recording.load_events(name) is None


# ================================================================ API


def test_recordings_api_requires_auth():
    with TestClient(app) as anon:
        res = anon.get("/api/panel/recordings")
    assert res.status_code in (401, 403)


def test_recordings_api_list_get_delete(authed, internal_mode):
    rec = _make()
    rec.output("demo")
    rec.close()
    name = rec.path.name

    listed = authed.get("/api/panel/recordings").json()
    assert listed["enabled"] is False
    names = [item["name"] for item in listed["items"]]
    assert name in names
    item = next(i for i in listed["items"] if i["name"] == name)
    assert item["size"] > 0 and item["time"] > 0

    got = authed.get(f"/api/panel/recordings/{name}")
    assert got.status_code == 200
    events = got.json()["events"]
    assert events[1]["data"] == "demo"

    assert authed.get("/api/panel/recordings/..%2Fconfig.json").status_code in (400, 404)
    assert authed.delete("/api/panel/recordings/..%2Fconfig.json").status_code in (400, 404)

    res = authed.delete(f"/api/panel/recordings/{name}")
    assert res.status_code == 200
    assert not rec.path.exists()
    assert authed.get(f"/api/panel/recordings/{name}").status_code == 404


def test_recording_prefs_defaults_and_bounds():
    from app.prefs import PrefsError, prefs

    assert prefs.get("terminal.record_sessions") is False
    assert prefs.get("terminal.record_max_mb") == 50
    with pytest.raises(PrefsError):
        prefs.update({"terminal.record_max_mb": 0})
