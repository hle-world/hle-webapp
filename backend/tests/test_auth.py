"""The management API must refuse unauthenticated callers and never echo secrets.

Covers the login token gate (backend/auth.py), the scoping of the
subdomain-keyed relay routes to locally managed tunnels, and the masking of
per-tunnel secrets in tunnel responses.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import re
import stat
import sys

import httpx
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from backend import auth
from backend import tunnel_manager as tm

FAKE_TUNNEL_KEY = "hle_" + "k" * 28
FAKE_UPSTREAM = "admin:upstream-secret-pw"


class _FakeProc:
    pid = 4242
    returncode = None

    def terminate(self) -> None:
        self.returncode = 0

    def kill(self) -> None:
        self.returncode = -9

    async def wait(self) -> int:
        return self.returncode or 0


@pytest.fixture
def main(tmp_path, monkeypatch):
    """Import backend.main fresh against a temp data dir."""
    monkeypatch.setenv("HLE_DATA_DIR", str(tmp_path))
    monkeypatch.delenv(auth.TOKEN_ENV, raising=False)
    monkeypatch.setenv("HLE_API_KEY", "hle_" + "g" * 28)
    monkeypatch.setattr(tm, "DATA_FILE", tmp_path / "tunnels.json")
    monkeypatch.setattr(tm, "LOG_DIR", tmp_path / "logs")

    async def _spawn(cfg):
        return _FakeProc()

    async def _monitor(*args, **kwargs):
        return None

    monkeypatch.setattr(tm, "_spawn", _spawn)
    monkeypatch.setattr(tm, "_monitor_tunnel", _monitor)
    tm._processes.clear()
    if "backend.main" in sys.modules:
        module = importlib.reload(sys.modules["backend.main"])
    else:
        module = importlib.import_module("backend.main")
    yield module
    tm._processes.clear()


def _token(tmp_path) -> str:
    return (tmp_path / auth.TOKEN_FILENAME).read_text().strip()


def _authed(main, tmp_path) -> TestClient:
    client = TestClient(main.app)
    client.headers["Authorization"] = f"Bearer {_token(tmp_path)}"
    return client


def _write_tunnel(tmp_path, **overrides) -> None:
    cfg = {
        "id": "t1",
        "service_url": "http://192.0.2.10:8080",
        "label": "svc",
        "subdomain": "svc-owner",
        "api_key": FAKE_TUNNEL_KEY,
        "upstream_basic_auth": FAKE_UPSTREAM,
    }
    cfg.update(overrides)
    (tmp_path / "tunnels.json").write_text(json.dumps({cfg["id"]: cfg}))


# ---------------------------------------------------------------------------
# Token lifecycle
# ---------------------------------------------------------------------------


def test_token_generated_with_0600_and_printed_once(tmp_path, capsys) -> None:
    token_file = tmp_path / "ui_token"
    token = auth.load_or_create_token(token_file)
    assert len(token) >= 32
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert token in capsys.readouterr().out

    assert auth.load_or_create_token(token_file) == token
    assert token not in capsys.readouterr().out


def test_env_token_overrides_file(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv(auth.TOKEN_ENV, "from-env-token")
    assert auth.load_or_create_token(tmp_path / "ui_token") == "from-env-token"
    assert not (tmp_path / "ui_token").exists()
    assert "from-env-token" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Refused without credentials
# ---------------------------------------------------------------------------


def _api_routes(app):
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/api"):
            path = re.sub(r"\{[^}]+\}", "1", route.path)
            for method in route.methods:
                yield method, path


def test_every_api_route_refuses_without_token(main) -> None:
    client = TestClient(main.app)
    routes = list(_api_routes(main.app))
    assert len(routes) > 20  # the whole surface, not a sample
    for method, path in routes:
        resp = client.request(method, path)
        assert resp.status_code == 401, (method, path, resp.status_code)
        assert resp.headers["www-authenticate"] == auth.AUTH_CHALLENGE


def test_wrong_bearer_and_wrong_cookie_refused(main) -> None:
    client = TestClient(main.app)
    assert (
        client.get("/api/tunnels", headers={"Authorization": "Bearer nope"}).status_code
        == 401
    )
    client.cookies.set(auth.COOKIE_NAME, "forged")
    assert client.get("/api/tunnels").status_code == 401


def test_ui_root_redirects_to_login(main) -> None:
    client = TestClient(main.app, follow_redirects=False)
    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "login"
    login = client.get("/login")
    assert login.status_code == 200
    assert "ui_token" in login.text


def test_login_rejects_wrong_token(main) -> None:
    client = TestClient(main.app, follow_redirects=False)
    resp = client.post("/login", data={"token": "wrong"})
    assert resp.status_code == 401
    assert auth.COOKIE_NAME not in resp.cookies


# ---------------------------------------------------------------------------
# Allowed with credentials
# ---------------------------------------------------------------------------


def test_bearer_token_allows_api(main, tmp_path) -> None:
    assert _authed(main, tmp_path).get("/api/tunnels").status_code == 200


def test_login_sets_strict_httponly_cookie(main, tmp_path) -> None:
    client = TestClient(main.app, follow_redirects=False)
    resp = client.post("/login", data={"token": _token(tmp_path)})
    assert resp.status_code == 303
    set_cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie
    # The cookie is derived from the token, not the token itself.
    assert _token(tmp_path).lower() not in set_cookie
    assert client.get("/api/tunnels").status_code == 200

    assert "max-age=" in set_cookie and "path=/" in set_cookie

    out = client.post("/logout")
    assert out.status_code == 303
    cleared = out.headers["set-cookie"].lower()
    assert cleared.startswith(f"{auth.COOKIE_NAME}=") and "max-age=0" in cleared
    assert client.get("/api/tunnels").status_code == 401


def test_secure_cookie_over_https(main, tmp_path) -> None:
    client = TestClient(main.app, follow_redirects=False)
    resp = client.post(
        "/login",
        data={"token": _token(tmp_path)},
        headers={"X-Forwarded-Proto": "https"},
    )
    assert "secure" in resp.headers["set-cookie"].lower()


# ---------------------------------------------------------------------------
# Session values: signed, expiring, invalidated by token rotation
# ---------------------------------------------------------------------------


def test_session_expires_server_side() -> None:
    now = 1_800_000_000.0
    value = auth.session_value("tok", now=now)
    assert auth.session_valid("tok", value, now=now + 60)
    assert not auth.session_valid("tok", value, now=now + auth.COOKIE_MAX_AGE + 1)
    # A tampered issue time breaks the signature.
    issued, _, sig = value.partition(".")
    assert not auth.session_valid("tok", f"{int(issued) + 999}.{sig}", now=now)
    assert not auth.session_valid("tok", "garbage", now=now)


def test_rotating_token_invalidates_sessions(main, tmp_path) -> None:
    client = TestClient(main.app, follow_redirects=False)
    client.post("/login", data={"token": _token(tmp_path)})
    assert client.get("/api/tunnels").status_code == 200

    # Rotation: delete the token file and restart.
    old = _token(tmp_path)
    (tmp_path / auth.TOKEN_FILENAME).unlink()
    rotated = importlib.reload(sys.modules["backend.main"])
    assert _token(tmp_path) != old
    cookie = client.cookies.get(auth.COOKIE_NAME)
    assert cookie
    client = TestClient(rotated.app, cookies={auth.COOKIE_NAME: cookie})
    assert client.get("/api/tunnels").status_code == 401
    bearer = {"Authorization": f"Bearer {old}"}
    assert client.get("/api/tunnels", headers=bearer).status_code == 401


def test_token_file_created_exclusively(tmp_path, monkeypatch) -> None:
    seen = {}
    real_open = auth.os.open

    def _spy(path, flags, mode=0o777):
        seen["flags"], seen["mode"] = flags, mode
        return real_open(path, flags, mode)

    monkeypatch.setattr(auth.os, "open", _spy)
    auth.load_or_create_token(tmp_path / "ui_token")
    assert seen["flags"] & auth.os.O_EXCL and seen["flags"] & auth.os.O_CREAT
    assert seen["mode"] == 0o600


# ---------------------------------------------------------------------------
# No bypass via path tricks or other methods
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/tunnels/"),
        ("GET", "//api/tunnels"),
        ("GET", "/login/../api/tunnels"),
        ("GET", "/api/../api/tunnels"),
        ("GET", "/API/tunnels"),
        ("HEAD", "/api/tunnels"),
        ("OPTIONS", "/api/tunnels"),
        ("GET", "/api/config"),
        ("GET", "/health"),
        ("GET", "/assets/index.js"),
        ("GET", "/index.html"),
        ("GET", "/login/x"),
    ],
)
def test_no_bypass_without_token(main, method, path) -> None:
    client = TestClient(main.app, follow_redirects=False)
    resp = client.request(method, path)
    assert resp.status_code in (401, 303), (method, path, resp.status_code)
    if resp.status_code == 303:
        assert resp.headers["location"] == "login"


# ---------------------------------------------------------------------------
# Brute force
# ---------------------------------------------------------------------------


ATTACKER = ("198.51.100.7", 40000)
OWNER = ("192.0.2.20", 40000)


@pytest.fixture
def clock(monkeypatch):
    now = [10_000.0]
    monkeypatch.setattr(auth.time, "monotonic", lambda: now[0])
    return now


@pytest.fixture
def no_sleep(monkeypatch):
    """Record slowdown sleeps instead of waiting."""
    slept: list[float] = []

    async def _sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(auth.asyncio, "sleep", _sleep)
    return slept


def _lock_out(client: TestClient) -> None:
    for _ in range(auth.MAX_FAILURES):
        assert client.post("/login", data={"token": "guess"}).status_code == 401


def test_lockout_refuses_right_token_until_window_passes(main, tmp_path, clock):
    client = TestClient(main.app, client=ATTACKER, follow_redirects=False)
    _lock_out(client)
    right = {"token": _token(tmp_path)}
    assert client.post("/login", data=right).status_code == 429
    bearer = {"Authorization": f"Bearer {_token(tmp_path)}"}
    assert client.get("/api/tunnels", headers=bearer).status_code == 429

    clock[0] += auth.FAILURE_WINDOW + 1
    assert client.post("/login", data=right).status_code == 303


def test_bearer_and_login_share_one_limiter(main, tmp_path) -> None:
    client = TestClient(main.app, client=ATTACKER, follow_redirects=False)
    for _ in range(auth.MAX_FAILURES):
        resp = client.get("/api/tunnels", headers={"Authorization": "Bearer guess"})
        assert resp.status_code == 401
    assert (
        client.get("/api/tunnels", headers={"Authorization": "Bearer x"}).status_code
        == 429
    )
    assert client.post("/login", data={"token": _token(tmp_path)}).status_code == 429


def test_lockout_is_per_address(main, tmp_path) -> None:
    _lock_out(TestClient(main.app, client=ATTACKER, follow_redirects=False))
    owner = TestClient(main.app, client=OWNER, follow_redirects=False)
    assert owner.post("/login", data={"token": _token(tmp_path)}).status_code == 303


def test_spoofed_forwarded_for_does_not_bypass(main, tmp_path) -> None:
    client = TestClient(main.app, client=ATTACKER, follow_redirects=False)
    _lock_out(client)
    for header in ("X-Forwarded-For", "X-Real-IP", "Forwarded"):
        resp = client.post(
            "/login",
            data={"token": _token(tmp_path)},
            headers={header: "203.0.113.99"},
        )
        assert resp.status_code == 429, header


def test_valid_session_exempt_from_lockout(main, tmp_path) -> None:
    client = TestClient(main.app, client=ATTACKER, follow_redirects=False)
    assert client.post("/login", data={"token": _token(tmp_path)}).status_code == 303
    for _ in range(auth.MAX_FAILURES + 5):
        client.get("/api/tunnels", headers={"Authorization": "Bearer guess"})
    # Same address, now locked out for token attempts, but the session works.
    assert client.get("/api/tunnels").status_code == 200


def test_distributed_flood_slows_but_never_locks_owner(main, tmp_path, no_sleep):
    for i in range(auth.GLOBAL_SLOWDOWN_AFTER * 3):
        flood = TestClient(main.app, client=(f"203.0.113.{i % 250}", 1000 + i))
        assert flood.post("/login", data={"token": "guess"}).status_code in (401, 429)
    assert no_sleep  # the global figure switched the slowdown on

    owner = TestClient(main.app, client=OWNER, follow_redirects=False)
    assert owner.post("/login", data={"token": _token(tmp_path)}).status_code == 303
    assert owner.get("/api/tunnels").status_code == 200
    bearer = {"Authorization": f"Bearer {_token(tmp_path)}"}
    fresh = TestClient(main.app, client=("192.0.2.21", 1))
    assert fresh.get("/api/tunnels", headers=bearer).status_code == 200


def test_concurrent_guesses_cannot_race_past_limit(main, monkeypatch) -> None:
    compares = []
    real = auth._token_matches

    def _counting(given, token):
        compares.append(given)
        return real(given, token)

    monkeypatch.setattr(auth, "_token_matches", _counting)
    # Force an await between reserve and compare on every attempt, so the
    # requests genuinely interleave.
    monkeypatch.setattr(auth, "SLOWDOWN_SECONDS", 0.01)
    main.app.state.ui_auth_limiter.slowdown_after = 0

    async def _run() -> list[int]:
        transport = httpx.ASGITransport(app=main.app, client=ATTACKER)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resps = await asyncio.gather(
                *(
                    client.get(
                        "/api/tunnels", headers={"Authorization": f"Bearer g{i}"}
                    )
                    for i in range(50)
                )
            )
        return [r.status_code for r in resps]

    codes = asyncio.run(_run())
    assert len(compares) <= auth.MAX_FAILURES
    assert codes.count(429) >= 50 - auth.MAX_FAILURES


def test_limiter_map_bounded_and_not_evictable(clock) -> None:
    limiter = auth.FailureLimiter(max_failures=3, window=60, max_keys=100)
    for _ in range(3):
        assert limiter.reserve("attacker")
    assert not limiter.reserve("attacker")
    for i in range(10_000):
        limiter.reserve(f"10.{i // 65536}.{i // 256 % 256}.{i % 256}")
    assert limiter.tracked() <= 100
    assert all(len(q) <= 3 for q in limiter._attempts.values())
    # Flooding new keys did not reset the locked-out entry.
    assert not limiter.reserve("attacker")
    clock[0] += 61
    assert limiter.reserve("attacker")


def test_release_gives_back_successful_attempts(clock) -> None:
    limiter = auth.FailureLimiter(max_failures=2, window=60)
    for _ in range(5):
        assert limiter.reserve("owner")
        limiter.release("owner")
    assert limiter.tracked() == 0


# ---------------------------------------------------------------------------
# Subdomain routes are limited to locally managed tunnels
# ---------------------------------------------------------------------------


def test_subdomain_routes_404_for_unmanaged_subdomain(
    main, tmp_path, monkeypatch
) -> None:
    _write_tunnel(tmp_path)
    called = []

    async def _fake(*args, **kwargs):
        called.append(args)
        return {"has_pin": False, "updated_at": None}

    for name in (
        "list_access_rules",
        "add_access_rule",
        "get_pin_status",
        "set_pin",
        "remove_pin",
        "list_share_links",
    ):
        monkeypatch.setattr(main.hle_api, name, _fake)
    client = _authed(main, tmp_path)

    for method, path, body in (
        ("GET", "/api/tunnels/someone-else/access", None),
        ("POST", "/api/tunnels/someone-else/access", {"email": "a@example.com"}),
        ("GET", "/api/tunnels/someone-else/pin", None),
        ("PUT", "/api/tunnels/someone-else/pin", {"pin": "1234"}),
        ("DELETE", "/api/tunnels/someone-else/pin", None),
        ("DELETE", "/api/tunnels/someone-else/basic-auth", None),
        ("GET", "/api/tunnels/someone-else/share", None),
    ):
        resp = client.request(method, path, json=body)
        assert resp.status_code == 404, (method, path)
    assert called == []

    assert client.get("/api/tunnels/svc-owner/pin").status_code == 200
    assert called == [("svc-owner",)]


# ---------------------------------------------------------------------------
# Secrets never appear in tunnel responses
# ---------------------------------------------------------------------------


def _assert_no_secrets(text: str) -> None:
    assert FAKE_TUNNEL_KEY not in text
    assert "upstream-secret-pw" not in text
    assert FAKE_UPSTREAM not in text


def test_list_and_get_mask_tunnel_secrets(main, tmp_path) -> None:
    _write_tunnel(tmp_path)
    client = _authed(main, tmp_path)
    resp = client.get("/api/tunnels")
    assert resp.status_code == 200
    _assert_no_secrets(resp.text)
    (tunnel,) = resp.json()
    assert "api_key" not in tunnel
    assert "upstream_basic_auth" not in tunnel
    assert tunnel["api_key_set"] is True
    assert tunnel["api_key_masked"] == "hle_...kkkk"
    assert tunnel["has_upstream_basic_auth"] is True
    assert tunnel["upstream_basic_auth_user"] == "admin"


def test_create_and_update_do_not_echo_secrets(main, tmp_path) -> None:
    client = _authed(main, tmp_path)
    created = client.post(
        "/api/tunnels",
        json={
            "service_url": "http://192.0.2.10:8080",
            "label": "svc",
            "api_key": FAKE_TUNNEL_KEY,
            "upstream_basic_auth": FAKE_UPSTREAM,
        },
    )
    assert created.status_code == 201, created.text
    _assert_no_secrets(created.text)
    tunnel_id = created.json()["id"]

    # Stored for the tunnel process, just not returned.
    stored = json.loads((tmp_path / "tunnels.json").read_text())[tunnel_id]
    assert stored["api_key"] == FAKE_TUNNEL_KEY
    assert stored["upstream_basic_auth"] == FAKE_UPSTREAM

    updated = client.patch(f"/api/tunnels/{tunnel_id}", json={"name": "Renamed"})
    assert updated.status_code == 200
    _assert_no_secrets(updated.text)
    # Omitting the secret fields leaves them unchanged.
    stored = json.loads((tmp_path / "tunnels.json").read_text())[tunnel_id]
    assert stored["api_key"] == FAKE_TUNNEL_KEY
    assert stored["upstream_basic_auth"] == FAKE_UPSTREAM

    cleared = client.patch(
        f"/api/tunnels/{tunnel_id}", json={"api_key": "", "upstream_basic_auth": ""}
    )
    assert cleared.status_code == 200
    assert cleared.json()["api_key_set"] is False
    assert cleared.json()["has_upstream_basic_auth"] is False
