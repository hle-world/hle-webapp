"""The management API must refuse unauthenticated callers and never echo secrets.

Covers the login token gate (backend/auth.py), the scoping of the
subdomain-keyed relay routes to locally managed tunnels, and the masking of
per-tunnel secrets in tunnel responses.
"""

from __future__ import annotations

import importlib
import json
import re
import stat
import sys

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

    client.post("/logout")
    client.cookies.clear()
    assert client.get("/api/tunnels").status_code == 401


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
