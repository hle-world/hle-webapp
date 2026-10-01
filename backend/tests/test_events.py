"""Parsing of ``--events jsonl`` lines into tunnel-manager state.

The hle-client emits one JSON event per line on stdout (schema:
``docs/events.md``). These tests pin down how each event name is mapped,
and — just as important — that a malformed or partial line is ignored
rather than crashing the reader task.
"""

from __future__ import annotations

import json

import pytest

from backend import tunnel_manager as tm
from backend.models import TunnelConfig


def _cfg(**overrides) -> TunnelConfig:
    base: dict = {"id": "t1", "service_url": "http://localhost:8080", "label": "svc"}
    base.update(overrides)
    return TunnelConfig(**base)


def _event(**overrides) -> str:
    """Build one wire-format event line, filling the schema's null keys."""
    base: dict = {
        "ts": "2026-09-25T10:00:00.101Z",
        "event": "connected",
        "level": "info",
        "source": "tunnel",
        "label": "svc",
        "subdomain": None,
        "public_url": None,
        "message": "",
        "code": None,
    }
    base.update(overrides)
    return json.dumps(base)


@pytest.fixture(autouse=True)
def _clean_state():
    tm._connected.clear()
    tm._user_stopped.clear()
    tm._last_errors.clear()
    tm._last_notices.clear()
    yield
    tm._connected.clear()
    tm._user_stopped.clear()
    tm._last_errors.clear()
    tm._last_notices.clear()


# ---------------------------------------------------------------------------
# Each event type
# ---------------------------------------------------------------------------


def test_notice_is_buffered_with_its_level_and_message() -> None:
    assert tm._parse_event_line(
        "t1",
        _event(
            event="notice",
            level="success",
            message="Auto-protect added you@example.com",
            code="auto_protect",
        ),
    )
    notices = tm.get_notices("t1")
    assert len(notices) == 1
    assert notices[0].level == "success"
    assert notices[0].message == "Auto-protect added you@example.com"


def test_notice_with_unknown_level_falls_back_to_info() -> None:
    tm._parse_event_line("t1", _event(event="notice", level="weird", message="hi"))
    assert tm.get_notices("t1")[0].level == "info"


def test_notice_with_empty_message_is_ignored() -> None:
    tm._parse_event_line("t1", _event(event="notice", level="info", message=""))
    assert tm.get_notices("t1") == []


def test_registered_marks_connected_and_persists_relay_url(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(tm, "DATA_FILE", tmp_path / "tunnels.json")
    tm._save_all({"t1": _cfg()})

    tm._parse_event_line(
        "t1",
        _event(
            event="registered",
            level="success",
            subdomain="svc-x7k",
            public_url="https://svc-x7k.hle.world",
            message="Tunnel registered",
        ),
    )

    assert "t1" in tm._connected
    cfg = tm._load_all()["t1"]
    assert cfg.subdomain == "svc-x7k"
    assert cfg.public_url == "https://svc-x7k.hle.world"


def test_registered_writes_only_when_a_value_changes(monkeypatch) -> None:
    cfg = _cfg()
    monkeypatch.setattr(tm, "_load_all", lambda: {"t1": cfg})
    saves: list[dict] = []
    monkeypatch.setattr(tm, "_save_all", lambda tunnels: saves.append(tunnels))

    line = _event(
        event="registered",
        subdomain="svc-x7k",
        public_url="https://svc-x7k.hle.world",
    )
    tm._parse_event_line("t1", line)
    tm._parse_event_line("t1", line)

    assert len(saves) == 1


def test_connected_alone_does_not_mark_the_tunnel_connected() -> None:
    tm._parse_event_line("t1", _event(event="connected", level="info"))
    assert "t1" not in tm._connected


def test_disconnected_marks_degraded_and_records_the_code() -> None:
    tm._connected.add("t1")
    tm._parse_event_line(
        "t1",
        _event(
            event="disconnected",
            level="warning",
            message="received 1012 (service restart)",
            code="1012",
        ),
    )
    assert "t1" not in tm._connected
    assert tm._last_errors["t1"] == "received 1012 (service restart) (code 1012)"


def test_error_records_the_message_and_code_without_dropping_connection() -> None:
    tm._connected.add("t1")
    tm._parse_event_line(
        "t1",
        _event(event="error", level="error", message="connect failed", code="4003"),
    )
    assert tm._last_errors["t1"] == "connect failed (code 4003)"
    assert "t1" in tm._connected


def test_fatal_records_the_error_and_drops_the_connection() -> None:
    tm._connected.add("t1")
    tm._parse_event_line(
        "t1",
        _event(
            event="fatal",
            level="error",
            message="Authentication failed",
            code="4001",
        ),
    )
    assert "t1" not in tm._connected
    assert tm._last_errors["t1"] == "Authentication failed (code 4001)"


def test_registered_clears_a_previous_error() -> None:
    tm._last_errors["t1"] = "old failure"
    tm._parse_event_line("t1", _event(event="registered", message="Tunnel registered"))
    assert "t1" not in tm._last_errors


def test_unknown_event_is_ignored() -> None:
    tm._parse_event_line("t1", _event(event="something_new", message="future"))
    assert "t1" not in tm._connected
    assert tm.get_notices("t1") == []
    assert tm._last_errors == {}


# ---------------------------------------------------------------------------
# Lines that are not events
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "WARNING: WS_FRAME for unknown stream_id",
        "Traceback (most recent call last):",
        "{not valid json",
        '{"ts":"2026-09-25T10:00:00.101Z"',  # truncated / partial line
        '["not", "an", "object"]',
        '{"no_event_key": true}',
    ],
)
def test_non_event_lines_return_false_without_raising(line: str) -> None:
    assert tm._parse_event_line("t1", line) is False
    assert tm._connected == set()
    assert tm.get_notices("t1") == []
    assert tm._last_errors == {}


def test_non_event_does_not_clobber_existing_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(tm, "DATA_FILE", tmp_path / "tunnels.json")
    tm._save_all({"t1": _cfg()})
    tm._parse_event_line("t1", _event(event="registered", subdomain="svc-x7k"))
    tm._parse_event_line("t1", "WARNING: something on stdout")
    assert "t1" in tm._connected
    assert tm._load_all()["t1"].subdomain == "svc-x7k"
