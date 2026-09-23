"""The argv we spawn must be accepted by the installed hle-client CLI.

A stale or invented flag makes every tunnel using it fail to start with
"No such option". Parsing the argv with the real click commands catches
that before release, without connecting to anything.
"""

from __future__ import annotations

import click
import pytest
from hle_client.cli import expose, webhook

from backend.models import TunnelConfig
from backend.tunnel_manager import _build_argv


def _parse(cmd: click.Command, argv: list[str]) -> dict:
    """Parse argv with click only (no callback runs); raises on unknown options."""
    ctx = cmd.make_context(cmd.name, argv)
    return ctx.params


def _cfg(**overrides) -> TunnelConfig:
    base: dict = {"id": "t1", "service_url": "http://localhost:8080", "label": "svc"}
    base.update(overrides)
    return TunnelConfig(**base)


def test_expose_argv_with_response_timeout_is_accepted_by_cli() -> None:
    argv = _build_argv(_cfg(response_timeout=300))
    assert argv[:2] == ["hle", "expose"]
    assert "--timeout" not in argv
    params = _parse(expose, argv[2:])
    assert params["service"] == "http://localhost:8080"
    assert params["service_label"] == "svc"


def test_expose_argv_all_flags_accepted_by_cli() -> None:
    argv = _build_argv(
        _cfg(
            response_timeout=60,
            verify_ssl=True,
            websocket_enabled=False,
            upstream_basic_auth="u:p",
            forward_host=True,
            auth_mode="none",
        )
    )
    params = _parse(expose, argv[2:])
    assert params["verify_ssl"] is True
    assert params["websocket"] is False
    assert params["upstream_basic_auth"] == "u:p"
    assert params["forward_host"] is True
    assert params["auth"] == "none"


def test_webhook_argv_with_response_timeout_is_accepted_by_cli() -> None:
    argv = _build_argv(
        _cfg(
            response_timeout=120,
            webhook_path="/webhook/github",
            service_url="http://localhost:9000/hook",
        )
    )
    assert argv[:2] == ["hle", "webhook"]
    assert "--timeout" not in argv
    params = _parse(webhook, argv[2:])
    assert params["path"] == "/webhook/github"
    assert params["forward_to"] == "http://localhost:9000/hook"


def test_unknown_option_is_rejected_by_cli() -> None:
    """Guard that the check above is meaningful: click really rejects bad flags."""
    argv = _build_argv(_cfg()) + ["--timeout", "300"]
    with pytest.raises(click.NoSuchOption):
        _parse(expose, argv[2:])
