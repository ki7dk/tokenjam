"""Unit tests for the ntfy alert channel — no real I/O; httpx is faked."""
from __future__ import annotations

from typing import Any

import pytest

from tokenjam.core.alerts import NtfyChannel, _build_channel
from tokenjam.core.config import AlertChannelConfig
from tokenjam.core.models import Alert, AlertType, Severity
from tokenjam.utils.time_parse import utcnow

TOPIC = "my-agent-alerts"


class _FakeClient:
    """Stands in for httpx.Client, recording the one POST a send makes."""

    calls: list[dict[str, Any]] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def post(
        self,
        url: str,
        content: str | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        type(self).calls.append({"url": url, "content": content, "headers": headers or {}})


@pytest.fixture
def fake_http(monkeypatch: pytest.MonkeyPatch) -> type[_FakeClient]:
    _FakeClient.calls = []
    monkeypatch.setattr("tokenjam.core.alerts.httpx.Client", _FakeClient)
    return _FakeClient


def _alert(
    severity: Severity = Severity.CRITICAL,
    detail: dict[str, Any] | None = None,
    title: str = "Budget exceeded",
) -> Alert:
    return Alert(
        alert_id="al_1",
        fired_at=utcnow(),
        type=AlertType.COST_BUDGET_DAILY,
        severity=severity,
        title=title,
        detail=detail if detail is not None else {"message": "daily spend over limit"},
        agent_id="my-agent",
    )


def _channel(**overrides: Any) -> NtfyChannel:
    config = AlertChannelConfig(type="ntfy", topic=TOPIC, **overrides)
    return NtfyChannel(config, include_captured_content=False)


# ── Factory registration ──────────────────────────────────────────────────

def test_build_channel_returns_an_ntfy_channel_for_the_ntfy_type():
    ch = _build_channel(
        AlertChannelConfig(type="ntfy", topic=TOPIC),
        include_captured_content=False,
    )
    assert isinstance(ch, NtfyChannel)
    assert ch.topic == TOPIC


# ── Severity → Priority ───────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.INFO,     "low"),
        (Severity.WARNING,  "default"),
        (Severity.CRITICAL, "high"),
    ],
)
def test_severity_maps_to_an_ntfy_priority(fake_http, severity, expected):
    _channel(min_severity="info").send(_alert(severity=severity))
    assert fake_http.calls[0]["headers"]["Priority"] == expected


def test_no_severity_reaches_the_max_priority(fake_http):
    # ntfy's max priority is an emergency escalation that overrides the
    # phone's notification sound, so nothing derives it from a severity.
    for severity in (Severity.INFO, Severity.WARNING, Severity.CRITICAL):
        _channel(min_severity="info").send(_alert(severity=severity))
    sent = [c["headers"]["Priority"] for c in fake_http.calls]
    assert "max" not in sent
    assert "urgent" not in sent
    assert "5" not in sent


def test_every_send_carries_a_priority_header(fake_http):
    # Without it every alert arrives at ntfy's default priority and a
    # critical is indistinguishable from an info on the phone.
    _channel().send(_alert())
    assert "Priority" in fake_http.calls[0]["headers"]


# ── Payload ───────────────────────────────────────────────────────────────

def test_send_posts_title_body_and_url(fake_http):
    _channel().send(_alert(title="Daily budget exceeded"))
    call = fake_http.calls[0]
    assert call["url"] == f"https://ntfy.sh/{TOPIC}"
    assert call["headers"]["Title"] == "Daily budget exceeded"
    assert "daily spend over limit" in call["content"]


def test_a_custom_server_is_honoured(fake_http):
    _channel(server="https://ntfy.example.com/").send(_alert())
    assert fake_http.calls[0]["url"] == f"https://ntfy.example.com/{TOPIC}"


def test_a_token_becomes_a_bearer_header(fake_http):
    _channel(token="tk_secret").send(_alert())
    assert fake_http.calls[0]["headers"]["Authorization"] == "Bearer tk_secret"


def test_no_token_sends_no_authorization_header(fake_http):
    _channel().send(_alert())
    assert "Authorization" not in fake_http.calls[0]["headers"]


def test_an_empty_topic_sends_nothing(fake_http):
    NtfyChannel(AlertChannelConfig(type="ntfy"), include_captured_content=False).send(_alert())
    assert fake_http.calls == []


def test_min_severity_suppresses_a_lower_alert(fake_http):
    _channel(min_severity="critical").send(_alert(severity=Severity.WARNING))
    assert fake_http.calls == []


# ── Critical Rule 5: captured content is stripped ─────────────────────────

def test_captured_content_is_stripped_by_default(fake_http):
    # No "message" key, or _format_detail_text returns it alone and the test
    # would pass without stripping anything.
    detail = {"prompt_content": "secret prompt", "tool_output": "secret output", "cost": 1.5}
    _channel().send(_alert(detail=detail))
    body = fake_http.calls[0]["content"]
    assert "secret prompt" not in body
    assert "secret output" not in body
    assert "1.5" in body


def test_captured_content_is_included_when_opted_in(fake_http):
    config = AlertChannelConfig(type="ntfy", topic=TOPIC)
    NtfyChannel(config, include_captured_content=True).send(
        _alert(detail={"prompt_content": "secret prompt", "cost": 1.5})
    )
    assert "secret prompt" in fake_http.calls[0]["content"]
