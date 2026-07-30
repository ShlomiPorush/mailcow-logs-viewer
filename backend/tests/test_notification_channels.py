"""Tests for notification channel specs, URL building and validation."""
import pytest

from app.services import notification_channels as nc


def test_all_types_have_fields_and_help():
    for ctype, spec in nc.CHANNEL_TYPES.items():
        assert spec["label"] and spec["help"], ctype
        assert spec["fields"], ctype
        for field in spec["fields"]:
            assert {"key", "label", "type"} <= set(field), (ctype, field)


def test_each_type_only_asks_for_its_own_fields():
    """A Slack channel must not ask for a Telegram chat ID, and vice versa."""
    slack = {f["key"] for f in nc.CHANNEL_TYPES["slack"]["fields"]}
    telegram = {f["key"] for f in nc.CHANNEL_TYPES["telegram"]["fields"]}
    assert slack == {"webhook_url"}
    assert telegram == {"bot_token", "chat_id"}
    assert "chat_id" not in slack


def test_telegram_url_is_built_from_token():
    url, kwargs = nc.build_request("telegram", {"bot_token": "TOK", "chat_id": "42"}, "S", "M")
    assert url == "https://api.telegram.org/botTOK/sendMessage"
    assert kwargs["json"]["chat_id"] == "42"
    assert "S" in kwargs["json"]["text"] and "M" in kwargs["json"]["text"]


def test_ntfy_url_is_server_plus_topic():
    url, kwargs = nc.build_request("ntfy", {"server_url": "https://ntfy.sh/", "topic": "alerts"}, "S", "M")
    assert url == "https://ntfy.sh/alerts"
    # Title travels as a query param so emoji subjects survive (headers are latin-1)
    assert kwargs["params"]["title"] == "S"
    assert "Title" not in kwargs["headers"]


def test_ntfy_token_becomes_auth_header():
    _url, kwargs = nc.build_request("ntfy", {"topic": "t", "token": "abc"}, "S", "M")
    assert kwargs["headers"]["Authorization"] == "Bearer abc"


def test_gotify_url_includes_token():
    url, _kw = nc.build_request("gotify", {"server_url": "https://g.example.com/", "app_token": "T"}, "S", "M")
    assert url == "https://g.example.com/message?token=T"


def test_slack_and_discord_use_their_webhook_url():
    url, kwargs = nc.build_request("slack", {"webhook_url": "https://hooks.slack.com/x"}, "S", "M")
    assert url == "https://hooks.slack.com/x" and "S" in kwargs["json"]["text"]
    url, kwargs = nc.build_request("discord", {"webhook_url": "https://discord/x"}, "S", "M")
    assert url == "https://discord/x" and "S" in kwargs["json"]["content"]


def test_custom_webhook_payload_and_optional_auth():
    url, kwargs = nc.build_request("webhook", {"url": "https://x/hook", "auth_header": "Bearer t"}, "S", "M")
    assert url == "https://x/hook"
    assert kwargs["json"]["source"] == "mailcow-logs-viewer"
    assert kwargs["headers"]["Authorization"] == "Bearer t"


def test_validate_requires_mandatory_fields():
    ok, err = nc.validate_config("telegram", {"bot_token": "x"})
    assert not ok and "Chat ID" in err
    ok, _ = nc.validate_config("telegram", {"bot_token": "x", "chat_id": "1"})
    assert ok


def test_validate_rejects_unknown_type():
    ok, err = nc.validate_config("carrier-pigeon", {})
    assert not ok and "Unknown channel type" in err


def test_optional_fields_are_not_required():
    ok, _ = nc.validate_config("ntfy", {"topic": "t"})   # server_url + token optional
    assert ok


def test_secrets_are_masked_and_preserved():
    masked = nc.mask_config("telegram", {"bot_token": "TOK", "chat_id": "42"})
    assert masked["bot_token"] == nc.MASK
    assert masked["chat_id"] == "42"

    merged = nc.merge_config("telegram", {"bot_token": "TOK", "chat_id": "42"},
                             {"bot_token": nc.MASK, "chat_id": "99"})
    assert merged == {"bot_token": "TOK", "chat_id": "99"}


def test_message_truncation():
    long_message = "x" * 5000
    _url, kwargs = nc.build_request("slack", {"webhook_url": "https://x"}, "S", long_message)
    assert len(kwargs["json"]["text"]) <= nc._MAX_MESSAGE_CHARS + 20


def test_blacklist_alert_fires_for_channel_only_setups():
    """Both blacklist alert blocks must dispatch when notification channels
    exist even if no email is configured (channels-only setups got nothing)."""
    import inspect
    from app import scheduler
    src = inspect.getsource(scheduler._run_check_monitored_hosts)
    gates = src.count("if notification_email or any_channel_configured():")
    assert gates == 2, f"expected both alert blocks gated on email OR channels, found {gates}"
    assert "if notification_email:\n" not in src
