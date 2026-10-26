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


# ---- An address the send cannot use ----

SECRET_HOOK = "http://[hooks.example/T000/B000/SECRETPATH"


@pytest.mark.parametrize("channel_type, config", [
    ("slack", {"webhook_url": SECRET_HOOK}),
    ("discord", {"webhook_url": "hooks.example/api/webhooks/SECRETPATH"}),
    ("gotify", {"server_url": "ftp://gotify.example", "app_token": "t"}),
    ("ntfy", {"server_url": "https://ntfy.example:99999", "topic": "t"}),
    ("webhook", {"url": "https:///SECRETPATH"}),
])
def test_validate_refuses_an_address_without_quoting_it(channel_type, config):
    ok, err = nc.validate_config(channel_type, config)
    assert not ok and "is not a valid URL" in err
    assert "SECRET" not in err and "99999" not in err


@pytest.mark.parametrize("channel_type, config", [
    ("slack", {"webhook_url": "https://hooks.slack.com/services/T0/B0/X"}),
    ("discord", {"webhook_url": "HTTPS://discord.com/api/webhooks/1/x"}),
    ("gotify", {"server_url": "http://gotify:8080", "app_token": "t"}),
    ("ntfy", {"server_url": "http://[2001:db8::5]:8080", "topic": "t"}),
    ("ntfy", {"server_url": "", "topic": "t"}),
    ("webhook", {"url": "http://10.0.0.5/hook?x=1"}),
])
def test_validate_keeps_the_addresses_that_work(channel_type, config):
    assert nc.validate_config(channel_type, config) == (True, "")


def test_an_unreadable_secret_url_gives_a_fixed_error():
    error = nc._sanitize_error("slack", {"webhook_url": SECRET_HOOK}, "cannot reach /T000/B000/SECRETPATH")
    assert error == nc._UNREADABLE_SECRET


def test_the_secret_path_is_masked_whatever_the_case_of_the_scheme():
    config = {"webhook_url": "HTTPS://hooks.example/services/T0/B0/SECRETPATH"}
    error = nc._sanitize_error("slack", config, "connect failed for /services/T0/B0/SECRETPATH")
    assert "SECRET" not in error and error.endswith("/" + nc.MASK)


@pytest.mark.parametrize("cut", [4, 10, 20])
def test_a_secret_cut_off_at_the_end_of_an_answer_is_masked(cut):
    path = "/services/T0/B0/SECRETPATH"
    error = nc._sanitize_error("slack", {"webhook_url": "https://hooks.example" + path},
                               "no such hook " + path[:cut])
    assert error == "no such hook /" + nc.MASK


def test_the_error_is_masked_before_it_is_cut(monkeypatch):
    path = "/services/T0/B0/SECRETPATH"

    async def post(url, kwargs):
        return 404, "x" * 180 + " no hook " + path  # the cut at 200 falls inside the path

    monkeypatch.setattr(nc, "_post", post)
    ok, error = nc.send_to_config("slack", {"webhook_url": "https://hooks.example" + path}, "S", "M")
    assert ok is False and "SECR" not in error and "/services" not in error


def test_a_send_to_an_unusable_address_is_not_tried(monkeypatch):
    async def post(url, kwargs):
        raise AssertionError("no request to an address the check refused")

    monkeypatch.setattr(nc, "_post", post)
    ok, error = nc.send_to_config("slack", {"webhook_url": SECRET_HOOK}, "S", "M")
    assert ok is False and "is not a valid URL" in error and "SECRET" not in error


def test_one_channel_failing_unexpectedly_leaves_the_others_their_alert(monkeypatch, caplog):
    from contextlib import contextmanager
    from types import SimpleNamespace

    rows = [SimpleNamespace(id=1, name="first", channel_type="slack", alert_types=None,
                            config={"webhook_url": "https://hooks.example/SECRETPATH"}),
            SimpleNamespace(id=2, name="second", channel_type="slack", alert_types=None,
                            config={"webhook_url": "https://hooks.example/other"})]

    class Session:
        def query(self, *args):
            return self

        def filter(self, *args):
            return self

        def all(self):
            return rows

    @contextmanager
    def context():
        yield Session()

    real_send = nc.send_to_config

    def send(channel_type, config, subject, message):
        if config["webhook_url"].endswith("SECRETPATH"):
            raise RuntimeError(f"broke on {config['webhook_url']}")
        return real_send(channel_type, config, subject, message)

    async def post(url, kwargs):
        sent.append(url)
        return 200, ""

    sent, recorded = [], []
    monkeypatch.setattr(nc, "get_db_context", context)
    monkeypatch.setattr(nc, "send_to_config", send)
    monkeypatch.setattr(nc, "_post", post)
    monkeypatch.setattr(nc, "_record_result", lambda *args: recorded.append(args))
    assert nc.send_to_all("Alert", "Body") == {"sent": 1, "failed": 1, "skipped": 0}
    assert sent == ["https://hooks.example/other"]
    assert recorded[0] == (1, False, nc._UNEXPECTED)
    assert "SECRET" not in caplog.text
