"""Text a mail sender chose reaches Slack and Discord as plain text.

Alerts quote such text, for example the subject of a report email the import
could not read. Slack reads <!channel> as a ping to everyone and <url|label>
as a link that hides its target; Discord pings for @everyone and @here and
hides a link behind [label](url). Slack text is now escaped, and Discord text
is broken up and sent with no mentions allowed.
"""
from app.services import notification_channels as nc

SENDER_TEXT = ("DMARC <!channel> @everyone @Here <https://phish.invalid/login|Sign in> "
               "[Sign in again](https://phish.invalid/) & more")


def test_slack_shows_sender_text_as_written():
    _url, kwargs = nc.build_request("slack", {"webhook_url": "https://hooks.example.com/x"},
                                    f"Subject: {SENDER_TEXT}", f"Body: {SENDER_TEXT}")
    text = kwargs["json"]["text"]
    assert "<" not in text and ">" not in text
    assert "&lt;!channel&gt;" in text
    assert "&lt;https://phish.invalid/login|Sign in&gt;" in text
    assert "&amp; more" in text and "&amp;lt;" not in text
    assert text.startswith("*Subject: ")


def test_discord_allows_no_mentions_and_no_hidden_links():
    _url, kwargs = nc.build_request("discord", {"webhook_url": "https://discord.example.com/x"},
                                    f"Subject: {SENDER_TEXT}", f"Body: {SENDER_TEXT}")
    body = kwargs["json"]
    assert body["allowed_mentions"] == {"parse": []}
    content = body["content"]
    assert "@everyone" not in content and "@Here" not in content
    assert "@\u200beveryone" in content and "@\u200bHere" in content
    assert "](" not in content
    assert content.startswith("**Subject: ")


def test_escaped_text_still_fits_the_length_limit():
    for channel in ("slack", "discord"):
        _url, kwargs = nc.build_request(channel, {"webhook_url": "https://hooks.example.com/x"},
                                        "S", "<>&@everyone](" * 1000)
        body = kwargs["json"]
        # Discord refuses content over 2000 characters
        assert len(body.get("text") or body.get("content")) <= nc._MAX_MESSAGE_CHARS + 20


def test_plain_text_channels_are_unchanged():
    _url, kwargs = nc.build_request("telegram", {"bot_token": "T", "chat_id": "1"}, "S", SENDER_TEXT)
    assert kwargs["json"]["text"] == f"S\n\n{SENDER_TEXT}"
