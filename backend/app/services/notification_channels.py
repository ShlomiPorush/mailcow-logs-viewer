"""
Notification channels - built-in support for common alert destinations.

Each channel type declares the fields it actually needs (a Slack channel asks
for its incoming-webhook URL, Telegram asks for a bot token and chat ID, ntfy
asks for a server and topic). The full endpoint URL is assembled here, so the
user never has to hand-craft one.

Multiple channels can be enabled at once. Each channel subscribes to the alert
topics it cares about (see ALERT_TYPES); a channel with no subscription list
receives everything.
Synchronous (requests) - call from a worker thread, never on the event loop.
"""
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from ..database import get_db_context
from ..models import NotificationChannel

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 10
# Discord's hard limit is 2000 characters; stay comfortably below it
_MAX_MESSAGE_CHARS = 1900


# The alert topics a channel can subscribe to. Every notification the app
# sends belongs to exactly one of these, so the settings UI can show what a
# destination will actually receive.
ALERT_TYPES: List[Dict] = [
    {
        "id": "security",
        "label": "Security",
        "description": "Compromised mailbox detected, authentication attacks, SMTP disabled by abuse protection",
    },
    {
        "id": "blacklist",
        "label": "IP blacklist",
        "description": "Your server IP was listed on a spam blacklist, or is listed no more",
    },
    {
        "id": "dns_changes",
        "label": "DNS record changes",
        "description": "A domain SPF, DKIM, DMARC, TLSA or MTA-STS record changed",
    },
    {
        "id": "dmarc_errors",
        "label": "DMARC processing errors",
        "description": "A DMARC report could not be imported or parsed",
    },
]

ALERT_TYPE_IDS = {t["id"] for t in ALERT_TYPES}


def channel_wants(channel_alert_types, alert_type: Optional[str]) -> bool:
    """Should this channel receive an alert of this type?

    An empty/missing subscription list means "everything", so channels created
    before topics existed keep receiving all alerts.
    """
    if not channel_alert_types:
        return True
    if not alert_type:
        return True          # untyped notification (e.g. a manual test)
    return alert_type in channel_alert_types


# Field specs drive the settings UI: only these fields are shown per type.
# secret=True fields are masked once saved.
CHANNEL_TYPES: Dict[str, Dict] = {
    "slack": {
        "label": "Slack",
        "help": "Create an Incoming Webhook in your Slack workspace (Apps -> Incoming Webhooks) and paste the URL.",
        "fields": [
            {"key": "webhook_url", "label": "Incoming Webhook URL", "type": "url", "required": True,
             "secret": True, "placeholder": "https://hooks.slack.com/services/T000/B000/XXXX"},
        ],
    },
    "discord": {
        "label": "Discord",
        "help": "In your Discord channel: Edit Channel -> Integrations -> Webhooks -> New Webhook, then copy the URL.",
        "fields": [
            {"key": "webhook_url", "label": "Webhook URL", "type": "url", "required": True,
             "secret": True, "placeholder": "https://discord.com/api/webhooks/..."},
        ],
    },
    "telegram": {
        "label": "Telegram",
        "help": "Create a bot with @BotFather to get the token, then message your bot and use @userinfobot to find your chat ID.",
        "fields": [
            {"key": "bot_token", "label": "Bot token", "type": "text", "required": True,
             "secret": True, "placeholder": "123456789:AAExample-Token"},
            {"key": "chat_id", "label": "Chat ID", "type": "text", "required": True,
             "placeholder": "123456789 or -100123456789 for a group"},
        ],
    },
    "ntfy": {
        "label": "ntfy",
        "help": "Use the public server (ntfy.sh) or your own. The topic is the channel name you subscribe to in the app.",
        "fields": [
            {"key": "server_url", "label": "Server URL", "type": "url", "required": False,
             "default": "https://ntfy.sh", "placeholder": "https://ntfy.sh"},
            {"key": "topic", "label": "Topic", "type": "text", "required": True,
             "placeholder": "mailcow-alerts"},
            {"key": "token", "label": "Access token", "type": "text", "required": False,
             "secret": True, "placeholder": "Only for protected topics"},
        ],
    },
    "gotify": {
        "label": "Gotify",
        "help": "Create an application in your Gotify server and copy its token.",
        "fields": [
            {"key": "server_url", "label": "Server URL", "type": "url", "required": True,
             "placeholder": "https://gotify.example.com"},
            {"key": "app_token", "label": "Application token", "type": "text", "required": True,
             "secret": True, "placeholder": "AXxxxxxxxxxxxxx"},
        ],
    },
    "webhook": {
        "label": "Custom webhook (JSON)",
        "help": "Any endpoint that accepts a JSON POST - n8n, Home Assistant, your own script.",
        "fields": [
            {"key": "url", "label": "Endpoint URL", "type": "url", "required": True,
             "placeholder": "https://example.com/hook"},
            {"key": "auth_header", "label": "Authorization header", "type": "text", "required": False,
             "secret": True, "placeholder": "Bearer <token> (optional)"},
        ],
    },
}

SECRET_FIELDS = {
    ctype: {f["key"] for f in spec["fields"] if f.get("secret")}
    for ctype, spec in CHANNEL_TYPES.items()
}

MASK = "********"


def _truncate(text: str, limit: int = _MAX_MESSAGE_CHARS) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "..."


def validate_config(channel_type: str, config: Dict) -> Tuple[bool, str]:
    """Check that all required fields for this type are present."""
    spec = CHANNEL_TYPES.get(channel_type)
    if not spec:
        return False, f"Unknown channel type: {channel_type}"
    for field in spec["fields"]:
        if field.get("required") and not str(config.get(field["key"], "")).strip():
            return False, f"{field['label']} is required"
    return True, ""


def build_request(channel_type: str, config: Dict, subject: str, message: str) -> Tuple[str, Dict]:
    """Assemble (url, requests-kwargs) for a channel. URLs are built here so
    the user only supplies the service-specific pieces."""
    text = _truncate(message)

    if channel_type == "slack":
        return config["webhook_url"], {"json": {"text": f"*{subject}*\n{text}"}}

    if channel_type == "discord":
        return config["webhook_url"], {"json": {"content": _truncate(f"**{subject}**\n{text}")}}

    if channel_type == "telegram":
        url = f"https://api.telegram.org/bot{config['bot_token']}/sendMessage"
        return url, {"json": {"chat_id": config["chat_id"], "text": f"{subject}\n\n{text}"}}

    if channel_type == "ntfy":
        server = (config.get("server_url") or "https://ntfy.sh").rstrip("/")
        url = f"{server}/{config['topic']}"
        headers = {"Priority": "default"}
        if config.get("token"):
            headers["Authorization"] = f"Bearer {config['token']}"
        # Title goes as a query parameter: HTTP headers can't carry the emoji
        # some alert subjects use, ?title= takes percent-encoded UTF-8
        return url, {"data": text.encode("utf-8"), "headers": headers,
                     "params": {"title": subject}}

    if channel_type == "gotify":
        server = config["server_url"].rstrip("/")
        url = f"{server}/message?token={config['app_token']}"
        return url, {"json": {"title": subject, "message": text, "priority": 5}}

    # custom webhook
    headers = {}
    if config.get("auth_header"):
        headers["Authorization"] = config["auth_header"]
    return config["url"], {
        "json": {
            "title": subject,
            "message": text,
            "source": "mailcow-logs-viewer",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "headers": headers,
    }


def _sanitize_error(channel_type: str, config: Dict, error_text: str) -> str:
    """Strip channel secrets from an error string before it is logged, stored
    in last_error, or returned by the API. requests embeds the target URL in
    its exception messages, and for Telegram/Gotify/Slack/Discord the URL (or
    its path) contains the token."""
    for key in SECRET_FIELDS.get(channel_type, set()):
        value = str(config.get(key, "") or "").strip()
        if not value:
            continue
        error_text = error_text.replace(value, MASK)
        if value.startswith("http"):
            # ConnectionError messages quote only the path part of the URL
            path = urlparse(value).path
            if path and len(path) > 1:
                error_text = error_text.replace(path, "/" + MASK)
    return error_text


def send_to_config(channel_type: str, config: Dict, subject: str, message: str) -> Tuple[bool, str]:
    """Send one notification. Returns (ok, error_message)."""
    ok, error = validate_config(channel_type, config)
    if not ok:
        return False, error
    try:
        url, kwargs = build_request(channel_type, config, subject, message)
        response = requests.post(url, timeout=_TIMEOUT_SECONDS, **kwargs)
        if 200 <= response.status_code < 300:
            return True, ""
        return False, _sanitize_error(channel_type, config,
                                      f"HTTP {response.status_code}: {response.text[:200]}")
    except Exception as e:
        return False, _sanitize_error(channel_type, config, str(e))


def _record_result(channel_id: int, ok: bool, error: str) -> None:
    try:
        with get_db_context() as db:
            row = db.query(NotificationChannel).filter(NotificationChannel.id == channel_id).first()
            if row:
                row.last_status = "success" if ok else "failed"
                row.last_error = None if ok else error[:500]
                row.last_sent_at = datetime.utcnow()
                db.commit()
    except Exception as e:
        logger.debug("Could not record channel result: %s", e)


def send_to_all(subject: str, message: str, alert_type: Optional[str] = None) -> Dict[str, int]:
    """Deliver to every enabled channel subscribed to this alert type.

    Returns {'sent': n, 'failed': n, 'skipped': n}.
    """
    try:
        with get_db_context() as db:
            all_channels = [
                {"id": c.id, "name": c.name, "type": c.channel_type,
                 "config": c.config or {}, "alert_types": c.alert_types}
                for c in db.query(NotificationChannel).filter(
                    NotificationChannel.enabled.is_(True)
                ).all()
            ]
    except Exception as e:
        logger.error("Could not load notification channels: %s", e)
        return {"sent": 0, "failed": 0, "skipped": 0}

    channels = [c for c in all_channels if channel_wants(c["alert_types"], alert_type)]
    skipped = len(all_channels) - len(channels)

    sent = failed = 0
    for channel in channels:
        ok, error = send_to_config(channel["type"], channel["config"], subject, message)
        _record_result(channel["id"], ok, error)
        if ok:
            sent += 1
            logger.info("Notification sent to '%s' (%s)", channel["name"], channel["type"])
        else:
            failed += 1
            logger.error("Notification to '%s' (%s) failed: %s", channel["name"], channel["type"], error)
    return {"sent": sent, "failed": failed, "skipped": skipped}


def has_enabled_channels() -> bool:
    try:
        with get_db_context() as db:
            return db.query(NotificationChannel).filter(
                NotificationChannel.enabled.is_(True)
            ).count() > 0
    except Exception:
        return False


def mask_config(channel_type: str, config: Dict) -> Dict:
    """Hide secret values before sending a channel to the browser."""
    secrets = SECRET_FIELDS.get(channel_type, set())
    return {
        k: (MASK if (k in secrets and str(v).strip()) else v)
        for k, v in (config or {}).items()
    }


def merge_config(channel_type: str, existing: Dict, incoming: Dict) -> Dict:
    """Keep the stored secret when the UI sends back the mask placeholder."""
    secrets = SECRET_FIELDS.get(channel_type, set())
    merged = dict(incoming or {})
    for key in secrets:
        if merged.get(key) == MASK:
            merged[key] = (existing or {}).get(key, "")
    return merged
