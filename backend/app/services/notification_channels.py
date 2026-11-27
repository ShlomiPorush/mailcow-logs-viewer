import asyncio
import codecs
import contextlib
import logging
import os
import re
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from ..database import get_db_context
from ..models import NotificationChannel

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 10
_TOTAL_SECONDS = 20
_MAX_ERROR_BYTES = 1024
_TOO_SLOW = "The destination took too long to respond. Try sending a test again."
_UNREADABLE_URL = "Could not send the notification. Check the destination URL and credentials."
_UNEXPECTED = "The send failed with an unexpected error. Check the application logs."
_MIN_CUT_SECRET = 4
_MAX_MESSAGE_CHARS = 1900


ALERT_TYPES: List[Dict] = [
    {
        "id": "security",
        "label": "Security",
        "description": "Unusual sending, login attacks, and blocked mailbox sending.",
    },
    {
        "id": "blacklist",
        "label": "Blocklists",
        "description": "Sending IPs added to or removed from blocklists.",
    },
    {
        "id": "dns_changes",
        "label": "DNS record changes",
        "description": "Changed DNS records, failed DNSSEC validation, or TLSA certificate mismatches.",
    },
    {
        "id": "dmarc_errors",
        "label": "Report import errors",
        "description": "DMARC or TLS reports that could not be imported.",
    },
]

ALERT_TYPE_IDS = {t["id"] for t in ALERT_TYPES}


def channel_wants(channel_alert_types, alert_type: Optional[str]) -> bool:
    if not channel_alert_types:
        return True
    if not alert_type:
        return True
    return alert_type in channel_alert_types


CHANNEL_TYPES: Dict[str, Dict] = {
    "slack": {
        "label": "Slack",
        "help": "Paste an incoming webhook URL from your Slack workspace.",
        "fields": [
            {"key": "webhook_url", "label": "Incoming webhook URL", "type": "url", "required": True,
             "secret": True, "placeholder": "https://hooks.slack.com/services/T000/B000/XXXX"},
        ],
    },
    "discord": {
        "label": "Discord",
        "help": "Paste a webhook URL from Discord > Edit Channel > Integrations > Webhooks.",
        "fields": [
            {"key": "webhook_url", "label": "Webhook URL", "type": "url", "required": True,
             "secret": True, "placeholder": "https://discord.com/api/webhooks/..."},
        ],
    },
    "telegram": {
        "label": "Telegram",
        "help": "Enter your bot token and the chat ID that should receive alerts. For a direct chat, message your bot first. For a group topic, enter its Topic ID.",
        "fields": [
            {"key": "bot_token", "label": "Bot token", "type": "text", "required": True,
             "secret": True, "placeholder": "123456789:AAExample-Token"},
            {"key": "chat_id", "label": "Chat ID", "type": "text", "required": True,
             "placeholder": "123456789 or -100123456789 for a group"},
            {"key": "message_thread_id", "label": "Topic ID", "type": "text", "required": False,
             "integer": True, "placeholder": "42",
             "hint": "Copy the topic link in Telegram and use its last number, for example 42 in t.me/c/1234567890/42."},
        ],
    },
    "ntfy": {
        "label": "ntfy",
        "help": "Use a topic you subscribe to in ntfy.",
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
        "help": "Use an endpoint that accepts JSON POST requests.",
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


def _readable_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        parsed.port
    except ValueError:
        return False
    return parsed.scheme.lower() in ("http", "https") and bool(parsed.hostname)


def validate_config(channel_type: str, config: Dict) -> Tuple[bool, str]:
    spec = CHANNEL_TYPES.get(channel_type)
    if not spec:
        return False, f"Unknown destination service: {channel_type}. Select a service from the list."
    for field in spec["fields"]:
        if field.get("required") and not str(config.get(field["key"], "")).strip():
            return False, f"Enter {field['label']}."
        value = str(config.get(field["key"]) or "").strip()
        if field.get("type") == "url" and value and not _readable_url(value):
            return False, f"{field['label']} is not a valid URL. Enter the full address, starting with https://"
        if field.get("integer") and value and not (value.isascii() and value.isdigit()):
            return False, f"{field['label']} must be a whole number, such as 42"
    return True, ""


def _slack_text(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_DISCORD_MASS_MENTION = re.compile(r"@(everyone|here)", re.IGNORECASE)
_ZERO_WIDTH_SPACE = "\u200b"


def _discord_text(text: str) -> str:
    text = _DISCORD_MASS_MENTION.sub(rf"@{_ZERO_WIDTH_SPACE}\1", text)
    return text.replace("](", f"]{_ZERO_WIDTH_SPACE}(")


def build_request(channel_type: str, config: Dict, subject: str, message: str) -> Tuple[str, Dict]:
    text = _truncate(message)

    if channel_type == "slack":
        return config["webhook_url"], {"json": {
            "text": _truncate(f"*{_slack_text(subject)}*\n{_slack_text(message)}")}}

    if channel_type == "discord":
        return config["webhook_url"], {"json": {
            "content": _truncate(f"**{_discord_text(subject)}**\n{_discord_text(message)}"),
            "allowed_mentions": {"parse": []},
        }}

    if channel_type == "telegram":
        url = f"https://api.telegram.org/bot{config['bot_token']}/sendMessage"
        payload = {"chat_id": config["chat_id"], "text": f"{subject}\n\n{text}"}
        topic = str(config.get("message_thread_id") or "").strip()
        if topic:
            payload["message_thread_id"] = int(topic)
        return url, {"json": payload}

    if channel_type == "ntfy":
        server = (config.get("server_url") or "https://ntfy.sh").rstrip("/")
        url = f"{server}/{config['topic']}"
        headers = {"Priority": "default"}
        if config.get("token"):
            headers["Authorization"] = f"Bearer {config['token']}"
        return url, {"content": text.encode("utf-8"), "headers": headers,
                     "params": {"title": subject}}

    if channel_type == "gotify":
        server = config["server_url"].rstrip("/")
        url = f"{server}/message?token={config['app_token']}"
        return url, {"json": {"title": subject, "message": text, "priority": 5}}

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
    secrets = []
    for key in SECRET_FIELDS.get(channel_type, set()):
        value = str(config.get(key, "") or "").strip()
        if not value:
            continue
        secrets.append(value)
        if value.lower().startswith("http"):
            try:
                parsed = urlparse(value)
            except ValueError:
                return _UNREADABLE_URL
            path, query = parsed.path, parsed.query
            if path and len(path) > 1:
                secrets.append(path)
            if query:
                secrets += [f"{path}?{query}", query]
    return _mask(error_text, secrets)


def _mask(text: str, secrets: List[str]) -> str:
    spans = []
    for secret in filter(None, secrets):
        start = text.find(secret)
        while start != -1:
            spans.append((start, start + len(secret)))
            start = text.find(secret, start + 1)
        for length in range(len(secret) - 1, _MIN_CUT_SECRET - 1, -1):
            if text.endswith(secret[:length]):
                spans.append((len(text) - length, len(text)))
                break
    if not spans:
        return text
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    out, last = [], 0
    for start, end in merged:
        out += [text[last:start], ("/" if text[start] == "/" else "") + MASK]
        last = end
    return "".join(out + [text[last:]])


def _verify():
    bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE")
    if not bundle:
        return True
    if os.path.isdir(bundle):
        return ssl.create_default_context(capath=bundle)
    return ssl.create_default_context(cafile=bundle)


def _decode(body: bytes, charset: Optional[str]) -> str:
    try:
        codecs.lookup(charset or "utf-8")
    except LookupError:
        charset = None
    return body.decode(charset or "utf-8", errors="replace")


async def _post(url: str, kwargs: Dict) -> Tuple[int, str]:
    headers = {**kwargs.get("headers", {}), "Accept-Encoding": "identity"}
    async with asyncio.timeout(_TOTAL_SECONDS):
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS, follow_redirects=False,
                                     verify=_verify()) as client:
            async with client.stream("POST", url, **{**kwargs, "headers": headers}) as response:
                if 200 <= response.status_code < 400:
                    return response.status_code, ""
                encoding = response.headers.get("content-encoding", "identity").strip().lower()
                if encoding not in ("", "identity"):
                    return response.status_code, ""
                body = bytearray()
                async with contextlib.aclosing(response.aiter_raw()) as chunks:
                    async for chunk in chunks:
                        body.extend(chunk[:_MAX_ERROR_BYTES - len(body)])
                        if len(body) >= _MAX_ERROR_BYTES:
                            break
                return response.status_code, _decode(bytes(body), response.charset_encoding)


def _run(coro):
    loop = asyncio.SelectorEventLoop()
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(_settle())
        finally:
            loop.close()


async def _settle() -> None:
    try:
        async with asyncio.timeout(1):
            await asyncio.get_running_loop().shutdown_asyncgens()
            await asyncio.sleep(0)
            others = asyncio.all_tasks() - {asyncio.current_task()}
            if others:
                await asyncio.wait(others)
    except TimeoutError:
        for task in asyncio.all_tasks() - {asyncio.current_task()}:
            task.cancel()


def send_to_config(channel_type: str, config: Dict, subject: str, message: str) -> Tuple[bool, str]:
    ok, error = validate_config(channel_type, config)
    if not ok:
        return False, error
    try:
        url, kwargs = build_request(channel_type, config, subject, message)
        status, text = _run(_post(url, kwargs))
    except (TimeoutError, httpx.TimeoutException):
        return False, _TOO_SLOW
    except Exception as e:
        return False, _sanitize_error(channel_type, config, str(e) or type(e).__name__)
    if 200 <= status < 300:
        return True, ""
    if 300 <= status < 400:
        return False, (f"HTTP {status}: the server redirected the request, "
                       f"and redirects are not followed. Enter the final URL of the service.")
    return False, f"HTTP {status}: {_sanitize_error(channel_type, config, text)[:200]}"


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
        try:
            ok, error = send_to_config(channel["type"], channel["config"], subject, message)
        except Exception as e:
            logger.error("Notification to '%s' (%s) failed unexpectedly: %s",
                         channel["name"], channel["type"], type(e).__name__)
            ok, error = False, _UNEXPECTED
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
    secrets = SECRET_FIELDS.get(channel_type, set())
    return {
        k: (MASK if (k in secrets and str(v).strip()) else v)
        for k, v in (config or {}).items()
    }


class SecretEndpointChanged(ValueError):
    pass


def _endpoint(channel_type: str, key: str, config: Dict) -> str:
    value = str(config.get(key) or "").strip()
    if not value and channel_type == "ntfy" and key == "server_url":
        value = "https://ntfy.sh"
    return value.rstrip("/")


def merge_config(channel_type: str, existing: Dict, incoming: Dict) -> Dict:
    secrets = SECRET_FIELDS.get(channel_type, set())
    merged = dict(incoming or {})
    existing = existing or {}
    moved = [f for f in CHANNEL_TYPES.get(channel_type, {}).get("fields", [])
             if f["key"] in ("server_url", "url")
             and _endpoint(channel_type, f["key"], merged) != _endpoint(channel_type, f["key"], existing)]
    for key in secrets:
        if merged.get(key) != MASK:
            continue
        stored = existing.get(key, "")
        if moved and str(stored or "").strip():
            label = next(f["label"] for f in CHANNEL_TYPES[channel_type]["fields"] if f["key"] == key)
            raise SecretEndpointChanged(
                f"You changed the {moved[0]['label']}. Enter the {label} again: "
                f"a stored secret is only sent to the server it was entered for.")
        merged[key] = stored
    return merged
