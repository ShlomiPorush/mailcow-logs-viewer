"""
A fake mailcow and Rspamd HTTP API, served in-process.

The demo does not replace MailcowAPI's methods. It hands MailcowAPI an httpx
client whose transport answers from this module instead of the network, so
every request, retry, parse and error path in the application runs exactly
as it does against a real server. Writes change the in-memory state, so a
visitor sees the result of a release, a ban or a rate-limit change until the
nightly reset rebuilds the world.

Log endpoints follow mailcow's Redis-list behaviour: newest first, 1-based
ranges (0-based for rspamd-history), and an empty list past the end.
"""
import asyncio
import copy
import json
import logging
import re
import threading
import time
from urllib.parse import unquote

import httpx

from . import world

logger = logging.getLogger(__name__)

LOG_SERVICES = ("acme", "api", "autodiscover", "dovecot", "netfilter", "postfix",
                "ratelimited", "rspamd-history", "sogo", "watchdog")
# mailcow keeps the newest LOG_LINES entries per service (default 9999)
DEFAULT_LOG_CAP = 10000
# Range requests on rspamd-history start at 0; the Redis lists start at 1
_INDEX_BASE = {"rspamd-history": 0}


def _json(data, status=200):
    return httpx.Response(status, content=json.dumps(data).encode(),
                          headers={"content-type": "application/json"})


def _success(msg):
    return _json([{"type": "success", "log": [], "msg": msg}])


class FakeMailcow:
    """State of the fictional server plus the request router."""

    def __init__(self, now=None, log_cap=DEFAULT_LOG_CAP):
        self._lock = threading.RLock()
        self.log_cap = log_cap
        self.reset(now)
        self._routes = [
            ("GET", re.compile(r"^/api/v1/get/logs/(?P<svc>[a-z-]+)/(?P<spec>\d+(?:-\d+)?)$"), self._get_logs),
            ("GET", re.compile(r"^/api/v1/get/mailq/all$"), self._get_queue),
            ("POST", re.compile(r"^/api/v1/edit/mailq$"), self._edit_queue),
            ("POST", re.compile(r"^/api/v1/delete/mailq$"), self._delete_queue),
            ("GET", re.compile(r"^/api/v1/get/quarantine/all$"), self._get_quarantine),
            ("GET", re.compile(r"^/inc/ajax/qitem_details\.php$"), self._get_qitem_details),
            ("POST", re.compile(r"^/api/v1/edit/qitem$"), self._edit_qitem),
            ("POST", re.compile(r"^/api/v1/delete/qitem$"), self._delete_qitem),
            ("GET", re.compile(r"^/api/v1/get/status/containers$"), self._get_containers),
            ("GET", re.compile(r"^/api/v1/get/status/vmail$"), self._get_vmail),
            ("GET", re.compile(r"^/api/v1/get/status/version$"), self._get_version),
            ("GET", re.compile(r"^/api/v1/get/status/host/ip$"), self._get_host_ip),
            ("GET", re.compile(r"^/api/v1/get/domain/all$"), self._get_domains),
            ("GET", re.compile(r"^/api/v1/get/alias-domain/all$"), self._get_alias_domains),
            ("GET", re.compile(r"^/api/v1/get/mailbox/all$"), self._get_mailboxes),
            ("POST", re.compile(r"^/api/v1/edit/mailbox$"), self._edit_mailbox),
            ("GET", re.compile(r"^/api/v1/get/app-passwd/all/(?P<mailbox>[^/]+)$"), self._get_app_passwords),
            ("POST", re.compile(r"^/api/v1/delete/app-passwd$"), self._delete_app_passwords),
            ("GET", re.compile(r"^/api/v1/get/rl-mbox/(?P<mailbox>[^/]+)$"), self._get_rl_mbox),
            ("GET", re.compile(r"^/api/v1/get/rl-domain/(?P<domain>[^/]+)$"), self._get_rl_domain),
            ("POST", re.compile(r"^/api/v1/edit/rl-mbox/?$"), self._edit_rl_mbox),
            ("POST", re.compile(r"^/api/v1/edit/rl-domain/?$"), self._edit_rl_domain),
            ("POST", re.compile(r"^/api/v1/delete/rlhash$"), self._delete_rlhash),
            ("GET", re.compile(r"^/api/v1/get/alias/all$"), self._get_aliases),
            ("GET", re.compile(r"^/api/v1/get/dkim/(?P<domain>[^/]+)$"), self._get_dkim),
            ("GET", re.compile(r"^/api/v1/get/transport/all$"), self._get_transports),
            ("GET", re.compile(r"^/api/v1/get/relayhost/all$"), self._get_relayhosts),
            ("GET", re.compile(r"^/api/v1/get/fail2ban$"), self._get_fail2ban),
            ("POST", re.compile(r"^/api/v1/edit/fail2ban$"), self._edit_fail2ban),
            ("POST", re.compile(r"^/api/v1/delete/fail2ban$"), self._unban_fail2ban),
            # Rspamd through the mailcow proxy, or direct when RSPAMD_URL is set
            ("GET", re.compile(r"^(?:/rspamd)?/maps$"), self._get_rspamd_maps),
            ("GET", re.compile(r"^(?:/rspamd)?/getmap$"), self._get_rspamd_map),
            ("POST", re.compile(r"^/api/v1/edit/rspamd-map$"), self._edit_rspamd_map),
        ]

    # ------------------------------------------------------------------ state

    def reset(self, now=None):
        """Rebuild the world as it is at ``now`` and drop every log line."""
        now = int(now or time.time())
        with self._lock:
            self.built_at = now
            self.domains = world.build_domains()
            self.alias_domains = copy.deepcopy(world.ALIAS_DOMAINS)
            self.mailboxes = world.build_mailboxes(now)
            self.aliases = world.build_aliases()
            self.queue = world.build_queue(now)
            self.quarantine = world.build_quarantine(now)
            self.containers = world.build_containers(now)
            self.fail2ban = world.build_fail2ban()
            self.app_passwords = world.build_app_passwords()
            self.domain_rate_limits = world.build_domain_rate_limits()
            self.rspamd_maps = {
                filename: {"id": i + 1, "content": content}
                for i, (filename, content) in enumerate(world.RSPAMD_MAPS)
            }
            self.logs = {svc: [] for svc in LOG_SERVICES}

    def push_logs(self, service, entries):
        """Add entries (oldest first) at the head, like Redis LPUSH."""
        if service not in self.logs:
            raise ValueError(f"unknown log service: {service}")
        with self._lock:
            buf = self.logs[service]
            buf[0:0] = list(reversed(entries))
            del buf[self.log_cap:]

    # ---------------------------------------------------------------- routing

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for method, pattern, func in self._routes:
            if request.method != method:
                continue
            match = pattern.match(path)
            if match:
                with self._lock:
                    return func(request, **{k: unquote(v) for k, v in match.groupdict().items()})
        logger.warning(f"[DEMO] Fake mailcow has no answer for {request.method} {path}")
        return _json({"type": "error", "msg": "route not found"}, status=404)

    @staticmethod
    def _body(request):
        try:
            return json.loads(request.content or b"null")
        except ValueError:
            return None

    # ------------------------------------------------------------------- logs

    def _get_logs(self, request, svc, spec):
        buf = self.logs.get(svc)
        if buf is None:
            return _json({"type": "danger", "msg": "unknown log type"})
        if "-" in spec:
            start, end = (int(x) for x in spec.split("-", 1))
            base = _INDEX_BASE.get(svc, 1)
            if end < start:
                return _json([])
            return _json(buf[max(start - base, 0):max(end - base + 1, 0)])
        return _json(buf[:int(spec)])

    # ------------------------------------------------------------------ queue

    def _get_queue(self, request):
        return _json(self.queue)

    def _edit_queue(self, request):
        body = self._body(request) or {}
        items = [str(i) for i in body.get("items", [])]
        action = (body.get("attr") or {}).get("action")
        everything = "mailqitems-all" in items
        if action == "super_delete":
            self.queue = [q for q in self.queue if not everything and q["queue_id"] not in items]
            return _success("Queue deleted")
        if action == "flush":
            # Deferred mail is retried and, in this world, delivered
            self.queue = [q for q in self.queue if q["queue_name"] == "hold"]
            return _success("Queue flushed")
        for q in self.queue:
            if everything or q["queue_id"] in items:
                if action == "hold":
                    q["queue_name"] = "hold"
                elif action == "unhold":
                    q["queue_name"] = "deferred"
        if action == "deliver":
            self.queue = [q for q in self.queue if not (everything or q["queue_id"] in items)]
            return _success("Delivery attempted")
        if action in ("hold", "unhold"):
            return _success("Queue item(s) updated")
        return _json([{"type": "danger", "msg": f"unknown action {action}"}])

    def _delete_queue(self, request):
        items = {str(i) for i in (self._body(request) or [])}
        self.queue = [q for q in self.queue if q["queue_id"] not in items]
        return _success("Queue item(s) deleted")

    # ------------------------------------------------------------- quarantine

    def _get_quarantine(self, request):
        return _json(self.quarantine)

    def _get_qitem_details(self, request):
        item_id = request.url.params.get("id", "")
        for item in self.quarantine:
            if str(item["id"]) == item_id:
                return _json([world.quarantine_details(item)])
        return _json({"type": "danger", "msg": "Item not found"})

    def _edit_qitem(self, request):
        body = self._body(request) or {}
        items = {str(i) for i in body.get("items", [])}
        action = (body.get("attr") or {}).get("action")
        messages = {"release": "Released", "learnham": "Learned as ham and released",
                    "learnspam": "Learned as spam and deleted"}
        if action not in messages:
            return _json([{"type": "danger", "msg": f"unknown action {action}"}])
        self.quarantine = [q for q in self.quarantine if str(q["id"]) not in items]
        return _success(messages[action])

    def _delete_qitem(self, request):
        items = {str(i) for i in (self._body(request) or [])}
        self.quarantine = [q for q in self.quarantine if str(q["id"]) not in items]
        return _success("Deleted")

    # ----------------------------------------------------------------- status

    def _get_containers(self, request):
        return _json([self.containers])

    def _get_vmail(self, request):
        used = sum(m["quota_used"] for m in self.mailboxes)
        total = 200 * world.GiB
        return _json([{"type": "info", "disk": "/dev/sdb1",
                       "used": f"{used / world.GiB:.1f}G", "total": "200G",
                       "used_percent": f"{round(used * 100 / total)}%"}])

    def _get_version(self, request):
        return _json({"version": world.MAILCOW_VERSION})

    def _get_host_ip(self, request):
        return _json([{"ipv4": world.SERVER_IPV4, "ipv6": world.SERVER_IPV6}])

    # ------------------------------------------------ domains, mailboxes, aliases

    def _get_domains(self, request):
        return _json(self.domains)

    def _get_alias_domains(self, request):
        return _json(self.alias_domains or {})

    def _get_mailboxes(self, request):
        return _json(self.mailboxes)

    def _edit_mailbox(self, request):
        body = self._body(request) or {}
        items = set(body.get("items", []))
        attrs = body.get("attr") or {}
        found = False
        for m in self.mailboxes:
            if m["username"] not in items:
                continue
            found = True
            for key, value in attrs.items():
                if key == "active":
                    m["active"] = m["active_int"] = int(value)
                elif key in m["attributes"]:
                    m["attributes"][key] = str(value)
                    if key == "smtp_access":
                        m["smtp_access"] = int(value)
        if not found:
            return _json([{"type": "danger", "msg": "access_denied"}])
        return _success(["mailbox_modified", ", ".join(sorted(items))])

    def _get_aliases(self, request):
        return _json(self.aliases)

    def _get_app_passwords(self, request, mailbox):
        return _json(self.app_passwords.get(mailbox, []))

    def _delete_app_passwords(self, request):
        ids = {str(i) for i in (self._body(request) or [])}
        for mailbox, entries in self.app_passwords.items():
            self.app_passwords[mailbox] = [e for e in entries if str(e["id"]) not in ids]
        return _success("App password(s) deleted")

    def _get_dkim(self, request, domain):
        if not any(d["domain_name"] == domain for d in self.domains):
            return _json([])
        return _json({"dkim_selector": "dkim",
                      "dkim_txt": f"v=DKIM1;k=rsa;t=s;s=email;p={world.DKIM_KEY}",
                      "length": "2048", "pubkey": world.DKIM_KEY})

    def _get_transports(self, request):
        return _json([])

    def _get_relayhosts(self, request):
        return _json([])

    # ------------------------------------------------------------ rate limits

    def _get_rl_mbox(self, request, mailbox):
        for m in self.mailboxes:
            if m["username"] == mailbox and m["rl"]:
                return _json(m["rl"])
        return _json({})

    def _get_rl_domain(self, request, domain):
        return _json(self.domain_rate_limits.get(domain, {}))

    @staticmethod
    def _rl_value(attrs):
        value = str(attrs.get("rl_value", "0"))
        frame = str(attrs.get("rl_frame", "h"))
        return None if value in ("", "0") else {"value": value, "frame": frame}

    def _edit_rl_mbox(self, request):
        body = self._body(request) or {}
        items = set(body.get("items", []))
        limit = self._rl_value(body.get("attr") or {})
        for m in self.mailboxes:
            if m["username"] in items:
                m["rl"] = limit or False
        return _success(["rl_saved", ", ".join(sorted(items))])

    def _edit_rl_domain(self, request):
        body = self._body(request) or {}
        limit = self._rl_value(body.get("attr") or {})
        for domain in body.get("items", []):
            if limit:
                self.domain_rate_limits[domain] = limit
            else:
                self.domain_rate_limits.pop(domain, None)
        return _success(["rl_saved", ", ".join(body.get("items", []))])

    def _delete_rlhash(self, request):
        # mailcow answers an empty JSON body here
        return httpx.Response(200, content=b"", headers={"content-type": "application/json"})

    # --------------------------------------------------------------- fail2ban

    def _get_fail2ban(self, request):
        return _json(self.fail2ban)

    @staticmethod
    def _split_list(value):
        return [v.strip() for v in re.split(r"[,\n]", value or "") if v.strip()]

    def _edit_fail2ban(self, request):
        attrs = (self._body(request) or {}).get("attr") or {}
        f2b = self.fail2ban
        for key in ("ban_time", "max_ban_time", "ban_time_increment", "max_attempts",
                    "retry_window", "netban_ipv4", "netban_ipv6"):
            if key in attrs:
                try:
                    f2b[key] = int(attrs[key])
                except (TypeError, ValueError):
                    return _json([{"type": "danger", "msg": f"invalid value for {key}"}])
        if "whitelist" in attrs:
            f2b["whitelist"] = "\n".join(self._split_list(attrs["whitelist"]))
        if "blacklist" in attrs:
            f2b["blacklist"] = "\n".join(self._split_list(attrs["blacklist"]))
        denied = self._split_list(f2b["blacklist"])
        allowed = set(self._split_list(f2b["whitelist"]))

        def network(entry):
            return entry if "/" in entry else f"{entry}/{f2b['netban_ipv6'] if ':' in entry else 32}"

        f2b["perm_bans"] = [{"network": network(e), "ip": e.split("/", 1)[0]} for e in denied]
        perm = {b["network"] for b in f2b["perm_bans"]}
        temp = [b for b in f2b["active_bans"]
                if b["network"] not in perm and b["banned_until"] != "Forever"
                and b["ip"] not in allowed]
        f2b["active_bans"] = temp + [
            {"network": b["network"], "ip": b["ip"], "banned_until": "Forever", "queued_for_unban": 0}
            for b in f2b["perm_bans"]
        ]
        return _success("Fail2ban settings saved")

    def _unban_fail2ban(self, request):
        ip = ((self._body(request) or {}).get("attr") or {}).get("ip", "")
        before = len(self.fail2ban["active_bans"])
        self.fail2ban["active_bans"] = [b for b in self.fail2ban["active_bans"]
                                        if b["ip"] != ip and b["network"] != ip]
        if len(self.fail2ban["active_bans"]) == before:
            return _json([{"type": "danger", "msg": f"{ip} is not banned"}])
        return _success(f"Unbanned {ip}")

    # ----------------------------------------------------------------- rspamd

    def _get_rspamd_maps(self, request):
        return _json([
            {"map": m["id"], "uri": f"/etc/rspamd/custom/{filename}",
             "description": filename, "editable": True, "loaded": True}
            for filename, m in self.rspamd_maps.items()
        ])

    def _get_rspamd_map(self, request):
        map_id = request.headers.get("map", "")
        for m in self.rspamd_maps.values():
            if str(m["id"]) == map_id:
                return httpx.Response(200, text=m["content"])
        return httpx.Response(404, text="map not found")

    def _edit_rspamd_map(self, request):
        body = self._body(request) or {}
        data = (body.get("attr") or {}).get("rspamd_map_data", "")
        for filename in body.get("items", []):
            if filename not in self.rspamd_maps:
                return _json([{"type": "danger", "msg": f"unknown map {filename}"}])
            self.rspamd_maps[filename]["content"] = data
        return _success(["map_content_saved", ", ".join(body.get("items", []))])


server = FakeMailcow()


def install(fake=server):
    """Route every MailcowAPI request to ``fake`` instead of the network."""
    from app.mailcow_api import MailcowAPI

    transport = httpx.MockTransport(fake.handle)

    def _get_client(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        client = self._clients.get(loop)
        if client is None or client.is_closed:
            client = httpx.AsyncClient(transport=transport, timeout=self.timeout)
            self._clients[loop] = client
        return client

    MailcowAPI._get_client = _get_client
    logger.warning("[DEMO] mailcow and Rspamd answer from the fictional demo server")
