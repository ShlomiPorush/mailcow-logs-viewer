"""
Fictional mail traffic for the demo, as mailcow would log it.

Each generated message is a small scenario (inbound, outbound, internal,
spam, rejected, deferred, bounced) written out as the Postfix, Rspamd and
Dovecot lines mailcow logs for it, in the exact formats the application's
parsers read. Around the messages come the rest of a server's day: NOQUEUE
rejects, brute-force attempts and bans in netfilter, rate-limit hits, and
the quieter services (SOGo, ACME, watchdog, API, autodiscover).

The generator only produces log entries. The fake mailcow server serves
them, and the application ingests them with its own jobs, so every page is
built by the same code as on a real installation.
"""
import random
import time
from dataclasses import dataclass, field

from . import world

DOVECOT_RELAY = "dovecot[172.22.1.250]:24"

SUBJECTS_INBOUND = [
    "Quarterly report draft", "Lunch on Thursday?", "Invoice 2026-0914", "Re: contract renewal",
    "Your order has shipped", "Meeting notes", "Updated price list", "Re: support ticket 4471",
    "Welcome aboard", "Travel itinerary", "Password reset request", "Weekly newsletter",
    "Re: project timeline", "Delivery confirmation", "Conference invitation", "Budget approval",
    # Hebrew and Arabic subjects, so right-to-left rendering shows up in the demo
    "\u05e1\u05d9\u05db\u05d5\u05dd \u05e4\u05d2\u05d9\u05e9\u05d4", "\u05d4\u05e6\u05e2\u05ea \u05de\u05d7\u05d9\u05e8 \u05de\u05e2\u05d5\u05d3\u05db\u05e0\u05ea", "\u062a\u0623\u0643\u064a\u062f \u0627\u0644\u0637\u0644\u0628", "\u062c\u062f\u0648\u0644 \u0627\u0644\u0627\u062c\u062a\u0645\u0627\u0639",
]
SUBJECTS_OUTBOUND = [
    "Re: Quarterly report draft", "Proposal attached", "Order confirmation #{n}", "Re: invoice question",
    "Follow-up from our call", "Your ticket #{n} was updated", "Receipt for your payment",
    "Re: contract renewal", "Shipping update for order #{n}", "Re: \u05e1\u05d9\u05db\u05d5\u05dd \u05e4\u05d2\u05d9\u05e9\u05d4",
]
SUBJECTS_SPAM = [
    "You are our lucky winner!", "Cheap meds, no prescription", "Your account will be suspended",
    "Urgent transfer needed", "Limited offer just for you", "Claim your prize today",
]
REMOTE_PEOPLE = ["jordan", "mia", "sam", "noah", "lena", "omar", "yuki", "ines", "accounts", "sales", "info"]


@dataclass
class Batch:
    """Entries per mailcow log service, in the order they were written."""
    logs: dict = field(default_factory=lambda: {svc: [] for svc in (
        "postfix", "rspamd-history", "dovecot", "netfilter", "ratelimited",
        "sogo", "acme", "watchdog", "api", "autodiscover")})

    def add(self, service, entry):
        self.logs[service].append(entry)


class Traffic:
    """Deterministic for a given seed, so a reset rebuilds the same week."""

    def __init__(self, seed=None):
        self.rng = random.Random(seed)
        self._future = {}
        self._qids = set()
        self._order = 1000

    # ---------------------------------------------------------------- helpers

    def qid(self):
        while True:
            q = "".join(self.rng.choice("0123456789ABCDEF") for _ in range(10))
            if q[0] != "0" and q not in self._qids:
                self._qids.add(q)
                return q

    @staticmethod
    def _postfix(batch, t, program, message, priority="info"):
        batch.add("postfix", {"time": str(int(t)), "program": program, "priority": priority, "message": message})

    def _mailbox(self, domain=None):
        boxes = [m for m in world.MAILBOXES if m[1] == domain] if domain else world.MAILBOXES
        local, dom, *_ = self.rng.choice(boxes)
        return world.address(local, dom)

    def _active_mailbox(self):
        while True:
            box = self._mailbox()
            if box not in world.INACTIVE_MAILBOXES and not box.startswith(("noreply@", "orders@")):
                return box

    def _remote(self):
        i = self.rng.randrange(len(world.REMOTE_DOMAINS))
        return (f"{self.rng.choice(REMOTE_PEOPLE)}@{world.REMOTE_DOMAINS[i]}",
                world.REMOTE_DOMAINS[i], world.REMOTE_IPS[i % len(world.REMOTE_IPS)])

    def _subject(self, pool):
        self._order += self.rng.randint(1, 7)
        return self.rng.choice(pool).replace("{n}", str(self._order))

    def _message_id(self, t, qid, domain):
        return f"{time.strftime('%Y%m%d%H%M%S', time.gmtime(t))}.{qid}@{domain}"

    @staticmethod
    def _symbol(name, score, options=(), description=None):
        sym = {"name": name, "score": score, "metric_score": score, "options": list(options)}
        if description:
            sym["description"] = description
        return {name: sym}

    def _symbols(self, kind, sender_domain, user=None):
        s = {}
        if kind == "ham":
            s.update(self._symbol("BAYES_HAM", -round(self.rng.uniform(1.5, 3.0), 2), ["99.0%"], "Message probably ham"))
            s.update(self._symbol("R_SPF_ALLOW", -0.2, ["+ip4"], "SPF verification allows sending"))
            s.update(self._symbol("R_DKIM_ALLOW", -0.2, [f"{sender_domain}:s=dkim"], "DKIM verification succeed"))
            s.update(self._symbol("DMARC_POLICY_ALLOW", -0.5, [sender_domain, "reject"], "DMARC permit policy"))
            s.update(self._symbol("MIME_GOOD", -0.1, ["text/plain"]))
        elif kind == "spam":
            s.update(self._symbol("BAYES_SPAM", round(self.rng.uniform(3.0, 5.1), 2), ["99.8%"], "Message probably spam"))
            s.update(self._symbol("R_SPF_SOFTFAIL", 0.6, ["~all"]))
            s.update(self._symbol("MIME_HTML_ONLY", 0.2))
            s.update(self._symbol("FROM_NEQ_ENVFROM", 0.5))
            s.update(self._symbol("RBL_SPAMHAUS_SBL", round(self.rng.uniform(2.0, 4.0), 1), ["203.0.113.66:from"]))
        elif kind == "reject":
            s.update(self._symbol("BAYES_SPAM", 5.1, ["100.0%"], "Message probably spam"))
            s.update(self._symbol("PHISHING", 4.5, [sender_domain], "Phished URL"))
            s.update(self._symbol("R_SPF_FAIL", 1.0, ["-all"]))
            s.update(self._symbol("DMARC_POLICY_REJECT", 2.0, [sender_domain, "reject"]))
            s.update(self._symbol("RBL_SPAMHAUS_ZEN", 6.0, ["203.0.113.77:from"]))
        if user:
            s.update(self._symbol("MAILCOW_AUTH", -20.0, [user], "mailcow authenticated"))
        return s

    def _rspamd(self, batch, t, mid, sender, rcpts, subject, ip, user, action, score, symbols, size, qid):
        batch.add("rspamd-history", {
            "message-id": mid, "qid": qid, "unix_time": int(t),
            "time_real": round(self.rng.uniform(0.05, 0.9), 3), "time_virtual": 0.02,
            "ip": ip, "user": user or "unknown",
            "sender_smtp": sender, "sender_mime": sender,
            "rcpt_smtp": list(rcpts), "rcpt_mime": list(rcpts),
            "subject": subject, "size": size, "action": action, "score": score,
            "required_score": 15, "is_skipped": False,
            "thresholds": {"reject": 15, "add header": 8, "rewrite subject": 12, "greylist": 7},
            "symbols": symbols,
        })

    def _dovecot(self, batch, t, rcpt, mid, folder="INBOX", verdict=None):
        session = "".join(self.rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
                          for _ in range(22))
        pid = self.rng.randint(100000, 999999)
        rest = verdict or f"stored mail into mailbox '{folder}'"
        batch.add("dovecot", {"time": str(int(t)), "program": "dovecot", "priority": "info",
                              "message": f"lmtp({rcpt})<{pid}><{session}>: sieve: msgid=<{mid}>: {rest}"})

    # -------------------------------------------------------------- scenarios

    def inbound(self, batch, t, kind="ham"):
        sender, sdomain, ip = self._remote()
        if kind != "ham":
            i = self.rng.randrange(len(world.SPAM_DOMAINS))
            sdomain, ip = world.SPAM_DOMAINS[i], world.SPAM_IPS[i]
            sender = f"{self.rng.choice(['promo', 'offers', 'security', 'billing'])}@{sdomain}"
        rcpt = self._active_mailbox()
        qid = self.qid()
        mid = self._message_id(t, qid, sdomain)
        subject = self._subject(SUBJECTS_INBOUND if kind == "ham" else SUBJECTS_SPAM)
        size = self.rng.randint(3_000, 400_000)
        host = f"mx.{sdomain}"
        self._postfix(batch, t, "postfix/smtpd", f"connect from {host}[{ip}]")
        self._postfix(batch, t, "postfix/smtpd", f"{qid}: client={host}[{ip}]")
        self._postfix(batch, t + 1, "postfix/cleanup", f"{qid}: message-id=<{mid}>")
        if kind == "reject":
            score = round(self.rng.uniform(16, 32), 2)
            self._rspamd(batch, t + 1, mid, sender, [rcpt], subject, ip, None, "reject", score,
                         self._symbols("reject", sdomain), size, qid)
            self._postfix(batch, t + 1, "postfix/cleanup",
                          f"{qid}: milter-reject: END-OF-MESSAGE from {host}[{ip}]: 5.7.1 Spam message rejected; "
                          f"from=<{sender}> to=<{rcpt}> proto=ESMTP helo=<{host}>")
            self._postfix(batch, t + 2, "postfix/smtpd", f"disconnect from {host}[{ip}] ehlo=1 mail=1 rcpt=1 data=0/1 quit=1 commands=4/5")
            return
        spam = kind == "spam"
        score = round(self.rng.uniform(8.5, 14.0), 2) if spam else round(self.rng.uniform(-4.0, 2.5), 2)
        self._postfix(batch, t + 1, "postfix/qmgr", f"{qid}: from=<{sender}>, size={size}, nrcpt=1 (queue active)")
        self._rspamd(batch, t + 1, mid, sender, [rcpt], subject, ip, None,
                     "add header" if spam else "no action", score,
                     self._symbols("spam" if spam else "ham", sdomain), size, qid)
        delay = round(self.rng.uniform(0.2, 1.8), 2)
        self._postfix(batch, t + 2, "postfix/lmtp",
                      f"{qid}: to=<{rcpt}>, relay={DOVECOT_RELAY}, delay={delay}, delays=0.1/0.01/0.01/{delay - 0.12:.2f}, "
                      f"dsn=2.0.0, status=sent (250 2.0.0 <{rcpt}> {qid[:6]}AAAA Saved)")
        self._postfix(batch, t + 2, "postfix/qmgr", f"{qid}: removed")
        self._postfix(batch, t + 2, "postfix/smtpd", f"disconnect from {host}[{ip}] ehlo=2 starttls=1 mail=1 rcpt=1 data=1 quit=1 commands=7")
        self._dovecot(batch, t + 2, rcpt, mid, "Junk" if spam else "INBOX")

    def outbound(self, batch, t, outcome="sent"):
        user = self._active_mailbox()
        client = self.rng.choice(world.CLIENT_IPS)
        rcpt, rdomain, rip = self._remote()
        qid = self.qid()
        mid = self._message_id(t, qid, user.split("@", 1)[1])
        subject = self._subject(SUBJECTS_OUTBOUND)
        size = self.rng.randint(2_000, 900_000)
        self._postfix(batch, t, "postfix/submission/smtpd", f"connect from unknown[{client}]")
        self._postfix(batch, t, "postfix/submission/smtpd",
                      f"{qid}: client=unknown[{client}], sasl_method=PLAIN, sasl_username={user}")
        self._postfix(batch, t + 1, "postfix/cleanup", f"{qid}: message-id=<{mid}>")
        self._postfix(batch, t + 1, "postfix/qmgr", f"{qid}: from=<{user}>, size={size}, nrcpt=1 (queue active)")
        self._rspamd(batch, t + 1, mid, user, [rcpt], subject, client, user, "no action",
                     round(self.rng.uniform(-22.0, -17.0), 2), self._symbols("ham", rdomain, user=user), size, qid)
        relay = f"mx.{rdomain}[{rip}]:25"
        if outcome in ("deferred", "deferred_pending"):
            self._postfix(batch, t + 3, "postfix/smtp",
                          f"{qid}: to=<{rcpt}>, relay={relay}, delay=2.1, delays=0.1/0/0.9/1.1, dsn=4.7.1, "
                          f"status=deferred (host mx.{rdomain}[{rip}] said: 450 4.7.1 Greylisted, please try again later "
                          f"(in reply to RCPT TO command))")
            if outcome == "deferred_pending":
                return
            t += self.rng.randint(300, 900)
        if outcome == "bounced":
            self._postfix(batch, t + 3, "postfix/smtp",
                          f"{qid}: to=<{rcpt}>, relay={relay}, delay=1.4, delays=0.1/0/0.6/0.7, dsn=5.1.1, "
                          f"status=bounced (host mx.{rdomain}[{rip}] said: 550 5.1.1 <{rcpt}>: Recipient address "
                          f"rejected: User unknown (in reply to RCPT TO command))")
            ndr = self.qid()
            self._postfix(batch, t + 3, "postfix/bounce", f"{qid}: sender non-delivery notification: {ndr}")
            self._postfix(batch, t + 3, "postfix/qmgr", f"{ndr}: from=<>, size={size // 10 + 2000}, nrcpt=1 (queue active)")
            self._postfix(batch, t + 4, "postfix/lmtp",
                          f"{ndr}: to=<{user}>, relay={DOVECOT_RELAY}, delay=0.3, delays=0.1/0/0/0.2, dsn=2.0.0, "
                          f"status=sent (250 2.0.0 <{user}> {ndr[:6]}AAAA Saved)")
            self._postfix(batch, t + 4, "postfix/qmgr", f"{ndr}: removed")
        else:
            delay = round(self.rng.uniform(0.6, 3.5), 1)
            self._postfix(batch, t + 3, "postfix/smtp",
                          f"{qid}: to=<{rcpt}>, relay={relay}, delay={delay}, delays=0.1/0/0.4/{delay - 0.5:.1f}, "
                          f"dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as {self.qid()})")
        self._postfix(batch, t + 4, "postfix/qmgr", f"{qid}: removed")
        self._postfix(batch, t + 4, "postfix/submission/smtpd", f"disconnect from unknown[{client}] ehlo=2 starttls=1 auth=1 mail=1 rcpt=1 data=1 quit=1 commands=8")

    def internal(self, batch, t):
        user = self._active_mailbox()
        rcpt = self._active_mailbox()
        while rcpt == user:
            rcpt = self._active_mailbox()
        client = self.rng.choice(world.CLIENT_IPS)
        qid = self.qid()
        mid = self._message_id(t, qid, user.split("@", 1)[1])
        subject = self._subject(SUBJECTS_OUTBOUND)
        size = self.rng.randint(2_000, 200_000)
        self._postfix(batch, t, "postfix/submission/smtpd",
                      f"{qid}: client=unknown[{client}], sasl_method=PLAIN, sasl_username={user}")
        self._postfix(batch, t + 1, "postfix/cleanup", f"{qid}: message-id=<{mid}>")
        self._postfix(batch, t + 1, "postfix/qmgr", f"{qid}: from=<{user}>, size={size}, nrcpt=1 (queue active)")
        self._rspamd(batch, t + 1, mid, user, [rcpt], subject, client, user, "no action",
                     round(self.rng.uniform(-21.0, -18.0), 2), self._symbols("ham", user.split("@", 1)[1], user=user),
                     size, qid)
        self._postfix(batch, t + 2, "postfix/lmtp",
                      f"{qid}: to=<{rcpt}>, relay={DOVECOT_RELAY}, delay=0.3, delays=0.1/0/0/0.2, dsn=2.0.0, "
                      f"status=sent (250 2.0.0 <{rcpt}> {qid[:6]}AAAA Saved)")
        self._postfix(batch, t + 2, "postfix/qmgr", f"{qid}: removed")
        self._dovecot(batch, t + 2, rcpt, mid)

    def noqueue(self, batch, t):
        ip = self.rng.choice(world.SPAM_IPS + world.ATTACKER_IPS)
        sender = f"{self.rng.choice(['a', 'x', 'news', 'promo'])}@{self.rng.choice(world.SPAM_DOMAINS)}"
        kind = self.rng.random()
        if kind < 0.4:
            rcpt = f"ghost{self.rng.randint(1, 99)}@example.com"
            reason = f"550 5.1.1 <{rcpt}>: Recipient address rejected: User unknown in virtual mailbox table"
        elif kind < 0.7:
            rcpt = self._mailbox()
            reason = f"554 5.7.1 Service unavailable; Client host [{ip}] blocked using zen.spamhaus.org"
        else:
            rcpt = f"someone@{self.rng.choice(world.REMOTE_DOMAINS)}"
            reason = f"554 5.7.1 <{rcpt}>: Relay access denied"
        self._postfix(batch, t, "postfix/postscreen", f"CONNECT from [{ip}]:{self.rng.randint(30000, 65000)} to [{world.SERVER_IPV4}]:25")
        self._postfix(batch, t + 1, "postfix/smtpd",
                      f"NOQUEUE: reject: RCPT from unknown[{ip}]: {reason}; from=<{sender}> to=<{rcpt}> proto=ESMTP helo=<bot>")

    def brute_force(self, batch, t):
        ip = self.rng.choice(world.ATTACKER_IPS)
        target = self.rng.choice(["admin@example.com", "info@example.com", "alice@example.com", "test@example.org"])
        attempts = self.rng.randint(3, 10)
        for i in range(attempts):
            ts = t + i * self.rng.randint(4, 40)
            if self.rng.random() < 0.7:
                msg = (f"{ip} matched rule id 3 (warning: unknown[{ip}]: SASL LOGIN authentication failed: "
                       f"UGFzc3dvcmQ6, sasl_username={target})")
            else:
                msg = (f"{ip} matched rule id 1 (imap-login: Disconnected (auth failed, 1 attempts in 2 secs): "
                       f"user=<{target}>, method=PLAIN, rip={ip}, lip=172.22.1.250, TLS)")
            batch.add("netfilter", {"time": int(ts), "priority": "warn", "message": msg})
            left = max(10 - (i + 1), 0)
            if left and i == attempts - 1:
                batch.add("netfilter", {"time": int(ts), "priority": "warn",
                                        "message": f"{left} more attempts in the next 600 seconds until {ip}/32 is banned"})
        if attempts >= 8:
            ts = t + attempts * 45
            batch.add("netfilter", {"time": int(ts), "priority": "crit", "message": f"Banning {ip}/32 for 1800 seconds"})
            batch.add("netfilter", {"time": int(ts + 1800), "priority": "info", "message": f"Unbanning {ip}/32"})

    def connection_noise(self, batch, t):
        """A connection that never becomes a message: a scanner or a sender
        that postscreen lets through and that hangs up."""
        ip = self.rng.choice(world.REMOTE_IPS + world.SPAM_IPS + world.ATTACKER_IPS)
        port = self.rng.randint(30000, 65000)
        self._postfix(batch, t, "postfix/postscreen", f"CONNECT from [{ip}]:{port} to [{world.SERVER_IPV4}]:25")
        verdict = self.rng.choice(["PASS OLD", "PASS NEW", "DNSBL rank 3 for"])
        self._postfix(batch, t + 1, "postfix/postscreen", f"{verdict} [{ip}]:{port}")
        if verdict.startswith("PASS"):
            self._postfix(batch, t + 1, "postfix/smtpd", f"connect from unknown[{ip}]")
            self._postfix(batch, t + 3, "postfix/smtpd",
                          f"disconnect from unknown[{ip}] ehlo=1 quit=1 commands=2")
        else:
            self._postfix(batch, t + 2, "postfix/postscreen", f"DISCONNECT [{ip}]:{port}")

    def credential_attack(self, batch, t):
        """A distributed password-guessing run against one account, large
        enough for the anomaly detector's auth-failure burst alert."""
        target = "admin@example.com"
        for i in range(26):
            ip = world.ATTACKER_IPS[i % len(world.ATTACKER_IPS)]
            batch.add("netfilter", {"time": int(t + i * 17), "priority": "warn", "message": (
                f"{ip} matched rule id 3 (warning: unknown[{ip}]: SASL LOGIN authentication failed: "
                f"UGFzc3dvcmQ6, sasl_username={target})")})

    def rate_limited(self, batch, t):
        user = self.rng.choice(["billing@example.com", "orders@shop.test", "alice@example.com"])
        rcpt, _, _ = self._remote()
        qid = self.qid()
        batch.add("ratelimited", {
            "time": str(int(t)), "user": user, "from": user, "rcpt": rcpt,
            "header_subject": self._subject(SUBJECTS_OUTBOUND), "qid": qid,
            "rl_hash": "RL" + "".join(self.rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12)),
            "rl_name": user, "rl_info": "mailbox", "message_id": self._message_id(t, qid, user.split("@", 1)[1]),
            "ip": self.rng.choice(world.CLIENT_IPS),
        })

    def background_services(self, batch, hour_start):
        """One hour of the quieter services."""
        t = hour_start
        for service in ("Postfix", "Dovecot", "Rspamd", "Unbound"):
            batch.add("watchdog", {"time": str(int(t + self.rng.randint(0, 300))), "service": service,
                                   "lvl": "100", "hpnow": "10", "hptotal": "10", "hpdiff": "0"})
        for _ in range(self.rng.randint(0, 3)):
            user = self._active_mailbox()
            batch.add("sogo", {"time": str(int(t + self.rng.randint(0, 3599))), "program": "sogod", "priority": "info",
                               "message": f'{self.rng.choice(world.CLIENT_IPS)} "POST /SOGo/so/{user}/Mail/0/folderINBOX/changes HTTP/1.1" 200 312/64 0.041 - - 0'})
        batch.add("api", {"time": str(int(t + self.rng.randint(0, 3599))), "uri": "/api/v1/get/logs/postfix/2000",
                          "method": "GET", "remote": "172.22.1.1", "data": ""})
        if self.rng.random() < 0.2:
            batch.add("autodiscover", {"time": str(int(t + self.rng.randint(0, 3599))), "program": "autodiscover",
                                       "priority": "info", "message": f"{self._active_mailbox()} autodiscover request (activesync)"})
        if time.localtime(t).tm_hour == 3:
            batch.add("acme", {"time": str(int(t + 60)), "program": "acme", "priority": "info",
                               "message": f"Certificate {world.MAIL_HOST} is valid for 57 more days, not renewing"})

    # ------------------------------------------------------------------ rates

    @staticmethod
    def _hour_weight(t):
        tm = time.localtime(t)
        workday = tm.tm_wday < 5
        curve = [0.2, 0.15, 0.1, 0.1, 0.15, 0.3, 0.6, 1.0, 1.5, 1.9, 2.0, 1.9,
                 1.6, 1.8, 1.9, 1.8, 1.5, 1.2, 0.9, 0.7, 0.6, 0.5, 0.4, 0.3]
        return curve[tm.tm_hour] * (1.0 if workday else 0.45)

    def generate(self, start, end, per_hour=6.0, min_weight=0.0, noise_per_minute=0.0):
        """Traffic that happens in [start, end).

        Rates are per hour and scaled to the part of each hour inside the
        window, so a one-minute window of the live trickle gets a minute's
        worth. Lines a scenario writes after ``end`` (a retry, an unban) are
        held back and returned by the call whose window reaches them, so no
        line ever carries a future time. ``per_hour`` is half the busiest
        weekday hour's message count; a weekday lands near 150 messages.
        The live trickle raises the quiet
        hours with ``min_weight`` and adds connection noise every minute, so
        a visitor from any time zone sees the server working.
        """
        batch = Batch()
        self._end = end
        hour = int(start) - int(start) % 3600
        while hour < end:
            lo, hi = max(hour, start), min(hour + 3600, end)
            frac = (hi - lo) / 3600
            weight = max(self._hour_weight(hour), min_weight)

            def when():
                return self.rng.uniform(lo, hi)

            if hour >= start:
                self.background_services(batch, hour)
            for _ in range(self._poisson(per_hour * weight * frac)):
                self.message(batch, when())
            for _ in range(self._poisson(1.2 * weight * frac)):
                self.noqueue(batch, when())
            if self.rng.random() < 0.25 * frac:
                self.brute_force(batch, when())
            if self.rng.random() < 0.2 * weight * frac:
                self.rate_limited(batch, when())
            for _ in range(self._poisson(noise_per_minute * 60 * frac)):
                self.connection_noise(batch, when())
            hour += 3600
        if end - start > 86400:
            # History ends with an attack still in progress
            self.credential_attack(batch, end - 480)
        return self._release(batch, end)

    def _release(self, batch, end):
        """Entries before ``end``, oldest first; later ones wait for their time."""
        key = {"rspamd-history": "unix_time"}
        ready = {}
        for svc, entries in batch.logs.items():
            entries = self._future.pop(svc, []) + entries
            k = key.get(svc, "time")
            now_entries = [e for e in entries if int(e[k]) < end]
            later = [e for e in entries if int(e[k]) >= end]
            if later:
                self._future[svc] = later
            now_entries.sort(key=lambda e: int(e[k]))
            ready[svc] = now_entries
        return ready

    def message(self, batch, t):
        r = self.rng.random()
        if r < 0.44:
            self.inbound(batch, t)
        elif r < 0.68:
            self.outbound(batch, t)
        elif r < 0.76:
            self.internal(batch, t)
        elif r < 0.84:
            self.inbound(batch, t, "spam")
        elif r < 0.91:
            self.inbound(batch, t, "reject")
        elif r < 0.96:
            # A recent deferral is still waiting for its retry, as in the mail queue
            recent = t > getattr(self, "_end", t + 1) - 3 * 3600
            self.outbound(batch, t, "deferred_pending" if recent else "deferred")
        else:
            self.outbound(batch, t, "bounced")

    def _poisson(self, lam):
        # Knuth; lam stays small here
        import math
        threshold, k, p = math.exp(-lam), 0, 1.0
        while True:
            p *= self.rng.random()
            if p <= threshold:
                return k
            k += 1
