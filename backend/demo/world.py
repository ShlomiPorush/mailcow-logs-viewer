"""
The fictional mail server the demo shows.

Everything here is invented: domains are reserved example names (RFC 2606)
or under the .test TLD, and every IP address is from the documentation
ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24; RFC 3849:
2001:db8::/32). Times are relative to the moment the world is built, so a
freshly reset demo always looks current.
"""
import time

GiB = 1024 ** 3
MiB = 1024 ** 2

SERVER_IPV4 = "203.0.113.10"
SERVER_IPV6 = "2001:db8::10"
MAIL_HOST = "mail.example.com"

# Hosted domains. example.net is an alias domain of example.com.
DOMAINS = [
    {"domain": "example.com", "active": 1, "max_mboxes": 50, "max_aliases": 400, "max_quota": 200 * GiB,
     "created": "2023-03-14 09:12:00", "backupmx": 0},
    {"domain": "example.org", "active": 1, "max_mboxes": 20, "max_aliases": 100, "max_quota": 50 * GiB,
     "created": "2024-06-02 16:40:00", "backupmx": 0},
    {"domain": "shop.test", "active": 1, "max_mboxes": 10, "max_aliases": 50, "max_quota": 20 * GiB,
     "created": "2025-01-20 11:05:00", "backupmx": 0},
    {"domain": "old-brand.test", "active": 0, "max_mboxes": 5, "max_aliases": 20, "max_quota": 5 * GiB,
     "created": "2021-11-08 08:00:00", "backupmx": 0},
]

ALIAS_DOMAINS = [
    {"alias_domain": "example.net", "target_domain": "example.com", "active": 1},
]

# (local part, domain, display name, quota GiB, used MiB, messages, rate limit per hour or None)
MAILBOXES = [
    ("alice", "example.com", "Alice Moreau", 10, 3480, 12840, 200),
    ("bob", "example.com", "Bob Tanaka", 10, 1210, 5320, None),
    ("carol", "example.com", "Carol Nguyen", 5, 4610, 20110, None),
    ("dave", "example.com", "Dave Okafor", 5, 820, 2210, None),
    ("erin", "example.com", "Erin Lindqvist", 5, 2290, 8640, None),
    ("frank", "example.com", "Frank Rossi", 5, 150, 640, None),
    ("billing", "example.com", "Billing", 2, 530, 3100, 500),
    ("noreply", "example.com", "No Reply", 1, 12, 40, 1000),
    ("grace", "example.org", "Grace Haddad", 10, 5020, 16400, None),
    ("heidi", "example.org", "Heidi Novak", 5, 740, 2980, None),
    ("ivan", "example.org", "Ivan Petrov", 5, 95, 310, None),
    ("orders", "shop.test", "Shop Orders", 5, 1880, 9420, 300),
    ("support", "shop.test", "Shop Support", 5, 960, 4150, None),
]

# Accounts without SMTP access or disabled, so badges vary
INACTIVE_MAILBOXES = {"ivan@example.org"}
NO_POP3 = {"alice@example.com", "bob@example.com", "carol@example.com", "grace@example.org"}

ALIASES = [
    ("sales@example.com", "alice@example.com,bob@example.com"),
    ("info@example.com", "alice@example.com"),
    ("hr@example.com", "erin@example.com"),
    ("postmaster@example.com", "alice@example.com"),
    ("abuse@example.com", "alice@example.com"),
    ("dmarc@example.com", "alice@example.com"),
    ("info@example.org", "grace@example.org"),
    ("team@example.org", "grace@example.org,heidi@example.org,ivan@example.org"),
    ("hello@shop.test", "support@shop.test"),
]
CATCH_ALL = ("@shop.test", "support@shop.test")

# Partners and senders on the internet the demo server talks to
REMOTE_DOMAINS = ["partner.test", "supplier.test", "customer-mail.test", "bank.test",
                  "travel.test", "news.test", "cloud-tools.test", "university.test"]
SPAM_DOMAINS = ["bulk-offers.test", "prize-center.test", "secure-login.test", "cheap-meds.test"]

REMOTE_IPS = ["198.51.100.21", "198.51.100.34", "198.51.100.47", "198.51.100.58",
              "192.0.2.61", "192.0.2.72", "192.0.2.83", "192.0.2.94"]
SPAM_IPS = ["203.0.113.66", "203.0.113.77", "203.0.113.88", "203.0.113.99"]
ATTACKER_IPS = ["203.0.113.5", "203.0.113.45", "198.51.100.200", "192.0.2.150", "192.0.2.201"]
CLIENT_IPS = ["192.0.2.10", "192.0.2.11", "198.51.100.12", "198.51.100.13"]

CONTAINERS = ["acme", "clamd", "dockerapi", "dovecot", "memcached", "mysql", "netfilter",
              "nginx", "ofelia", "olefy", "php-fpm", "postfix", "redis", "rspamd", "sogo",
              "solr", "unbound", "watchdog"]

MAILCOW_VERSION = "2026-08"

# Deterministic, obviously fake key material (not a real RSA key)
DKIM_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAdemoDEMOdemoDEMOdemoDEMOdemoDEMOdemoDEMOdemoKEY0AQAB"

RSPAMD_MAPS = [
    ("global_mime_from_blacklist.map", "# Header-From denylist\n@prize-center.test\n@cheap-meds.test\n"),
    ("global_mime_from_whitelist.map", "# Header-From allowlist\n@partner.test\nstatements@bank.test\n"),
    ("global_smtp_from_blacklist.map", "# Envelope sender denylist\n@bulk-offers.test\n"),
    ("global_smtp_from_whitelist.map", "# Envelope sender allowlist\n@supplier.test\n"),
    ("global_rcpt_blacklist.map", "# Recipient denylist\n"),
    ("global_rcpt_whitelist.map", "# Recipient allowlist\npostmaster@example.com\nabuse@example.com\n"),
    ("fishy_tlds.map", "/\\.test$/i\n/\\.invalid$/i\n"),
    ("bad_words.map", "/\\bprize\\b/i\n/\\bwinner\\b/i\n/\\burgent transfer\\b/i\n"),
    ("bad_words_de.map", "/\\bgewinner\\b/i\n"),
    ("bad_languages.map", ""),
    ("bulk_header.map", "/^X-Mailer: MassMailer/i\n"),
    ("bad_header.map", "/^X-Spam-Tool:/i\n"),
    ("monitoring_nolog.map", "# Hosts excluded from logging\n192.0.2.250\n"),
]


def address(local, domain):
    return f"{local}@{domain}"


def mailbox_addresses():
    return [address(local, domain) for local, domain, *_ in MAILBOXES]


def build_domains():
    by_domain = {}
    for local, domain, _, quota_gib, used_mib, messages, _ in MAILBOXES:
        entry = by_domain.setdefault(domain, {"count": 0, "bytes": 0, "msgs": 0})
        entry["count"] += 1
        entry["bytes"] += used_mib * MiB
        entry["msgs"] += messages
    aliases_by_domain = {}
    for alias, _ in ALIASES:
        dom = alias.split("@", 1)[1]
        aliases_by_domain[dom] = aliases_by_domain.get(dom, 0) + 1

    result = []
    for d in DOMAINS:
        stats = by_domain.get(d["domain"], {"count": 0, "bytes": 0, "msgs": 0})
        aliases = aliases_by_domain.get(d["domain"], 0)
        result.append({
            "domain_name": d["domain"],
            "active": d["active"],
            "mboxes_in_domain": stats["count"],
            "mboxes_left": d["max_mboxes"] - stats["count"],
            "max_num_mboxes_for_domain": d["max_mboxes"],
            "aliases_in_domain": aliases,
            "aliases_left": d["max_aliases"] - aliases,
            "max_num_aliases_for_domain": d["max_aliases"],
            "created": d["created"],
            "bytes_total": stats["bytes"],
            "msgs_total": stats["msgs"],
            "quota_used_in_domain": str(stats["bytes"]),
            "max_quota_for_domain": d["max_quota"],
            "backupmx": d["backupmx"],
            "relay_all_recipients": 0,
            "relay_unknown_only": 0,
        })
    return result


def build_mailboxes(now=None):
    now = int(now or time.time())
    result = []
    for i, (local, domain, name, quota_gib, used_mib, messages, rl) in enumerate(MAILBOXES):
        username = address(local, domain)
        quota = quota_gib * GiB
        used = used_mib * MiB
        active = 0 if username in INACTIVE_MAILBOXES else 1
        # Staggered, recent logins; service accounts never log in over IMAP
        service_account = local in ("noreply", "billing", "orders")
        last_imap = 0 if service_account or not active else now - (i * 1370 + 600)
        last_smtp = 0 if not active else now - (i * 911 + 120)
        result.append({
            "username": username,
            "name": name,
            "domain": domain,
            "local_part": local,
            "active": active,
            "active_int": active,
            "quota": quota,
            "quota_used": used,
            "percent_in_use": round(used * 100 / quota) if quota else 0,
            "messages": messages,
            "last_imap_login": last_imap,
            "last_pop3_login": 0,
            "last_smtp_login": last_smtp,
            "spam_aliases": 1 if local in ("alice", "grace") else 0,
            "rl": {"value": str(rl), "frame": "h"} if rl else False,
            "smtp_access": 1,
            "attributes": {
                "imap_access": "1",
                "pop3_access": "0" if username in NO_POP3 else "1",
                "smtp_access": "1",
                "sieve_access": "1",
                "sogo_access": "1",
                "tls_enforce_in": "1" if domain == "example.com" else "0",
                "tls_enforce_out": "0",
            },
        })
    return result


def build_aliases():
    result = [{"id": i + 1, "address": a, "goto": goto, "active": 1, "is_catch_all": 0}
              for i, (a, goto) in enumerate(ALIASES)]
    result.append({"id": len(result) + 1, "address": CATCH_ALL[0], "goto": CATCH_ALL[1],
                   "active": 1, "is_catch_all": 1})
    return result


def build_queue(now=None):
    # Recipients are outside the generated traffic's address pool: a bounce in
    # the history would otherwise suppress them, and the suppression cleanup
    # would delete these queue items before a visitor sees them.
    now = int(now or time.time())
    return [
        {"queue_name": "deferred", "queue_id": "4Qd7Kx2Lm9", "arrival_time": now - 5 * 3600,
         "message_size": 48213, "sender": "alice@example.com",
         "recipients": ["jordan.lee@customer-mail.test (connect to mx.customer-mail.test[198.51.100.34]:25: Connection timed out)"]},
        {"queue_name": "deferred", "queue_id": "4Qd8Pz5Rt1", "arrival_time": now - 2 * 3600,
         "message_size": 15320, "sender": "billing@example.com",
         "recipients": ["accounts-payable@travel.test (host mx.travel.test[192.0.2.72] said: 452 4.2.2 Mailbox full)"]},
        {"queue_name": "deferred", "queue_id": "4Qd9Wv3Hs6", "arrival_time": now - 40 * 60,
         "message_size": 9120, "sender": "orders@shop.test",
         "recipients": ["mia.chen@university.test (host mx.university.test[198.51.100.58] said: 421 4.7.0 Try again later)"]},
        {"queue_name": "hold", "queue_id": "4QdAYn8Ce2", "arrival_time": now - 26 * 3600,
         "message_size": 212044, "sender": "frank@example.com",
         "recipients": ["all-staff@partner.test"]},
        {"queue_name": "active", "queue_id": "4QdBJm1Uf4", "arrival_time": now - 20,
         "message_size": 6620, "sender": "noreply@example.com",
         "recipients": ["sam.ortiz@cloud-tools.test"]},
    ]


def build_quarantine(now=None):
    now = int(now or time.time())
    items = [
        ("Your account will be suspended today", "security@secure-login.test", "alice@example.com", 19.4, "reject", 0, 3),
        ("You are our lucky winner!", "promo@prize-center.test", "bob@example.com", 17.2, "reject", 0, 9),
        ("Invoice 88213 overdue", "billing@bulk-offers.test", "billing@example.com", 12.6, "add header", 1, 20),
        ("Cheap meds, no prescription", "deals@cheap-meds.test", "carol@example.com", 15.8, "reject", 0, 31),
        ("Re: urgent transfer", "ceo@secure-login.test", "grace@example.org", 14.1, "reject", 0, 46),
        ("Limited offer just for you", "news@bulk-offers.test", "orders@shop.test", 9.3, "add header", 0, 70),
    ]
    result = []
    for i, (subject, sender, rcpt, score, action, virus, hours_ago) in enumerate(items):
        result.append({
            "id": 5101 + i,
            "qid": f"4QqQ{i}Ab{i}Zx",
            "subject": subject,
            "sender": sender,
            "rcpt": rcpt,
            "score": score,
            "action": action,
            "virus_flag": virus,
            "created": now - hours_ago * 3600,
            "notified": 1,
        })
    return result


def quarantine_details(item):
    virus = bool(item.get("virus_flag"))
    symbols = [
        {"name": "BAYES_SPAM", "group": "statistics", "score": 5.1, "options": ["99.62%"]},
        {"name": "PHISHING", "group": "phishing", "score": 4.5, "options": ["secure-login.test"]},
        {"name": "FROM_NEQ_ENVFROM", "group": "headers", "score": 0.5, "options": []},
        {"name": "R_SPF_FAIL", "group": "policies", "score": 1.0, "options": ["-all"]},
        {"name": "DMARC_POLICY_REJECT", "group": "policies", "score": 2.0, "options": [item["sender"].split("@", 1)[1], "reject"]},
        {"name": "RBL_SPAMHAUS_SBL", "group": "rbl", "score": 4.0, "options": ["203.0.113.66:from"]},
    ]
    if virus:
        symbols.insert(0, {"name": "CLAM_VIRUS", "group": "antivirus", "score": 8.0, "options": ["Demo.Test.Signature"]})
    return {
        "subject": item["subject"],
        "header_from": f"\"{item['sender'].split('@', 1)[0].title()}\" <{item['sender']}>",
        "env_from": item["sender"],
        "recipients": [{"address": item["rcpt"], "type": "smtp"}, {"address": item["rcpt"], "type": "to"}],
        "score": item["score"],
        "action": item["action"],
        "symbols": symbols,
        "text_plain": (
            "This is a demo message. Everything in this demo is fictional.\n\n"
            f"{item['subject']}\n\nClick the link below to continue.\n"
        ),
        "text_html": f"<p>This is a demo message.</p><p>{item['subject']}</p>",
        "fuzzy_hashes": [],
    }


def build_containers(now=None):
    now = now or time.time()
    started = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(now - 6 * 86400 - 3 * 3600))
    return {
        f"{name}-mailcow": {
            "type": "info",
            "container": f"{name}-mailcow",
            "state": "running",
            "started_at": started,
            "image": f"ghcr.io/mailcow/{name}:demo",
            "id": f"demo{i:04d}",
        }
        for i, name in enumerate(CONTAINERS)
    }


def build_fail2ban():
    return {
        "ban_time": 1800,
        "max_ban_time": 86400,
        "ban_time_increment": 1,
        "max_attempts": 10,
        "retry_window": 600,
        "netban_ipv4": 32,
        "netban_ipv6": 128,
        "whitelist": "192.0.2.10\n198.51.100.12",
        "blacklist": "203.0.113.99",
        "active_bans": [
            {"network": "203.0.113.5/32", "ip": "203.0.113.5", "banned_until": "24m 10s", "queued_for_unban": 0},
            {"network": "198.51.100.200/32", "ip": "198.51.100.200", "banned_until": "11m 42s", "queued_for_unban": 0},
            {"network": "203.0.113.99/32", "ip": "203.0.113.99", "banned_until": "Forever", "queued_for_unban": 0},
        ],
        "perm_bans": [{"network": "203.0.113.99/32", "ip": "203.0.113.99"}],
    }


def build_app_passwords():
    result = {}
    next_id = 1
    for username in ("alice@example.com", "carol@example.com", "grace@example.org", "orders@shop.test"):
        entries = []
        for name in ("Phone", "Laptop"):
            entries.append({"id": next_id, "name": name, "mailbox": username, "active": 1})
            next_id += 1
        result[username] = entries
    return result


def build_domain_rate_limits():
    return {"example.com": {"value": "2000", "frame": "h"}, "shop.test": {"value": "500", "frame": "h"}}
