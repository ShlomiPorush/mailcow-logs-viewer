"""
Fictional DMARC aggregate and SMTP TLS reports, one per reporter per day.

They are written in the formats real receivers send (RFC 7489 XML, RFC 8460
JSON), gzip-compressed, and imported through the application's own upload
path, so the DMARC pages parse, enrich and store them exactly as they would
a report that arrived by mail.
"""
import gzip
import json
import random
import time
from xml.sax.saxutils import escape

from . import world

REPORTERS = [
    ("Example Mail Provider", "noreply-dmarc@provider.test", "provider.test"),
    ("Partner Mail Services", "dmarc-reports@partner.test", "partner.test"),
    ("University Mail", "postmaster@university.test", "university.test"),
]
# Domains that publish a DMARC record with rua (see fake_internet.ZONES)
POLICIES = {"example.com": ("reject", "s", "s"), "example.org": ("none", "r", "r")}

FORWARDER_IP = "198.51.100.47"
SPOOFER_IPS = ["203.0.113.88", "203.0.113.66", "192.0.2.201"]


def _record(ip, count, domain, dkim, spf, disposition):
    return (
        "<record><row>"
        f"<source_ip>{ip}</source_ip><count>{count}</count>"
        f"<policy_evaluated><disposition>{disposition}</disposition><dkim>{dkim}</dkim><spf>{spf}</spf></policy_evaluated>"
        "</row>"
        f"<identifiers><header_from>{domain}</header_from></identifiers>"
        "<auth_results>"
        f"<dkim><domain>{domain}</domain><selector>dkim</selector><result>{dkim}</result></dkim>"
        f"<spf><domain>{domain}</domain><result>{spf}</result></spf>"
        "</auth_results></record>"
    )


def dmarc_report(rng, org, email, reporter_domain, domain, day_start):
    policy, adkim, aspf = POLICIES[domain]
    fail_disposition = "reject" if policy == "reject" else "none"
    records = [_record(world.SERVER_IPV4, rng.randint(8, 60), domain, "pass", "pass", "none")]
    if rng.random() < 0.6:
        records.append(_record(FORWARDER_IP, rng.randint(1, 6), domain, "pass", "fail", "none"))
    if rng.random() < 0.5:
        records.append(_record(rng.choice(SPOOFER_IPS), rng.randint(1, 25), domain, "fail", "fail", fail_disposition))
    end = day_start + 86399
    report_id = f"{reporter_domain}-{domain}-{day_start}"
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?><feedback><version>1.0</version>'
        f"<report_metadata><org_name>{escape(org)}</org_name><email>{email}</email>"
        f"<report_id>{report_id}</report_id>"
        f"<date_range><begin>{day_start}</begin><end>{end}</end></date_range></report_metadata>"
        f"<policy_published><domain>{domain}</domain><adkim>{adkim}</adkim><aspf>{aspf}</aspf>"
        f"<p>{policy}</p><sp>{policy}</sp><pct>100</pct></policy_published>"
        + "".join(records) +
        "</feedback>"
    )
    filename = f"{reporter_domain}!{domain}!{day_start}!{end}.xml.gz"
    return filename, gzip.compress(xml.encode("utf-8"))


def tls_report(rng, org, email, reporter_domain, day_start):
    day = time.strftime("%Y-%m-%d", time.gmtime(day_start))
    failures = rng.choice([0, 0, 0, 1, 3])
    policy = {
        "policy": {
            "policy-type": "sts",
            "policy-string": ["version: STSv1", "mode: enforce", f"mx: {world.MAIL_HOST}", "max_age: 604800"],
            "policy-domain": "example.com",
            "mx-host": [world.MAIL_HOST],
        },
        "summary": {"total-successful-session-count": rng.randint(20, 140),
                    "total-failure-session-count": failures},
    }
    if failures:
        policy["failure-details"] = [{
            "result-type": "certificate-host-mismatch",
            "sending-mta-ip": rng.choice(world.REMOTE_IPS),
            "receiving-mx-hostname": world.MAIL_HOST,
            "failed-session-count": failures,
        }]
    report = {
        "organization-name": org,
        "date-range": {"start-datetime": f"{day}T00:00:00Z", "end-datetime": f"{day}T23:59:59Z"},
        "contact-info": email,
        "report-id": f"{day}T00:00:00Z_{reporter_domain}_example.com",
        "policies": [policy],
    }
    filename = f"{reporter_domain}!example.com!{day_start}!{day_start + 86399}.json.gz"
    return filename, gzip.compress(json.dumps(report).encode("utf-8"))


def build(now, days=7, seed=None):
    """All reports for the ``days`` complete UTC days before ``now``."""
    rng = random.Random(seed)
    today = int(now) - int(now) % 86400
    files = []
    for d in range(days, 0, -1):
        day_start = today - d * 86400
        for org, email, reporter_domain in REPORTERS:
            for domain in POLICIES:
                if reporter_domain == "university.test" and domain == "example.org":
                    continue
                files.append(dmarc_report(rng, org, email, reporter_domain, domain, day_start))
            if reporter_domain != "university.test":
                files.append(tls_report(rng, org, email, reporter_domain, day_start))
    return files
