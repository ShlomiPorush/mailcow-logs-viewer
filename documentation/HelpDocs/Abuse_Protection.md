# Abuse Protection - User Guide

## Overview
Abuse Protection watches how much mail each of your mailboxes **sends**. When a mailbox suddenly sends far more than it should - the classic sign of a compromised account being used for spam - the system disables **sending (SMTP)** for that mailbox.

**Receiving is never affected.** The user keeps full access to their mail over IMAP/webmail; they simply cannot send until the account is secured and you re-enable it.

> **Requires:** a Read-Write API key (`MAILCOW_API_KEY_RW`) and `SMTP_ABUSE_ENABLED=true`. Without both, this panel is read-only.

## Two layers of protection

| Layer | What it does | Configure under |
|-------|--------------|-----------------|
| **Anomaly Detection** | *Alerts only.* Compares each mailbox to **its own** recent sending pattern, so it catches a takeover even at modest volumes. Also alerts on bursts of failed logins. | Settings → Anomaly Detection |
| **Abuse Protection** | *Acts.* Applies a **hard** limit (e.g. more than 100 messages per hour) and disables SMTP for that mailbox. | Settings → SMTP Abuse |

Both appear in the same alert feed: a banner on the Dashboard, plus email and webhook notifications.

## What happens when a mailbox is blocked

1. **SMTP is disabled** for that mailbox in mailcow - it can no longer send.
2. **App passwords are revoked** (optional but recommended). A compromised account is usually abused through an app password, so revoking them cuts off the attacker even if they still have the password.
3. **You are notified** by email and/or webhook.
4. **The mailbox owner is notified**, explaining that sending is paused, that they can still read mail, and who to contact. Set `SMTP_ABUSE_HELP_ADDRESS` to put your support address in that message.
5. **A security alert** appears on the Dashboard and the action is written to the audit trail.

## Using this page

### Blocked by abuse protection
Mailboxes this system has blocked. Click **Re-enable SMTP** once you have secured the account (password reset, app passwords reviewed).

Only mailboxes blocked *by this feature* are listed here. A mailbox that simply has SMTP switched off in mailcow - for example an incoming-only address such as a DMARC report mailbox - is not treated as an abuse case.

### Outbound activity
Every mailbox that sent mail during the current window, with its message count and status:

- **Normal** - under the limit
- **Over limit** - above the limit; it will be blocked on the next run unless whitelisted
- **Whitelisted** - exempt from automatic blocking
- **SMTP disabled** - currently blocked

Use **Disable SMTP** to block a mailbox immediately without waiting for the threshold.

### Whitelist
Mailboxes that legitimately send in bursts and must never be blocked automatically - newsletters, ticketing systems, monitoring, backup reports. Click **Edit whitelist**, enter one address per line, and save.

## After re-enabling a mailbox

When you re-enable SMTP, automatic blocking is paused for that mailbox for a grace period (`SMTP_ABUSE_UNBLOCK_GRACE_MINUTES`, default 60 minutes).

This matters: the messages the compromised account already sent stay inside the rolling window for a while. Without the grace period, the very next check would immediately block the mailbox again and your action would appear to do nothing.

## Choosing a threshold

Start high and tighten later:

1. Look at the **Outbound activity** list over a few normal days and note your busiest legitimate mailbox.
2. Set `SMTP_ABUSE_THRESHOLD` comfortably above that number.
3. Whitelist any bulk senders.
4. Once you are confident there are no false positives, lower the threshold.

A threshold that is too low blocks real users; a threshold that is too high lets a compromised account send more spam before it is stopped. Anomaly Detection (alerts only) is a safe way to watch for takeovers while you tune the hard limit.

## Related settings

| Setting | Purpose |
|---------|---------|
| `SMTP_ABUSE_ENABLED` | Master switch |
| `SMTP_ABUSE_THRESHOLD` | Messages allowed within the window |
| `SMTP_ABUSE_WINDOW_MINUTES` | Length of the rolling window |
| `SMTP_ABUSE_REVOKE_APP_PASSWORDS` | Also revoke app passwords when blocking |
| `SMTP_ABUSE_UNBLOCK_GRACE_MINUTES` | Pause auto-blocking after a manual re-enable |
| `SMTP_ABUSE_HELP_ADDRESS` | Support address shown to the blocked user |

See [ENV_Settings.md](../ENV_Settings.md) for the full reference.
