# Abuse Protection - User Guide

## Overview
Abuse Protection watches how much mail each of your mailboxes **sends**. When a mailbox suddenly sends far more than it should - the classic sign of a compromised account being used for spam - the system disables **sending (SMTP)** for that mailbox.

**Receiving is never affected.** The user keeps full access to their mail over IMAP/webmail; they simply cannot send until the account is secured and you re-enable it.

> [!NOTE]
> Abuse Protection is a new feature and is currently in **Beta**. If you run into unexpected behavior or false positives, please open an issue on the project's GitHub page so it can be improved.

> [!WARNING]
> **Requires:** a Read-Write API key (**Settings → Mailcow → Connection**) and Abuse Protection switched on under **Settings → SMTP Abuse (Beta) → Enable**. Without both, this panel is read-only.

> [!NOTE]
> Settings are edited on the **Settings** page (requires `SETTINGS_EDIT_VIA_UI_ENABLED=true`). Every setting can also be provided as an environment variable - see [ENV_Settings.md](../ENV_Settings.md).

## Why is this important?
A single compromised mailbox can send thousands of spam messages in minutes. That traffic gets your server IP listed on blacklists, damages your sending reputation, and hurts deliverability for every user on the server. Stopping outbound abuse quickly limits the damage - while keeping the owner's mailbox readable so they are not locked out of their own mail.

## Features

### 🔍 Two Layers of Protection

| Layer | What it does | Configure under |
|-------|--------------|-----------------|
| **Anomaly Detection** | *Alerts only.* Compares each mailbox to **its own** recent sending pattern, so it catches a takeover even at modest volumes. Also alerts on bursts of failed logins. | Settings → Anomaly Detection (Beta) |
| **Abuse Protection** | *Acts.* Applies a **hard** limit (e.g. more than 100 messages per hour) and disables SMTP for that mailbox. | Settings → SMTP Abuse (Beta) |

Both appear in the same alert feed: a banner on the Dashboard, plus email and webhook notifications.

**How Anomaly Detection decides:**
- Each mailbox is compared against its **own** baseline sending rate over the past days - there is no global threshold, so a takeover of a normally quiet mailbox is caught even at modest volumes.
- **Daily-pattern learning:** a mailbox that bursts at the same time of day on past days (scheduled newsletters, digests, automated reports) is recognized as following its own routine and does not trigger an alert. A burst at an unusual hour, or one much larger than the usual daily batch (roughly double or more), still alerts.
- Bursts of failed logins are also detected, as a sign of brute-force or credential-stuffing attacks against an account.

### 🚫 What Happens When a Mailbox Is Blocked

1. **SMTP is disabled** for that mailbox in mailcow - it can no longer send.
2. **App passwords are revoked** (optional but recommended). A compromised account is usually abused through an app password, so revoking them cuts off the attacker even if they still have the password.
3. **You are notified** by email and/or webhook.
4. **The mailbox owner is notified**, explaining that sending is paused, that they can still read mail, and who to contact. Set the help address under **Settings → SMTP Abuse (Beta) → Response** to put your support address in that message.
5. **A security alert** appears on the Dashboard and the action is written to the audit trail.

### 📋 Blocked by Abuse Protection
Mailboxes this system has blocked. Click **Re-enable SMTP** once you have secured the account (password reset, app passwords reviewed).

> [!NOTE]
> Only mailboxes blocked *by this feature* are listed here. A mailbox that simply has SMTP switched off in mailcow - for example an incoming-only address such as a DMARC report mailbox - is not treated as an abuse case.

### 📈 Outbound Activity
Every mailbox that sent mail during the current window, with its message count and status:

- **Normal** - under the limit
- **Over limit** - above the limit; it will be blocked on the next run unless whitelisted
- **Whitelisted** - exempt from automatic blocking
- **SMTP disabled** - currently blocked

Use **Disable SMTP** to block a mailbox immediately without waiting for the threshold.

### ✅ Whitelist
Mailboxes that legitimately send in bursts and must never be blocked automatically - newsletters, ticketing systems, monitoring, backup reports. Click **Edit whitelist**, enter one address per line, and save.

## After Re-enabling a Mailbox

When you re-enable SMTP, automatic blocking is paused for that mailbox for a grace period (configurable under **Settings → SMTP Abuse (Beta) → Response**, default 60 minutes).

> [!NOTE]
> This matters: the messages the compromised account already sent stay inside the rolling window for a while. Without the grace period, the very next check would immediately block the mailbox again and your action would appear to do nothing.

## Choosing a Threshold

Start high and tighten later:

1. Look at the **Outbound Activity** list over a few normal days and note your busiest legitimate mailbox.
2. Set the threshold (**Settings → SMTP Abuse (Beta) → Limit**) comfortably above that number.
3. Whitelist any bulk senders.
4. Once you are confident there are no false positives, lower the threshold.

> [!TIP]
> A threshold that is too low blocks real users; a threshold that is too high lets a compromised account send more spam before it is stopped. Anomaly Detection (alerts only) is a safe way to watch for takeovers while you tune the hard limit.

## Related Settings

All of these live under **Settings → SMTP Abuse (Beta)**:

| Setting | Purpose |
|---------|---------|
| Enable → **SMTP Abuse Enabled** | Master switch |
| Limit → **SMTP Abuse Threshold** | Messages allowed within the window |
| Limit → **SMTP Abuse Window Minutes** | Length of the rolling window |
| Response → **SMTP Abuse Revoke App Passwords** | Also revoke app passwords when blocking |
| Response → **SMTP Abuse Unblock Grace Minutes** | Pause auto-blocking after a manual re-enable |
| Response → **SMTP Abuse Help Address** | Support address shown to the blocked user |

See [ENV_Settings.md](../ENV_Settings.md) for the equivalent environment variables.
