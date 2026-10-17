# Dashboard

![Dashboard](../../images/docs/dashboard-light.webp#gh-light-mode-only)
![Dashboard](../../images/docs/dashboard-dark.webp#gh-dark-mode-only)

## Needs attention

Server checks cover an unreachable mailcow API, blocklisted sending addresses, stopped containers, DMARC recommendations and available app or mailcow updates. An unreachable API means logs and server data may be out of date.

DMARC attention means a stricter policy is recommended, the pass rate is low or new failing senders were found.

A Fail2ban warning about a whole IPv6 `/32` network identifies an entry an earlier version wrote for a single address. Review it under [Entries tagged Whole network](Security.md#entries-tagged-whole-network).

Blocklist, Fail2ban and DMARC checks are omitted while their respective features are off.

### Security alerts

The Dashboard shows up to 20 undismissed alerts, newest first:

- **Outbound volume spike** means a mailbox sent far more than its usual rate.
- **Authentication failure burst** means many failed logins for one username in a short time.
- **SMTP disabled (abuse protection)** means outgoing spam protection stopped the mailbox from sending. See [Outgoing spam](Abuse_Protection.md).

Dismissal hides an alert. A later incident can raise another after the cooldown. Volume spike and login burst alerts also go by email and to destinations that receive security alerts; see [Notifications](../Notifications.md).

### Show activity

**Show activity** compares the mailbox's sending or the username's failed logins around the alert with earlier activity.

![Show activity window](../../images/docs/dashboard-alert-activity-light.webp#gh-light-mode-only)
![Show activity window](../../images/docs/dashboard-alert-activity-dark.webp#gh-dark-mode-only)

The check window comes from the alert, or from the outgoing spam block, rather than today's settings. Volume spike alerts also supply their original baseline period; other alerts use the current **Anomaly Baseline Days**. **Unknown** means the app cannot recover the original window.

The hourly rate is the alert-window count converted to an hour, not a separate count. For SMTP blocks it is compared with the sending limit; for volume spikes, with the mailbox's usual rate. Login bursts show the threshold and the number of distinct source addresses.

Short chart views use 15-minute bars. The baseline view uses hours, or several hours per bar for baselines longer than 7 days. The chart extends 2 hours after the alert and highlights its window when known.

**Around the alert** covers one check window before the alert to an hour after it, or 60 minutes before when the window is unknown. Sending alerts group recipient domains, delivery results and subjects; login alerts group source addresses, countries and networks. Missing logs may have expired under retention settings.

Compare recipients, subjects and results with the user's normal sending. Failed logins from one address may be a device with an old password; many addresses can indicate a distributed attack.

**Open in Messages** filters by **Authenticated User**, including mail sent from aliases. **Open in Security** filters Events by username. Dismissing an SMTP block alert does not restore sending; use [Outgoing spam](Abuse_Protection.md).

## Mail flow

The figures cover the last 24 hours:

| Figure | What it counts |
|---|---|
| **Messages** | Messages first seen in the period, each counted once as on the Messages page. A message to three recipients is one message and three deliveries. |
| **Blocked** | Deliveries that bounced, were rejected or were marked as spam. The percentage uses deliveries, not unique messages. |
| **Deferred** | Deliveries still waiting to be retried. |
| **Auth Fails** | Failed mail logins recorded as SASL authentication failures in Netfilter. |

The smaller figures give 7-day totals, plus the 24-hour delivery count under Messages. Hourly bars count Rspamd scans, split into clean and spam.

Selecting a bar changes the figures to that hour and the smaller figures to 24-hour totals. **View these messages** applies that hour to Messages and clears its other filters. Selecting the same bar again restores the full day.

## Latest messages

This list counts deliveries, unlike the Messages figure. It shows the 11 deliveries with the most recent log activity. See [message details](Messages.md#message-details).

## Security

**To review** counts addresses that tried to log in during the last 24 hours and are not banned. **Banned now** counts those of them banned by Fail2ban or the protection rules.

**Protection N of M on** counts enabled protections. A tick means at least one bans; an eye means the enabled protections only watch. Expand the count for individual states and unmet requirements, such as MaxMind GeoIP or a read-write key for outgoing spam protection.

## Server health

- **Containers** turns red when one is stopped; ignored containers are counted separately.
- **Background jobs** counts healthy jobs out of those running. Failed jobs turn the card red; jobs off with their feature are separate.
- **Mail storage** turns amber above 75% and red above 90%.
- **Message linking** is the share of messages whose logs are fully linked. Amber means some are incomplete.
- **Blocklists** uses the last check. **Unknown** or **No check yet** is not a clean result.
- **Update check failed** means the app could not reach GitHub to check its version.

See [Status](Status.md) and [About](About.md) for details.

## Settings that change this page

- **Settings** > **Anomaly Detection (Beta)** enables volume spike and login burst alerts and sets their limits. It is off by default (`ANOMALY_DETECTION_ENABLED`).
- **Settings** > **SMTP Abuse (Beta)** controls the protection that raises SMTP disabled alerts.
- **Settings** > **Features** hides the Security panel and stops its sidebar failed-login count when Security is off. IP Blacklist Monitor controls the Blocklists card and attention row; DMARC & TLS controls the DMARC row.
- **Settings** > **Notifications** selects destinations for security alerts.

## When something is missing

- **All figures are 0 with no recent activity.** Logs have not been imported, or mailcow is unreachable. Check **Settings** > **Mailcow**.
- **No security alerts appear.** Anomaly detection is off by default.
- **A card shows "-".** Data has not loaded, or mailcow did not answer.
- **Latest messages says "Failed to load activity".** The app's database did not answer. Check **View Container Logs**.
- **Show activity says "Could not load the activity".** Try again; the message includes the server's answer.

## How the security alerts are decided

Anomaly detection runs every check interval (15 minutes by default) and looks back one check interval from the time it runs.

**Outbound volume spike** counts authenticated submissions for the mailbox that logged in, including mail sent from aliases. Forged external senders do not count. All conditions must hold:

- At least **Anomaly Volume Min Messages** were sent in the window (default 30).
- The hourly rate is at least **Anomaly Volume Multiplier** times the usual rate over **Anomaly Baseline Days** (defaults 5 and 7). A mailbox with no history counts as 1 message an hour.
- The burst does not match time slots on at least two earlier baseline days. A slot includes the check window plus an hour on either side; at least half the current volume counts as similar.

The alert is **CRITICAL** at twice the multiplier, otherwise **WARNING**.

**Authentication failure burst** triggers at **Anomaly Auth Failure Threshold** failed logins per username in the window (default 20). It is **CRITICAL** at three times the threshold.

The same mailbox or username cannot alert again for the same reason for **Anomaly Alert Cooldown Hours** (default 6). Anomaly detection never blocks anything. [Outgoing spam protection](Abuse_Protection.md) handles sending blocks.
