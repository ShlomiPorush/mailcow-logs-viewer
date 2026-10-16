# Dashboard

The Dashboard combines imported mail logs with live server data from mailcow: attention items, mail flow, recent deliveries, protections and server health.

![Dashboard](../../images/docs/dashboard-light.webp#gh-light-mode-only)
![Dashboard](../../images/docs/dashboard-dark.webp#gh-dark-mode-only)

For navigation, theme, sign-in and read-write API key notices, see [Using the app](../Using_the_App.md).

## Needs attention

**Needs attention** lists server checks, then security alerts. With none, it says "Nothing needs attention right now."

The server checks, each with a button to where you handle it:

| Row | When it shows | Button |
|---|---|---|
| **mailcow is not reachable** | The mailcow API did not answer. Logs and server data may be out of date. | **Open settings** |
| **mail.example.com is on a blocklist**, or **N of your addresses are on a blocklist** | The last blocklist check found one of your sending addresses listed. The row says on how many lists. | **Check listing** (opens Status) |
| **A mailcow container is stopped**, or **N mailcow containers are stopped** | mailcow reports a stopped container. The row says how many are running. | **Open status** |
| **DMARC needs attention for example.com**, or **for N domains** | DMARC Insights recommends a stricter policy, reports a low pass rate, or sees new failing senders. The row shows the first recommendation. | **Open DMARC** |
| **Version X is available** | A newer version of this app exists. | **Read changes** |
| **mailcow X is available** | A newer mailcow version exists. | **Read changes** |

**Read changes** opens the release notes in a window; a click anywhere on those two rows does the same. The blocklist row is not checked while **IP Blacklist Monitor** is turned off, and the DMARC row while **DMARC & TLS** is turned off.

### Security alerts

Under the server checks come up to 20 security alerts you have not dismissed yet, newest first. Each row shows a **WARNING** or **CRITICAL** tag, a title, what was found and when. There are three kinds:

| Alert | What it means |
|---|---|
| **Outbound volume spike: alice@example.com** | The mailbox sent far more than its own usual rate. This is how a hijacked mailbox sending spam usually looks. |
| **Authentication failure burst: bob@example.com** | Many failed logins for one username in a short time, typically password guessing. |
| **SMTP disabled (abuse protection): carol@example.com** | Outgoing spam protection turned off sending for the mailbox. See [Abuse Protection](Abuse_Protection.md). |

How the first two are decided is explained in [How the security alerts are decided](#how-the-security-alerts-are-decided).

- **Show activity** opens the history behind the alert (see below). A click anywhere on the row does the same.
- **Dismiss** hides that alert; **Dismiss all alerts** hides all current alerts. A later incident can create a new alert after the cooldown.

The volume spike and failed login alerts are also sent by email, with the subject `[Security]` followed by the title, and to the notification destinations that receive security alerts; see [Notifications](../Notifications.md). How an **SMTP disabled** alert is reported is described in [Abuse Protection](Abuse_Protection.md).

### Show activity

**Show activity** compares activity around the alert with earlier activity for that mailbox or username.

![Show activity window](../../images/docs/dashboard-alert-activity-light.webp#gh-light-mode-only)
![Show activity window](../../images/docs/dashboard-alert-activity-dark.webp#gh-dark-mode-only)

A row of figures comes first:

- For a volume spike: **Sent in the alert's N minutes**, the same as **That is, an hour**, **Usual, an hour** over the baseline days, and **Sent in the N days before**.
- For a login burst: **Failed logins in N minutes**, **The alert starts at**, **From addresses** and **Failed in the N days before**. The activity query includes all matching username events, and **From addresses** counts only the six addresses listed, so these figures are not a complete failed-login breakdown.

The chart shows **What it sent** or **Failed logins** for that subject. Choose **24 hours**, **2 days** or the baseline length (default 7 days). Short views use 15-minute bars; the baseline view uses hours. The alert window is highlighted, with its time marked and a usual-rate line for volume spikes. Hover for counts. The chart extends 2 hours after the alert.

**Around the alert** lists what happened from one check window before the alert (15 minutes by default) to an hour after it:

- For a volume spike: **Recipient domains**, **What happened to them** (the delivery results) and the **Subjects**.
- For a failed login burst: the **Addresses**, **Countries** and **Networks** that tried.

If the logs of that time are gone, it says "Nothing in the logs around the alert. They may have been cleaned up since."

Compare recipient domains, subjects and results with the user's normal sending. A failed-login burst from one address may be a device with an old password; many addresses can indicate a distributed attack.

<!-- VERIFY: Show activity on an "SMTP disabled (abuse protection)" alert: the code treats every alert that is not a volume spike as a failed login burst and looks up failed logins for the email address. Check what the window shows and whether the button should be Open in Messages. -->

**Open in Messages** filters by the sender on a volume alert. For submissions from an alias, use **Authenticated User** in Messages to find the sending mailbox. **Open in Security** filters Events by username on a login alert. **Dismiss the alert** hides the alert.

For an **SMTP disabled** alert, **Show activity** currently shows the failed-login view and **Open in Security**, rather than outgoing messages. Use [Outgoing spam](Abuse_Protection.md) for mailbox controls.

## Mail flow

**Mail flow, last 24 hours** compares current activity with earlier totals:

| Figure | What it counts | Smaller line |
|---|---|---|
| **Messages** | Messages first seen in the last 24 hours, each counted once as on the Messages page. A message to three recipients is one message and three deliveries. | Deliveries in 24 hours, and messages in 7 days |
| **Blocked** | Deliveries that bounced, were rejected or were marked as spam | 7 days, and the share of the 24-hour deliveries |
| **Deferred** | Deliveries still waiting to be retried | 7 days |
| **Auth Fails** | Failed mail logins (SASL authentication failures) in the Netfilter log | 7 days |

Hourly bars split Rspamd scans into **Clean** and **Spam**. Hover for counts; the chart ends at **Now**.

A click on a bar shows that hour's figures, and the title changes to the hour (for example **Mail flow, 14:00 to 15:00**). The smaller lines then show the 24-hour totals. Two buttons appear:

- **View these messages** opens the Messages page with its time filter set to that hour and every other filter cleared.
- **All 24 hours** goes back to the full day. A second click on the same bar does the same.

## Latest messages

**Latest messages** lists the 11 deliveries with the most recent log activity, with their time, outcome, sender, recipient and subject. Click one for [message details](Messages.md#message-details), or **View all** for Messages. Before logs arrive it says "No recent activity".

## Security

The right column starts with **Security**, a short view of the [Security](Security.md) page:

- **To review** counts the addresses that tried to log in during the last 24 hours and are not banned. **Banned now** counts those of them banned by Fail2ban and the protection rules, in red when there are any. These are the two lists of the Security **Overview** tab at its default period, and a click on either opens it.
- **Protection N of M on** says how many protections are on and names them. A tick means at least one protection bans; an eye means the ones that are on only watch. A click unfolds every protection with its state (**On**, **Watching only**, **Off** or **Unknown**) and a short note, such as the Fail2ban limits or "needs MaxMind GeoIP". A click on a protection opens its card on the Security **Settings** tab.
- **Open Security** opens the Security page.

The protections listed are Fail2ban, Trap accounts, Unknown accounts, Repeat offenders, Attacking networks, Countries, Possible stolen password and Outgoing spam.

## Server health

Health cards open the related Status view, except **This app**, which opens About. **Status** in the heading opens the Server tab.

| Card | Shows | Opens |
|---|---|---|
| **Containers** | Running containers out of all, and **All running** or how many are stopped and ignored. Red when one is stopped. | Status, Server |
| **Blocklists** | **N clean**, **X of Y listed** with the listed hosts (red), **Check error** or **Unknown**, and when it was last checked. Before the first check: "No check yet; the first one runs by itself". | Status, Blocklists |
| **Background jobs** | Healthy jobs out of those running, and the names of failed jobs, how many are off with their feature, or **None failed**. Red when a job failed. | Status, Jobs |
| **Mail storage** | Percentage used, and used of total. Amber above 75%, red above 90%. | Status, Server |
| **Message linking** | The share of messages whose logs are fully linked, and the counts. Amber while some are incomplete. | Status, Server |
| **This app** | The running version, and **Up to date** or the newer version. | About |

See [Status](Status.md) and [About](About.md) for what is behind each card.

## Hosted

**Hosted** shows how many **Domains**, **Mailboxes** and **Aliases** your mailcow server has.

## Settings that change this page

- **Settings** > **Anomaly Detection (Beta)** turns the volume spike and failed login alerts on and sets their limits. It is off by default (`ANOMALY_DETECTION_ENABLED`). See [How the security alerts are decided](#how-the-security-alerts-are-decided) for each setting.
- **Settings** > **SMTP Abuse (Beta)** controls the outgoing spam protection that raises **SMTP disabled** alerts.
- **Settings** > **Features**: with **Security** off, the Security panel is hidden and no failed logins are counted in the sidebar. With **IP Blacklist Monitor** off, the **Blocklists** card and the blocklist row are gone. With **DMARC & TLS** off, there is no DMARC row.
- **Settings** > **Notifications** decides where security alerts are sent.

## When something is missing

- **The figures are all 0 and Latest messages says "No recent activity".** The app has not imported any logs yet, or it cannot reach mailcow. A **mailcow is not reachable** row in Needs attention says which. Check the connection under **Settings** > **Mailcow**.
- **No security alerts ever appear.** Anomaly detection is off by default. Turn it on under **Settings** > **Anomaly Detection (Beta)**.
- **The Security panel is missing.** The Security feature is turned off under **Settings** > **Features**.
- **The Blocklists card is missing.** The IP Blacklist Monitor feature is turned off.
- **A card shows "-".** The data has not loaded yet, or mailcow did not answer. Press **Refresh**.
- **Latest messages shows "Failed to load activity" with an error.** The app's database did not answer. **View Container Logs** shows the error.
- **Show activity says "Could not load the activity".** Try again in a moment; the message includes the server's answer.

## How the security alerts are decided

Anomaly detection runs every check interval (15 minutes by default) and looks at the window since the last run.

**Outbound volume spike** counts authenticated submissions for the mailbox that logged in, including mail sent from its aliases. Forged external senders do not count. All these conditions must hold:

- It sent at least **Anomaly Volume Min Messages** in the window (default 30).
- Its hourly rate is at least **Anomaly Volume Multiplier** times its usual hourly rate over the last **Anomaly Baseline Days** (defaults 5 and 7). A mailbox with no history counts as 1 message an hour.
- The burst does not match at least two earlier days' time slots within the baseline. A slot includes the check window plus an hour on either side; at least half the current volume counts as similar.

The alert is **CRITICAL** when the rate is at least twice the multiplier, otherwise **WARNING**.

**Authentication failure burst.** A username alerts when it collects at least **Anomaly Auth Failure Threshold** failed logins in the window (default 20). The alert says from how many addresses they came. It is **CRITICAL** at three times the threshold.

After an alert, the same mailbox or username does not alert again for the same reason for **Anomaly Alert Cooldown Hours** (default 6). Anomaly detection only raises alerts; it never blocks anything. Blocking a mailbox that sends too much is the job of outgoing spam protection, see [Abuse Protection](Abuse_Protection.md).
