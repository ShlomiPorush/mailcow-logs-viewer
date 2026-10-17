# Status

![Status, Server](../../images/docs/status-server-light.webp#gh-light-mode-only)
![Status, Server](../../images/docs/status-server-dark.webp#gh-dark-mode-only)

## Needs attention

Ignoring a container only stops the app from counting it as a problem; it does not start or stop the container. Ignoring a blocklist applies to every monitored address. The app saves both choices, and they work even while editing in Settings is off.

The counters on the tabs show stopped containers on **Server**, listed addresses on **Blocklists** and failed jobs on **Jobs**. The **Blocklists** tab is described in [IP Blacklist Monitor](IP_Blacklist_Monitor.md).

## Server

**Mail storage** turns amber above 75% and red above 90%.

When a newer mailcow is out, **Update Available** shows its release notes; it does not update mailcow.

**Message linking** counts how many messages are fully linked. The app links each message's Postfix log lines to its Rspamd scan. Expired means the app stopped waiting for more log lines, not that the message expired in the queue.

Only the container state `running` counts as running. An ignored container stays in the list, marked **ignored**, with **Stop ignoring** to count it again.

### Log import

A recent **Last Fetch Run** with an older **Last Import** usually means mailcow had no new lines.

**Waiting to be linked** lists up to five recent messages that are not fully linked yet. The app keeps trying until they are linked or reach **Max Correlation Age Minutes** (10 by default, under **Settings** > **Correlation**), then marks them expired.

## Jobs

![Status, Jobs](../../images/docs/status-jobs-light.webp#gh-light-mode-only)
![Status, Jobs](../../images/docs/status-jobs-dark.webp#gh-dark-mode-only)

**Run** starts a job now; its schedule stays the same. **DMARC & TLS IMAP Import** and **IP Blacklist Check (All Hosts)** can also be started elsewhere in the app. When **Run** meets such a run already in progress, it does not start a second one: the job stays **running** and then shows the result of the run in progress. A job whose feature is off under **Settings** > **Features** has no **Run** and is marked **feature off**. A job that is off for another reason, such as a missing read-write API key or a setting that is off, is marked **off**, says why and has a **Settings** button that opens the right category.

A manual run does everything the scheduled run does. **Sync to Rspamd**, **Cleanup Deferred Queue**, **Protection Rules**, **Outgoing Spam** and **Process Quarantine Rules** can change mailcow, **IP Blacklist Check (All Hosts)** and **Anomaly Detection** can send alerts, and **Weekly Summary Report** sends the summary email. See [Notifications](../Notifications.md).

The **Live Logs** jobs always run, because other pages read some raw logs even when the Logs page is off.

## When something is missing

- **Never** under **Last Import** means no entries of that log are stored yet. **Never** under **Last Fetch Run** and **Not run yet** on a job mean nothing ran since the app last started: that history is kept in memory and a restart clears it.
- **A panel shows an error.** The app could not read that part from mailcow. Check that the mailcow API key is valid and that mailcow allows API access from the app's address.

Version checks and connection tests are on [About](About.md).
