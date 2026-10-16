# Status

**Status** shows whether mailcow and this app are healthy: containers, mail storage, blocklists, log imports, message linking and background jobs. The data comes from the mailcow API and from the app itself.

<!-- SHOT: status-server | Status > Server with Needs attention, Mail storage, mailcow, Message linking and Containers -->

## Needs attention

The panel above the tabs lists what needs a decision, each with its action: a stopped container (**Ignore**), an address on a blocklist (**Look up** on the list's own site, or **Ignore this list**) and a failed job (**Run now**). When there is nothing, it says **Everything is running. Nothing needs you right now.**

Ignoring a container only stops the app from counting it as a problem; it does not start or stop the container. Ignoring a blocklist applies to every monitored address. The app saves both choices, and they work even while editing in Settings is off.

The counters on the tabs show stopped containers on **Server**, listed addresses on **Blocklists** and failed jobs on **Jobs**. The **Blocklists** tab is described in [IP Blacklist Monitor](IP_Blacklist_Monitor.md).

## Server

**Mail storage** shows how full the mail disk is, with the used and total size and the disk name when mailcow reports them. It turns amber above 75% and red above 90%.

**mailcow** shows the mailcow version and the total and active **Domains**, **Mailboxes** and **Aliases**. When a newer mailcow is out, **Update Available** shows its release notes; it does not update mailcow.

**Message linking** shows how many messages are fully linked, as a percentage and as complete, incomplete and expired counts. The app links each message's Postfix log lines to its Rspamd scan. Expired means the app stopped waiting for more log lines, not that the message expired in the queue.

### Containers

**All** shows every container and **Problems** only the stopped ones. Only the state `running` counts as running. Stopped containers come first and ignored ones last.

Each tile shows the name and the state or uptime. A stopped container has **Ignore**; an ignored one stays in the list, marked **ignored**, with **Stop ignoring** to count it again.

### Log import

For **Postfix Logs**, **Rspamd Logs** and **Netfilter Logs** you see **Last Fetch Run**, **Last Import**, **Total Entries** and **Oldest Entry**. A recent fetch with an older import usually means mailcow had no new lines.

**Waiting to be linked** lists up to five recent messages that are not fully linked yet, with **Message ID**, **From and to** and **Age**. The app keeps trying until they are linked or reach **Max Correlation Age Minutes** (10 by default, under **Settings** > **Correlation**), then marks them expired.

## Jobs

**All**, **Problems** and **Off** filter the jobs. Open a group to see each job's description, schedule, last run, status and last error. A group with a failed job opens by itself.

<!-- SHOT: status-jobs | Status > Jobs with a failed group expanded, an off job with Settings and an enabled job with Run -->

| Group | Jobs |
| --- | --- |
| **Log Processing** | **Fetch Logs**, **Cleanup Logs** |
| **Correlation Engine** | **Complete Correlations**, **Update Final Status**, **Expire Correlations**, **Dovecot Deliveries** |
| **Data Sync** | **Sync Active Domains**, **Mailbox Statistics**, **Alias Statistics**, **Sync Transports & Relayhosts** |
| **DMARC & TLS** | **DMARC & TLS IMAP Import**, **Cleanup DMARC & TLS Reports**, **Weekly Summary Report** |
| **Security & Monitoring** | **DNS Check (All Domains)**, **IP Blacklist Check (All Hosts)**, **Protection Rules** |
| **System** | **Check App Version**, **Update MaxMind Databases** |
| **Live Logs** | **Fetch Raw Logs**, **Cleanup Raw Logs** |
| **Devices** | **ActiveSync Devices**, **Cleanup ActiveSync Devices** |
| **Spam Filter** | **Detect Suppressions**, **Sync to Rspamd**, **Expire Suppressions**, **Cleanup Deferred Queue** |
| **Quarantine** | **Process Quarantine Rules** |

**Run** starts a job now; its schedule stays the same. While a job runs, its **Run** button is disabled. A job whose feature is off under **Settings** > **Features** has no **Run** and is marked **feature off** or **off**. A job that is off for another reason, such as a missing read-write API key or a setting that is off, says why and has a **Settings** button that opens the right category.

A manual run does everything the scheduled run does. **Sync to Rspamd**, **Cleanup Deferred Queue**, **Protection Rules** and **Process Quarantine Rules** can change mailcow, **IP Blacklist Check (All Hosts)** can send blocklist alerts, and **Weekly Summary Report** sends the summary email. See [Notifications](../Notifications.md).

## Settings that change this page

- A feature turned off under **Settings** > **Features** turns its jobs off. With **IP Blacklist Monitor** off, the **Blocklists** tab is hidden and listings leave **Needs attention**.
- The **Live Logs** jobs always run, because other pages read some raw logs even when the Logs page is off.
- Fetch intervals, retention and message linking are set in [Settings](Settings.md).

Version checks and connection tests are on [About](About.md).

## When something is missing

- **Never** under **Last Import** means no entries of that log are stored yet. **Never** under **Last Fetch Run** and **Not run yet** on a job mean nothing ran since the app last started: that history is kept in memory and a restart clears it.
- **A panel shows an error.** The app could not read that part from mailcow. Check that the mailcow API key is valid and that mailcow allows API access from the app's address.
- **A job failed.** Read its error under the job before you run it again.
