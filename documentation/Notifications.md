# Notifications

The app sends alerts by email and to destinations you add, such as Slack, Telegram or ntfy. Set both up in **Settings** > **Notifications**; email also needs **Settings** > **SMTP**.

## Alert destinations

![Settings, Notifications](../images/docs/notifications-destinations-light.webp#gh-light-mode-only)
![Settings, Notifications](../images/docs/notifications-destinations-dark.webp#gh-dark-mode-only)

ntfy defaults to `https://ntfy.sh`. A self-hosted service needs a URL the app's container can reach. Enter the final URL: the app does not follow redirects.

**Send test** in the editor tries the values you typed without saving them. **Test** in the list tries the saved destination, even a disabled one. Saved secrets show as `********`; type them again to use **Send test**.

The dot next to a destination shows whether its last message got through, and a failure shows its error. If you change a destination's server URL, type its token again: a saved token is only sent to the server it was entered for.

![Add destination](../images/docs/notifications-editor-light.webp#gh-light-mode-only)
![Add destination](../images/docs/notifications-editor-dark.webp#gh-dark-mode-only)

## Which alert goes where

Each alert goes to its email recipients and to every enabled destination that has its topic ticked.

| Topic | Events | Email recipients |
| --- | --- | --- |
| **Security** | Anomaly detection, protection rules and abuse protection blocks. | **Admin Email** |
| **IP blacklist** | A host is listed, fewer hosts are listed, or all are clear again. | **Blacklist Alert Email**, else **Admin Email** |
| **DNS record changes** | A changed SPF, DKIM, DMARC, TLSA, MTA-STS or TLS-RPT record, DNSSEC that stopped validating, or a TLSA record that no longer matches the certificate. | **Admin Email** |
| **DMARC processing errors** | DMARC or TLS report emails the IMAP import could not read. | **Report Import Error Email**, else **Admin Email** |

Unticking all topics is the same as ticking all; to stop a destination, turn off **Enabled**.

Protection rule messages follow each rule's **Email me when it bans** box (**Email me on every alert** for **Possible stolen password**), which covers destinations as well; see [Protection rules](HelpDocs/Security.md#protection-rules). Adding a destination does not turn on any of these features.

## Email addresses

Each address field takes several addresses separated by commas; they all get one message and see each other in `To`. Settings refuses an entry that is not an email address, and an invalid address from the environment is skipped and logged.

## SMTP

Email needs **SMTP Enabled** with a host, user and password, or with **SMTP Relay Mode**, a host and **SMTP From** ([all SMTP fields](HelpDocs/Settings.md#smtp)); enabled destinations receive their subscribed alerts without SMTP, but the weekly summary and mailbox-owner notices are email-only.

**SMTP Verify SSL** defaults to **Off**; **Automatic** checks dotted host names but skips `localhost`, IP addresses and single-label container names, while **On** always checks the certificate.

**Test SMTP** sends a real email to **Admin Email** (or **SMTP User** when it is empty), even while **SMTP Enabled** is off.

## Every email subject

A topic in the last column means the message goes to that topic's email recipients and destinations.

| Subject | When it is sent | Sent to |
| --- | --- | --- |
| `SMTP Test - mailcow Logs Viewer` | **Test SMTP**. | **Admin Email**, or **SMTP User** |
| `[Security] Outbound volume spike: {mailbox}` | Anomaly detection: a mailbox sends far above its usual rate. | **Security** |
| `[Security] Authentication failure burst: {username}` | Anomaly detection: a username reaches the failed sign-in threshold. | **Security** |
| `Possible stolen password` | A sign-in after failed tries from the same address, or from a country the account has not used in 30 days. Bans from the same run are listed too. | **Security** |
| `Protection rules banned addresses` | A protection rule run banned addresses. | **Security** |
| `Protection rules could not ban` | Bans failed in a run with nothing else to report. The next run retries. | **Security** |
| `[Security] SMTP disabled (abuse protection): {mailbox}` | Abuse protection stops sending for a mailbox, automatically or when you block it. | **Security** |
| `Security alert: outgoing mail has been paused for your account` | The same event, to the mailbox owner: sending is paused, receiving still works, a mail app that used a revoked app password needs a new one (when they were revoked), and whom to contact. | The blocked mailbox, by email only |
| `DNS records changed for {domain}: {types}` | A DNS check finds a record changed since the last check, with old and new values. | **DNS record changes** |
| `Blacklist: 1 host is on a blacklist` or `Blacklist: {count} hosts are on a blacklist` | A check of all hosts finds a listing. Only hosts on a list that alerts are counted. Repeats on every such check while the listing lasts. | **IP blacklist** |
| `Blacklist: 1 host still listed (was {previous})` or `Blacklist: {count} hosts still listed (was {previous})` | Fewer hosts are listed than at the last check. | **IP blacklist** |
| `Blacklist: all hosts are clear` | No host is listed any more. | **IP blacklist** |
| `DMARC & TLS: 1 report email could not be imported` or `DMARC & TLS: {count} report emails could not be imported` | An IMAP import skipped report emails. | **DMARC processing errors** |
| `Weekly summary: {start date} to {end date}` | Monday at 09:00, or **Run**. | **Admin Email**, by email only |

Blocklist alerts come from the daily 05:00 check, the check at startup, **Check all now** on **Status** > **Blocklists** and **Run** on **IP Blacklist Check (All Hosts)**; a check of one host sends nothing. Ignored lists never count, and UCEPROTECT Level 2 and 3 do not count on their own. The previous count is kept in memory, so a restart resets it.

The weekly summary is sent on Mondays at 09:00 in the app's time zone (`TZ`) and covers the seven days before it: mail, the current system figures, blocklists, DNS problems and the five mailboxes with the most failures. **Run** on **Weekly Summary Report** under **Status** > **Jobs** sends it at once, unless **Enable Weekly Summary** is off. **Enable Weekly Summary** and **DNS Change Alerts Enabled** are both on by default.

What the owner of a blocked mailbox is told is in [Outgoing spam](HelpDocs/Abuse_Protection.md#what-happens-when-a-mailbox-is-stopped). Turning sending back on sends no email.

## Custom webhook payload

A **Custom webhook (JSON)** destination gets a POST like this:

```json
{
  "title": "Test notification",
  "message": "This is a test notification from mailcow Logs Viewer. If you can read this, the channel is working.",
  "source": "mailcow-logs-viewer",
  "timestamp": "2026-10-16T09:00:00+00:00"
}
```

Destinations get plain text, cut to about 1,900 characters; email has the full text. The app waits up to 10 seconds for a destination to answer.

## When nothing arrives

- **A destination gets nothing.** Check **Enabled**, its topics and its error, then click **Test**. A test skips the topic check.
- **There is no Notifications tab.** It appears only while `SETTINGS_EDIT_VIA_UI_ENABLED` is on, and it stays read-only until you click **Migrate Settings from ENV**; see [Settings](HelpDocs/Settings.md#enable-editing-and-migrate-from-env). Saved destinations keep working either way.

The old single webhook (`WEBHOOK_*` variables) becomes a destination once during the upgrade, if no destination exists yet. After that the app ignores those variables.
