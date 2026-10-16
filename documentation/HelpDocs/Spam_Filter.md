# Spam Filter

The Spam Filter page manages the addresses your mailcow server stops sending to, and the Rspamd maps that allow or block mail. The suppression list is kept in this app's database and written to an Rspamd map; the maps are read from Rspamd and saved through the mailcow API.

The page has two tabs: **Suppressions** and **Rspamd Maps**.

## Suppressions

![Spam Filter, Suppressions](../../images/docs/spam-filter-suppressions-light.webp#gh-light-mode-only)
![Spam Filter, Suppressions](../../images/docs/spam-filter-suppressions-dark.webp#gh-dark-mode-only)

Suppressions block recipients that keep bouncing, plus addresses and domains you add by hand. The app writes active entries to `global_rcpt_blacklist.map` (**Recipient Denylist**) so Rspamd rejects new mail to them. See [How suppressions work](#how-suppressions-work).

The tab refreshes itself every 30 seconds while no dialog is open.

### Key figures

**Active** counts enabled entries; **Hard Bounces** and **Soft Bounces** count active entries with those reasons. **Pending Sync** counts active entries not yet written to Rspamd.

### Find a suppression

- The search field (**Search email, notes...**) looks in the address, the notes and the last bounce message. Press Enter to search.
- **Reason**: **All Reasons**, **Hard Bounce**, **Soft Bounce**, **Deferred Stuck**, **Rejected** or **Manual**.
- **State**: **Active Only** (the default), **All**, **Inactive** or **Expired**. **Expired** shows entries that were turned off because their expiry date passed.
- **Clear filters** empties the search, sets **Reason** to all and **State** back to **Active Only**.

Next to the search are **Add Suppression**, **Sync to Rspamd** and **More**, which holds **Export CSV** and **Import CSV**.

### The list

<!-- VERIFY: owner's decision pending (finding 42): the Will unsync tag can never appear (it needs active=False with synced_to_rspamd=True, which no code path leaves). The Rspamd row below does not mention it; update that row once decided. -->
| Column | What it shows |
|---|---|
| **Address** | The suppressed address. Click it to copy. A domain suppression shows the domain with a **Domain** tag; hover over the tag for the stored pattern. **Inactive** and **Expired** tags mark entries that are off. Notes appear under the address. |
| **Reason** | Why the address is suppressed (see below) and the source: `auto` (added by the app), `manual` (added in the dialog) or `import` (from a CSV file). |
| **Bounces** | How many bounces the app has counted, with the hard (`H:`) and soft (`S:`) counts. |
| **Expiry** | When the suppression ends, for example "Expires in 6 days", or **Permanent**. |
| **Rspamd** | **Synced** when the entry is in the Rspamd map, **Pending** when it still has to be written. Disabling an entry marks it for the next sync; the row does not reliably show whether its old map entry is still present. |
| **Added** | How long ago the entry was created. Hover for the exact time. |

Sort by **Address**, **Reason**, **Bounces**, **Expiry** or **Added**. Use **Prev** and **Next** for pages of 50 entries. Row actions are **Edit**, **Disable** or **Enable**, and **Delete**.

Reasons are **Hard Bounce** (`5.x.x`), **Soft Bounce** (`4.x.x`), **Deferred Stuck** (queue cleanup), **Rejected** (another bounce status) and **Manual**. Soft-bounce log detection runs only with **Queue Cleanup Enabled** off.

### Automatic suppressions

With **Suppression Enabled** on, the app adds suppressions in two ways.

From the Postfix logs, every 5 minutes (**Detect Suppressions**, needs **Suppression Auto Detect** on):

- It checks delivery-agent `bounced` lines imported in the last 10 minutes, plus `deferred` lines when **Queue Cleanup Enabled** is off. Connection-time rejections (`NOQUEUE`) do not create suppressions.
- It skips bounce notifications themselves (empty sender or `MAILER-DAEMON`), so your own sender addresses are never suppressed.
- It skips recipients whose domain is listed in **Suppression Whitelist Domains**. The domain must match exactly; a subdomain is not covered.
- A hard bounce follows **Suppression Hard Bounce Action**; a soft bounce follows **Suppression Soft Bounce Action**.
- For a hard bounce, the app also deletes the messages for that recipient that are still in the mailcow queue. This needs the read-write key.

From the mail queue, every 5 minutes (**Cleanup Deferred Queue**, needs **Queue Cleanup Enabled** on and the read-write key):

- It looks at the deferred queue in mailcow. A message that arrived longer ago than **Queue Cleanup Threshold Minutes** (60 by default) is deleted from the queue, and its recipients are suppressed with the reason **Deferred Stuck**.

<!-- VERIFY: owner's decision pending (finding 6): cleanup_deferred_queue_job deletes stuck mail to whitelisted domains too and only skips the suppression. Update the next paragraph and the Suppression Whitelist Domains item below once decided. -->
The whitelist prevents recipient suppression, but it does not protect queued messages from deletion. Cleanup uses age since arrival, including time before a message became deferred.

A new automatic entry lasts **Suppression Base Expiry Days** (7 by default). Each detected bounce sets the expiry to base days times bounce count, capped at **Suppression Max Expiry Days** (90). Each bounce in the log is counted once. Another detection also reactivates an inactive entry, except a soft bounce under **Count then suppress** that has not reached the threshold.

After it adds or updates entries, the app writes the list to Rspamd at once when **Suppression Rspamd Sync** is on. An automatic entry is always written as the exact address, so an odd-looking recipient can never block other recipients.

### Add a suppression

![Add Suppression dialog](../../images/docs/spam-filter-add-suppression-light.webp#gh-light-mode-only)
![Add Suppression dialog](../../images/docs/spam-filter-add-suppression-dark.webp#gh-dark-mode-only)

**Add Suppression** opens a dialog:

| Field | What to enter |
|---|---|
| **Type** | **Email Address** or **Domain**. |
| **Email Address** or **Domain Name** | The address, for example `bob@example.net`, or a plain domain name, for example `example.net`. |
| **Reason** | **Manual**, **Hard Bounce**, **Soft Bounce**, **Deferred Stuck** or **Rejected**. |
| **Notes (optional)** | Why you added it. |
| **Permanent block** | On by default. Turn it off to set **Expires after (days)**, from 1 to 365, 7 by default. |

A domain is stored as the pattern `/^.+@example\.net$/i`, which matches every address at exactly that domain, not its subdomains. Only a plain domain name is accepted; anything else shows "Enter a plain domain name, for example example.com". With **Type** set to **Email Address** you can also enter your own pattern between slashes, such as `/^.+@example\.(net|org)$/i`. When the app writes it to Rspamd, it anchors the whole pattern so it cannot match more than the full address.

If the address is already actively suppressed, the dialog says "This address is already suppressed". If it exists but is off, it is turned on again as a permanent manual entry, and the expiry fields are ignored.

What adding a suppression changes in mailcow:

- With the read-write key, the app deletes the messages to that address that are waiting in the mailcow queue. For a domain, it deletes queued messages to every recipient at that domain.
- The app then writes the list to Rspamd.

The **Suppress** button on the [Queue](Queue.md) page opens the same dialog with the recipient filled in and the note "Added from queue page".

### Edit, disable and delete

**Edit Suppression** shows the address, reason, source, bounces and creation time. Edit **Notes** or **Permanent block**. For a temporary entry, set **Expiry date & time**; **+7 days**, **+14 days**, **+30 days** and **+90 days** extend that date. Use **Save Changes**.

**Disable** turns an entry off and keeps it in the list. **Enable** turns it on again. If its expiry date has already passed, set a new expiry or mark it permanent with **Edit**; otherwise **Expire Suppressions** turns it off again within the hour.

**Delete** removes the entry after you confirm. It cannot be undone.

After you add, edit, enable, disable, delete or import, the page writes the list to Rspamd in the background when the read-write key is configured. A disabled or deleted address leaves the Rspamd map with that write.

### Sync to Rspamd

**Sync to Rspamd** writes active entries to `global_rcpt_blacklist.map` and reports total and new counts. Automatic sync runs every 10 minutes with **Suppression Enabled**, **Suppression Rspamd Sync**, the Rspamd password and read-write API key configured.

The app owns only part of the map. It keeps every line above its start marker and replaces everything from the marker to the end marker:

```
# Entries added by hand stay here
/^alice@example\.org$/i

# === MANAGED BY MAILCOW LOGS VIEWER - DO NOT EDIT BELOW ===
# Last sync: 2026-01-15T08:30:00Z | Active: 2
/^bob@example\.net$/i
/^(?:.+@example\.com)$/i
# === END MANAGED SECTION ===
```

- The map is written only when the managed entries changed, so Rspamd does not reload it for nothing.
- If the app cannot read the current map, it does not write it, so your own lines are never lost. The sync is recorded as failed and runs again next time.
- A bare address among your own lines, such as `carol@example.org`, is anchored to `/^carol@example\.org$/i` during the sync. In this map a bare address would also match every longer address that contains it.

### Import and export

**Export CSV** downloads every suppression as `spam_suppressions.csv` with the columns `email`, `type`, `reason`, `source`, `notes`, `bounce_count`, `hard_bounces`, `soft_bounces`, `active`, `expires_at` and `created_at`, plus a helper column the app uses to read its own export back.

**Import CSV** reads a `.csv` file with the columns `email`, `type`, `reason` and `notes`:

- A header row is optional. If the first cell is `email` or `address`, the columns are read by name; otherwise they are read in that order.
- Addresses that already exist, and repeats within the file, are skipped.
- A `type` other than `email` or `domain` becomes `email`. A `reason` other than `hard_bounce`, `soft_bounce`, `rejected` or `manual` becomes `manual`.
- For a domain, use the pattern form, such as `/^.+@example\.net$/i`, as the export writes it.
- Imported entries are active, permanent and have the source `import`.

The result gives imported and skipped counts. Re-importing an export does not restore state or expiry: `active` and `expires_at` are ignored, and `deferred_stuck` becomes `manual`.

## Rspamd Maps

![Spam Filter, Rspamd Maps](../../images/docs/spam-filter-maps-light.webp#gh-light-mode-only)
![Spam Filter, Rspamd Maps](../../images/docs/spam-filter-maps-dark.webp#gh-dark-mode-only)

This tab lists the 13 Rspamd map files mailcow ships, grouped as **Sender Rules**, **Recipient Rules**, **Content Rules** and **System**. Each row shows the map's name and purpose, its file name, and whether Rspamd has it **Loaded** or **Not loaded**. **Recipient Denylist** carries an **Auto-managed** tag because the suppression list writes to it.

| Map | File | What it does in mailcow |
|---|---|---|
| **Header-From: Denylist** | `global_mime_from_blacklist.map` | Header From match adds 2050 to the score. |
| **Header-From: Allowlist** | `global_mime_from_whitelist.map` | Header From match subtracts 2050. |
| **Envelope Sender Denylist** | `global_smtp_from_blacklist.map` | Envelope sender match adds 2050. |
| **Envelope Sender Allowlist** | `global_smtp_from_whitelist.map` | Envelope sender match subtracts 2050. |
| **Recipient Denylist** | `global_rcpt_blacklist.map` | Rejects mail to matching recipients. Holds the suppression list. |
| **Recipient Allowlist** | `global_rcpt_whitelist.map` | Accepts mail to matching recipients. |
| **Fishy TLDs** | `fishy_tlds.map` | Suspicious top-level domains. Only fired together with bad words. |
| **Bad Words** | `bad_words.map` | Words in the message text. Only fired together with fishy TLDs. |
| **Bad Words DE** | `bad_words_de.map` | German bad words. Only fired together with fishy TLDs. |
| **Bad Languages** | `bad_languages.map` | Languages to score as spam. |
| **Bulk Mail Headers** | `bulk_header.map` | Header patterns of bulk and mass mail. |
| **Bad Mail Headers** | `bad_header.map` | Header patterns of junk mail. |
| **Monitoring Hosts** | `monitoring_nolog.map` | Hosts excluded from logging. |

The app treats every map the same way: a line between slashes is checked as a regular expression, and bare addresses are anchored when you save. See [How Rspamd maps work](#how-rspamd-maps-work).

### Edit a map

![Map editor for Recipient Denylist](../../images/docs/spam-filter-map-editor-light.webp#gh-light-mode-only)
![Map editor for Recipient Denylist](../../images/docs/spam-filter-map-editor-dark.webp#gh-dark-mode-only)

Open a map to edit its text. Lines starting with `#` are comments; blank lines do not count as entries. **Rspamd Maps** in the breadcrumb returns to the list.

Edits show a **Modified** tag and save bar. **Discard** reloads from Rspamd; **Save changes** validates and writes the map.

**Validate** checks the text without saving:

- A line written as `/pattern/` or `/pattern/i` must be a valid regular expression. An invalid one is reported as an error with its line number.
- A bare address, such as `dave@example.com`, is reported as a warning: in a regular-expression map it also matches every address that contains it, such as `eve.dave@example.com`. The app anchors it when you save.
- Other lines (words, domains, header patterns, language codes) are accepted as they are.

Validation lists errors and warnings by line.

**Save changes** refuses invalid maps, anchors bare addresses and writes the whole map through mailcow. The result gives entry and anchoring counts; the editor shows the saved text. Rspamd reloads the map.

> [!WARNING]
> In **Recipient Denylist**, add your own entries only above the line `# === MANAGED BY MAILCOW LOGS VIEWER - DO NOT EDIT BELOW ===`. The suppression sync replaces everything between that line and `# === END MANAGED SECTION ===`, so entries you add there are lost on the next sync.

The page does not refresh the editor on its own, so an unsaved edit is not overwritten.

### Regex Wizard

**+ Regex Wizard** opens **Regex Pattern Generator**. Choose a type and value; **Add** appends the generated pattern to the map.

| Type | Value | Generated pattern | Matches |
|---|---|---|---|
| **Exact Email** | `user@example.com` | `/^user@example\.com$/i` | That address only. |
| **Domain** | `example.com` | `/^.+@(.+\.)?example\.com$/i` | Every address at `example.com` and its subdomains. |
| **TLD** | `xyz` | `/^.+\.xyz$/i` | Every value ending in `.xyz`. |
| **Keyword** | `sale` | `/.*sale.*/i` | Every value that contains `sale`. |

The explanation always says "Blocks", but the effect depends on the map: in an allowlist the same pattern allows.

## Settings that change this page

In **Settings** > **Spam Filter**:

- **Suppression Enabled** defaults off. **Suppression Auto Detect** and **Suppression Rspamd Sync** default on and control bounce detection and automatic map writes. Page edits can sync even when these automatic switches are off.
- **Suppression Hard Bounce Action** defaults to **Suppress**; **Ignore** skips hard bounces.
<!-- VERIFY: owner's decision pending (finding 14): the soft-bounce settings apply only to log detection, which runs only while Queue Cleanup Enabled is off (on by default). Keep or change the note below once decided. -->
- **Suppression Soft Bounce Action** defaults to **Count then suppress**. It records soft bounces on an inactive entry and activates it when the recipient reaches **Suppression Soft Bounce Threshold** soft bounces (3 by default). **Suppress** activates at the first soft bounce; **Ignore** skips soft bounces. Deferred messages are read from the logs only while **Queue Cleanup Enabled** is off; while it is on, the queue cleanup handles them instead.
- **Queue Cleanup Enabled** defaults on. **Queue Cleanup Threshold Minutes** defaults to 60, measured since arrival.
- **Suppression Base Expiry Days** and **Suppression Max Expiry Days** default to 7 and 90. Repeated detections extend expiry as [described above](#automatic-suppressions).
- **Suppression Whitelist Domains** accepts comma-separated exact domains and prevents suppression, but does not protect queued mail from deletion.

Under **Settings** > **Mailcow**, **Rspamd Password** is required to read maps and sync. Leave **Rspamd URL** empty to use mailcow's path; set a direct URL such as `http://rspamd-mailcow:11334` if that path fails. **Connection** > **mailcow API Key (read-write)** enables map writes, sync and queue deletion. See [Settings](Settings.md#spam-filter).

On **Status** > **Jobs**, the **Spam Filter** group offers **Run** for **Detect Suppressions** (5 minutes), **Sync to Rspamd** (10 minutes), **Expire Suppressions** (hourly) and **Cleanup Deferred Queue** (5 minutes).

All require **Suppression Enabled**. With it off, manual entries can still sync, but expiry does not run. See [Settings](Settings.md), [Status](Status.md) and [environment variables](../ENV_Settings.md).

## When something is missing

| Situation | What you see |
|---|---|
| The Spam Filter feature is turned off | The page shows **Spam Filter is disabled** with **Go to Dashboard**. Turn it on in **Settings** > **Features**. |
| No read-write API key | **Suppressions** shows **Syncing to Rspamd is locked**: the list is kept in the app but not sent to Rspamd. **Sync to Rspamd** is disabled and new entries stay **Pending**. Queue cleanup does not run. **Rspamd Maps** shows **Read-Only Mode**: you can open every map, but the text is read-only and **Validate**, **+ Regex Wizard** and the save bar are hidden. |
| No Rspamd password | **Rspamd Maps** shows **Rspamd Not Configured** with **Go to Settings**. **Sync to Rspamd** fails with "Rspamd password not configured", and the automatic sync does not run. |
| Rspamd cannot be reached | **Rspamd Maps** says "Unable to load Rspamd maps. Check the application logs." Check the Rspamd password and the **Rspamd URL** setting. |
| No suppressions match | **No Suppressions**: "Suppressed addresses will appear here when detected or added manually." |

Adding, editing and deleting suppressions need no read-write API key. When that key is configured, creating a suppression can also delete matching queued messages, and page edits can trigger a sync. Writing to Rspamd and deleting queued mail need the read-write key. [Getting started](../GETTING_STARTED.md) explains how to create it.

## How suppressions work

When a message cannot be delivered, the receiving server answers with a status code. A code starting with `5` (such as `5.1.1`, unknown user) is a permanent failure, a hard bounce. A code starting with `4` (such as `4.2.2`, mailbox full) is temporary; Postfix keeps the message in its deferred queue and retries it.

Sending again and again to an address that bounces wastes resources and can hurt your server's reputation with the receiving provider. A suppression stops it: the address goes into the Rspamd recipient denylist, and Rspamd rejects new mail to it before it is sent. Automatic suppressions expire, so an address that starts working again is not blocked forever.

## How Rspamd maps work

Rspamd maps hold values used by mail filtering rules. The app saves them through the mailcow API; Rspamd reloads changed files.

In a regular-expression map, every line is a pattern, and a pattern matches when it is found anywhere in the value. That is why a bare line such as `ann@example.com` also matches `joann@example.com`, and why the app writes and anchors addresses as `/^ann@example\.com$/i`. The `^` and `$` tie the pattern to the start and end of the value, and the `i` ignores case.
