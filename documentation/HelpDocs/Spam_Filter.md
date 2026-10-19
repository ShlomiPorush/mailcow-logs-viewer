# Spam Filter

Suppressions are kept in the app's database and written to Rspamd's recipient denylist. Other Rspamd maps are read from Rspamd and saved through mailcow's API.

## Suppressions

![Spam Filter, Suppressions](../../images/docs/spam-filter-suppressions-light.webp#gh-light-mode-only)
![Spam Filter, Suppressions](../../images/docs/spam-filter-suppressions-dark.webp#gh-dark-mode-only)

Active suppressions go into `global_rcpt_blacklist.map` (**Recipient Denylist**), where Rspamd rejects new mail to matching recipients.

### Key figures

**Active** counts enabled entries. **Hard Bounces** and **Soft Bounces** count active entries with those reasons, not individual bounces. **Pending Sync** counts active entries not yet written to Rspamd.

### Find a suppression

Search matches the address, notes and last bounce message. **Expired** shows entries turned off after their expiry date passed.

### The list

| Value | Meaning |
|---|---|
| **Reason** | Hard Bounce: `5.x.x`; Soft Bounce: `4.x.x`; Deferred Stuck: queue cleanup; Rejected: another bounce status. |
| Source | `auto`: added by the app; `manual`: added in the dialog; `import`: CSV; **From Rspamd**: added in mailcow to this app's part of the Rspamd map, or loaded back from it when Spam Filter was turned on again. These are permanent and no automatic handling changes them; you can edit or delete them. |
| **Bounces** | Total counted bounces, with hard (`H:`) and soft (`S:`) counts. |
| **Rspamd** | **Synced**: in step with the map; **Pending**: waiting to be added, or, on a disabled or expired entry, to be removed. |

### Block details

**Block details** on a row shows why the address is blocked, newest first: each bounce that blocked it, extended its block or only counted toward the threshold, each stuck message the queue cleanup deleted, and each change by hand. A bounce keeps the server's reply, the sender, the subject, the Queue ID, the Message-ID and that message's Postfix lines for this address (at most 50, always with the line that decided it). The details are copied when they happen, so they stay after the logs and the message are deleted, for as long as the address is on the list. **Open message** opens the message while it is still on **Messages**. Addresses blocked before this version show only the reason their row kept.

### Automatic suppressions

With **Handle undeliverable mail automatically** on (**Settings** > **Queue Management**), two jobs add entries every 5 minutes:

- **Detect Suppressions** checks delivery-agent `bounced` lines imported in the last 10 minutes, and `deferred` lines when a temporary failure keeps retrying. It runs when a Queue Management choice needs the Postfix logs. Connection-time rejections (`NOQUEUE`) do not create suppressions. Empty senders and `MAILER-DAEMON` are skipped.
- **Cleanup Deferred Queue**, when a temporary failure is set to **Delete after N minutes in the queue** and the read-write key is set, deletes deferred messages older than those minutes (60 by default) and suppresses their recipients as **Deferred Stuck**. The age counts from arrival, including time before a message became deferred. The recipients are blocked before the message is deleted: if the deletion fails, the next run deletes it without counting it again. A message with no address that can be blocked stays in the queue.

**Exclude these domains** lists exact domains, without subdomains. Their addresses are never blocked automatically, and a queued message to any of them is never deleted automatically, by cleanup or after a permanent failure. For a permanent failure, other queued messages to the blocked address are deleted when the read-write key is set.

Automatic entries start with **Base block length** (7 days by default). Each bounce sets expiry to base days times bounce count, capped at **Maximum block length** (90). Log lines are counted once across restarts and overlapping runs. Detection reactivates inactive entries, except soft bounces below the failures that **Keep retrying; block new mail after N failures** waits for.

Earlier versions could double-count bounces. When temporary failures are set to block after N failures, the upgrade disables automatic soft-bounce suppressions and resets their counts to 0. The next sync removes them from Rspamd; new bounces must reach the threshold again. The application log reports how many were lifted. Other entries are unchanged.

With **Sync with Rspamd** on, new and updated automatic entries are written to Rspamd right after detection. Automatic entries always match the exact address.

### Add a suppression

![Add Suppression dialog](../../images/docs/spam-filter-add-suppression-light.webp#gh-light-mode-only)
![Add Suppression dialog](../../images/docs/spam-filter-add-suppression-dark.webp#gh-dark-mode-only)

A domain must be entered as a plain name. It matches that exact domain, excluding subdomains. **Email Address** also accepts patterns such as `/^.+@example\.(net|org)$/i`; the app anchors the whole pattern when writing it to Rspamd.

Entries are permanent by default. Temporary entries last 1 to 365 days, 7 by default. Adding an existing inactive address reactivates it as a permanent manual entry and ignores the expiry fields; an active duplicate is refused.

With the read-write key, adding an entry deletes queued messages to that address, or every recipient at that domain.

### Edit, disable and delete

**Disable** keeps the entry and removes its block from Rspamd with the next write. Re-enabling an expired entry requires a new expiry or **Permanent block**; otherwise the hourly expiry job disables it again. **Delete** removes the entry permanently; its block is removed from Rspamd with the next write.

With **Sync with Rspamd** on, adding, enabling, disabling, deleting or importing is written to Rspamd at once.

### Sync with Rspamd

With **Sync with Rspamd** on (**Settings** > **Queue Management**), the list and the app's part of `global_rcpt_blacklist.map` are kept in step both ways, by themselves. Every 10 minutes, and before every write, the app reads its part of the map: a block deleted there in mailcow is deleted from the list, and a block added there joins the list as **From Rspamd**. Then the list's changes are written. A change that could not be written waits, shown as **Pending**, and is written on the next try. Reading needs the Rspamd password; writing also needs the read-write key. It does not need **Handle undeliverable mail automatically**: a list kept by hand syncs too.

With it off, the list is not synced: it does not change what Rspamd blocks, and changes made in mailcow do not come into it until the sync is on again. A note above the list says so.

The app's part is the section between these markers; your own entries go above or below it:

```
# === MANAGED BY MAILCOW LOGS VIEWER - DO NOT EDIT BELOW ===
# === END MANAGED SECTION ===
```

A write starts from the map as it is then and changes only the list's waiting entries, so changes made in mailcow stay; one made at the very moment of a write can still be lost. Nothing is written when nothing changes. If the map cannot be read, or the markers are missing or repeated, nothing is read in or written until that is fixed. A write counts only when mailcow confirms it; one whose answer was lost is checked on the next read. Connecting to another mailcow or Rspamd makes every active entry wait to be written there; none is deleted. An entry deleted from the list before this version while its block stayed in Rspamd comes back as **From Rspamd**. Your own lines, above and below the app's section, stay. Bare addresses among them are anchored during sync so they cannot match longer addresses containing them; a line with regex characters, such as `.*@example\.com`, is left as written.

### When the sync stops or starts

Turning **Sync with Rspamd** off, or turning Spam Filter off with its list, asks whether to remove the app's blocks from Rspamd or keep them. Removing empties only the managed section; your lines above it stay. Turning the sync back on first reads in what changed in mailcow meanwhile, then says how many of the list's changes will be written, with **Start fresh** to empty both the list and the managed section.

### Import and export

Export includes every suppression and its state, counts and expiry. Import reads `email`, `type`, `reason` and `notes`:

- Headers are optional. If the first cell is `email` or `address`, columns are read by name; otherwise use the order above.
- Existing addresses and repeats are skipped.
- Unknown types become `email`. Reasons other than `hard_bounce`, `soft_bounce`, `rejected` or `manual` become `manual`.
- Domain entries need pattern form, such as `/^.+@example\.net$/i`, as in the export.
- Imported entries are active and permanent, with source `import`. Re-importing an export does not restore state or expiry, and `deferred_stuck` becomes `manual`.

## Rspamd Maps

![Spam Filter, Rspamd Maps](../../images/docs/spam-filter-maps-light.webp#gh-light-mode-only)
![Spam Filter, Rspamd Maps](../../images/docs/spam-filter-maps-dark.webp#gh-dark-mode-only)

Header-From and envelope-sender denylists add 2050 to the spam score; their allowlists subtract 2050. Recipient Denylist rejects matching recipients; Recipient Allowlist accepts them. Fishy TLDs and bad-word rules fire only together. Monitoring Hosts excludes matching hosts from logging.

**Auto-managed** on Recipient Denylist means the suppression list writes to it.

### Edit a map

![Map editor for Recipient Denylist](../../images/docs/spam-filter-map-editor-light.webp#gh-light-mode-only)
![Map editor for Recipient Denylist](../../images/docs/spam-filter-map-editor-dark.webp#gh-dark-mode-only)

Lines starting with `#` are comments; blank lines do not count as entries. Validation checks slash-delimited regular expressions and warns about bare addresses. Other lines, including words, domains, header patterns and language codes, are accepted as entered.

Saving refuses invalid patterns, anchors bare addresses and writes the whole map through mailcow. Rspamd reloads it. **Discard** reloads from Rspamd. The editor does not refresh automatically while you edit.

> [!NOTE]
> In **Recipient Denylist**, the lines between `# === MANAGED BY MAILCOW LOGS VIEWER - DO NOT EDIT BELOW ===` and `# === END MANAGED SECTION ===` are the suppression list. An entry you add or delete there is added to or deleted from the list on the next read. Keep each marker line once.

### Regex Wizard

The wizard's **Domain** pattern includes subdomains, unlike a domain suppression. Its explanation says "Blocks", but the map determines the effect: the same pattern in an allowlist allows matching mail.

## Settings that change this page

Under **Settings** > **Queue Management**:

- **Sync with Rspamd** defaults on. **Handle undeliverable mail automatically** defaults off; it decides only whether blocks are added automatically.
- **Permanent delivery failure** defaults to blocking new mail to the address and deleting its queued mail; **Do nothing** skips permanent failures.
- **Temporary delivery failure** defaults to **Delete after 60 minutes in the queue and block the recipients**. Keeping the message instead counts soft bounces on an inactive entry, which turns active after the set failures (3 by default), or at the first one; **Do nothing; keep retrying** skips them.
- **Exclude these domains** accepts comma-separated exact domains.

The jobs, including hourly expiry, require **Handle undeliverable mail automatically**, except the sync with Rspamd. With it off, expiry does not run.

Under **Settings** > **Mailcow**, set **Rspamd Password** to read or sync maps. Leave **Rspamd URL** empty to use mailcow's path; try a direct URL such as `http://rspamd-mailcow:11334` if that fails. See [Settings](Settings.md#queue-management).

## When something is missing

- **No read-write API key**: suppressions can be added, edited and deleted locally, but cannot sync. Maps are read-only and queue cleanup does not run. See [Getting started](../GETTING_STARTED.md).
- **No Rspamd password**: maps cannot load and sync does not run.
- **Rspamd cannot be reached**: check the application logs, password and **Rspamd URL**.

## How suppressions work

A delivery status starting with `5`, such as `5.1.1` (unknown user), is a permanent failure or hard bounce. A `4` status, such as `4.2.2` (mailbox full), is temporary; Postfix keeps retrying from the deferred queue. Suppressions reject new mail to failing recipients before it is sent. Automatic entries expire so recovered recipients are not blocked forever.

## How Rspamd maps work

Maps provide values for mail-filtering rules. In a regular-expression map, each line matches anywhere in the value: bare `ann@example.com` also matches `joann@example.com`. The app writes `/^ann@example\.com$/i` instead: `^` and `$` anchor the full value, and `i` ignores case.
