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

<!-- VERIFY: owner's decision pending (finding 42): the Will unsync tag can never appear (it needs active=False with synced_to_rspamd=True, which no code path leaves). The Rspamd row below does not mention it; update that row once decided. -->
| Value | Meaning |
|---|---|
| **Reason** | Hard Bounce: `5.x.x`; Soft Bounce: `4.x.x`; Deferred Stuck: queue cleanup; Rejected: another bounce status. |
| Source | `auto`: added by the app; `manual`: added in the dialog; `import`: CSV. |
| **Bounces** | Total counted bounces, with hard (`H:`) and soft (`S:`) counts. |
| **Rspamd** | **Synced**: written to the map; **Pending**: awaiting a write. Disabling marks the entry for the next sync; the row does not reliably show whether its old map entry remains. |

### Automatic suppressions

With **Suppression Enabled** on, two jobs add entries every 5 minutes:

- **Detect Suppressions**, with **Suppression Auto Detect** on, checks delivery-agent `bounced` lines imported in the last 10 minutes. It also checks `deferred` lines when **Queue Cleanup Enabled** is off. Connection-time rejections (`NOQUEUE`) do not create suppressions. Empty senders and `MAILER-DAEMON` are skipped.
- **Cleanup Deferred Queue**, with **Queue Cleanup Enabled** on and the read-write key, deletes deferred messages older than **Queue Cleanup Threshold Minutes** (60 by default) and suppresses their recipients as **Deferred Stuck**.

Log detection skips recipients in **Suppression Whitelist Domains**, matching exact domains without subdomains. Hard and soft bounces follow their configured actions. For a hard bounce, matching queued messages are also deleted when the read-write key is available.

<!-- VERIFY: owner's decision pending (finding 6): cleanup_deferred_queue_job deletes stuck mail to whitelisted domains too and only skips the suppression. Update the next paragraph and the Suppression Whitelist Domains item below once decided. -->
The whitelist prevents recipient suppression, but it does not protect queued messages from deletion. Cleanup uses age since arrival, including time before a message became deferred.

Automatic entries start with **Suppression Base Expiry Days** (7 by default). Each bounce sets expiry to base days times bounce count, capped at **Suppression Max Expiry Days** (90). Log lines are counted once across restarts and overlapping runs. Detection reactivates inactive entries, except soft bounces below the **Count then suppress** threshold.

Earlier versions could double-count bounces. When **Suppression Soft Bounce Action** is **Count then suppress**, the upgrade disables automatic soft-bounce suppressions and resets their counts to 0. The next sync removes them from Rspamd; new bounces must reach the threshold again. The application log reports how many were lifted. Other entries are unchanged.

With **Suppression Rspamd Sync** on, new and updated automatic entries are written to Rspamd right after detection. Automatic entries always match the exact address.

### Add a suppression

![Add Suppression dialog](../../images/docs/spam-filter-add-suppression-light.webp#gh-light-mode-only)
![Add Suppression dialog](../../images/docs/spam-filter-add-suppression-dark.webp#gh-dark-mode-only)

A domain must be entered as a plain name. It matches that exact domain, excluding subdomains. **Email Address** also accepts patterns such as `/^.+@example\.(net|org)$/i`; the app anchors the whole pattern when writing it to Rspamd.

Entries are permanent by default. Temporary entries last 1 to 365 days, 7 by default. Adding an existing inactive address reactivates it as a permanent manual entry and ignores the expiry fields; an active duplicate is refused.

With the read-write key, adding an entry deletes queued messages to that address, or every recipient at that domain, then writes the suppression list to Rspamd.

### Edit, disable and delete

**Disable** keeps the entry but removes its block on the next sync. Re-enabling an expired entry requires a new expiry or **Permanent block**; otherwise the hourly expiry job disables it again. **Delete** removes the entry permanently.

Adding, editing, enabling, disabling, deleting or importing triggers a background sync when the read-write key is configured.

### Sync to Rspamd

Manual sync writes active entries to `global_rcpt_blacklist.map`. Automatic sync runs every 10 minutes with **Suppression Enabled**, **Suppression Rspamd Sync**, the Rspamd password and read-write key configured.

The app replaces only the section between these markers; put your own entries above it:

```
# === MANAGED BY MAILCOW LOGS VIEWER - DO NOT EDIT BELOW ===
# === END MANAGED SECTION ===
```

The map is written only when managed entries change. If the existing map cannot be read, sync fails without writing and retries next time. Bare addresses in your own lines are anchored during sync so they cannot match longer addresses containing them.

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

> [!WARNING]
> In **Recipient Denylist**, add your own entries only above the line `# === MANAGED BY MAILCOW LOGS VIEWER - DO NOT EDIT BELOW ===`. The suppression sync replaces everything between that line and `# === END MANAGED SECTION ===`, so entries you add there are lost on the next sync.

### Regex Wizard

The wizard's **Domain** pattern includes subdomains, unlike a domain suppression. Its explanation says "Blocks", but the map determines the effect: the same pattern in an allowlist allows matching mail.

## Settings that change this page

Under **Settings** > **Spam Filter**:

- **Suppression Enabled** defaults off. **Suppression Auto Detect** and **Suppression Rspamd Sync** default on. Page edits can sync even when these automatic switches are off.
- **Suppression Hard Bounce Action** defaults to **Suppress**; **Ignore** skips hard bounces.
<!-- VERIFY: owner's decision pending (finding 14): the soft-bounce settings apply only to log detection, which runs only while Queue Cleanup Enabled is off (on by default). Keep or change the note below once decided. -->
- **Suppression Soft Bounce Action** defaults to **Count then suppress**: soft bounces are counted on an inactive entry, which turns active at **Suppression Soft Bounce Threshold** (3 by default). **Suppress** activates at the first bounce; **Ignore** skips them. These actions apply to deferred log detection only when **Queue Cleanup Enabled** is off.
- **Queue Cleanup Enabled** defaults on.
- **Suppression Whitelist Domains** accepts comma-separated exact domains and prevents suppression, but does not protect queued mail from deletion.

The jobs, including hourly expiry, require **Suppression Enabled**. With it off, manual entries can still sync, but expiry does not run.

Under **Settings** > **Mailcow**, set **Rspamd Password** to read or sync maps. Leave **Rspamd URL** empty to use mailcow's path; try a direct URL such as `http://rspamd-mailcow:11334` if that fails. See [Settings](Settings.md#spam-filter).

## When something is missing

- **No read-write API key**: suppressions can be added, edited and deleted locally, but cannot sync. Maps are read-only and queue cleanup does not run. See [Getting started](../GETTING_STARTED.md).
- **No Rspamd password**: maps cannot load and sync does not run.
- **Rspamd cannot be reached**: check the application logs, password and **Rspamd URL**.

## How suppressions work

A delivery status starting with `5`, such as `5.1.1` (unknown user), is a permanent failure or hard bounce. A `4` status, such as `4.2.2` (mailbox full), is temporary; Postfix keeps retrying from the deferred queue. Suppressions reject new mail to failing recipients before it is sent. Automatic entries expire so recovered recipients are not blocked forever.

## How Rspamd maps work

Maps provide values for mail-filtering rules. In a regular-expression map, each line matches anywhere in the value: bare `ann@example.com` also matches `joann@example.com`. The app writes `/^ann@example\.com$/i` instead: `^` and `$` anchor the full value, and `i` ignores case.
