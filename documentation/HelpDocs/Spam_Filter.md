# Spam Filter - User Guide

## Overview
The Spam Filter page provides two key features for managing email delivery and spam protection through your mailcow server's Rspamd integration.

## Features

### 1. Suppressions (Email Suppression List)
Manage a list of email addresses that should be blocked from receiving outbound emails. This prevents wasted sending to addresses that consistently bounce.

#### How It Works
- **Automatic Detection**: The system monitors your Postfix logs for bounced and rejected emails
- **Smart Filtering**: Only real outbound messages are processed - bounce notifications (DSN messages from MAILER-DAEMON) are automatically skipped to prevent your own sender addresses from being suppressed
- **Progressive Blocking**: Each repeated bounce extends the suppression duration:
  - 1st bounce → 7 days (configurable)
  - 2nd bounce → 14 days
  - 3rd bounce → 21 days
  - Capped at the configured maximum (default: 90 days)
- **Accurate Counting**: If the same recipient bounces several times within a single scan, all of those bounces are consolidated into **one** suppression entry with an accurate bounce count - no duplicate entries are created, and the progressive expiry is based on the real total
- **Rspamd Sync**: Active suppressions are automatically synced to Rspamd's recipient denylist. The sync **only writes when the managed entries actually changed** - in steady state nothing is rewritten, so Rspamd is not forced to truncate and reload the map on every run
- **Auto-Refresh**: The suppressions list refreshes automatically to show real-time changes

#### Bounce Types & Queue Behavior
| Type | DSN Code | Detection Method | Queue Cleanup |
|------|----------|------------------|---------------|
| **Hard Bounce** | 5.x.x | Postfix logs (every 5 min) | ✅ Stuck queue items deleted immediately |
| **Soft Bounce / Deferred** | 4.x.x | Live queue scan (every 5 min) | ✅ Deleted after threshold (default: 60 min) |

> **How it works:** Hard bounces are detected from Postfix log entries. Deferred emails are detected by scanning the live mail queue - if an email has been stuck longer than the configurable threshold, it is automatically deleted from the queue and the recipient is suppressed. This is more reliable than log-based detection on busy servers.

#### Managing Suppressions
- **Add Manually**: Click "Add Suppression" to manually block an email address or domain
- **Toggle Active/Inactive**: Use the Enable/Disable button to temporarily deactivate
- **Delete**: Permanently remove a suppression entry
- **Search & Filter**: Filter by reason (hard bounce, soft bounce, rejected, manual) or status
- **Import/Export**: Bulk import from CSV or export the full list
- **Suppress from Queue**: Use the "Suppress" button on queue items to quickly add the recipient to the suppression list

#### Domain Suppressions
When a domain-based suppression is created (e.g., blocking all emails to `@example.com`), the system stores it as a regex pattern for Rspamd compatibility. In the UI, these entries display the **clean domain name** instead of the raw regex, with a "Domain" badge. Hover over the badge to see the actual regex pattern.

#### Sync Status
- ✓ **Synced**: Entry is active in Rspamd's denylist
- ⟳ **Pending**: Entry needs to be synced to Rspamd
- ⊘ **Will Unsync**: Entry was deactivated and will be removed from Rspamd on next sync

#### Manual Job Triggers
All suppression background jobs can be manually triggered from the **Status page → Background Jobs**:
- **detect_suppressions**: Scan recent Postfix logs for hard bounce emails
- **cleanup_deferred_queue**: Scan live queue for stuck deferred emails
- **sync_suppressions**: Sync active suppressions to Rspamd
- **expire_suppressions**: Deactivate expired suppression entries

---

### 2. Rspamd Maps
Direct editor for all 13 Rspamd map files available in mailcow. These maps control email filtering rules at the Rspamd level. All maps support both plain text entries and regex patterns.

#### Map Categories

**Sender Rules**
- **Header-From Denylist**: Block emails by From header address
- **Header-From Allowlist**: Allow emails by From header address
- **Envelope Sender Denylist**: Block by envelope sender address
- **Envelope Sender Allowlist**: Allow by envelope sender address

**Recipient Rules**
- **Recipient Denylist**: Block sending to specific recipients (auto-managed by Suppressions)
- **Recipient Allowlist**: Allow sending to specific recipients

**Content Rules**
- **Bad Words / Bad Words DE**: Word patterns that trigger spam scoring (fired with fishy TLDs)
- **Fishy TLDs**: Suspicious top-level domains (fired with bad words)
- **Bad Languages**: Blocked language codes
- **Bulk Mail Headers / Bad Mail Headers**: Header patterns for junk detection

**System**
- **Monitoring Hosts**: Hosts excluded from Rspamd logging

#### Regex Wizard
The map editor includes a built-in **Regex Pattern Generator** that lets you create regex patterns without knowing regex syntax:

1. Click the **"Regex Wizard"** button above the editor
2. Select a pattern type:
   | Type | Input | Generated Pattern |
   |------|-------|-------------------|
   | **Exact Email** | `user@example.com` | `user@example.com` |
   | **Domain** | `example.com` | `/.+example\.com/i` |
   | **TLD** | `xyz` | `/.+\.xyz$/i` |
   | **Keyword** | `sale` | `/.*sale.*/i` |
3. Type your value - the regex pattern is generated live with an explanation
4. Click **"Add"** to insert it into the editor

> The "Domain" type follows mailcow's standard regex format (`/.+example\.com/i`) which matches the domain and all its subdomains.

#### Important Notes
- The Recipient Denylist is partially auto-managed by the Suppression feature
- Manual entries above the managed section marker are preserved during sync
- Changes require a Read-Write API key (**Settings → Mailcow → Connection**)
- Lines starting with `#` are comments, empty lines are ignored

---

## Configuration

Configure these settings in **Settings → Spam Filter** (the Rspamd connection itself - password and address - is configured under **Settings → Mailcow → Rspamd**):

| Setting | Default | Description |
|---------|---------|-------------|
| Suppression → **Suppression Enabled** | `false` | Master switch for the suppression system |
| Suppression → **Suppression Auto Detect** | `true` | Auto-detect hard bounces from Postfix logs |
| Suppression → **Suppression Rspamd Sync** | `true` | Auto-sync suppression list to Rspamd |
| Whitelist → **Suppression Whitelist Domains** | - | Domains that should never be suppressed |
| Hard Bounces (5.x.x) → **Suppression Hard Bounce Action** | `suppress` | Hard bounces (5.x.x): `suppress` or `ignore` |
| Soft Bounces (4.x.x) - Log Detection → **Suppression Soft Bounce Action** | `count` | Soft bounces in logs (4.x.x): `suppress`, `count`, or `ignore` |
| Soft Bounces (4.x.x) - Log Detection → **Suppression Soft Bounce Threshold** | `3` | Soft bounces before suppression (when action=`count`) |
| Block Duration → **Suppression Base Expiry Days** | `7` | Block duration in days (× bounce count for repeats) |
| Block Duration → **Suppression Max Expiry Days** | `90` | Maximum block duration cap |
| Deferred Queue Cleanup → **Queue Cleanup Enabled** | `true` | Auto-delete stuck deferred emails from queue |
| Deferred Queue Cleanup → **Queue Cleanup Threshold Minutes** | `60` | Minutes before a stuck deferred email is deleted |

> [!NOTE]
> Settings are edited on the **Settings** page (requires `SETTINGS_EDIT_VIA_UI_ENABLED=true`). Every setting can also be provided as an environment variable - see [ENV_Settings.md](../ENV_Settings.md).

---

## Prerequisites

1. **Rspamd Password**: Set it under **Settings → Mailcow → Rspamd** to enable map reading
2. **Read-Write API Key**: Set it under **Settings → Mailcow → Connection** to enable map editing, queue management, and sync
3. **Suppression Enabled**: Switch it on under **Settings → Spam Filter → Suppression** to activate auto-detection

## Troubleshooting

### "Rspamd Not Configured"
- Set the Rspamd password under **Settings → Mailcow → Rspamd**
- This is the Rspamd web UI password, not the mailcow admin password

### Suppressions Not Syncing
- Verify both the Rspamd password (**Settings → Mailcow → Rspamd**) and the Read-Write API key (**Settings → Mailcow → Connection**) are configured
- Check the Status page → Background Jobs → Spam Filter for job errors
- Use the manual "Sync to Rspamd" button to trigger an immediate sync

### Own Sender Addresses Being Suppressed
- This was a known issue that has been fixed. The system now filters out bounce notification (DSN) entries by checking the sender field - bounce notifications always have an empty sender or `MAILER-DAEMON`
- Only recipients of real outbound messages are considered for suppression

### Deferred Emails Stay in Queue Too Long
- Check that both **Queue Cleanup Enabled** (Settings → Spam Filter → Deferred Queue Cleanup) and **Suppression Enabled** (Settings → Spam Filter → Suppression) are switched on
- The default threshold is 60 minutes - adjust **Queue Cleanup Threshold Minutes** in the same group
- Requires a Read-Write API key (**Settings → Mailcow → Connection**) to delete queue items
- Check the Status page → Background Jobs → Spam Filter for the "Cleanup Deferred Queue" job status

### Map Save Errors
- Ensure a Read-Write API key with write permissions is configured (**Settings → Mailcow → Connection**)
- Check regex patterns for syntax errors using the "Validate" button
