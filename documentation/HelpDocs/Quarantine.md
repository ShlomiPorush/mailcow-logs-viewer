# Quarantine - User Guide

## Overview
The Quarantine page displays emails that mailcow has intercepted based on spam score, virus detection, or other filtering rules. You can manually release or delete quarantined messages, and set up **Auto-Rules** to automate this process.

## Quarantined Messages
Each quarantined email shows:
- **Sender → Recipient** - who sent the email and who it was intended for
- **Subject** - the email subject line
- **Score** - the spam score assigned by Rspamd (higher = more likely spam)
- **Action** - why it was quarantined (e.g., reject, virus)

### Manual Actions
If a Read-Write API key (**Settings → Mailcow → Connection**) is configured, you can:
- **Release** - deliver the email to the recipient's inbox
- **Delete** - permanently remove the email from quarantine
- **Not Spam** - release the email AND train Rspamd that it is legitimate (improves future filtering)
- **Spam** - delete the email AND train Rspamd that it is spam (improves future filtering)
- **Rule** - create an auto-rule pre-filled with this email's data
- **Select All / Bulk Actions** - release, delete, mark as not spam, or mark as spam for multiple items at once

### Email Details
Click **Details** or the email subject to open a detail modal showing:
- **Subject, From, Envelope From, Recipients** - full header info with click-to-copy
- **Score & Action** - the spam score and the action that was taken
- **Rspamd Symbols** - a table of all Rspamd rules that matched, sorted by score impact. Symbols with a score of 0 (informational only) are collapsed in an accordion
- **Email Content** - preview of the email body (plain text or HTML)
- **Action Buttons** - Release, Delete, Not Spam, Spam buttons in a sticky footer at the bottom of the modal

## Quarantine Auto-Rules

> **Requires:** a Read-Write API key (**Settings → Mailcow → Connection**)

Auto-Rules let you define matching patterns to automatically release or delete quarantined emails - no manual intervention needed. The feature is always active when a Read-Write API key is configured; if you don't want automation, simply don't create any rules.

### How It Works
1. A background job runs at a configurable interval (default: every 5 minutes)
2. It fetches all current quarantine items from mailcow
3. Each item is checked against your **enabled** rules
4. Matching items are automatically released or deleted
5. All actions are logged for auditing

### Creating Rules

#### From the Rules Panel
Click **Add Rule** in the Auto-Rules section to open the rule creation modal.

#### From a Quarantine Email (Quick-Fill)
Click the **Rule** button next to any quarantine email. The modal opens pre-filled with the email's data and shows a **Quick-fill bar** with clickable buttons:
- **Sender** - sets match type to "Sender" with the full email address
- **Domain** - sets match type to "Sender Domain" with just the domain part
- **Recipient** - sets match type to "Recipient" with the recipient address

### Rule Configuration

| Field | Description | Example |
|-------|-------------|---------|
| **Name** | A friendly name for the rule | "Allow billing notifications" |
| **Match Type** | Which email field to match against | Sender, Sender Domain, Recipient, Subject |
| **Match Value** | The value or pattern to match | `noreply@billing.com` |
| **Match Mode** | How to match the value | Exact Match, Contains, Regex |
| **Action** | What to do with matched emails | Release or Delete |

### Match Modes

| Mode | Description | Example |
|------|-------------|---------|
| **Exact Match** | Value must match exactly (case-insensitive) | `alerts@monitoring.com` matches only that address |
| **Contains** | Value is found anywhere in the field (case-insensitive) | `invoice` matches "Your invoice is ready" |
| **Regex** | Full regular expression pattern (advanced) | `.*\.(ru|cn)$` matches Russian/Chinese domains |

### Match Types

| Type | Description | Example |
|------|-------------|---------|
| **Sender** | Full sender email address | `alerts@monitoring.com` |
| **Sender Domain** | Domain part of sender address | `trusted-service.com` |
| **Recipient** | Full recipient email address | `admin@mydomain.com` |
| **Subject** | Email subject line | `invoice` or `.*payment.*` |

### Priority: Delete Always Wins
If both a Release rule and a Delete rule match the same email, the **Delete rule always takes priority**. This ensures that deny rules (delete) can never be overridden by allow rules (release), similar to firewall deny/allow logic.

### Safety Features
- **Max Actions Per Run** - configurable limit (default: 50) prevents accidental mass-processing from overly broad rules
- **Enable/Disable** - toggle individual rules on or off without deleting them
- **Dry-Run Test** - the "Test Rules" button shows what would match without taking any action
- **Action History** - every automated action is logged with sender, recipient, subject, matched rule, and timestamp

### Test Rules (Dry-Run)
Click **Test Rules** to preview which currently quarantined emails would be affected. The results are:
- **Grouped by rule** - each rule shows as a section header with its matched emails listed below
- **Shows disabled rules** - matches from disabled rules appear faded with a "Disabled - will not execute" badge, so you can preview a rule's effect before enabling it
- **Summary counters** - large matched/total count at the top with breakdown of active vs disabled matches

### Action History
Click the **History** button to view recent automated actions. Each entry shows:
- The action taken (Release / Delete)
- Sender and recipient
- Which rule matched
- When the action occurred

Logs are retained for a configurable period (default: 30 days).

## Configuration

These settings live under **Settings → Quarantine → Auto-Rules Scheduler**:

| Setting | Default | Description |
|---------|---------|-------------|
| **Quarantine Rules Max Actions** | `50` | Safety limit: maximum emails to release/delete per scheduler run |
| **Quarantine Rules Interval** | `5` | Minutes between rule processing runs (lower = faster, higher = less load) |
| **Quarantine Rules Log Retention Days** | `30` | Days to keep action history |

> [!NOTE]
> Settings are edited on the **Settings** page (requires `SETTINGS_EDIT_VIA_UI_ENABLED=true`). Every setting can also be provided as an environment variable - see [ENV_Settings.md](../ENV_Settings.md).

> **Note:** The auto-rules feature requires a valid Read-Write API key (**Settings → Mailcow → Connection**). Without it, the scheduler will not process rules. If no rules are defined, the background job simply does nothing.

## Background Job
The **Process Quarantine Rules** job appears in **Status → Background Jobs** under the "Quarantine" category, showing its interval, status, and last run time. You can also manually trigger it with the "Run Now" button.
