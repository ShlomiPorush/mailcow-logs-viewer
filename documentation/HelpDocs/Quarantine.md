# Quarantine

Quarantine is read live from mailcow, rather than from imported message history. The sidebar count is the number of held messages.

## Messages

![Quarantine, Messages](../../images/docs/quarantine-messages-light.webp#gh-light-mode-only)
![Quarantine, Messages](../../images/docs/quarantine-messages-dark.webp#gh-dark-mode-only)

Messages without a spam score sort last. **Why** is the Rspamd action that sent the message to quarantine; **Virus** means mailcow flagged a virus. List scores turn red at 15.

### Actions on one message

All actions are carried out by mailcow and need the read-write API key:

| Action | Effect |
|---|---|
| **Release** | Delivers the held message to its recipient. |
| **Not spam** | Releases it and trains Rspamd that it is legitimate mail. |
| **Spam** | Deletes it and trains Rspamd that it is spam. |
| **Delete** | Permanently deletes it. |

**Rule** opens a new auto-rule filled in from the message; it does not act on the message immediately.

### Actions on several messages

Selected messages support release, deletion and spam learning with the same effects. **Release All** and **Delete All** act on every message in the list.

### Message details

![Quarantine Item Details window](../../images/docs/quarantine-details-light.webp#gh-light-mode-only)
![Quarantine Item Details window](../../images/docs/quarantine-details-dark.webp#gh-dark-mode-only)

Detail scores are green below 6, amber from 6 and red from 15. Rspamd symbols are sorted by their positive or negative effect on the score; zero-score symbols are folded away. See [How Rspamd decides](#how-rspamd-decides).

If the message has no plain-text part, its HTML part is displayed as text. Fuzzy hashes appear only when mailcow returns them.

## Auto-Rules

![Quarantine, Auto-Rules](../../images/docs/quarantine-auto-rules-light.webp#gh-light-mode-only)
![Quarantine, Auto-Rules](../../images/docs/quarantine-auto-rules-dark.webp#gh-dark-mode-only)

Auto-rules compare a message field with a value, then request release or deletion. The panel counts all rules; the tab counts only enabled rules. **Hits** counts confirmed actions, not every match.

### Create a rule

![Add Quarantine Rule dialog](../../images/docs/quarantine-rule-dialog-light.webp#gh-light-mode-only)
![Add Quarantine Rule dialog](../../images/docs/quarantine-rule-dialog-dark.webp#gh-dark-mode-only)

Rule names are required and limited to 255 characters; match values to 500. New rules start with **Release** and are enabled when saved, ready for the next run.

**Sender** and **Recipient** compare addresses, **Sender Domain** compares the part after `@`, and **Subject** compares the subject line. All match modes ignore case:

| Mode | What matches |
|---|---|
| **Exact Match** | The whole field equals the value. |
| **Contains** | The value occurs anywhere in the field. `example.com` also matches `user@mail.example.com`. |
| **Regex (advanced)** | The pattern matches anywhere. Use `^` and `$` for the whole field: `^news[0-9]*@example\.com$` matches `news@example.com` and `news42@example.com`. |

**Contains** escapes special characters and stores the result as a pattern, so it also gets a **Regex** tag in the list.

### Limits on patterns

Contains and regex rules inspect only the first 1000 field characters; exact matches compare the whole field. A regex match exceeding 0.1 seconds is skipped, with the rule named in the application log.

Invalid patterns and nested repetition such as `(a+)+` are refused on save. Older saved patterns with nested repetition are skipped with a log warning until edited.

### Create a rule from a message

**Rule** starts a release rule matching the sender. Quick fill can replace this with the sender's domain or recipient and updates generated names. Change the action to **Delete** to remove matching mail.

### Edit a rule

A saved Contains rule reopens with its plain text. Other patterns open as Regex (advanced), so saving preserves their match mode.

Earlier versions could escape Contains text twice during editing and stop it matching. Upgrades automatically repair affected Sender Domain rules and name them in the application log. Sender, Recipient and Subject rules are left alone because their values can contain real backslashes.

A **Check** tag marks a Contains rule that looks for a backslash. **Repair** removes one level of escaping and saves it; like any rule change, it needs the read-write API key. Leave it unchanged if the backslash is intentional.

### Which rule wins

Each message is handled by at most one rule. Delete rules are checked before release rules, and the first match wins. If both actions match, the message is deleted.

### How the rules run

**Process Quarantine Rules** checks current quarantine every **Quarantine Rules Interval** (5 minutes by default). It uses enabled rules and handles at most **Quarantine Rules Max Actions** messages (50 by default) per run; the rest wait.

Only actions confirmed by mailcow enter history and increase Hits. Failed actions stay unrecorded, are logged as errors and leave the messages for the next run. Other messages in the same run still count. History is kept for **Quarantine Rules Log Retention Days** (30 by default).

Use **Run** under **Status** > **Jobs** > **Quarantine** to process immediately. Interval changes apply on save without a restart. The job runs only when the Quarantine feature and read-write API key are both enabled.

### Test Rules

**Test Rules** checks current quarantine without acting or applying the action limit. It includes disabled rules and checks delete rules first, assigning each message to its first match.

Disabled rules can claim matches before enabled rules. Results mark them **Disabled - will not execute**, so a preview may differ from the scheduled run.

### History

History shows the last 20 confirmed actions. Deleting a rule does not remove these records.

## Settings that change this page

Set the action limit, interval and history retention under **Settings** > **Quarantine** > **Auto-Rules Scheduler**. The action limit bounds the damage from a rule matching more messages than intended.

Configure **mailcow API Key (read-write)** under **Settings** > **Mailcow** > **Connection**. See [Environment settings](../ENV_Settings.md) for environment-variable configuration.

## When something is missing

- With Quarantine off under **Settings** > **Features**, the page is disabled.
- The read-only key can list messages and open details. Release, deletion, spam learning and every rule operation require the read-write key. Without it, auto-rules are locked and their job does not run. See [Getting started](../GETTING_STARTED.md) for creating the keys.
- **Failed to load quarantine** or **Failed to load details** means mailcow did not answer; the message includes the reason.
- **Failed to load rules** gives the server's reason for the failure.

## How Rspamd decides

Rspamd adds scores from matching rules. Positive scores point toward spam; negative scores toward legitimate mail. Mailcow's thresholds turn the total into an action such as `add header` or `reject`. Zero-score symbols are informational. The symbols in message details explain the score.

**Not spam** and **Spam** train Rspamd with the message as legitimate mail or spam, respectively.
