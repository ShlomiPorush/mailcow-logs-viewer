# Quarantine

The Quarantine page shows the messages mailcow holds in its quarantine and the rules that release or delete them for you. The list is read live from the mailcow API each time you open the page and again every 30 seconds while it is open. The number next to **Quarantine** in the sidebar is the number of held messages.

The page has two tabs: **Messages** and **Auto-Rules**.

## Messages

![Quarantine, Messages](../../images/docs/quarantine-messages-light.webp#gh-light-mode-only)
![Quarantine, Messages](../../images/docs/quarantine-messages-dark.webp#gh-dark-mode-only)

The summary counts held messages. With none held, the list says **No quarantined messages**.

### The list

Use the **Sort** picker above the list to change the order:

- **Newest first** (the default): the most recently held message on top.
- **Score: high to low**: the clearest spam on top.
- **Score: low to high**: the messages most likely to be false positives on top.

Messages without a score sort last. Your sort survives refreshes and actions.

Each row shows:

| Column | What it shows |
|---|---|
| **Message** | The subject, and under it the sender and mailcow's queue ID. A message without a subject shows **No subject**. |
| **For** | The recipient. |
| **Why** | The Rspamd action that sent the message to quarantine, such as `reject` or `add header`. A **Virus** tag appears when mailcow flagged the message as a virus. |
| **Score** | The Rspamd score. A score of 15 or more is shown in red. |
| **Held** | How long ago the message was held. Hover over it for the exact time. |
| **Actions** | The buttons described below. |

Click a row or its subject to open the message details.

### Actions on one message

These buttons appear when a read-write API key is configured (see [When something is missing](#when-something-is-missing)). Every action is carried out by mailcow, and the list reloads afterwards.

| Button | What happens in mailcow | Asks first |
|---|---|---|
| **Release** | Releases the message, which delivers it to the recipient. | No |
| **Not spam** | Releases the message and trains Rspamd that it is not spam. | Yes |
| **Spam** | Deletes the message and trains Rspamd that it is spam. | Yes |
| **Rule** | Nothing in mailcow. Opens a new auto-rule filled in from this message (see [Create a rule from a message](#create-a-rule-from-a-message)). | No |
| **Delete** | Deletes the message permanently. | Yes |

### Actions on several messages

Select rows, or use **Select All** and **Deselect All**. Selected messages support:

- **Release Selected**: releases the selected messages.
- **Delete Selected**: deletes the selected messages permanently.
- **Not Spam**: releases the selected messages and trains Rspamd that they are not spam.
- **Learn Spam**: deletes the selected messages and trains Rspamd that they are spam.

With nothing selected, the toolbar shows **Release All** and **Delete All** instead. They act on every message in the list. Each bulk action asks for confirmation and states how many messages it affects.

### Message details

![Quarantine Item Details window](../../images/docs/quarantine-details-light.webp#gh-light-mode-only)
![Quarantine Item Details window](../../images/docs/quarantine-details-dark.webp#gh-dark-mode-only)

**Quarantine Item Details** shows:

- **Subject**, **From (Header)**, **Envelope From** and **Recipients**. Each recipient shows its type next to the address. Click a value to copy it.
- **Score**: green below 6, amber from 6, red from 15.
- **Action**: the Rspamd action, as in the **Why** column.
- **Rspamd Symbols**: a table of every Rspamd rule that matched, with **Symbol**, **Group**, **Score** and **Details**. Symbols are sorted by how much they moved the score, positive or negative. Symbols with a score of 0 are folded under **Informational symbols (score 0)**. See [How Rspamd decides](#how-rspamd-decides).
- **Email Content**: the message text. When the message has no plain-text part, the HTML part is shown as text.
- **Fuzzy Hashes**: shown when mailcow returns fuzzy hashes for the message.

With the read-write key, the bottom of the window has **Spam**, **Not Spam**, **Delete** and **Release**. They do the same as the buttons in the row.

## Auto-Rules

![Quarantine, Auto-Rules](../../images/docs/quarantine-auto-rules-light.webp#gh-light-mode-only)
![Quarantine, Auto-Rules](../../images/docs/quarantine-auto-rules-dark.webp#gh-dark-mode-only)

Auto-rules compare a message field with a value, then tell mailcow to release or delete matches.

The panel **Quarantine Auto-Rules** shows how many rules exist. The number on the **Auto-Rules** tab counts the enabled rules. The toolbar has **Add Rule**, **Test Rules** and **History**.

Each rule in the list shows:

- Its name, a **Release** or **Delete** tag, a **Regex** tag when the rule uses the **Contains** or **Regex (advanced)** match mode, and a **Disabled** tag when it is off.
- The match type and value, for example "Sender Domain: `example.net`".
- **Hits**: how many messages the rule has acted on, the time of the last one, and the rule's notes.

Use **Enabled** or **Disabled** to toggle a rule, **Edit** to change it, or **Delete** to remove it after confirmation. Deletion keeps its history.

With no rules, the list says **No rules configured. Click "Add Rule" to create one.**

### Create a rule

![Add Quarantine Rule dialog](../../images/docs/quarantine-rule-dialog-light.webp#gh-light-mode-only)
![Add Quarantine Rule dialog](../../images/docs/quarantine-rule-dialog-dark.webp#gh-dark-mode-only)

**Add Rule** opens the **Add Quarantine Rule** dialog:

| Field | What to enter |
|---|---|
| **Rule Name** | A name you recognize, up to 255 characters. Required. |
| **Match Type** | The field of the held message to compare: **Sender**, **Sender Domain**, **Recipient** or **Subject**. |
| **Action** | **Release** or **Delete**. New rules start with **Release**. |
| **Match Value** | The value or pattern to compare with, up to 500 characters. Required. |
| **Match Mode** | **Exact Match**, **Contains** or **Regex (advanced)**. The hint under the field shows an example for the chosen mode. |
| **Notes (optional)** | Why the rule exists. Shown in the rule list. |

**Create Rule** saves and enables the rule for the next run.

**Sender** and **Recipient** compare email addresses. **Sender Domain** compares the part after `@`; **Subject** compares the subject line.

The match modes:

| Match Mode | Matches when | Example |
|---|---|---|
| **Exact Match** | The field equals the value. Case is ignored. | `noreply@example.com` matches only that address. |
| **Contains** | The value appears anywhere in the field. Case is ignored. | `example.com` matches `alerts@example.com` and `user@mail.example.com`. |
| **Regex (advanced)** | The regular expression finds a match anywhere in the field. Case is ignored. Use `^` and `$` to match the whole field. | `^news[0-9]*@example\.com$` matches `news@example.com` and `news42@example.com`. |

The app stores a **Contains** rule as a pattern with every special character escaped, which is why the rule list shows the **Regex** tag on it.

### Limits on patterns

**Contains** and **Regex (advanced)** inspect the first 1000 field characters; **Exact Match** compares the whole field. Regex matches have a 0.1-second limit. A timeout skips the match and names the rule in the application log.

Invalid expressions and nested repetition such as `(a+)+` are refused on save. Older saved patterns with nested repetition are skipped with a log warning until edited.

### Create a rule from a message

**Rule** starts a release rule matching the message's sender, named "Rule for" followed by that address.

Above the fields, **Quick fill from email:** offers up to three chips:

- **Sender:** sets the match type to **Sender** and the value to the sender address.
- **Domain:** sets the match type to **Sender Domain** and the value to the sender's domain.
- **Recipient:** sets the match type to **Recipient** and the value to the recipient address.

Quick fill also replaces a generated rule name. Change **Action** to **Delete** if you want to remove matching mail.

### Edit a rule

**Edit** opens the **Edit Rule** dialog with the rule's values. Click **Save Changes** to store them.

A **Contains** rule opens as **Contains** with its plain text, and any other pattern opens as **Regex (advanced)**, so saving keeps the rule as it was.

Editing a **Contains** rule in an earlier version escaped its text a second time, so the rule stopped matching. The upgrade repairs such **Sender Domain** rules by itself and names each one in the application log, since a domain cannot contain a backslash. **Sender**, **Recipient** and **Subject** rules are not changed, because their text can contain a real backslash. In the rules list, a **Contains** rule whose text looks for a backslash gets a **Check** tag with the note "Looks for a backslash. An earlier version may have changed this rule when it was edited." **Repair** removes one level of escaping and saves the rule; it needs the read-write API key like any rule change. Leave the rule as it is if it really looks for a backslash.

### Which rule wins

Each held message is handled by one rule at most. The app checks the **Delete** rules first and then the **Release** rules, and the first rule that matches decides. If a **Delete** rule and a **Release** rule both match a message, the message is deleted. The dialog repeats this under **Priority**.

### How the rules run

**Process Quarantine Rules** runs every **Quarantine Rules Interval** (5 minutes by default). It reads current quarantine, matches enabled rules and requests release or deletion for up to **Quarantine Rules Max Actions** messages (50). Other messages wait.

Only the releases and deletions that mailcow confirms are added to the history and counted in the rule's **Hits**. Old history is removed after **Quarantine Rules Log Retention Days** (30). If mailcow refuses a release or deletion, that message is not recorded, the error goes to the application log, and the message stays in quarantine for the next run. The other messages of the same run still count.

You can see the job and start it at once with **Run** on **Status** > **Jobs**, in the **Quarantine** group. See [Status](Status.md).

A new **Quarantine Rules Interval** applies as soon as you save it. The job starts once the read-write API key and the Quarantine feature are both on, and stops when either is off. No restart is needed.

### Test Rules

**Test Rules** checks current quarantine without acting. It includes disabled rules, checks delete rules first and assigns each message to its first match. The action limit does not apply.

With matches, **Test Results** gives matched and total counts, then groups sender, recipient and subject by rule. Disabled rules show **Disabled - will not execute** and can claim matches before enabled rules. With no matches, a notice gives the number checked.

### History

**History** toggles **Recent Activity**, the last 20 recorded matches with their action, addresses and time. Hover over the time for the rule name. Before the first match it says **No actions recorded yet**.

## Settings that change this page

In **Settings** > **Quarantine** > **Auto-Rules Scheduler**:

| Setting | Default | What it does |
|---|---|---|
| **Quarantine Rules Max Actions** | `50` | The most messages one run releases or deletes. Protects you from a rule that matches far more than intended. |
| **Quarantine Rules Interval** | `5` | Minutes between runs. |
| **Quarantine Rules Log Retention Days** | `30` | Days to keep the rule history. |

The read-write key is **mailcow API Key (read-write)** in **Settings** > **Mailcow** > **Connection**. Each setting can also come from an environment variable. See [Settings](Settings.md) and [Environment settings](../ENV_Settings.md).

## When something is missing

| Situation | What you see |
|---|---|
| The Quarantine feature is turned off | The page shows **Quarantine is disabled** with **Go to Dashboard**. Turn it on in **Settings** > **Features**. |
| No read-write API key | **Messages** shows the list with a **Details** button per row and the notice **Quarantine actions are locked**: release, delete, spam learning and the auto-rules need the read-write key. The details window shows the same notice instead of its buttons. **Auto-Rules** shows **Auto-Rules are locked** with **Open Settings**, and **Process Quarantine Rules** does not run. |
| Nothing is held | **No quarantined messages**. |
| mailcow does not answer | **Failed to load quarantine** with the reason. In the details window, **Failed to load details**. |
| The rules cannot be loaded | **Failed to load rules** with the reason. |

Reading the quarantine and opening the details need only the read-only key. Every action that changes the quarantine, and every rule operation, needs the read-write key. [Getting started](../GETTING_STARTED.md) explains how to create both keys in mailcow.

## How Rspamd decides

Rspamd checks every message against many rules. Each rule that matches adds a symbol with a score: a positive score points to spam, a negative score points to legitimate mail. The message score is the sum, and the score thresholds set in mailcow turn it into an action such as `add header` or `reject`. The **Why** column and the **Action** field show that action.

The **Rspamd Symbols** table in the details window lists the symbols behind a score, so you can see why a message was held. A symbol with a score of 0 is informational and did not change the result.

**Not spam** and **Spam** ask mailcow to train Rspamd with the message, as legitimate mail or as spam, so Rspamd learns from your own mail.
