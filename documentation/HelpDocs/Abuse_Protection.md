# Outgoing spam

Outgoing spam protection stops a mailbox from sending when it sends more messages than a limit you set within a set time, the usual sign of a hijacked account sending spam. Mail keeps arriving and IMAP access stays enabled. If you also revoke app passwords, clients using those passwords need new ones to sign in again. It is the **Outgoing spam** card on [Security](Security.md) > **Settings**, and its settings are also under **Settings** > **SMTP Abuse (Beta)**.

The feature is marked **Beta**. It is off by default and needs a read-write API key to act.

## The Outgoing spam card

The card switch turns the protection on or off. **Edit** opens its settings. The closed card shows the current limit and, while enabled, **Stops mailboxes**, or **Needs a Read-Write key** when that key is missing.

![Security, Settings, the Outgoing spam card open](../../images/docs/abuse-card-light.webp#gh-light-mode-only)
![Security, Settings, the Outgoing spam card open](../../images/docs/abuse-card-dark.webp#gh-dark-mode-only)

The open card turns the sentence into fields:

- "Stop a mailbox from sending when it sends more than (messages) within (minutes)": the limit. The minutes are a rolling window, counted back from each check.
- "After you let it send again, wait (minutes) before it can be stopped again": a pause after re-enabling. This prevents old messages still in the window from causing an immediate new block. `0` disables the pause.
- **Revoke its app passwords**: when a mailbox is stopped, its app passwords are deleted in mailcow too. Clients using any revoked password, including IMAP clients, lose access until you issue a replacement.
- **Who users should contact**: the address the email to the mailbox owner names. When it is empty, the email names the admin email address, or "your administrator".

Use the Security **Settings** tab's **Save changes** or **Discard** bar.

Below the fields, the card shows the mailboxes. **Refresh** reads them again.

### Blocked by abuse protection

The mailboxes this protection stopped, with the number of messages each sent in the window. Only mailboxes stopped by this app are listed. A mailbox that has SMTP turned off in mailcow for another reason, such as a mailbox that only receives DMARC reports, is not shown here or in the activity list.

**Re-enable SMTP** lets the mailbox send again after you confirm. When the pause is set, the list says for how many minutes automatic blocking is paused for it.

### Outbound activity

The 200 busiest mailboxes that sent mail in the window, busiest first, five per page with **Previous** and **Next**. The columns are **Mailbox**, **Sent** with the window length (for example **Sent (60m)**) and **Status**:

- **Normal**: under the limit.
- **Over limit**: above the limit. The next check can stop it unless it is whitelisted or still in its pause after re-enabling.
- **Whitelisted**: never stopped automatically.

**Disable SMTP** stops a mailbox now, without waiting for the limit, after you confirm. The confirmation says whether its app passwords will be revoked. It does the same as an automatic stop, including the app passwords, the emails and the Dashboard alert.

### Whitelist

Whitelist legitimate bulk senders, one address per line, up to 5000. **Save changes** saves the list.

Enter the mailbox that logs in to send, not an alias it sends from: messages count for the mailbox that logged in. A whitelisted mailbox can still be stopped by hand with **Disable SMTP**.

Under the field, the saved entries are listed with a **Filter** box. **Remove** on an entry takes it off at once.

## What is counted

The protection checks every minute. It counts, per mailbox, the messages sent within the window:

- Only mail a mailbox sent after logging in counts. A message counts when its Rspamd scan shows an authenticated sender. Mail from outside that only claims one of your addresses as its sender does not count, so nobody outside can get a mailbox stopped.
- Each message counts for the mailbox that logged in, not for the address in its From. Mail sent from an alias, or from another address mailcow lets the mailbox send as, counts for that mailbox, and that mailbox is stopped.
- The counter counts messages, not recipients: a message to many recipients is one submission and counts once.

A mailbox is stopped when its count is above the limit (more than 100 with the default), unless it is whitelisted, already stopped, or in its pause after you re-enabled it.

## What happens when a mailbox is stopped

1. The app turns off SMTP access for the mailbox in mailcow. The mailbox can no longer send; incoming delivery continues and IMAP stays enabled. If mailcow refuses (for example because the address is an alias, not a mailbox), nothing is recorded and the next check tries again.
2. With **Revoke its app passwords** on, the app deletes all of the mailbox's app passwords in mailcow.
3. The app records the action, with the count, the limit and the number of app passwords revoked.
4. A critical alert "SMTP disabled (abuse protection):" with the mailbox appears under Needs attention on the [Dashboard](Dashboard.md).
5. You get an email with the subject `[Security] SMTP disabled (abuse protection): alice@example.com`, showing what it sent, the limit and the app passwords revoked. It goes to the admin email address and to the notification destinations that receive the Security topic. See [Notifications](../Notifications.md).
6. The mailbox owner gets an email with the subject `Security alert: outgoing mail has been paused for your account`. It says that sending is paused and receiving still works, and, when app passwords were revoked, that a mail app that used one needs a new one. It asks them to change their password, remove app passwords they no longer use and contact the address from **Who users should contact**. This email is sent only when the app's SMTP settings are configured.

## Letting a mailbox send again

1. Secure the account in mailcow: change its password and check its app passwords. Revoked app passwords are deleted; the user creates new ones where needed.
2. Click **Re-enable SMTP** on the mailbox in **Blocked by abuse protection**.
3. The pause starts (60 minutes by default). The mailbox can send even if the messages it sent before are still in the window. After the pause, it is stopped again if it goes over the limit.

> [!TIP]
> Re-enable a stopped mailbox from this card, not in mailcow. The app keeps a mailbox it stopped as stopped until you re-enable it here, and does not check it again in the meantime, even if SMTP was turned back on in mailcow.

## Choosing the limit

Check **Outbound activity** over normal sending cycles. Set a limit above legitimate bursts and whitelist known bulk senders. A low limit can stop real users.

Anomaly detection is a separate feature that only alerts. It compares each mailbox with its own usual sending, and a spike shows on the Dashboard with **Show activity**, which shows what the mailbox sent and to whom. It counts mail the same way as this protection. See [Dashboard](Dashboard.md) and **Settings** > **Anomaly Detection (Beta)**.

## Settings that change this page

These settings are under **Settings** > **SMTP Abuse (Beta)**, and the card edits the same values. Each can also be set by an environment variable; see [Settings](Settings.md) and [environment variables](../ENV_Settings.md).

| Setting | Variable | Default | Card field |
|---|---|---|---|
| **SMTP Abuse Enabled** | `SMTP_ABUSE_ENABLED` | Off | The card's switch |
| **SMTP Abuse Threshold** | `SMTP_ABUSE_THRESHOLD` | 100 | The messages in the limit |
| **SMTP Abuse Window Minutes** | `SMTP_ABUSE_WINDOW_MINUTES` | 60 | The minutes in the limit |
| **SMTP Abuse Unblock Grace Minutes** | `SMTP_ABUSE_UNBLOCK_GRACE_MINUTES` | 60 | The pause |
| **SMTP Abuse Revoke App Passwords** | `SMTP_ABUSE_REVOKE_APP_PASSWORDS` | On | **Revoke its app passwords** |
| **SMTP Abuse Help Address** | `SMTP_ABUSE_HELP_ADDRESS` | Empty | **Who users should contact** |

The read-write API key is set under **Settings** > **Mailcow** > **Connection** (`MAILCOW_API_KEY_RW`).

## When something is missing

- **No read-write API key**: the protection does not run, even with the switch on. The Protection row shows **Outgoing spam** as off with "needs a Read-Write key". The card shows "Abuse protection controls are locked", says the key is needed and offers **Open Settings**. The activity stays readable; **Disable SMTP**, **Re-enable SMTP** and the whitelist are locked.
- **The protection is off**: the panel says "Automatic protection is off." and shows the activity of the window. A locked area says to turn **Outgoing spam** on with the switch to stop a mailbox, let it send again or edit the whitelist.
- **Editing settings is off** (`SETTINGS_EDIT_VIA_UI_ENABLED` is not `true`): the values are shown read-only under "Editing settings is off", and the switch is disabled. Set the variable in `.env` and run `docker compose up -d` to edit them here; a restart does not read `.env` again.
- **Settings are not migrated yet**: the values are read-only under "Settings are not migrated yet" until you click **Migrate Settings from ENV** on the Settings page. **Open Settings** goes there.
- **A value set by an environment variable**: its field is disabled; change it in the environment.
- **The Security page is off**: the card is not reachable, but the protection keeps running if it is on. Its settings stay under **Settings** > **SMTP Abuse (Beta)**.
- **The panel cannot load**: it says "Could not load abuse protection."
