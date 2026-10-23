# Outgoing spam

Outgoing spam protection disables a mailbox's SMTP access when it exceeds a sending threshold. Incoming delivery and IMAP stay enabled, but revoking app passwords also disconnects clients using them. The feature is **Beta**, off by default, and needs a read-write API key.

Configure it on [Security](Security.md) > **Settings** > **Outgoing spam**, or under **Settings** > **SMTP Abuse (Beta)**.

## The Outgoing spam card

![Security, Settings, the Outgoing spam card open](../../images/docs/abuse-card-light.webp#gh-light-mode-only)
![Security, Settings, the Outgoing spam card open](../../images/docs/abuse-card-dark.webp#gh-dark-mode-only)

The time window rolls back from each check. The pause after re-enabling prevents messages still in that window from immediately stopping the mailbox again; `0` disables the pause.

**Revoke its app passwords** deletes all app passwords when stopping a mailbox. Clients using them, including IMAP clients, need replacements. **Who users should contact** sets the address in the owner's email; if empty, it uses the admin email address or "your administrator".

### Blocked by abuse protection

Only mailboxes stopped by this app appear here. Mailboxes whose SMTP access was disabled elsewhere do not appear here or in outbound activity. **Re-enable SMTP** starts the configured pause before automatic blocking can resume.

### Outbound activity

Activity covers the 200 busiest mailboxes in the window. **Over limit** means the next check can stop the mailbox unless it is whitelisted or in its pause.

**Disable SMTP** stops a mailbox immediately, with the same app-password revocation, emails and Dashboard alert as an automatic stop.

### Whitelist

Enter the mailbox that logs in to send, not an alias it sends from. Up to 5000 addresses, one per line. Whitelisting prevents automatic stops; **Disable SMTP** can still stop it by hand.

## What is counted

The protection checks every minute and counts authenticated messages, not recipients. A message to many recipients counts once. It counts against the mailbox that logged in, even when sent from an alias or another permitted From address. Outside mail that merely claims your address does not count.

The mailbox is stopped only when its count is above the threshold, unless whitelisted, already stopped or in its pause.

## What happens when a mailbox is stopped

1. The app turns off SMTP access in mailcow. Incoming delivery continues and IMAP stays enabled. If mailcow refuses the change, nothing is recorded and the next check retries.
2. With **Revoke its app passwords** on, all its app passwords are deleted.
3. The app records the count, threshold and number of revoked passwords, and adds a critical alert under [Dashboard > Needs attention](Dashboard.md).
4. The admin email address and destinations receiving the Security topic get an email with the count, threshold and revoked-password count. See [Notifications](../Notifications.md).
5. If the app's SMTP settings are configured, the mailbox owner gets an email explaining the pause and any revoked passwords. It asks them to change their password, remove unused app passwords and contact the configured help address.

## Letting a mailbox send again

Change its password in mailcow and check its app passwords. Revoked passwords are deleted; create replacements where needed. Then use **Re-enable SMTP** under **Blocked by abuse protection**. The pause starts, lasting 60 minutes by default. Afterward, exceeding the threshold can stop it again.

Re-enable it from this card. Turning SMTP back on in mailcow leaves the app's stopped state in place, so it does not check that mailbox again.

## Choosing the limit

Check activity over normal sending cycles. Set the threshold above legitimate bursts and whitelist known bulk senders.

Anomaly detection counts mail the same way but only alerts, comparing each mailbox with its usual sending. See [Dashboard](Dashboard.md) and **Settings** > **Anomaly Detection (Beta)**.

## Settings that change this page

Defaults under **Settings** > **SMTP Abuse (Beta)**: protection off, more than 100 messages within 60 minutes, a 60-minute pause after re-enabling, app-password revocation on and help address empty. The card edits the same settings. Environment variables are listed in [environment variables](../ENV_Settings.md).

## When something is missing

- **No read-write API key**: protection does not run even if enabled. Activity stays readable, but stopping, re-enabling and whitelist changes are locked.
- **Protection off**: activity stays readable, but stopping, re-enabling and whitelist changes require turning protection on.
- **Editing settings is off**: set `SETTINGS_EDIT_VIA_UI_ENABLED=true` in `.env` and run `docker compose up -d`. A restart does not reread `.env`.
- **Settings are not migrated yet**: use **Migrate Settings from ENV** on [Settings](Settings.md).
- **A value is set by an environment variable**: change it in the environment.
- **Security page off**: outgoing protection keeps running if enabled. Its settings remain under **Settings** > **SMTP Abuse (Beta)**.
