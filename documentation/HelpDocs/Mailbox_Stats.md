# Mailbox Stats

Counts cover only messages this app has recorded, not the mailbox's whole history. For sending limits, see [Rate Limits](Rate_Limits.md).

![Mailbox Stats, Statistics](../../images/docs/mailbox-stats-statistics-light.webp#gh-light-mode-only)
![Mailbox Stats, Statistics](../../images/docs/mailbox-stats-statistics-dark.webp#gh-dark-mode-only)

## Statistics

The summary counts every mailbox and alias for the chosen period (30 days by default); the search and filters do not change it. **Failed** is sent mail that bounced or was rejected; **Failure Rate** divides that count by sent mail. Each message counts once per address, using its best delivery outcome, so a later successful delivery is not a failure.

Days, for **Today** and for custom dates, are days in the app's time zone (`TZ`, UTC when unset), as in the activity window.

The search finds mailbox addresses, display names and alias addresses. In **Domain**, an alias domain shows as "alias of" its target and lists the target's mailboxes.

**Active Only** hides mailboxes that are inactive or deleted in mailcow. **Hide Zero Activity** hides mailboxes, and aliases inside a mailbox, with no messages in the period. Both start checked.

## Mailbox details

A service tag under the address (**IMAP**, **POP3**, **SMTP**, **Sieve**) is lit when the service is on; **TLS** is lit when TLS is enforced. Hover **IMAP**, **POP3** or **SMTP** for the last login. The counts in the row include the mailbox's aliases. **Failed** is the share of sent mail that bounced or was rejected, amber from 5% and red from 10%.

In an open row, **Created / Modified** are the times this app first recorded the mailbox and last synced it, not mailcow's own dates. **Message Statistics** counts the mailbox and its aliases together; click a count to open [Messages](Messages.md) searched for the mailbox address, with that direction or status. The **Aliases** table gives the same counts per alias; **domain alias** marks an address on a mailcow alias domain.

## Activity window

Click the small chart in **Activity** to see the mailbox's sent and received messages, aliases included, per hour for periods up to two days and per day for longer ones.

![Activity window](../../images/docs/mailbox-stats-activity-light.webp#gh-light-mode-only)
![Activity window](../../images/docs/mailbox-stats-activity-dark.webp#gh-dark-mode-only)

## Settings that change this page

The counts come from the message history, which **Retention Days** under **Settings** > **Fetch** keeps for 7 days by default. A longer period cannot show more than that. Mailbox and alias details sync from mailcow every 5 minutes, and the list can be up to 5 minutes old.

**Mailbox Stats** and **Rate Limits** are separate switches under **Settings** > **Features**. Turning off **Mailbox Stats** deletes the stored mailbox and alias details, not the messages. While **Rate Limits** is on, the mailbox details stay, because Rate Limits reads each mailbox's limit from them. If **Rate Limits** stays on, the sidebar entry is called **Rate Limits** and opens only that tab.

## When something is missing

**No mailboxes found** means the filters hide every mailbox, or the first sync from mailcow has not finished. Clear the filters, then check **Mailbox Statistics** and **Alias Statistics** under [Status](Status.md#jobs) > **Jobs**.
