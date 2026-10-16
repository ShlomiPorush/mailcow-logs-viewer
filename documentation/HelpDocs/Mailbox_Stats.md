# Mailbox Stats

**Mailbox Stats** lists your mailboxes and their aliases from mailcow, with the messages this app has recorded for each of them. The page has two tabs: **Statistics** and [**Rate Limits**](Rate_Limits.md).

<!-- SHOT: mailbox-stats-statistics | Mailbox Stats > Statistics with filters and an expanded mailbox showing services, counts and aliases -->

## Statistics

The four figures at the top show **Messages Sent**, **Messages Received**, **Failed** and **Failure Rate** for the chosen period. They count every mailbox and alias; the search and filters do not change them. **Failed** is sent mail that bounced or was rejected.

**Period** offers **Today**, **7 Days**, **30 Days** (the default) and **90 Days**. For other dates, enter **From** and **To** and click **Apply Custom Range**. **Today** and custom dates start at midnight UTC.

The search finds mailbox addresses, display names and alias addresses. **Domain** lists each domain with its number of mailboxes; an alias domain shows as "alias of" its target and lists the target's mailboxes.

Sort with **Sort** or the column headings; the default is most sent first.

Under **Filters**, **Active Only** and **Hide Zero Activity** start checked. **Active Only** hides mailboxes that are inactive or deleted in mailcow. **Hide Zero Activity** hides mailboxes, and aliases inside a mailbox, with no messages in the period. **Clear filters** restores all defaults. More mailboxes load as you scroll, 50 at a time.

## Mailbox details

Under each address are its name, storage, number of aliases and the tags **IMAP**, **POP3**, **SMTP**, **Sieve** and **TLS**. A tag is lit when the service is on (**TLS**: when TLS is enforced); hover it for the last login. The counts in the row include the mailbox's aliases. **Failed** is the share of sent mail that bounced or was rejected, amber from 5% and red from 10%.

Click a row to open it. It shows quota used, messages in the mailbox, **Rate Limit** (**None**, or for example `100/hour`) and the last IMAP, POP3 and SMTP login (**Never** when mailcow has no record). **Created / Modified** are the times this app first recorded the mailbox and last synced it, not mailcow's own dates.

**Message Statistics** shows the mailbox and its aliases together: **Traffic** has **Sent**, **Received** and **Internal**, and **Sent mail** has **Delivered**, **Deferred**, **Bounced** and **Rejected**. Click a count to open [Messages](Messages.md) searched for the mailbox address, with that direction or status.

The **Aliases** table gives the same counts per alias, with the tags **catch-all**, **domain alias** (the address on a mailcow alias domain) and **inactive**.

## Activity window

Click the small chart in **Activity** to see the mailbox's sent and received messages, aliases included, per hour for periods up to two days and per day for longer ones. **Open its messages** opens Messages searched for the mailbox.

<!-- SHOT: mailbox-stats-activity | Activity window with sent and received bars and Open its messages -->

## Settings that change this page

The counts come from the message history, which **Retention Days** under **Settings** > **Fetch** keeps for 7 days by default. A longer period cannot show more than that. Mailbox and alias details sync from mailcow every 5 minutes, and the list can be up to 5 minutes old.

**Mailbox Stats** and **Rate Limits** are separate switches under **Settings** > **Features**. Turning off **Mailbox Stats** deletes the stored mailbox and alias details, not the messages. If **Rate Limits** stays on, the sidebar entry is called **Rate Limits** and opens only that tab.

## When something is missing

**No mailboxes found** means the filters hide every mailbox, or the first sync from mailcow has not finished. Clear the filters, then check **Mailbox Statistics** and **Alias Statistics** under [Status](Status.md#jobs) > **Jobs**.

If the page cannot load, it shows **Failed to load mailbox statistics** with **Retry**.

The counts cover only mail this app has recorded, not the mailbox's whole history.
