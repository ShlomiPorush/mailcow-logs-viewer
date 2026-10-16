# Rate Limits

**Mailbox Stats** > **Rate Limits** shows who ran into mailcow's sending limits and lets you change the limit of each mailbox and domain. The hits come from mailcow's `ratelimited` log, which this app collects; the limits are read from mailcow.

![Rate Limits](../../images/docs/rate-limits-page-light.webp#gh-light-mode-only)
![Rate Limits](../../images/docs/rate-limits-page-dark.webp#gh-dark-mode-only)

## Rate limit activity

The chart counts blocked sends in the chosen **Window**. **Last 24 hours** shows them per hour; **Last 7 days**, **Last 30 days** (the default), **Last 90 days** and **Last year** show them per day.

<!-- VERIFY: owner's decision pending (finding 35): windows longer than the raw log retention. Update this note once decided. -->
> [!NOTE]
> Hits are kept only as long as the raw logs: **Raw Logs Retention Days** under **Settings** > **Logs**, 2 days by default. With the default, every window longer than two days shows the same two days. The page also reads at most the newest 5,000 hits.

## Blocked senders

The table lists every sender with recorded hits, newest **Last hit** first. **Hits** counts all of a sender's recorded hits, not only those in the window. Search by sender address. **Limit** is the mailbox's own limit, and **Last reset** shows a counter reset made from this page.

Click a sender to see each refused message with **Time**, **Recipient**, **Subject** and **Queue id**, newest first, up to 2,000. **All senders** goes back to the list.

**Reset counter** lets the sender send again right away; the limit stays as it is. The button appears only when mailcow's log names the counter.

![Blocked sender detail](../../images/docs/rate-limits-sender-light.webp#gh-light-mode-only)
![Blocked sender detail](../../images/docs/rate-limits-sender-dark.webp#gh-dark-mode-only)

## Configured limits

The table lists every domain, then every active mailbox, with its limit or **No limit**. **All**, **Mailboxes** and **Domains** filter by type, the search filters by name, and **Hide no limit** hides entries without a limit.

To change one entry, click **Edit**, enter the number of messages in **Allow**, choose **per second**, **per minute**, **per hour** or **per day**, and click **Save**. **Remove limit** removes it after you confirm; saving `0` does the same.

**Apply to filtered** sets one limit on everything the table shows, and only on that. The panel shows how many mailboxes and domains match. Enter the limit, click **Apply** and confirm; `0` removes the limit from all of them. One apply can change up to 1,000 entries. An entry the app no longer knows, for example one deleted in mailcow since the page loaded, is skipped and keeps its limit.

![Configured limits filtered to example.com](../../images/docs/rate-limits-bulk-light.webp#gh-light-mode-only)
![Configured limits filtered to example.com](../../images/docs/rate-limits-bulk-dark.webp#gh-dark-mode-only)

## Settings that change this page

Changing limits and resetting counters need the read-write API key. Without it, **Editing rate limits is locked** appears, **Edit** and **Apply to filtered** are gone, and **Reset counter** is disabled. See [The Read-Write API key](../Using_the_App.md#the-read-write-api-key).

**Rate Limits** under **Settings** > **Features** is separate from **Mailbox Stats**; with only Rate Limits on, the sidebar entry is called **Rate Limits**. While it is on, the app collects the `ratelimited` log even if the Logs page is off or the service is unticked there. Turning it off asks you to confirm first: it forgets the counter resets and deletes the collected hits, unless the Logs page still collects that service. The retention of the hits stays under **Settings** > **Logs**, also while the Logs page is off.

## When something is missing

**No rate limit hits have been collected** means the app has no recorded hits. A limit creates no hit until mailcow refuses a message.

**No matches** means the search or filters hide every row. **Domain limits could not be read from mailcow** means mailcow did not answer for at least one domain; the mailbox limits still show.

If the page cannot load, it shows **Failed to load rate limits**. Press **Refresh** to try again.

## How sending limits work

A limit is a setting: so many messages per second, minute, hour or day. The counter is what mailcow has counted against it; once the allowance is used up, mailcow refuses the sender's mail. **Reset counter** empties it so the sender can send now; changing the limit changes the rule for later mail.

mailcow uses a mailbox's own limit when it has one, and the domain limit then does not apply to that mailbox. Mailboxes without their own limit share the domain limit: together they can send that many messages per period. Limits apply to senders that authenticate to mailcow, that is, your own mailboxes. They are separate from [SMTP abuse protection](Abuse_Protection.md), which turns off a mailbox's SMTP access.
