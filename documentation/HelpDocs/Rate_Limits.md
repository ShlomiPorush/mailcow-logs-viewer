# Rate Limits

Hits come from mailcow's `ratelimited` log; configured limits come from mailcow.

![Rate Limits](../../images/docs/rate-limits-page-light.webp#gh-light-mode-only)
![Rate Limits](../../images/docs/rate-limits-page-dark.webp#gh-dark-mode-only)

## Rate limit activity

The chart counts blocked sends in the selected window: hourly for the last 24 hours, daily for longer windows.

<!-- VERIFY: owner's decision pending (finding 35): windows longer than the raw log retention. Update this note once decided. -->
Hits are kept only as long as **Raw Logs Retention Days** under **Settings** > **Logs**, 2 days by default. With that default, longer windows show the same two days. The page reads at most the newest 5,000 hits.

## Blocked senders

**Hits** counts all recorded hits for a sender, regardless of the chart's window. **Limit** is the mailbox's own limit; **Last reset** records a reset made here. Sender details include up to 2,000 refused messages.

**Reset counter** lets the sender send again immediately without changing its limit. It appears only when mailcow's log names the counter.

![Blocked sender detail](../../images/docs/rate-limits-sender-light.webp#gh-light-mode-only)
![Blocked sender detail](../../images/docs/rate-limits-sender-dark.webp#gh-dark-mode-only)

## Configured limits

**Remove limit** and saving `0` both remove a limit.

**Apply to filtered** changes only matching rows, up to 1,000 entries per apply. A value of `0` removes their limits. Entries the app no longer knows are skipped and keep their limits.

## Settings that change this page

Changing limits and resetting counters require the [read-write API key](../Using_the_App.md#the-read-write-api-key).

The Rate Limits feature is separate from Mailbox Stats. While enabled, it collects `ratelimited` logs even if the Logs page is off or that service is unticked there. Turning it off forgets counter resets and deletes collected hits, unless the Logs page still collects the service. Retention stays under **Settings** > **Logs**, even with the Logs page off.

## When something is missing

No hits appear until mailcow refuses a message. **Domain limits could not be read from mailcow** means at least one domain could not be read; mailbox limits still show.

## How sending limits work

A limit allows a number of messages per period. Once the allowance is used, mailcow refuses further sends. Resetting the counter empties the count; changing the limit changes the rule.

A mailbox's own limit overrides the domain limit. Mailboxes without their own limit share the domain allowance. Limits apply to authenticated senders and are separate from [SMTP abuse protection](Abuse_Protection.md), which disables SMTP access.
