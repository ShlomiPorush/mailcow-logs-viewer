# Rate Limits - User Guide

## Overview

mailcow can cap how much mail a mailbox or a domain is allowed to send - for example **500 messages per hour**. When a sender runs out of allowance, mailcow refuses the message with a temporary error and the sender is stuck until the allowance refills.

This page answers the two questions that come up when that happens:

*   **Who is hitting the limits?** - the activity chart and the blocked senders list.
*   **What are the limits?** - one table with every mailbox and domain limit, editable in place.

It is a view of the **Mailbox Statistics** page (tab **Rate Limits**), but it works on its own - it does not need Mailbox Statistics to be enabled.

> **Note**: Rate limits apply to **sending** only. Receiving mail is never affected.

## The one thing worth understanding: limit vs counter

These are two different things, and mixing them up is the usual source of confusion.

| | **Limit** | **Counter** |
|---|---|---|
| What it is | Configuration: "500 messages per hour" | The live tally of what this sender has already used |
| Where it lives | mailcow's mailbox/domain settings | mailcow's rate limit engine, in memory |
| Changes when | You edit it | Every message sent; it drains on its own over time |
| Shown in | **Configured limits** and the **Limit** badge | Not shown as a number - you see its effect: the sender is blocked |

The counter works like a leaky bucket: every message sent adds a drop, and the bucket drains continuously over the time frame. Once it is full, mail is refused until enough has drained out.

So there are two different fixes for a blocked sender:

*   **The sender is legitimately over a sensible limit, just now** - use **Reset counter**. It empties the bucket so they can send immediately. Their limit stays exactly as it was.
*   **The limit itself is wrong for this sender** - edit it in **Configured limits**. A mailbox such as `newsletter@example.com` may simply need a bigger allowance than everybody else.

## Rate limit activity

The first card shows **blocked sends over time** as a bar chart, so you can see whether this is a one-off or something that happens every day.

*   The **window selector** on the right switches between **Last 24 hours**, **Last 7 days** and **Last 30 days** (the default). It controls this whole page, not just the chart.
*   Over the 24 hour window each bar is **one hour**; over 7 and 30 days each bar is **one day**.
*   Quiet buckets are drawn as gaps at zero rather than skipped, so the shape of the chart is honest.
*   The subtitle above the chart summarises the window, for example *"1,204 blocked sends from 3 senders"*.

If nobody was blocked in the window, the card says so and suggests widening it.

## Blocked senders

Every sender that mailcow refused during the selected window, most recently blocked first.

| Column | Meaning |
|---|---|
| **Sender** | The address that was refused |
| **Hits** | How many sends were blocked in this window |
| **Last hit** | When it was last refused |
| **Limit** | That mailbox's own configured limit, or **No limit** |
| **Last reset** | A green badge if the counter was reset, with the time |
| | **Reset counter** button |

Click any row to open that sender's detail.

> **Note**: This list is **history**, built from the logs this viewer has collected. It is not a list of senders who are blocked *right now*. Entries stay visible for the whole window even after you release the sender - that is intentional, so that a recurring problem does not disappear from view.

### Sender detail

The detail view replaces the table with everything known about one sender: the address, the time of the last hit, the current limit, the reset badge if there is one, and a table of the **most recent refused messages** - time, recipient, subject and queue id. **All senders** takes you back to the list.

The queue id is the message's id in the mail logs, useful if you want to trace it on the **Messages** page.

> **Note**: A handful of recent messages is kept per sender, not all of them. The **Hits** count is the real total for the window; the detail table is a sample of the latest ones.

### Reset counter

**Reset counter** clears the live counter in mailcow so the sender can send again straight away. You are asked to confirm first.

What it does **not** do:

*   It does not change the sender's limit. The next batch of mail fills the bucket again at the same rate.
*   It does not remove the sender from this list, and it does not delete their hits. Instead a green **Reset** badge appears with the time.

That badge is the audit trail: it tells you - and the next person looking at this page - that somebody already dealt with this sender, and when.

> **Note**: If a sender needs resetting repeatedly, their limit is too low for what they actually do. Raise it rather than resetting every morning.

## Configured limits

One table for domains and mailboxes together, so a domain cap and the mailboxes underneath it are visible side by side. It lists **every local domain** (limit or not) and **every mailbox that has a limit**. Mailboxes without one are not listed - they send uncapped and there is nothing to show.

*   **Type** - Domain or Mailbox.
*   **Name** - the domain or the mailbox address.
*   **Limit** - for example `500/h`, or **No limit**.
*   **Edit** - opens the inline form on that row.

Above the table:

*   **All / Mailboxes / Domains** filter the table by type.
*   **Search** narrows it by name.

> **Note**: A domain limit caps the domain **as a whole**, on top of each mailbox's own limit. A mailbox can be blocked by its domain's limit even when it is well inside its own.

### Editing a limit

Click **Edit** to open a form under the row:

1.  **Allow** - how many messages, as a whole number.
2.  **per second / minute / hour / day** - the time frame.
3.  **Save** applies it in mailcow immediately.
4.  **Remove limit** takes the cap off entirely, so that mailbox or domain sends without one.
5.  **Cancel** closes the form and changes nothing.

Changes take effect on the next message; mail already refused is not retried any sooner.

> **Warning**: Editing requires a **Read-Write API key** (`MAILCOW_API_KEY_RW`), configured under **Settings → Mailcow → Connection**. Without it the page is read-only: a yellow banner appears and the Edit and Reset counter buttons are hidden. Reading the page works fine with the read-only key.

## Where the data comes from

| What | Source | Freshness |
|---|---|---|
| Blocked sends, senders, refused messages | The `ratelimited` log collected by this viewer | As current as log collection; limited by log retention |
| Mailbox limits | Background mailbox sync from mailcow | Every 5 minutes |
| Domain limits | The mailcow API | Cached for a few minutes, refreshed after you edit one |

A few consequences worth knowing:

*   The activity and sender lists are read from the **local database only**, never from mailcow. This page still answers when mailcow is unreachable - only editing and resetting need it.
*   If your **log retention** is shorter than the selected window, the older part of the chart will be incomplete.
*   A mailbox limit you change in mailcow directly may take up to 5 minutes to appear here. A limit changed on this page is shown immediately.
*   If domain limits cannot be read, an amber notice appears above the table and mailbox limits are still shown.

## Turning the feature off

Rate Limits is a feature toggle (`rate-limits`) under **Settings → Application → Features**, or the `DISABLED_FEATURES` environment variable. Switching it off hides the tab and stops the related background work; mailcow keeps enforcing its limits either way.

It is independent of Mailbox Statistics - you can run either one without the other. With Mailbox Statistics disabled, this page *is* the Rate Limits page and the Statistics tab is gone.
