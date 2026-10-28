# Search

![Search](../../images/docs/search-all-light.webp#gh-light-mode-only)
![Search](../../images/docs/search-all-dark.webp#gh-dark-mode-only)

## Opening the search

Press `/` while you are not typing in a field and no window is open. Global search is unavailable in the wide Messages layout; use that page's search or open another page.

Escape closes search and clears its text. Clicking outside closes it but keeps the text.

## What it finds

Pages and settings match from the first character. Server results need at least two:

| Kind | What matches |
|---|---|
| **Pages** | Page and tab names. |
| **Settings** | Labels or keys, such as `csv_export_limit`. Results open the field for editing. |
| **Messages** | Sender, recipient, subject, Message-ID, queue ID, client IP and authenticated user. |
| **Domains** | Domain names. |
| **Mailboxes** | Mailbox addresses, display names and aliases. |
| **Suppressions** | Blocked addresses, their notes and the last server reply, active or not. Results open Outbound > Suppressions filtered to the address. |
| **IP addresses** | Addresses that tried to log in during the last day, including banned addresses. |

IP searches accept only digits, letters a to f, dots and colons. Use Security Events for older addresses.

Message details open over search, keeping its results available when you close the message.

## Tabs and counts

**All** shows the first 3 results per kind; individual tabs show up to 10. Counts can exceed the displayed results. **Open in Messages**, **Open in Mailbox Stats** and **Open in Suppressions** search those pages with the same text to show more.

A warning mark means that kind's lookup failed. Try again; other kinds may still have results.

On a phone, changing kind hides the keyboard.

## When something is missing

- Domains, mailboxes, suppressions and IP addresses are omitted while **Domains**, **Mailbox Stats**, **Suppressions** or **Security** is off under **Settings** > **Features**. Disabled pages are omitted too. Suppressions are also omitted while **Sync with Rspamd** is off: the app keeps no list then.
- Settings results are unavailable when UI editing is off (`SETTINGS_EDIT_VIA_UI_ENABLED`), because the read-only page has no editable fields to open.
- Messages older than **Keep logs for (days)** under **Settings** > **Fetch** have been deleted from the database. The default is 7 days.
