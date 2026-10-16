# Search

The search in the top bar finds pages and their tabs, settings, messages, domains, mailboxes and IP addresses from one box. Pages and settings are found in the app itself; the other kinds are looked up on the server as you type.

<!-- SHOT: search-all | The search open on a wide screen with "example" typed: the All tab with Pages, Settings, Messages, Domains and Mailboxes sections, the counts in the tabs and the key hints at the bottom -->

## Opening the search

- On a wide screen the box **Search everything** sits in the top bar of every page except Messages, which has no top bar. Click it, or press `/` anywhere while you are not typing in a field and no window is open.
- On a phone the search button in the top bar opens the search over the whole screen. **Cancel** closes it.
- Escape closes the search and clears the text. A click outside the panel closes it and keeps the text for the next time.

## What it finds

Pages and settings are found from the first character you type. Messages, domains, mailboxes and IP addresses need at least two characters; until then the panel says "Type one more character to search the messages, domains, mailboxes and addresses too." The server is asked once you pause typing for a moment, and an older search still running is dropped.

<!-- VERIFY: a Settings result while SETTINGS_EDIT_VIA_UI_ENABLED is off: the field the search scrolls to may not exist on the read-only Settings page. Check that it still opens the right place. -->

| Kind | What matches | A result shows | Opening it |
|---|---|---|---|
| **Pages** | The name of a page in the sidebar, or the name of one of its tabs | The page and its group, or the tab and its page | Opens the page or the tab |
| **Settings** | A setting label or key, such as `csv_export_limit` | The setting and its Settings tab | Opens Settings. With UI editing enabled, it selects the tab and focuses the available field; the read-only layout may have no such field. |
| **Messages** | The same fields as the search on the Messages page: sender, recipient, subject, Message-ID, queue ID, client IP and authenticated user | Subject, sender and recipient, and how long ago it was seen | Opens the message details window over the search |
| **Domains** | The domain name | How many mailboxes it has, and **Inactive** for an inactive domain | Opens the Domains page with that domain's details open |
| **Mailboxes** | The mailbox address, its display name, or one of its aliases | The address and the display name | Opens Mailbox Stats with that mailbox open |
| **IP addresses** | Part of an address that tried to log in during the last day, from the Security page's **To review** and **Banned** lists | The address, **Banned** or **To review**, its country, the number of attempts and when it was last seen | Opens the Security **Events** tab filtered on that address |

The IP addresses kind is only asked when the text can be part of an address: digits, the letters a to f, dots and colons. Typing a name finds no addresses.

A message opened from the search opens over it. When you close the message, the search is still there with its results, ready for the next one. Every other result closes the search when it opens.

## Tabs and counts

The panel has a tab for **All** and one per kind, each with the number of results.

- **All** shows the first 3 results of each kind under a heading with the kind's count. **See all** next to a heading opens that kind's tab.
- A kind's tab lists up to 10 results. **Messages** and **Mailboxes** start with a line that gives the full count and a link, **Open in Messages** or **Open in Mailbox Stats**, which opens that page searched for the same text. Domains and IP addresses say "The first 10 of N" when there are more.
- The text you typed is highlighted in each result.
- While a kind is still being looked up its tab shows a busy mark, and a tab whose lookup failed shows a warning mark. A failed kind says "This search failed. Try again in a moment."
- A kind with no results says "Nothing found for" the text you typed.

## Keyboard and phones

Use the arrow keys to move through results, Enter to open one, Tab or Shift+Tab to change kind, and Escape to close. The panel shows the key hints.

On a phone the search fills the screen. Changing kind hides the keyboard. Back closes a message opened over the search before it closes the search itself.

## When something is missing

- **There is no search box on the Messages page.** The Messages page has its own layout without a top bar. Use its own search box, or open any other page first.
- **A kind is missing from the tabs.** Domains are not searched while the **Domains** feature is off, mailboxes while **Mailbox Stats** is off, and IP addresses while **Security** is off (**Settings** > **Features**). Pages that are turned off are not found either.
- **An address you expect is not found.** The IP addresses kind covers only addresses that tried to log in during the last day. For older events, use the filters on the Security **Events** tab.
- **An old message is not found.** The app keeps logs for **Retention Days** under **Settings** > **Fetch** (7 by default). Older messages are deleted from the database.
