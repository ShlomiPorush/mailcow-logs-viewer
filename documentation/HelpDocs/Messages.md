# Messages

The Messages page lists messages the app has imported from your mailcow server and shows their delivery results. The app builds each message from the Postfix, Rspamd and Dovecot logs it imports from mailcow, and links them as described in [How a message is put together](#how-a-message-is-put-together).

![Messages](../../images/docs/messages-light.webp#gh-light-mode-only)
![Messages](../../images/docs/messages-dark.webp#gh-dark-mode-only)

## Layout

On wide screens the filters, list and reading pane sit side by side. On narrower screens, **Outcome:**, **Direction:** and **Time:** replace the filter column. When there is room for a reading pane, the first message opens automatically. Otherwise, messages open in a window or a phone sheet.

The wide layout has no top bar. Use the page search, or open another page for global search. The phone top bar still has global search. See [Using the app](../Using_the_App.md).

## Filters

Each filter choice shows how many messages match it.

| Group | Choices |
|---|---|
| **Outcome** | **All messages**, **Delivered**, **Deferred**, **Bounced**, **Rejected**, **Spam**, **Discarded (Sieve)** |
| **Direction** | **Any direction**, **Inbound**, **Outbound**, **Internal** |
| **Time** | **All Time**, **Today**, **7 Days**, **30 Days**, **90 Days**, **Custom range** |

- Each group counts matches with the other groups applied, so you can see how changing one filter affects the result.
- **Spam** shows messages whose final status is spam and also those Rspamd classed as spam, whatever happened to them afterwards.
- **Today** starts at midnight. **7 Days**, **30 Days** and **90 Days** count back from now. A preset ends at the moment you pick it. Presets and custom dates use browser time; list timestamps use the [time-zone rules](../Using_the_App.md#time-zone). After you pick one, the **Time:** button reads **Last 7 Days** and so on.
- **Custom range** opens **From** and **To** date fields and **Apply**. The range runs from the start of the From day to the end of the To day in browser time, and the **Time:** button shows the two days. Both dates are required; the end date cannot be before the start date.
- **Export CSV** at the bottom of the column downloads the filtered list, see [Export CSV](#export-csv).

Above the list:

- The search box, "Search (sender, recipient, subject, IP, user)...", searches when you press Enter. It matches part of the sender, recipient, subject, Message-ID, queue ID, client IP or authenticated user, ignoring upper and lower case.
- The filter button next to it ("Filter by sender, recipient, user or IP") opens four more fields: **Sender**, **Recipient**, **Authenticated User** and **Source IP**, with **Apply** and **Clear**. Each matches part of the value. The button shows how many of these fields are set.
- A summary line gives the number of messages found, and **Clear filters** resets every filter, the search and the time.

Other pages open Messages with filters already set, for example **View these messages** on the Dashboard's mail flow chart or the counts on Mailbox Stats.

## The list

The list shows the newest messages first, by the time the message was first seen, 50 at a time. More load as you scroll down; the end of the list says "All N messages shown". If loading more fails, "Could not load more messages." appears with **Try again**.

Each row shows:

- The sender and the time: the time of day for today, the date for earlier days. Pointing at the time shows the full date and time.
- The subject, or "No subject".
- The outcome tag: **Delivered**, **Sent**, **Deferred**, **Bounced**, **Rejected**, **Spam**, **Discarded** or **Expired**. A message without a final outcome shows **Linked** when all its logs are linked, or **Pending** while the app still waits for its Postfix logs.
- The direction tag (**inbound**, **outbound** or **internal**), and **SPAM** when Rspamd classed it as spam.
- The recipient, and **Folder:** with the mailbox folder when Dovecot stored it (for example `INBOX` or `Junk`).
- **Deliveries:** with a number, when the same message was delivered more than once, for example forwarded, sent to several recipients, or released from quarantine.

Each row is one message, not one delivery. Deliveries that share a Message-ID are grouped, and the earliest delivery that matches your filters stands for the message. The total in the summary line counts messages the same way, so it agrees with the Dashboard's **Messages** figure.

The first batch refreshes every 30 seconds, with the time filter kept. Search, address, outcome and direction filters or loading more stop refreshes. A preset covers time up to the moment you picked it, so pick it again to see newer messages.

## Message details

Click a message for its details. The same details open from Dashboard activity and global search.

![Message details window on the Logs tab for a deferred message](../../images/docs/message-details-logs-light.webp#gh-light-mode-only)
![Message details window on the Logs tab for a deferred message](../../images/docs/message-details-logs-dark.webp#gh-dark-mode-only)

### The header

Above the tabs:

- The subject, and **From**, **To** and **When**. With several recipients the label reads **To (N)** and every recipient is listed. The addresses copy on click.
- A delivery outcome sentence, including the target folder, next server or failure reason when available. Size and direction follow it.
- When Rspamd scanned the message: **Spam score**, **Action** and **Class** (**SPAM** or **CLEAN**). The score is red at or above the message's spam limit. A click opens the **Spam Analysis** tab.

The four tabs are **Overview**, **Logs**, **Spam Analysis** and **Security**.

### Overview

**What happened** lists the delivery steps with their times:

- **Received from** the client IP, with the receiving program and "authenticated as" the user who logged in, or **Rejected while receiving**.
- **Queued as** the Postfix queue ID.
- **Rspamd score** with the action Rspamd took.
- **Delivered to**, **Deferred for** or **Bounced for** the next server or recipient, with the Postfix status and its code.
- The mailbox delivery Dovecot reported: **Stored in mailbox**, **Discarded by Sieve**, **Rejected by Sieve**, **Forwarded by Sieve** or **Delivery to mailbox failed**.

A step that repeats, such as a deferred delivery Postfix retries, is shown once with the number of attempts. With no logs yet it says "No delivery steps recorded yet."

When Dovecot did something other than store the message (a Sieve rule discarded, refused or forwarded it, or the store failed), a box **Mailbox delivery:** explains it, with the Sieve reason or the error when Dovecot logged one. This matters because Postfix logs `status=sent` as soon as it hands the message to Dovecot; what happens after that is only visible here.

**Delivery journey** groups repeated deliveries, such as forwarding or release from quarantine. Expand it for each delivery's addresses, time, outcome and folder. **viewing** marks the current delivery; click another to open it. **no final status** marks an unfinished delivery.

**Identifiers** lists, when known:

- **Client IP**, with the country flag, country and city, and the network owner. The location needs MaxMind GeoIP (**Settings** > **MaxMind**).
- **Authenticated user**, the mailcow account that logged in to send it, with "Verified (MAILCOW_AUTH)" when Rspamd confirmed the login.
- **Queue ID** and **Message ID**.

Every value copies on click.

### Logs

The **Logs** tab shows the raw log lines of the delivery:

- **Delivery Error**, in red, when a delivery did not succeed: the answer of the remote server, or Postfix's reason, per recipient. The same error from several retries is shown once with the number of attempts.
- A summary strip with **From**, **To (N)**, **Final Status**, **Queue ID**, **Client IP** and **Relay**.
- **Delivery Summary by Recipient**, when the message had several recipients: each recipient with its status and the server it was handed to.
- **Complete Log Timeline**, with the number of entries: every Postfix line for the message's queue ID and the Dovecot delivery lines, in time order. Each line shows its time, its program, the recipient, the status, the log text, and the **Relay** and **Delay** when Postfix logged them. With both Postfix and Dovecot lines, chips **All**, **postfix** and **dovecot** show one source at a time.

Without Postfix lines the tab says "No Postfix delivery logs available".

### Spam Analysis

The **Spam Analysis** tab shows Rspamd's verdict:

- **Score** with the message's **Limit**, the **Action** Rspamd took, and the **Class**, **SPAM** or **CLEAN**.
- **Detection Symbols**: every Rspamd rule that matched, with its description and options, sorted by weight. A positive score (toward spam) is red and a negative one green. Symbols that scored 0 are hidden; **Show zero scores** shows them and **Hide zero scores** hides them again.

A message Rspamd did not scan says "No spam analysis data available".

### Security

**Security** shows the client IP's failed logins and bans from an hour before to an hour after the message. With events, the tab shows their number in red.

Events include time, IP, action, **User**, **Method**, **Attempts remaining** and the log line. Without them, it says "No security events detected".

The tab is hidden while the **Security** feature is off.

### Closing the details

Close the window with **Close**, Escape, a click outside, or Back. Closing the reading pane leaves it empty until you select another message.

## Export CSV

**Export CSV** downloads filtered results as `messages_` followed by the date and time. If nothing matches, it says "No data to export. Try different filters."

The file has these columns: **Time**, **Sender**, **Recipient**, **Subject**, **Direction**, **Status**, **Queue ID**, **Message ID**, **Spam Score**, **Is Spam**, **User**, **IP** and **Is Complete**.

The export applies the same filters and search as the list, but differs in two ways:

<!-- VERIFY: owner's decision pending (finding 20): the export's row structure (one row per delivery) and its order (latest activity). Update the next item once decided. -->
- It has one row per delivery, not per message, ordered by the latest activity.
- It stops at **CSV Export Limit** rows (**Settings** > **Application**, 10000 by default).

A text cell that starts with `=`, `+`, `-` or `@` gets a leading apostrophe, so a spreadsheet does not read it as a formula.

**Export CSV** appears only in the wide layout with the filters column.

## Settings that change this page

| Setting | Where | Effect |
|---|---|---|
| **Retention Days** (`RETENTION_DAYS`) | **Settings** > **Fetch** | How long messages and their logs are kept. Default 7 days. |
| **Blacklist Emails** (`BLACKLIST_EMAILS`) | **Settings** > **Fetch**, **Excluded addresses** | Addresses whose mail is not stored or shown, such as a BCC archive or a monitoring mailbox. Comma-separated. |
| **Raw Logs Retention Days** (`RAW_LOGS_RETENTION_DAYS`) | **Settings** > **Logs** | How long the Dovecot lines in the Logs tab are kept. Default 2 days. The mailbox delivery result itself is kept with the message. |
| **Max Correlation Age Minutes**, **Correlation Check Interval** | **Settings** > **Correlation** | How long and how often the app tries to link a message's logs. |
| **CSV Export Limit** (`CSV_EXPORT_LIMIT`) | **Settings** > **Application** | The most rows an export holds. Default 10000. |
| **Maxmind Account Id**, **Maxmind License Key** | **Settings** > **MaxMind** | Country, city and network of the client IP. |
| **Security** | **Settings** > **Features** | Turned off, hides the Security tab of the details. |

See [Using the app](../Using_the_App.md#time-zone) for how `TZ` affects timestamps.

## When something is missing

- **A message shows Pending.** The app has the Rspamd scan but not yet the Postfix logs. It keeps trying for **Max Correlation Age Minutes**. If mail is flowing and many messages stay pending, check **Message linking** on the [Status](Status.md) page.
- **No folder and no mailbox delivery step.** The message was not delivered to a local mailbox, or the Dovecot lines are older than **Raw Logs Retention Days**.
- **No Spam Analysis.** Rspamd did not scan this delivery. A release from quarantine, for example, is delivered again without a new scan.
- **No country next to the client IP.** MaxMind GeoIP is not configured, or the address has no known location.
- **"Failed to load messages" with an error.** The app's database did not answer. **View Container Logs** in the sidebar tools shows the error.
- **A message you expect is not listed.** It may be older than **Retention Days**, or it involves an address in **Blacklist Emails**.
- No **Export CSV** button: widen the browser until the filters column appears.

## How a message is put together

**Postfix** logs connections, queue IDs and delivery attempts: `sent`, `deferred` (temporary failure, retried) or `bounced` (permanent failure). **Rspamd** adds score, symbols, client IP, authenticated user, subject and Message-ID. **Dovecot** records LMTP mailbox delivery and Sieve outcomes.

The app links these by queue ID and Message-ID into one message. The direction comes from the scan: a message sent by a user who logged in is **outbound**, other mail is **inbound**, and a message between local addresses that Postfix handed straight to Dovecot is **internal**.

A message can be delivered more than once under the same Message-ID, for example when an alias forwards it or when it is released from quarantine. Each delivery has its own sender, recipient and outcome. The list shows the message once with the number of deliveries, and the details show them together as the delivery journey.
