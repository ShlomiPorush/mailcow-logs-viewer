# Messages

The app builds messages from imported Postfix, Rspamd and Dovecot logs. See [How a message is put together](#how-a-message-is-put-together).

![Messages](../../images/docs/messages-light.webp#gh-light-mode-only)
![Messages](../../images/docs/messages-dark.webp#gh-dark-mode-only)

## Filters

Filter counts apply the other groups' choices, so each count shows what changing that filter would return. **Spam** includes both messages with a final spam status and those Rspamd classed as spam, whatever happened afterwards.

**Today** starts at midnight; the day-count presets count back from now. Each preset ends when you pick it. Custom ranges include both whole days. Days are days in the [app's time zone](../Using_the_App.md#time-zone).

Search matches part of the sender, recipient, subject, Message-ID, queue ID, client IP or authenticated user, ignoring case. It runs on Enter. The separate sender, recipient, authenticated user and source IP filters also match partial values.

## The list

Messages appear newest first by first-seen time, in batches of 50. Each row represents one message. Deliveries sharing a Message-ID are grouped, and the earliest delivery matching your filters represents the message. The total counts messages the same way as the Dashboard.

**Deliveries** counts all deliveries of that message, including forwarding, multiple recipients and quarantine releases. **SPAM** means Rspamd classed the message as spam. Without a final outcome, **Linked** means its logs are linked; **Pending** means the app still waits for Postfix logs.

The list updates by itself, with every filter. At the top of the list, new messages appear there. Further down, the list stays where it is and **N new messages** appears at the top; select it to go to them. Oldest first, new messages go at the end of the list, and the button appears there. A time preset such as **Today** always runs up to now. A custom range stays as you chose it.

## Message details

![Message details window on the Logs tab for a deferred message](../../images/docs/message-details-logs-light.webp#gh-light-mode-only)
![Message details window on the Logs tab for a deferred message](../../images/docs/message-details-logs-dark.webp#gh-dark-mode-only)

### Overview

Repeated steps, such as deferred retries, appear once with the attempt count. A message to several recipients shows one step per outcome with its number of recipients; **View** lists them in the Logs tab.

**Mailbox delivery** explains Sieve discards, refusals, forwarding or storage failures. Postfix reports `status=sent` when it hands a message to Dovecot; only Dovecot tells you what happened afterwards.

**Delivery journey** groups repeated deliveries under the same Message-ID. Each has its own addresses, outcome and folder. **viewing** marks the open delivery; **no final status** marks an unfinished one.

**Authenticated user** is the account that logged in to send the message. **Verified (MAILCOW_AUTH)** means Rspamd confirmed the login. Client IP location and network information need MaxMind GeoIP under **Settings** > **MaxMind**.

### Logs

**Delivery Error** gives the remote server's response or Postfix's reason for failure. Repeated identical errors appear once with an attempt count.

A message to several recipients lists them under **Recipients** instead, problems first, each with the last status Postfix logged for it and the reason. **Not logged** means Postfix has no delivery line for that address yet. Click a recipient, or pick one under **Recipient**, to see only its lines; lines that belong to every recipient stay, dimmed and marked **All recipients**. A status or a search in the list narrows the timeline the same way, to the recipients it shows.

The timeline combines Postfix lines for the queue ID with Dovecot delivery lines in time order. **No Postfix delivery logs available** means no Postfix lines were linked to this delivery.

### Spam Analysis

The spam score turns red at the message's own spam limit. Positive detection-symbol scores point toward spam; negative scores toward legitimate mail. Symbols are sorted by weight. Zero-score symbols are hidden until **Show zero scores** is enabled.

**No spam analysis data available** means Rspamd did not scan this delivery.

### Security

Events belong to the client IP and cover an hour before to an hour after the message. The tab is hidden when the Security feature is off.

## Export CSV

The export uses the list's filters and search, with two differences:

<!-- VERIFY: owner's decision pending (finding 20): the export's row structure (one row per delivery) and its order (latest activity). Update the next item once decided. -->
- It has one row per delivery, not per message, ordered by the latest activity.
- It stops at **CSV export limit (rows)** rows (**Settings** > **Application**, 10000 by default).

Text cells starting with `=`, `+`, `-` or `@` get a leading apostrophe so a spreadsheet does not treat them as formulas. **Export CSV** is available only in the wide layout with the filters column.

## Settings that change this page

- **Settings** > **Fetch** > **Keep logs for (days)** (`RETENTION_DAYS`) keeps messages and their logs for 7 days by default. **Addresses to exclude** (`BLACKLIST_EMAILS`) keeps mail to or from the listed addresses out of Messages; use a comma-separated list.
- **Settings** > **Logs** > **Keep raw logs for (days)** (`RAW_LOGS_RETENTION_DAYS`) keeps Dovecot lines for 2 days by default. The mailbox delivery result itself stays with the message.
- **Settings** > **Message linking** > **Stop looking after (minutes)** and **Check every (seconds)** control how long and how often the app tries to link logs.

## When something is missing

- **Pending.** The Rspamd scan arrived before the Postfix logs. The app keeps trying for **Stop looking after (minutes)**. If many messages stay pending while mail flows, check **Message linking** on [Status](Status.md).
- **No folder and no mailbox delivery step.** The message was not delivered to a local mailbox, or the app could not link its Dovecot lines to it. The folder and result stay after the Dovecot lines pass **Keep raw logs for (days)**.
- **No Spam Analysis.** Quarantine releases, for example, are delivered again without a new scan.
- **No country for the client IP.** MaxMind GeoIP is not configured, or the address has no known location.
- **Failed to load messages.** The app's database did not answer. Check **View Container Logs**.
- **An expected message is absent.** It may be older than **Keep logs for (days)**, or involve an address in **Addresses to exclude**.

## How a message is put together

Postfix records connections, queue IDs and delivery attempts: `sent`, `deferred` (temporary failure, retried) or `bounced` (permanent failure). Rspamd adds score, symbols, client IP, authenticated user, subject and Message-ID. Dovecot records mailbox delivery and Sieve outcomes.

The app links these by queue ID and Message-ID into one message. The direction comes from the scan: a message sent by a user who logged in is **outbound**, other mail is **inbound**, and a message from a local sender to local recipients that came from inside (a login or a private address) and that Postfix handed straight to Dovecot is **internal**.
