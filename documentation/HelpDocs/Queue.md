# Queue

The Queue page shows the messages waiting in the Postfix queue of your mailcow server, read live from the mailcow API each time the page loads. With a read-write API key you can retry, hold, release and delete them.

<!-- SHOT: queue | Queue page with the Read-Write key: the summary under the title, the toolbar with Select All, Flush All and Delete All, and three rows: one Deferred with a remote server answer, one On hold, one Active -->

## Summary

The summary counts messages waiting for retry, on hold and being delivered. The sidebar shows the total. With none queued, the page says "The queue is empty."

## Mail Queue

The **Mail Queue** list shows every queued message, newest first.

- The search box "Search sender/recipient..." keeps the messages whose sender or any recipient contains the text. Press Enter to search.
- **Filters** opens a **Queue ID** field with **Apply**, to find one message by its Postfix queue ID.
- The line above the list counts the messages shown, and **Clear filters** empties both fields.

The search and the queue ID filter work on the queue as loaded, without asking mailcow again.

Each row shows:

| Column | What it shows |
|---|---|
| **Recipient** | Every recipient of the message. Under them: "From" the sender, "queued" how long ago (point at it for the exact time), and "ID" the queue ID. Addresses and the ID copy on click. |
| **State** | The Postfix queue the message is in: **Deferred** (amber), **Active** (green), **On hold**, **Incoming**, or another queue name. See [How the Postfix queue works](#how-the-postfix-queue-works). |
| **Last response** | The last answer Postfix got for each recipient, usually the remote server's reason for refusing or delaying the message. With several recipients, each answer starts with its address. A held message without an answer shows "Put on hold". |
| **Size** | The size of the message. |
| **Actions** | The buttons described below. |

On a phone the rows stack, one message per block.

The page updates itself every 30 seconds while it is open, and again after every action.

## Actions

Queue actions need a [read-write API key](../Using_the_App.md#the-read-write-api-key). Without it the queue stays readable, but actions and selection controls are hidden.

Each row has:

- **Retry** asks Postfix to try delivering the message now.
- **Hold** moves the message to the hold queue, where Postfix leaves it alone until it is released. A held message has **Unhold** instead, which puts it back in line for delivery.
- **Delete** removes the message from the queue after you confirm "Delete this message from the queue?".
- **Suppress** opens the **Add Suppression** dialog of the Spam Filter page with the recipient filled in, so future mail to that address is blocked. With several recipients, **Suppress** is a menu where you pick the address. See [Spam Filter](Spam_Filter.md).

Above the list:

- A checkbox on each row and **Select All** (then **Deselect All**) select messages.
- With messages selected, **Retry Selected** retries them after "Retry delivery of N message(s)?", and **Delete Selected** deletes them after "Permanently delete N message(s) from the queue?". The number selected is shown next to them.
- **Flush All** retries every message in the queue after "Flush (retry delivery of) ALL messages in the queue?".
- **Delete All** deletes every message in the queue after "Permanently delete ALL messages from the queue? This cannot be undone." It is hidden while messages are selected.

Actions are disabled while a request runs. A notice shows the result or failure reason.

> [!WARNING]
> A deleted message is gone for good. Postfix removes it without delivering it and without telling the sender, so use **Delete All** only when you know every message in the queue is unwanted, such as spam sent from a hijacked mailbox.

## Settings that change this page

- **Settings** > **Mailcow** > **Connection**: **mailcow API Key (read-write)** (`MAILCOW_API_KEY_RW`) turns on the actions.
- **Settings** > **Spam Filter** > **Deferred Queue Cleanup**: when **Suppression Enabled**, **Queue Cleanup Enabled**, the Spam Filter feature and the read-write API key are all on, **Cleanup Deferred Queue** runs every 5 minutes. It deletes deferred messages whose age since arrival reaches **Queue Cleanup Threshold Minutes** (60 by default) and suppresses recipients outside the whitelist. Messages to whitelisted domains are still deleted. See [Spam Filter](Spam_Filter.md#automatic-suppressions).
- **Settings** > **Features**: turning off **Queue** removes the page and its counter.

## When something is missing

- **Queue actions are locked**: add the read-write API key through **Open Settings**. This also unlocks **Suppress** on this page.
- **"Failed to load queue" with a reason.** The app could not read the queue from mailcow. Check the mailcow connection on the [Status](Status.md) page.
- **"No matching queue entries".** No queued message matches the search or the queue ID. **Clear filters** shows the whole queue.

## How the Postfix queue works

Postfix keeps every message it has accepted in a queue until it is delivered. The queue name in the **State** column tells where a message is:

- **Incoming:** newly arrived and being prepared.
- **Active:** Postfix is delivering it right now.
- **Deferred:** a delivery attempt failed with a temporary error (the remote server was down, refused with a 4xx code, or the connection timed out). Postfix tries again on its own at growing intervals. When the message is still not delivered after the queue lifetime (`maximal_queue_lifetime`, 5 days in a default Postfix), Postfix gives up and bounces it to the sender.
- **Hold:** put aside by an administrator. Postfix never delivers a held message until it is released.

**Retry** and **Flush All** only make Postfix try sooner; a message that fails again goes back to the deferred queue. The **Last response** column is the quickest way to see why it fails: a full mailbox, a blocklist listing of your server, or a remote server that refuses your mail. A recipient that keeps failing is a candidate for **Suppress**.
