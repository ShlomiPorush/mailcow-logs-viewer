# Queue

The queue is read live from mailcow, rather than from imported message history.

![Queue page](../../images/docs/queue-light.webp#gh-light-mode-only)
![Queue page](../../images/docs/queue-dark.webp#gh-dark-mode-only)

## Counts

The summary counts messages waiting for retry, on hold and being delivered. The sidebar shows the total of all queued messages.

## Mail Queue

Search matches part of the sender or any recipient. Search and the queue ID filter use the loaded queue without asking mailcow again.

**Last response** is Postfix's last result for each recipient, usually the remote server's reason for delaying or refusing delivery. See [How the Postfix queue works](#how-the-postfix-queue-works) for queue states.

## Actions

Retry, hold, release and delete need a [read-write API key](../Using_the_App.md#the-read-write-api-key). Reading the queue and adding a suppression do not.

**Retry** requests an immediate delivery attempt; **Flush All** retries the entire queue. Neither fixes the cause of a failure. **Hold** prevents delivery until **Unhold** returns the message to the delivery queue.

**Suppress** opens the Spam Filter's **Add Suppression** dialog for the recipient, to block future mail to that address. With the read-write key, saving it also deletes the queued messages to that address. With multiple recipients, choose the address to suppress. See [Spam Filter](Spam_Filter.md).

**Retry Selected** and **Delete Selected** affect selected messages. **Delete All** affects the entire queue.

> [!WARNING]
> Deletion is permanent. Postfix removes the message without delivering it or telling the sender. Use **Delete All** only when every queued message is unwanted, such as spam from a hijacked mailbox.

## Settings that change this page

<!-- VERIFY: owner's decision pending (finding 6): queue cleanup deletes stuck mail to whitelisted domains too. Update the last sentence of the next item once decided. -->
- **Settings** > **Spam Filter** > **Deferred Queue Cleanup**: when **Suppression Enabled**, **Queue Cleanup Enabled**, the Spam Filter feature and the read-write API key are all on, **Cleanup Deferred Queue** runs every 5 minutes. It deletes deferred messages whose age since arrival reaches **Queue Cleanup Threshold Minutes** (60 by default) and suppresses recipients outside the whitelist. Messages to whitelisted domains are still deleted. See [Spam Filter](Spam_Filter.md#automatic-suppressions).
- Turning off **Queue** under **Settings** > **Features** removes the page and its counter.

## When something is missing

**Failed to load queue** means the app could not read it from mailcow. Check the mailcow connection on [Status](Status.md).

## How the Postfix queue works

- **Incoming** messages are newly arrived and being prepared.
- **Active** messages are being delivered.
- **Deferred** means a temporary delivery failure, such as a timeout or a remote 4xx response. Postfix retries at growing intervals. After `maximal_queue_lifetime` (5 days in default Postfix), it gives up and bounces the message to the sender.
- **Hold** prevents delivery until an administrator releases the message.

A failed manual retry returns the message to the deferred queue. Check **Last response** for the cause, such as a full mailbox, a blocklisting of your server or a remote refusal.
