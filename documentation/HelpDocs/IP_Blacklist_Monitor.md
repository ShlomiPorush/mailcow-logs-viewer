# Blocklists

**Status** > **Blocklists** checks the public addresses your mail leaves from against DNS blocklists.

![Status, Blocklists](../../images/docs/status-blocklists-light.webp#gh-light-mode-only)
![Status, Blocklists](../../images/docs/status-blocklists-dark.webp#gh-dark-mode-only)

## Monitored addresses

**Check all now** checks every address again, waiting 10 seconds between addresses.

| Result | Meaning |
| --- | --- |
| **Listed on** | At least one list you count reports the address. |
| **Clean on** | No list you count reports it. Single lists can still have failed. |
| **Check error** | No listing, but a Spamhaus query failed or more than half of the queries failed. |

Listings appear under the address with the list's answer. **Look up** opens the list's lookup page (for lists that have an HTTPS one), where you can see the reason and request removal. The app cannot remove a listing. Hover a result for the DNS answer or the error.

## Ignore a list

Ignoring a list applies to every address: the app still checks and shows it, but no longer counts it or alerts on it. The saved results stay, so a list counts again at once when you stop ignoring it.

## Settings that change this page

**Settings** > **Blocklists** chooses which addresses are checked:

| Setting | Default | What is checked |
| --- | --- | --- |
| **Mail server IP (auto-detected)** | On | The WAN address that mailcow reports. |
| **Transport IPs** | On | The public addresses of active mailcow transports. |
| **Relayhost IPs** | On | The public addresses of active mailcow relayhosts. |
| **Additional hosts** | Empty | More IPv4 or IPv6 addresses and hostnames, comma-separated. |

A hostname is resolved to all of its IPv4 addresses; private addresses are skipped. If mail leaves through a relay, turn off **Mail server IP (auto-detected)**. The SPF addresses on [Domains](Domains.md) are set separately.

**DNS resolvers** sets the resolvers, comma-separated; empty uses the container's resolver. Use your own recursive resolver (in mailcow, `172.22.1.254`): Spamhaus refuses queries from public resolvers such as Google, Cloudflare or Quad9.

Turning off **Blocklists** under **Settings** > **Features** hides this tab and the blocklist figures on the Dashboard and Status, stops the checks, and deletes the saved results.

## Checks and alerts

The app checks every address shortly after it starts and daily at 05:00 in the app's time zone. Scheduled checks reuse results younger than 24 hours; the buttons always query again. Every 6 hours the app reads transports and relayhosts from mailcow and checks new addresses right away, without alerts.

A check that finds a listing sends an **IP blacklist** alert, again on every later check while the listing lasts. Scheduled checks and **Check all now** send it; **Check now** does not. The app also tells you when fewer addresses are listed and when all are clear. UCEPROTECT Level 2 or Level 3 listings alone send no alert. The email goes to **Blocklist alert email**, or to **Admin Email** when that is empty; see [Notifications](../Notifications.md).

## When something is missing

**No Monitored Hosts** means there is no address to check: the first sync has not run, every source is off, or no source gives a public address.

These answers count as errors, never as listings. Fix the resolver before you ask anyone to remove a listing.

- `127.255.x.x`: the list refused the query. Spamhaus does this for public resolvers and for too many queries.
- `127.0.0.1`: a resolver or ad blocker is rewriting the list's domain.
- An answer outside `127.0.0.0/8`: the resolver rewrites "not found" answers.
- A Spamhaus answer outside its listing codes `127.0.0.2` to `127.0.0.11`.

An IPv6 address is checked only against lists that answer IPv6 queries (Spamhaus ZEN, SBL and XBL, and s5h.net), so it shows fewer lists.

## How DNS blocklists work

A DNS blocklist is a DNS zone. To check `192.0.2.10` on `zen.spamhaus.org`, the app looks up `10.2.0.192.zen.spamhaus.org`. "Not found" means not listed. An answer in `127.0.0.0/8` means listed, and the exact answer says which list part or reason applies.

Each receiving server chooses its lists and what a listing does: reject the mail, raise its spam score, or nothing. A listing can hurt delivery, but not every recipient rejects your mail. Some lists, such as Spamhaus PBL, list ranges that should not send mail directly, not addresses that sent spam.
