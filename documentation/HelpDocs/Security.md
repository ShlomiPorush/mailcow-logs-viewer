# Security

Security combines mailcow's netfilter logs and Fail2ban policy with the app's own [protection rules](#protection-rules).

## Overview

![Security, Overview](../../images/docs/security-overview-light.webp#gh-light-mode-only)
![Security, Overview](../../images/docs/security-overview-dark.webp#gh-dark-mode-only)

### To review, Banned and History

- **To review**: every address that tried in the period and is not banned, including watched catches and allowlisted addresses.
- **Banned**: addresses banned by a rule, Fail2ban or the denylist. A Fail2ban ban that mailcow is about to lift is not counted.
- **History**: the 200 newest rule catches that ended.

Attempts are netfilter rule matches. Failed logins include SMTP authentication, IMAP, POP3, Sieve, SOGo and mailcow or Rspamd UI logins. SMTP protocol probes count as attempts without being failed logins.

### Period, Country and Network

The list and both charts count the selected period. "Since" beside the period means the stored logs start later; log retention is set in [Settings](Settings.md). Chart bars count attempts, so one address can contribute many. Country and network data come from MaxMind GeoIP; a network groups addresses by the organization that owns the address block.

**History** has no period or network filter; the country filter applies to it.

### Each address and what you can do

| State | Meaning |
|---|---|
| A rule name | A rule in watch mode caught it. Nothing was banned. |
| **Banning** | A rule caught it; the ban will be written on the next run. |
| **Not banned yet** | Writing the ban failed. The next run tries again. |
| **Possible stolen password** | Alert only: nothing was banned. |
| **Allowlisted** | Exempt from bans, unless also denylisted. |
| **Denylisted** | Banned until removed. |

- **Ban** uses the rule's current ban length. **Ban permanently** adds a denylist entry until removal. Rule expiry removes only entries the app owns.
- A single address is written as `/32` for IPv4 or `/128` for IPv6. **Ban permanently** and **Allow** do not duplicate an address already held in another notation.
- **Unban** lifts Fail2ban's ban. If Fail2ban banned a network, it lifts the whole network, named on the button. Further failures can cause another ban. Denylisted addresses must be removed from the denylist instead.
- When Fail2ban bans a whole network around an attacker (**Ban the network** under **Settings** on this page), **Banned** shows the network as a row of its own, such as `198.51.96.0/20` tagged **Whole network** with its number of addresses, and the addresses from it on the list as **Banned through** that network. The network's row offers only **Unban**.
- **Undo** cancels a pending rule ban or removes the denylist entry the app added. **Dismiss** closes a watched catch without changing mailcow. Both pause that rule for this address for 7 days.
- Removing an allowlist or denylist entry removes the covering entry, which may be a network.

Address details include the accounts tried and the 40 newest netfilter lines. The failed-login count covers the selected period; if none occurred in that period, it falls back to the last 24 hours from the newest log lines.

### History

- **No new activity**: a watched catch had no activity for 7 days. It was never banned and can be caught again.
- **Ban ended**: the ban length passed and the app lifted the ban.
- **Ban undone**: you used **Undo**.
- **Dismissed**: you used **Dismiss**, or the address was allowlisted before its ban was written.

## Lists

![Security, Lists](../../images/docs/security-lists-light.webp#gh-light-mode-only)
![Security, Lists](../../images/docs/security-lists-dark.webp#gh-dark-mode-only)

The lists belong to mailcow. The allowlist exempts addresses from Fail2ban and protection rules; the denylist blocks until removal and wins if both contain an address. Entries can be addresses or CIDR networks.

Removing a rule's entry works like **Undo**, including the 7-day pause. Changes take a few seconds in mailcow. The app rereads both lists before every change to preserve entries added elsewhere.

### Entries tagged Whole network

Earlier versions wrote single IPv6 addresses as `/32`, such as `2001:db8::1/32`. mailcow reads that as the whole `2001:db8::/32` network, blocking or exempting all its addresses. **Whole network** marks these entries, but not an intentional network entry such as `2001:db8::/32`.

**Repair** replaces the entry with the single address as `/128` and reads mailcow's list back to confirm it. **Remove** deletes it instead. Both need the read-write API key. Until repaired or removed, the entry appears under [Dashboard > Needs attention](Dashboard.md#needs-attention). The app never changes it without your action.

## Settings

![Security, Settings](../../images/docs/security-settings-light.webp#gh-light-mode-only)
![Security, Settings](../../images/docs/security-settings-dark.webp#gh-dark-mode-only)

### Fail2ban

This changes mailcow's Fail2ban policy. **Always on** means the app cannot turn Fail2ban off.

| Setting | Effect and limits |
|---|---|
| Failed logins before a ban | Attempts within the retry window; at least 1. |
| Retry window | Seconds in which failures count; at least 1. |
| Ban time | First ban length; at least 60 seconds. |
| **longer each time it comes back** | Increases the ban length for repeated bans. |
| Longest ban | At least 60 seconds and no shorter than the first ban. |
| **Ban the network, IPv4** | Prefix length 8 to 32. `32` bans one address; shorter prefixes ban its surrounding network. |
| **Ban the network, IPv6** | Prefix length 8 to 128. `128` bans one address. |

mailcow's **Manage Fail2Ban externally**, under **System** > **Configuration** > **Options** > **Fail2ban parameters**, keeps the ban list but sets no firewall rules. You must block those addresses with your own firewall. The app does not expose this option and preserves it when saving policy or lists.

### Protection rules

The app's six rules are off on installation. They run after each log fetch (every 60 seconds by default), or through **Run** on **Protection Rules** on [Status](Status.md). They read only lines received since their last run: enabling a rule does not catch earlier attacks.

Five rules catch attacking addresses. **Watch first**, the default mode, records them for review. **Ban** writes them to mailcow's denylist and needs a read-write API key. A watched address that attacks again after switching to **Ban** can then be banned.

Switching back to **Watch first** cancels unwritten automatic bans. Written bans finish normally, and manually requested bans stay. Expiry removes only entries the app added. **Undo** and **Dismiss** pause the rule for that address for 7 days; watched catches with no activity for 7 days move to **History**.

Rules exclude allowlisted addresses, private, loopback and link-local networks, the mailcow server's IP and literal IPs checked by the [blocklist monitor](IP_Blacklist_Monitor.md). Allowlisting an address cancels its pending ban.

**Email me when it bans** covers successful and failed ban attempts. **Email me on every alert** covers **Possible stolen password**. Each run sends at most one email, grouping addresses by outcome; expiry sends none. Destinations must receive the Security topic. See [Notifications](../Notifications.md).

#### Trap accounts

Catches an address that tries a nonexistent trap account. A bare name such as `admin` matches at any domain; `test@example.com` matches only that address. Real mailboxes and aliases cannot be saved as traps and are skipped if created later. Up to 500 names; default ban length: 30 days.

#### Unknown accounts

Catches an address trying several nonexistent accounts within a time window. A login without a domain counts as nonexistent. A full address counts if it is neither a mailbox nor an alias and its domain has no catch-all. Alias domains count as their target domain.

A successful SMTP or IMAP login from the address in the last 24 hours exempts it. Defaults: 5 accounts within 60 minutes, banned for 7 days. Allowed: 2 to 100 accounts, 5 to 1440 minutes.

#### Repeat offenders

Counts Fail2ban's own bans, excluding denylist entries. Default: 3 bans within 30 days, then banned until removed by hand. Allowed: 2 to 50 bans, 1 to 365 days.

#### Attacking networks

Catches a whole IPv4 `/24` when enough of its addresses appear in the netfilter log. IPv6 networks are not caught. Networks containing an allowlisted or internal address, or the mailcow server, are exempt.

Default: 5 addresses within 24 hours, banned for 1 day. Allowed: 2 to 256 addresses, 1 to 168 hours.

#### Countries

Catches failed logins from selected countries and requires MaxMind GeoIP. Successful logins are not caught. Default ban length: 7 days.

> [!WARNING]
> In **Ban** mode this rule bans every address of the picked countries that fails a single login, including your own users who mistype a password while traveling. Start with **Watch first**.

#### Possible stolen password

Alerts on a successful SMTP or IMAP login after failures from the same address. Default: 3 failures within 60 minutes. Allowed: 1 to 50 failures, 5 to 1440 minutes.

The country check, on by default, also alerts on a login from a country absent from that account's SMTP logins in the last 30 days. It requires MaxMind GeoIP and skips accounts with no other SMTP login in that period.

This rule never bans. Alerts remain in **To review** until dismissed. Change the account's password and check its app passwords in mailcow.

### Outgoing spam

[Outgoing spam](Abuse_Protection.md) stops mailboxes that exceed a sending threshold. Without a read-write API key, it cannot run even when switched on.

## Events

![Security, Events](../../images/docs/security-events-light.webp#gh-light-mode-only)
![Security, Events](../../images/docs/security-events-dark.webp#gh-dark-mode-only)

Events are netfilter log lines. When a line names no account, the account column shows attempts left before a ban. IP and username filters match part of the value.

**Unban** and **Ban permanently** have the same effects as on the [Overview](#each-address-and-what-you-can-do). **Export CSV** includes all matching events up to the export limit in [Settings](Settings.md).

## Settings that change this page

- Turning **Settings** > **Features** > **Security** off stops netfilter fetching and protection rules and deletes stored netfilter logs.
- **Settings** > **Mailcow** > **Connection**: the read-write API key (`MAILCOW_API_KEY_RW`), needed for every change written to mailcow: bans, unbans, list entries, the Fail2ban policy, a rule in **Ban** mode and lifting a written rule ban.
- **Settings** > **MaxMind** supplies country, city and network data.

## When something is missing

- **No read-write API key**: mailcow changes are locked. Rules still watch and can be edited in **Watch first** mode. **Dismiss**, and **Undo** on a pending ban, still work. Lifting a ban already written to mailcow requires the key. See [Getting started](../GETTING_STARTED.md).
- **mailcow does not answer about Fail2ban**: its bans are missing, **Banned** shows only rule bans, and new bans cannot be made here.
- **No MaxMind GeoIP**: the Countries rule cannot be enabled, and the stolen-password country check is disabled. An empty country chart can also mean the listed addresses have no country data.

## How Fail2ban works in mailcow

mailcow's `netfilter-mailcow` container matches authentication failures and SMTP protocol errors against rules. Reaching the attempt limit within the retry window bans the address or its configured surrounding network. Repeated bans can grow to the maximum ban time.

The container runs on the host network; bans become rules in the Docker host's `MAILCOW` firewall chain. Private and loopback addresses are never banned. Policies and lists live in mailcow. Protection rules add bans to its denylist and remove only entries they own.
