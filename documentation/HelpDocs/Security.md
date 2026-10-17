# Security

The Security page shows who tries to get into your mail server, what stops them, and what waits for your decision. It reads the netfilter log that mailcow's Fail2ban writes, the Fail2ban settings and lists from the mailcow API, and the catches of the app's own protection rules.

The tabs are **Overview**, **Lists**, **Settings** and **Events**. The page refreshes every 30 seconds.

## Overview

**Overview** groups login attempts and probes by address for the selected period. Its tab count is **To review**.

![Security, Overview](../../images/docs/security-overview-light.webp#gh-light-mode-only)
![Security, Overview](../../images/docs/security-overview-dark.webp#gh-dark-mode-only)

### The Protection row

**Protection** shows the Fail2ban policy, each [rule](#protection-rules) as banning, watching, alerting or off, and whether **Outgoing spam** is on. When **Outgoing spam** is switched on but there is no read-write API key, it shows as off with "needs a Read-Write key", because the check cannot run. Click a protection to edit it. On a phone, expand the **Protection** chip first.

### To review, Banned and History

Three buttons above the list choose what it shows. **To review** and **Banned** show their counts.

- **To review**: every address that tried in the period and is not banned. A rule's catch that is not banned yet is here, and so is an address on the allowlist, tagged **Allowlisted**.
- **Banned**: addresses banned by a rule, by Fail2ban itself, or by the denylist (tagged **Denylisted**). A Fail2ban ban that mailcow is about to lift is not counted.
- **History**: the rules' catches that ended. It shows the 200 newest.

Attempts are netfilter rule matches. Failed logins include SMTP authentication, IMAP, POP3, Sieve, SOGo and mailcow or Rspamd UI logins. SMTP protocol probes count as attempts without being failed logins.

The list loads 50 rows at a time as you scroll, newest activity first. When all rows are loaded and there are more than 50, the end says how many are shown.

### Period, Country and Network

- **Period**: **Last 24 hours**, **Last 7 days**, **Last 30 days** or **Last 90 days**. The list and both panels beside it count the same period. When the stored logs start later than the period, the picker says "since" and the date of the oldest stored line. How long logs are kept is set on the [Settings](Settings.md) page.
- **Country**: shows only the addresses from one country. Its panel is the **Where attacks come from** chart.
- **Network**: shows only the addresses of one network (the organization that owns the address block). Its panel is **Networks that try most**.

A picked country or network shows as a chip above the list; its cross shows every country or network again. **History** has no period or network filter; the country filter applies to it.

### Each address and what you can do

Each row shows the address, its attempts in the period, a tag, its country and when it was last seen. The sentence under it says why the address is there. The buttons depend on its state:

| Tag | What it means | Buttons |
|---|---|---|
| No tag | The address tried, and no rule caught it. The row also shows when Fail2ban bans, for example "Fail2ban bans at 5 within 10m". | **Ban permanently**, **Allow** |
| A rule name, such as **Trap accounts** | A rule in watch mode caught it. Nothing was banned. | **Ban** with the rule's ban length, **Dismiss** |
| **Banning** | A rule in ban mode caught it; the ban is written on the next run. | **Undo** |
| **Not banned yet** | Writing the ban to mailcow failed. The error is shown, and the next run tries again. | **Undo** |
| **Possible stolen password** (red) | An account logged in in a suspicious way. Alert only: nothing was banned. | **Dismiss** |
| **Banned** by a rule | A rule banned it. The row says when, and until when or "until removed". | **Undo** (with the read-write key) |
| **Banned** by Fail2ban | Fail2ban banned it. The row shows the time left, then Fail2ban lets it try again. | **Unban**, **Ban permanently** |
| **Allowlisted** | It is on the allowlist, so it is never banned. If a network entry holds it, the entry is shown. | **Remove from allowlist** |
| **Denylisted** | It is on the denylist: banned until removed. | **Remove from denylist** |

What the actions do:

- **Ban** uses the rule's current ban length; **Ban permanently** keeps the address denylisted until removal. Rule bans expire only entries the app owns.
- A permanent row ban needs confirmation. A single address is written as `/32` for IPv4 and `/128` for IPv6.
- **Allow** adds an allowlist entry after confirmation. The denylist still takes priority if both lists contain it.
- **Ban permanently** and **Allow** do not add an address that the list already holds in another notation, such as `198.51.100.7` and `198.51.100.7/32`. The message then says the address "is already in the allowlist", or "is already in the blacklist" for the denylist.
- **Unban** lifts the ban Fail2ban actually made, after confirmation. When Fail2ban bans networks (see **Ban the network** under [Fail2ban](#fail2ban)), the whole banned network, such as `198.51.100.0/24`, is unbanned. The button and confirmation on the Overview name that network, and the message afterwards names what was unbanned. The row disappears immediately; mailcow can take a few seconds. Further failures can cause another ban.
- If Fail2ban has no ban for the address, **Unban** changes nothing and says the address "is not banned by Fail2ban now". For an address on the denylist it says to remove it from the denylist instead.
- **Undo** cancels a pending rule ban or removes the denylist entry the app added. **Dismiss** closes a watched catch without changing mailcow. Both pause that rule for this address for 7 days.
- **Remove from allowlist** or **Remove from denylist** removes the covering entry after confirmation.

### The details of an address

Address details show location, network, failed logins, **Accounts it tried**, rule catches under **What the rules said**, and the 40 newest netfilter lines under **Raw log**. **All events of this address** opens filtered Events.

The failed-login count covers the selected period and names it, for example "in the last 7 days". An address with no failed logins in that period shows the count of the last 24 hours from its newest log lines.

### Where attacks come from and Networks that try most

**Where attacks come from** ranks 10 countries, splitting review and banned attempts and marking countries watched by the **Countries** rule. **Networks that try most** ranks 8 networks. Both show address and attempt counts; click to filter the list.

Both panels use the list's period. Their bars count attempts; an address may contribute many attempts. Location and network data come from MaxMind GeoIP.

### History

**History** keeps the rules' catches that ended, each with its rule and how it ended:

- **No new activity**: a watched catch with no new activity for 7 days. It was never banned. If the address comes back, the rule catches it again.
- **Ban ended**: the rule's ban length passed and the app lifted the ban.
- **Ban undone**: you clicked **Undo**.
- **Dismissed**: you clicked **Dismiss**, or the address went on the allowlist before its ban was written.

## Lists

The **Lists** tab shows mailcow's Fail2ban allowlist and denylist, one entry per row. The number on the tab is the count of both. An entry can be a single address or a network, such as `192.0.2.0/24`.

![Security, Lists](../../images/docs/security-lists-light.webp#gh-light-mode-only)
![Security, Lists](../../images/docs/security-lists-dark.webp#gh-dark-mode-only)

- **Allowlist**: never banned, by Fail2ban or by the rules. Put your own offices and monitoring here. An entry that failed logins today says how many, and that it was never banned.
- **Denylist**: banned until removed. The denylist wins over the allowlist. An entry says who added it: "Added by hand", or "Added by" and a rule name with the end of its ban.

Use **Add** for an address or CIDR network. An address without a prefix is added as `/32` for IPv4 and `/128` for IPv6. An address the list already holds in another notation is not added again. **Remove** asks for confirmation. Removing a rule entry works like **Undo**, including the week-long pause for that rule. Changes take a few seconds in mailcow.

### Entries tagged Whole network

Earlier versions of the app wrote a single IPv6 address as a `/32`, such as `2001:db8::1/32`. mailcow reads that entry as the whole network `2001:db8::/32`, so on the denylist it blocks every address of that network, and on the allowlist it exempts all of them from Fail2ban. The **Lists** tab tags such an entry **Whole network** and says which network it blocks or exempts. A network you entered on purpose, such as `2001:db8::/32`, is not tagged.

**Repair** replaces the entry with the single address as `/128`, such as `2001:db8::1/128`, after confirmation. The app makes the change in one edit of mailcow's list and reads the list back to confirm it. **Remove** deletes the entry instead. Both need the read-write API key. While any such entry is left, the [Dashboard](Dashboard.md#needs-attention) lists it under **Needs attention**. The app never changes these entries without your click.

The app reads both lists fresh from mailcow right before every change, so an entry added in mailcow in the meantime is kept.

## Settings

**Settings** has cards for **Fail2ban**, six [protection rules](#protection-rules) and **Outgoing spam**. **Edit** shows fields; **Done** closes them. Card switches turn protections on or off, except Fail2ban, which is always on.

![Security, Settings](../../images/docs/security-settings-light.webp#gh-light-mode-only)
![Security, Settings](../../images/docs/security-settings-dark.webp#gh-dark-mode-only)

Use **Save changes** or **Discard** for pending edits. Failed edits stay on screen with an error.

The **Email alerts** box at the bottom says where the emails go: to the destinations that receive the Security topic. **Notifications** opens those settings. See [Notifications](../Notifications.md).

### Fail2ban

This card changes mailcow's own Fail2ban policy. It is tagged **Always on**: the app cannot turn Fail2ban off. The sentence reads: an address that fails a number of logins within a number of seconds is banned for a number of seconds, longer each time it comes back, up to a longest ban.

| Field | What it sets in mailcow | Allowed values |
|---|---|---|
| Failed logins before a ban | Max attempts | 1 or more |
| Retry window | The time in which the failed logins are counted, in seconds | 1 or more |
| Ban time | The length of the first ban, in seconds | 60 or more |
| **longer each time it comes back** | Ban time increment: each new ban of the same address lasts longer | On or off |
| Longest ban | Max ban time, in seconds | 60 or more, not shorter than the ban time |
| **Ban the network, IPv4** | The prefix length Fail2ban bans for an IPv4 address. `32` bans one address; a shorter prefix bans the network around it. | 8 to 32 |
| **Ban the network, IPv6** | The same for IPv6. `128` bans one address. | 8 to 128 |

Saving needs a [read-write API key](#when-something-is-missing). The app rereads the lists before saving to keep entries added elsewhere.

mailcow also has **Manage Fail2Ban externally**, in **System** > **Configuration** > **Options** > **Fail2ban parameters**. With it on, Fail2ban keeps its ban list but sets no firewall rules, and you block the listed addresses with your own firewall. The app does not show this option, and keeps its current value when it changes Fail2ban settings or lists.

### Protection rules

The protection rules are the app's own additions to Fail2ban. Five of them catch attacking addresses: **Trap accounts**, **Unknown accounts**, **Repeat offenders**, **Attacking networks** and **Countries**. The sixth, **Possible stolen password**, only alerts. All six are off when you install the app.

The rules run after every log fetch (every 60 seconds by default) and when you click **Run** on **Protection Rules** on the [Status](Status.md) page. They read only the netfilter lines that came in since their last run.

> [!NOTE]
> A rule never reaches back. Turning a rule on catches what happens from then on, not the attacks already in the log.

Catching rules have two modes:

- **Watch first** (default) records catches in **To review**; choose **Ban** or **Dismiss** there.
- **Ban** writes catches to mailcow's denylist and needs a read-write API key. A watched address that attacks again after the mode changes can then be banned.

Switching back to **Watch first** cancels unwritten automatic bans. Written bans finish normally, and bans you requested by hand stay.

**Ban length** choices are 1 hour, 6 hours, 1 day, 7 days, 30 days, 90 days or until removed by hand. Expiry removes only denylist entries the app added. **Undo** and **Dismiss** pause the rule for that address for a week. A watched catch with no activity for 7 days moves to **History**.

Rules exclude the Fail2ban allowlist, private, loopback and link-local networks, the mailcow server's IP and literal IPs checked by the [blocklist monitor](IP_Blacklist_Monitor.md). Adding an address to the allowlist cancels its pending ban.

**Email me when it bans** includes successful and failed ban attempts. **Email me on every alert** covers **Possible stolen password**. Each run groups addresses into at most one email: `Possible stolen password`, `Protection rules banned addresses` or `Protection rules could not ban`. Ban expiry sends none. See [Notifications](../Notifications.md).

Each rule card:

#### Trap accounts

Catches any address that tries to log in to one of your trap names. A trap name is an account that does not exist and that only an attacker would try, such as `admin`, `info` or `test@example.com`.

- A bare name, such as `admin`, matches that name at any domain. A full address matches only itself.
- A real mailbox or alias can never be a trap name: saving refuses it. A trap name that later becomes a real mailbox or alias is skipped.
- **Tried in the last 7 days, and no such mailbox here** suggests up to 12 names attackers tried, with their number of tries. A click adds one.
- Up to 500 trap names. Default ban length: 30 days.

#### Unknown accounts

Catches an address that tries a number of accounts that do not exist within a number of minutes. An account does not exist when the login has no domain, or when it is a full address that is not a mailbox or alias and its domain has no catch-all alias. Alias domains count as their target domain.

An address with a successful SMTP or IMAP login in the last 24 hours is never caught, so a user who mistyped an address is safe.

Accounts: 2 to 100 (default 5). Minutes: 5 to 1440 (default 60). Default ban length: 7 days.

#### Repeat offenders

Catches an address that Fail2ban banned a number of times within a number of days. Only Fail2ban's own bans count, not denylist entries.

Bans: 2 to 50 (default 3). Days: 1 to 365 (default 30). Default ban length: until removed by hand.

#### Attacking networks

Catches a whole IPv4 network (a `/24`) when a number of its addresses show up in the netfilter log within a number of hours. The ban goes on the denylist as the network, such as `198.51.100.0/24`. IPv6 networks are not caught.

A network that holds an allowlisted address, an internal address or the mailcow server is never caught.

Addresses: 2 to 256 (default 5). Hours: 1 to 168 (default 24). Default ban length: 1 day.

#### Countries

Catches an address that fails to log in from one of the countries you pick. Only failed logins are caught: a user who logs in from one of these countries is not affected.

Type a country name or its two-letter code and pick it from the list. **Failed logins in the last 7 days came from** suggests up to 12 countries with their number of failed logins. This rule needs the MaxMind GeoIP databases; without them it cannot be turned on. Default ban length: 7 days.

> [!WARNING]
> In **Ban** mode this rule bans every address of the picked countries that fails a single login, including your own users who mistype a password while traveling. Start with **Watch first**.

#### Possible stolen password

Alerts when an account logs in successfully after a number of failed tries from the same address within a number of minutes. With **Also alert on a login from a country the account did not use in 30 days**, it also alerts when an account logs in from a country that none of its SMTP logins of the last 30 days came from. An account with no other SMTP login in those 30 days is not checked for this.

This rule never bans: banning would lock out the real user. Its alerts stay in **To review** until you **Dismiss** them. SMTP and IMAP logins are checked. The country check needs the MaxMind GeoIP databases.

Failed tries: 1 to 50 (default 3). Minutes: 5 to 1440 (default 60). The country check is on by default.

If you get this alert, change the account's password and check its app passwords in mailcow.

### Outgoing spam

This card stops a mailbox from sending when it sends more than a set number of messages in a set time. It has its own page: [Outgoing spam](Abuse_Protection.md).

## Events

**Events** shows netfilter lines newest first, 50 per page. Its tab count follows the filters.

![Security, Events](../../images/docs/security-events-light.webp#gh-light-mode-only)
![Security, Events](../../images/docs/security-events-dark.webp#gh-dark-mode-only)

Each event shows **When**, **Address**, **Account** (or the attempts left before a ban, when the line names no account), **Action** and **Where** (country and city, with the network on hover). The arrow at the end of a row shows the full log line.

- **Action**: **All Actions**, **BAN**, **UNBAN**, **Warning** or **Info**.
- **Country**: the countries in the log.
- **Filters** shows **IP Address** and **Username**; both match part of the value. Press Enter or click **Apply**.
- **Clear filters** removes them all.

**Unban** shows on a ban event and on an address that is on the denylist. It asks mailcow to lift the Fail2ban ban; for an address on the denylist it says to remove it from the denylist on **Lists** instead. **Ban permanently** on a warning or unban event adds the address to the denylist. Both work as on the [Overview](#each-address-and-what-you-can-do).

**Export CSV** downloads the events that match all the filters, up to the CSV export limit set in [Settings](Settings.md).

## Settings that change this page

- **Settings** > **Features** > **Security**: turns the whole page off, and with it the netfilter log fetch and the protection rules. Turning it off deletes the stored netfilter log; you are asked to confirm first.
- **Settings** > **Mailcow** > **Connection**: the read-write API key (`MAILCOW_API_KEY_RW`) that every change on this page needs.
- **Settings** > **MaxMind**: the GeoIP databases for countries, cities and networks.
- **Settings** > **Notifications**: where the rules' emails go.
- **Settings** > **SMTP Abuse (Beta)**: the [outgoing spam](Abuse_Protection.md) protection.

See [Settings](Settings.md) for each of them.

## When something is missing

- **Security is off**: opening the page shows "Security is disabled" with a button to the Dashboard.
- **No read-write API key**: with only the read-only key, the page shows everything and changes nothing in mailcow. Locked areas say so: "Ban, Allow and Unban are locked" on the Overview, "The lists are read-only here" on Lists, "Editing Fail2ban is locked" on the Fail2ban card and "Ban and Unban are locked" on Events, each with **Open Settings**. Rules can still watch, and **Dismiss** and **Undo** on a pending ban still work. A ban a rule already wrote to mailcow can only be lifted with the read-write API key, so it shows no **Undo**, and its denylist entry no **Remove**. **Ban** is disabled. See [Getting started](../GETTING_STARTED.md) for creating the key.
- **mailcow does not answer about Fail2ban**: the Overview says that its bans are not shown and nothing can be banned from here, **Banned** shows only the rules' bans, and the Lists and the Fail2ban card say that mailcow did not answer. The Protection row shows Fail2ban with "?". The next refresh tries again.
- **No MaxMind GeoIP**: the country panel says "No country for these addresses. Configure MaxMind to see where they come from." The **Countries** card shows **Needs MaxMind GeoIP** and cannot be turned on, and the country check of **Possible stolen password** is disabled. The same text shows when MaxMind is set up but the listed addresses have no country.
- **Empty lists**: "Nothing to review." on **To review**, "Nothing is banned right now." on **Banned**, "Nothing here yet." on **History**, and "No logs found" on **Events**.

## How Fail2ban works in mailcow

Mailcow's `netfilter-mailcow` container reads the log lines that Postfix, Dovecot and SOGo send it, and the failed logins the mailcow web interface reports. It matches them against its rules: failed SMTP, IMAP, POP3, SOGo, mailcow UI and Rspamd UI logins, and SMTP protocol errors. Reaching the attempt limit within the retry window bans the address, or the configured network around it. Repeated bans can grow up to the maximum ban time.

The container runs on the host network, so a ban is a rule in the `MAILCOW` chain of the Docker host's firewall (nftables or iptables, whichever the host uses). Private and loopback addresses are never banned.

The allowlist exempts addresses; the denylist blocks until removal and takes priority. Policies and lists live in mailcow. The app reads them with its read-only API key and changes them with its read-write API key.

Netfilter logs matches, remaining attempts, bans and unbans. **Events** shows those lines; **Overview** and protection rules group them. A protection rule writes its bans to the same denylist and removes only entries it owns on expiry or **Undo**.
