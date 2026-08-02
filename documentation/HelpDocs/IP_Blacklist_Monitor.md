# IP Blacklist Monitor - User Guide

## Overview
The IP Blacklist Monitor checks the hosts your outbound mail can leave from against ~30 common DNS-based Blackhole Lists (DNSBL). It is not limited to a single server IP: the auto-detected WAN IP, the public IPs of your mailcow transports and relayhosts, and any manually configured hosts can all be monitored side by side. Being blacklisted can severely impact your email deliverability.

## Why is this important?
If an IP your mail is sent from is blacklisted, emails from your server may be rejected or marked as spam by receiving servers. Regular monitoring ensures you can take quick action to request delisting.

## Features

### 🖥️ Monitored Hosts
Monitoring covers every host your mail can actually leave from - each one gets its own expandable card with a source badge, its own status, and its own results. Each source has its own toggle under **Settings → IP Blacklist (RBL) → Monitoring sources**:

- **Auto-detected WAN IP** (on by default) - the server IP reported by the mailcow status API. Disable this when your outbound mail leaves through a relay host.
- **mailcow transports** (on by default) - each active transport nexthop is resolved to **all** of its public A records. A relay hostname often has several A records (round-robin pool) and mail can leave from any of them, so monitoring only the first would leave blind spots.
- **mailcow relayhosts** (on by default) - same resolution as transports.
- **Manual hosts** - a comma-separated list of IPv4/IPv6 addresses and hostnames in the same settings group. Hostnames are resolved to all their public IPs. These can even be hosts unrelated to this mailcow server, if you want to keep an eye on other IPs you care about.

> [!NOTE]
> Settings are edited on the **Settings** page (requires `SETTINGS_EDIT_VIA_UI_ENABLED=true`). Every setting can also be provided as an environment variable - see [ENV_Settings.md](../ENV_Settings.md).

> [!TIP]
> Source toggle changes apply **immediately**: the monitored list is reconciled with your settings every time the page loads, so a just-saved change shows up right away. Enabling the transports or relayhosts source additionally triggers an immediate sync, so the new hosts appear without waiting for the next scheduled run.

Hosts from mailcow (transports/relayhosts) are re-synced every 6 hours. Private and loopback IPs are filtered out automatically. A host that has been deactivated - removed in mailcow or from your settings - is kept in the database for 30 days and then purged for good.

### 🔄 Automated Background Monitoring
- **Daily Auto-Check**: The system automatically checks all monitored hosts against the supported blacklists every day at **5:00 AM**.
- **Startup Check**: A check is also performed shortly after the application starts.
- **Results Caching**: Results are stored for 24 hours to minimize unnecessary DNS traffic.

### 📧 Email Notifications
If any monitored host is found on a blacklist during an automated check, the system sends an alert to the configured alert email (**Settings → Notifications → Email addresses** - the **Blacklist Alert Email**, falling back to the **Admin Email**) and to your configured notification destinations.
- **Detailed Report**: The alert includes exactly which lists have flagged which host.
- **Direct Links**: Quick links to the removal pages of the respective blacklists.
- **Cleared / Improved**: You are also notified when previously listed hosts drop off the blacklists.

> [!NOTE]
> **Notification Policy:** To prevent alert fatigue, some aggressive or paid-removal-only lists (specifically **UCEPROTECT Level 2** and **Level 3**) will **NOT** trigger a notification if they are the only ones listing a host. These lists often block entire subnets or ASNs and are typically not actionable by individual server admins.

### ▶️ Manual Checks
- **Check Now** (Status page): starts a fresh background check of **all** monitored hosts, with a live progress bar showing which blacklist is currently being queried.
- **Run Check for this Host** (inside each host card): forces a fresh check of just that host, bypassing the 24-hour cache, with the same progress bar. Useful right after you have requested delisting and want to confirm the result.
- Status indicators per blacklist:
  - **Green**: Not listed (Clean)
  - **Red**: Listed (Blacklisted)
  - **Yellow/Gray**: Check failed, rejected, or not yet run

### 📊 Dashboard Summary
The **Blacklist Status** card on the Dashboard aggregates **all** monitored hosts:
- **Status** is "Listed" if *any* host is listed, and "Clean" only when fresh data exists and nothing is listed.
- With more than one monitored host, a **Hosts Listed** row shows how many hosts are affected (e.g. `1/3`).
- **Listed On** sums listings across all hosts with fresh results.

### 🛡️ Supported Blacklists
The monitor checks against ~30 reputable lists, including:
- Spamhaus (ZEN/SBL/XBL/PBL)
- Barracuda (b.barracudacentral.org)
- SpamCop (bl.spamcop.net)
- UCEPROTECT (Levels 1-3)
- PSBL, Mailspike, s5h.net, Blocklist.de, SURBL, invaluement, and others

> [!NOTE]
> The zone list is kept current: **SORBS** (shut down in 2024) and **CBL** (absorbed into Spamhaus XBL) have been removed. Dead zones would only produce meaningless errors or false "clean" results.

### 🌐 IPv6 Support
IPv6 addresses are checked **only** against the zones that actually serve IPv6 listings (Spamhaus ZEN/SBL/XBL and s5h.net). Most DNSBLs are IPv4-only: querying them for an IPv6 address always returns "not found", which would show up as a meaningless "clean" and give you false confidence. Skipping those zones keeps IPv6 results honest, so an IPv6 host is checked against fewer zones than an IPv4 host.

### 🔍 Reading Check Results
Hover over any blacklist card to see the **raw DNS answer code** behind the result. How to read it:

- A genuine DNSBL listing is always an address inside `127.0.0.0/8`, typically `127.0.0.x`, where `x` is a documented listing code that tells you *why* the IP is listed (check the blacklist's website for its code table).
- The app **rejects answers that are not valid DNSBL codes** instead of reporting a false listing or a false "clean":
  - `127.0.0.1` is never a valid listing (per RFC 5782). It is the classic answer of a DNS blocker (Pi-hole, router ad-block, ISP filter) intercepting the blacklist domain - the result is shown as unknown, with an explanation.
  - A **non-127.x** answer means your resolver is rewriting "not found" responses (NXDOMAIN redirection to an ad server, captive portal, etc.) - also shown as unknown.

### 🎯 Spamhaus Specifics
Spamhaus is the blacklist that matters most for deliverability, so it gets special handling:

- **Public resolvers are rejected by Spamhaus.** Queries arriving via Google, Cloudflare, Quad9 or DoH get a rejection code (`127.255.255.x`) instead of a real answer. If you see "Query rejected: sent via a public/open DNS resolver", enter your own recursive resolver under **Settings → IP Blacklist (RBL) → DNS resolver** (in mailcow: `172.22.1.254`).
- **Answers are validated** against Spamhaus's documented listing codes (`127.0.0.2` through `127.0.0.11`). Anything else from a Spamhaus zone is not treated as a listing.
- **A failed Spamhaus check is reported as unknown, never as "clean".** If the Spamhaus zones could not be checked, the honest overall answer is that the status is unknown - even if every other zone came back clean.

## Troubleshooting

### What if I am blacklisted?
1. **Identify the List**: Expand the host's card to see which specific list has flagged the IP.
2. **Visit the List's Website**: Click the provided link to visit their lookup/removal page.
3. **Check the Reason**: They often provide a reason (e.g., spam trap hits, compromised account, high volume). The raw answer code (on hover) tells you the listing category.
4. **Request Delisting**: Follow their specific procedure to request removal.
5. **Fix the Root Cause**: Ensure your server is not sending spam, is fully secured, and is not an open relay.
6. **Verify**: Use **Run Check for this Host** to confirm the delisting took effect.

### "Query rejected" or "unknown" results
- Spamhaus rejects queries sent through public resolvers - enter your own recursive resolver under **Settings → IP Blacklist (RBL) → DNS resolver** (mailcow: `172.22.1.254`).
- "Invalid answer" messages mean a filtering or rewriting resolver (ad-blocker, captive portal) is interfering with DNSBL lookups. Point the **DNS resolver** setting at a clean recursive resolver.

### Common False Positives
- **Dynamic IPs**: Many lists block residential/dynamic IP ranges. Ensure your server has a static IP and proper reverse DNS (rDNS).
- **"Bad Neighborhood"**: Sometimes entire IP blocks are listed because of other bad actors in the same range (common with some VPS providers).

## Best Practices
- **Monitor Regularly**: Let the background job do the work, but check the dashboard occasionally.
- **Cover All Exit Points**: If mail leaves through a relay, enable the transports/relayhosts sources (and consider disabling the WAN IP source if it never sends mail directly).
- **Maintain Reputation**: Ensure strict SPF, DKIM, and DMARC policies are enforced.
- **Secure Your Server**: Prevent your server from being used as an open relay by spammers.
