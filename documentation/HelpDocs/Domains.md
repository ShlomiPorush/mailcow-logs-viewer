# Domains

The Domains page lists the domains of your mailcow server and checks the DNS records that decide whether their mail is trusted: SPF, DKIM, DMARC, DNSSEC, DANE and MTA-STS. The domain list and the DKIM key come from the mailcow API; the records are read from public DNS.

![Domains page](../../images/docs/domains-list-light.webp#gh-light-mode-only)
![Domains page](../../images/docs/domains-list-dark.webp#gh-dark-mode-only)

## The page head

**Updated** gives the last check of all domains, or **Not checked yet**. Checking one domain does not change that time.

The summary counts domains, inactive domains and domains needing a DNS change. Only SPF, DKIM and DMARC warnings or errors count toward **needs a DNS change** and its filter. **DNS looks right.** does not mean every optional check passed.

**Check Now** checks every active domain and every alias domain at once. When it finishes, a message says how many domains were checked and the list reloads. If one of the domains could not be checked, the message says **DNS check failed**; the others are still saved. While a check runs, a second one is refused with **DNS check already in progress**.

The app also checks all domains on its own: about a minute after it starts, then every 6 hours.

## The domain list

Above the list, **Search domains...** filters by name and **Show only domains with issues** keeps the domains that need a DNS change. **Clear filters** resets both.

Each row shows:

- **Domain**: the name, an **Inactive** tag for a domain that is turned off in mailcow, and under it the number of mailboxes and aliases. A domain that needs a DNS change also says "needs a DNS change".
- **SPF**, **DKIM**, **DMARC**, **DNSSEC**, **DANE**, **MTA-STS**: the result of each check, as **OK**, **Warning** or **Error**. A `-` means the check has not run yet or could not reach a result. Point at a result to see its message.
- **Storage**: the space the domain's mailboxes use.

On a phone the results are icons: a check mark for OK, an exclamation mark for a warning and a cross for an error.

There is no MX column. The app does not check MX records on their own; it reads them only as part of the DANE and MTA-STS checks.

Inactive domains stay in the list but are left out of **Check Now** and of the checks every 6 hours. Use **Check** in the open domain to check one.

## An open domain

Click a row to open it. On a phone, the open domain has two tabs, **DNS checks** and **Details**; on a wider screen both parts show at once.

![An open domain](../../images/docs/domains-open-light.webp#gh-light-mode-only)
![An open domain](../../images/docs/domains-open-dark.webp#gh-dark-mode-only)

### DNS Security Records

One card per check, in the same order as the columns. Each card has:

- The check's name and its result: **OK**, **Warning**, **Error** or **Not checked**.
- A message that says what was found, for example "SPF configured correctly with strict -all policy".
- **View Record**: the record as it is published in DNS, with a button to copy it. For DKIM it also shows the **Record Name**, such as `dkim._domainkey.example.com`.
- **Checked IPs** on the SPF card: see [SPF](#spf).
- Warnings and notes, one per line.
- **Expected Value** on a DKIM card with an error: the record mailcow expects, to copy into your DNS.

Next to the heading, **Updated** says when this domain was last checked. **Check** checks this domain again right away and shows the new results with the domain still open. It checks only this domain, not its alias domains.

### Details

mailcow's domain details include mailbox and alias usage against their limits, **Storage Used** and quota (**Unlimited** when unset), **Total Messages**, **Created Date** and the relay flags **Backup MX**, **Relay All Recipients** and **Relay Unknown Only**.

### Alias domains

Expand **Alias domains** for their DNS cards. Alias domains deliver to their target domain's mailboxes, but sending under an alias domain still needs appropriate authentication records. DMARC can inherit the organizational domain's policy.

The app reads the alias domains from mailcow when it starts and every 6 hours after that. Alias domains are checked by **Check Now** and by the checks every 6 hours.

## The checks

The checks use public DNS resolvers, with DNS over HTTPS as a fallback. They do not use records available only in your internal DNS. Cached answers and propagation can make other servers see a different result.

When a lookup fails, for example because it timed out, the card says the check failed instead of reporting the record as missing.

### SPF

The check reads the TXT record at the domain that starts with `v=spf1` and reports:

- **Error** when there is no SPF record, when there is more than one (receivers then treat SPF as broken), when the record does not start with `v=spf1 `, when it has no `all` at the end and no `redirect=`, when it needs more than 10 DNS lookups, or when it allows every server with `+all` (a bare `all` counts as `+all`).
- **Error** when a sending IP of yours is not allowed by the record. The message names the IP.
- **Error** for a mechanism the check does not know. It accepts the mechanisms `ip4`, `ip6`, `a`, `mx`, `include`, `exists`, `ptr` and `all`, and the modifiers `redirect=` and `exp=`.
- **Warning** for `?all`, which protects almost nothing.
- **Warning** for a mechanism written with `=` instead of `:`, such as `include=spf.example.net`. SPF reads it as an unknown modifier and ignores it, so the message asks "Did you mean include:spf.example.net?".
- **Warning** for `ptr`, which RFC 7208 discourages because it is slow and unreliable. The check counts it as a DNS lookup but does not evaluate it.
- **OK** for `-all` and for `~all`. With `~all` the message suggests `-all`.

Other modifiers (`name=value`), such as `ra=` from RFC 6652, are ignored, as RFC 7208 requires.

The lookup count includes nested `include:` terms. See [The SPF record](#the-spf-record) for the limit.

**Checked IPs** tests configured sending IPs against SPF, following `include:` and `redirect=`. Each shows its source and **Authorized** or **Not authorized**. Configure sources under **Settings** > **Domains** > **SPF check sources**:

| Setting | Source label | Default |
|---|---|---|
| **Domain SPF Source Server IP** | Auto-detected WAN | On |
| **Domain SPF Source Transports** | Transport | Off |
| **Domain SPF Source Relayhosts** | Relay host | Off |
| **Domain SPF Source Manual Hosts** | Configured | Empty |
| **Domain SPF Source DMARC History** | DMARC history | Off |

- **Auto-detected WAN** is the public IP mailcow reports for the server. Turn it off when your mail leaves through a relay host and the server's own IP is not meant to be in SPF.
- **Transport** and **Relay host** are the public IPs of the active transports and relay hosts in mailcow. Private and loopback addresses are skipped.
- **Configured** takes IP addresses and host names, separated by commas. Add only addresses that send mail: every entry must pass, so an inbound-only MX here causes a false error.
- **DMARC history** adds up to 20 addresses that passed SPF for the domain in the DMARC reports of the last 30 days. When no reports exist, or the newest is more than 7 days old, the card says so.

> [!NOTE]
> With relaxed alignment, a mail service that sends from its own subdomain can pass DMARC for you without being in your domain's SPF record. Its addresses then show up in the DMARC history source and fail this check, which is a false error. That is why the DMARC history source is off by default.

### DKIM

The check asks mailcow for the domain's DKIM selector and key, reads the TXT record at `<selector>._domainkey.<domain>` and compares the two tag by tag.

- **Error** when mailcow has no DKIM key for the domain, when the record is missing, or when the record does not match. A mismatch is a different public key (`p=`), a different key type (`k=`), a version other than `DKIM1`, or an `h=` list that does not allow `sha256`, which mailcow signs with. A card with an error shows the **Expected Value** to publish.
- **Error** when the record has `t=y`. In test mode receivers treat failed signatures as if the message were not signed.
- **Error** when the key is empty (`p=`), which revokes it.
- **Warning** when the key matches but other tags differ from mailcow, for example a `t=s` that your DNS provider dropped. These differences do not break signatures.
- **OK** when the published record matches mailcow.

Tag order, spaces and line breaks inside the key do not count as differences. A `t=s` record adds a note: signatures with this key must use the same domain in `i=` as in `d=`, not a subdomain of it. That is the recommended setting. See [RFC 6376, section 3.6.1](https://www.rfc-editor.org/rfc/rfc6376.html#section-3.6.1).

### DMARC

The check reads the TXT record at `_dmarc.<domain>` that starts with `v=DMARC1`.

- **Error** when there is no record.
- **Warning** for `p=none`, or a record without a known policy. The message says the policy is too weak.
- **OK** for `p=quarantine` and `p=reject`.

The DMARC & TLS page shows more about the record and what changing its policy would do. See [DMARC & TLS](DMARC.md).

### DNSSEC

The check looks the domain up through validating resolvers.

- **OK**: the domain is signed and the chain of trust from the parent zone is intact.
- **Warning**: the domain is not signed. Or it publishes keys, but the DS record at the registrar is missing, so nobody can validate it.
- **Error**: validation fails. Resolvers that check signatures cannot resolve the domain at all, so mail to and from it can fail. The usual cause is a DS record at the registrar that no longer matches the keys at the DNS provider.
- **Not checked**: the lookup failed or the domain does not exist in DNS.

### DANE

The DANE check reads MX hosts and their `_25._tcp.<mx-host>` TLSA records, then connects on port 25 to compare certificates.

- **OK**: the MX records, the TLSA records and the MX host addresses are DNSSEC-validated, and the certificate matches, or could not be compared, on every MX host.
- **Error**: DANE is active and a TLSA record does not match the certificate of an MX host. Senders that use DANE refuse to deliver to it. This usually happens after the certificate's key changed and the TLSA record was not updated.
- **Warning**: no TLSA records are published (DANE is optional); or they are published but not DNSSEC-validated, so senders ignore them; or a record does not match the certificate while DNSSEC is still off, which breaks mail as soon as DNSSEC is turned on. Also a warning when an MX host has no TLSA record, or when no record uses the recommended `3 1 1` form.
- **Not checked**: the domain has a null MX and accepts no mail, it has no MX records, or the lookups failed.

Notes give each certificate result. Comparison supports usage 3 (DANE-EE), including mailcow's `3 1 1`. An unreachable port 25 gives "not compared", not a mismatch.

### MTA-STS

The check reads `_mta-sts.<domain>`, fetches the HTTPS policy without redirects and checks its `mx:` patterns against MX hosts. See [The MTA-STS policy](#the-mta-sts-policy) for the file path and syntax.

- **OK**: the policy is in `enforce` mode and covers every MX host.
- **Error**: more than one `v=STSv1` record; the record exists but the policy file cannot be fetched; the file has no `version: STSv1` or an unknown mode; or an MX host is missing from an enforced policy, so those senders refuse to deliver through it.
- **Warning**: no record (MTA-STS is optional), mode `testing` (failures are reported but delivery is not protected), mode `none`, or an MX host missing from a policy that is not enforced.

The notes show the mode, the policy id, the max age and the MX patterns of the policy.

### TLS-RPT

The same checks also read the TLS-RPT record at `_smtp._tls.<domain>`. It has no card on this page; the DMARC & TLS page shows it with the domain's TLS reports. See [DMARC & TLS](DMARC.md).

## DNS change alerts

Checks compare records with the previous results. Changes alert **Admin Email** and destinations receiving **DNS record changes**, with old and new values. Example subject: `DNS records changed for example.com: SPF, DKIM`.

An alert is sent when:

- An SPF, DKIM, DMARC, TLSA, MTA-STS or TLS-RPT record has a new value, appeared, or verifiably disappeared.
- DNSSEC stops validating for a domain that validated before.
- A DNSSEC-validated TLSA record stops matching the certificate of an MX host.

A failed lookup or a timeout never counts as a change, so a DNS hiccup does not raise an alarm. The first check of a domain has nothing to compare with and sends no alert. Alias domains are watched the same way.

**DNS Change Alerts Enabled** under **Settings** > **Notifications** defaults on. See [Notifications](../Notifications.md).

## The weekly summary

The weekly summary email has a **DNS issues** section that lists the active domains whose SPF, DKIM or DMARC check ended in an error at the last check. Warnings, such as `p=none`, are not listed. See [Notifications](../Notifications.md).

## Settings that change this page

| Where | Setting | What it does |
|---|---|---|
| **Settings** > **Domains** | **SPF check sources** | Which sending IPs every SPF record must allow. See [SPF](#spf). |
| **Settings** > **Notifications** | **DNS Change Alerts Enabled** | Sends an alert when a record changes. On by default. |
| **Settings** > **Features** | **Domains** | Turns the page and its DNS checks on or off. |

Each setting also has an environment variable, for example `DOMAIN_SPF_SOURCE_SERVER_IP` and `DNS_CHANGE_ALERTS_ENABLED`. See [Settings](Settings.md) and [ENV_Settings.md](../ENV_Settings.md).

## When something is missing

- The page is not in the menu: the Domains feature is off. Turn it on under **Settings** > **Features**. While it is off, the DNS checks every 6 hours do not run.
- **Failed to load domains**: the app could not read the domain list from mailcow. The message under it gives the reason. Check the mailcow connection on the Status page. A read-only mailcow API key is enough for this page.
- **No domains found**: mailcow has no domains.
- **Not checked yet**: the first check has not run. It starts about a minute after the app starts; **Check Now** runs it at once.
- A card says **Not checked** with a message: the check could not reach a result. The message says why, for example a failed lookup or a domain without MX records.
- **DKIM not configured in mailcow**: mailcow has no DKIM key for the domain. Create one in mailcow under the domain's DKIM settings, then publish it.
- A message that ends with "Check the application logs.": something unexpected went wrong in the check. The app's log has the details.
- A record you changed still shows the old value: the public resolvers keep an answer until its TTL runs out. Wait for the record's TTL, then use **Check**.

## How the DNS records work

### The SPF record

SPF checks the connecting IP against the envelope sender domain's record, not the visible From address. For a server that sends directly:

```text
example.com.  TXT  "v=spf1 mx a -all"
```

Add an `include:` for an authorized sending service, for example `include:spf.mailservice.example.net`. Mail sent through a relay needs the relay's IPs authorized too.

Publish one SPF record. `-all` returns fail for unmatched IPs; `~all` returns softfail. Neither passes DMARC through SPF, though aligned DKIM can still pass. `+all` authorizes every IP. Forwarding can break SPF because the connecting IP changes.

SPF allows 10 DNS-querying terms during evaluation, including nested terms. Exceeding that gives `permerror`; not every sending IP reaches the same terms. The app counts `include`, `a`, `mx`, `exists` and `redirect`. See [RFC 7208, section 4.6.4](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4).

### The DKIM record

DKIM signs mail with a private key; receivers check the signature with the DNS public key at `<selector>._domainkey.<domain>`. Publish the value from mailcow or **Expected Value**. Whitespace and quoted TXT fragments do not change the key.

Use a 2048-bit RSA key when supported by your DNS provider. Remove testing flag `t=y` after setup. Flag `t=s` requires the signature's `i=` domain to equal its `d=` domain; it does not prohibit mail from subdomains. See [RFC 6376, section 3.6.1](https://www.rfc-editor.org/rfc/rfc6376.html#section-3.6.1).

For rotation, publish a new selector first, switch signing, then retain the old key long enough for queued mail to arrive.

### The DMARC record

DMARC connects SPF and DKIM to the visible From domain. Publish its record at `_dmarc.example.com`. Policies `none`, `quarantine` and `reject` request monitoring, suspicious-mail handling and rejection. Receivers apply their own policies too. See [How DMARC works](DMARC.md#how-dmarc-works) for alignment, reporting and policy changes.

### DNSSEC signing

Your DNS provider signs the zone and publishes DNSKEY records; your registrar publishes the matching DS record in the parent zone. A missing DS leaves no chain of trust. A mismatched DS can break resolution and mail. Coordinate keys and DS records when moving DNS providers.

### DANE and TLSA records

DANE authenticates an MX host's TLS certificate through DNSSEC. For mailcow's usual public-key pin:

```text
_25._tcp.mail.example.com.  TLSA  3 1 1 <SHA-256 hash of the certificate's public key>
```

The values mean end-entity certificate (3), public key (1) and SHA-256 (1). Keeping the same key preserves the pin through certificate renewal. Publish records for every MX host. Before changing keys, publish both old and new pins and allow caches to update. A validated pin that matches no active key stops DANE delivery.

### The MTA-STS policy

MTA-STS requires TLS and a trusted certificate without DNSSEC. Initial policy discovery can be blocked, unlike DANE. See [RFC 8461, section 10.2](https://www.rfc-editor.org/rfc/rfc8461.html#section-10.2).

Publish `v=STSv1; id=20260101T000000` at `_mta-sts.example.com` and serve this file at `https://mta-sts.example.com/.well-known/mta-sts.txt` without redirects:

```text
version: STSv1
mode: enforce
mx: mail.example.com
max_age: 604800
```

Start with `mode: testing` and read [TLS reports](DMARC.md#how-tls-rpt-and-mta-sts-work) before enforcing. Every MX must match a policy line; `*.example.com` matches one label. Change `id` when the policy changes. The HTTPS host needs a trusted certificate.
