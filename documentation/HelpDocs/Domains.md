# Domains

The Domains page lists the domains of your mailcow server and checks the DNS records that decide whether their mail is trusted: SPF, DKIM, DMARC, DNSSEC, DANE and MTA-STS. The domain list and the DKIM key come from the mailcow API; the records are read from public DNS.

![Domains page](../../images/docs/domains-list-light.webp#gh-light-mode-only)
![Domains page](../../images/docs/domains-list-dark.webp#gh-dark-mode-only)

## When domains are checked

The app checks every active domain and every alias domain about a minute after it starts, then every 6 hours. **Check Now** does the same at once. If one of the domains could not be checked, the message says **DNS check failed**; the others are still saved. While a check runs, a second one is refused with **DNS check already in progress**.

Inactive domains (turned off in mailcow) stay in the list but are left out of these checks. **Check** in an open domain checks that domain right away, active or not, but not its alias domains. **Updated** at the top gives the last check of all domains; checking one domain does not change it.

## The results

Only SPF, DKIM and DMARC warnings or errors count toward **needs a DNS change** and its filter, so **DNS looks right.** does not mean every optional check passed.

A `-` in the list means the check has not run yet or could not reach a result. Point at a result to see its message. A card with **Not checked** says why.

The app reads MX records only as part of the DANE and MTA-STS checks.

![An open domain](../../images/docs/domains-open-light.webp#gh-light-mode-only)
![An open domain](../../images/docs/domains-open-dark.webp#gh-dark-mode-only)

### Alias domains

Expand **Alias domains** in an open domain for their DNS cards. Alias domains deliver to their target domain's mailboxes, but sending under an alias domain still needs appropriate authentication records. DMARC can inherit the organizational domain's policy. The app reads the alias domains from mailcow when it starts and every 6 hours after that.

## The checks

The checks use public DNS resolvers, with DNS over HTTPS as a fallback. They do not see records that exist only in your internal DNS. Cached answers and propagation can make other servers see a different result. When a lookup fails, for example because it timed out, the card says the check failed instead of reporting the record as missing.

### SPF

The check reads the TXT record at the domain that starts with `v=spf1` and reports:

- **Error** when there is no SPF record, when there is more than one (receivers then treat SPF as broken), when the record does not start with `v=spf1 `, when it has no `all` at the end and no `redirect=`, when it needs more than 10 DNS lookups, or when it allows every server with `+all` (a bare `all` counts as `+all`).
- **Error** when a sending IP of yours is not allowed by the record. The message names the IP.
- **Error** for a term the check does not accept: an unknown mechanism, a name that only starts like one (such as `mxfoo`), an `ip4:` or `ip6:` value that is not an address of that family, or a CIDR length out of range (0 to 32 for IPv4, 0 to 128 for IPv6). It accepts the mechanisms `ip4`, `ip6`, `a`, `mx`, `include`, `exists`, `ptr` and `all` in any letter case, and the modifiers `redirect=` and `exp=`. `a` and `mx` may carry a CIDR length, such as `a/24` or `mx//64`.
- **Warning** for `?all`, which protects almost nothing.
- **Warning** for a mechanism written with `=` instead of `:`, such as `include=spf.example.net`. SPF reads it as an unknown modifier and ignores it, so the message asks "Did you mean include:spf.example.net?".
- **Warning** for `ptr`, which RFC 7208 discourages because it is slow and unreliable. The check counts it as a DNS lookup but does not evaluate it.
- **OK** for `-all` and for `~all`. With `~all` the message suggests `-all`.

Other modifiers (`name=value`), such as `ra=` from RFC 6652, are ignored, as RFC 7208 requires. The lookup count includes nested `include:` terms and the record a `redirect=` points to. See [The SPF record](#the-spf-record) for the limit.

**Checked IPs** on the SPF card tests your sending IPs against the record, following `include:` and `redirect=`. An `a` or `mx` term with a CIDR length, such as `a/24`, covers the whole network around each address it resolves to. A term with a macro (`%{...}`) cannot be expanded by the app and is skipped. Choose the sources under **Settings** > **Domains** > **SPF check sources**:

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
- **DMARC history** adds up to 20 addresses that passed SPF for the domain in the DMARC reports of the last 30 days. When no reports exist, or the newest is more than 7 days old, the card says so. It is off by default because of false errors: with relaxed alignment, a mail service that sends from its own subdomain can pass DMARC for you without being in your SPF record, and its addresses then fail this check.

### DKIM

The check asks mailcow for the domain's DKIM selector and key, reads the TXT record at `<selector>._domainkey.<domain>` and compares the two tag by tag.

- **Error** when mailcow has no DKIM key for the domain, when the record is missing, or when the record does not match. A mismatch is a different public key (`p=`), a different key type (`k=`), a version other than `DKIM1`, or an `h=` list that does not allow `sha256`, which mailcow signs with. A card with an error shows the **Expected Value** to publish.
- **Error** when the record has `t=y`. In test mode receivers treat failed signatures as if the message were not signed.
- **Error** when the key is empty (`p=`), which revokes it.
- **Warning** when the key matches but other tags differ from mailcow, for example a `t=s` that your DNS provider dropped. These differences do not break signatures.
- **OK** when the published record matches mailcow.

Tag order, spaces and line breaks inside the key do not count as differences. A `t=s` record adds a note: signatures with this key must use the same domain in `i=` as in `d=`, not a subdomain of it. That is the recommended setting.

### DMARC

The check reads the TXT record at `_dmarc.<domain>` that starts with `v=DMARC1`.

- **Error** when there is no record.
- **Warning** for `p=none`, or a record without a known policy.
- **OK** for `p=quarantine` and `p=reject`.

[DMARC & TLS](DMARC.md) shows more about the record and what changing its policy would do.

### DNSSEC

The check looks the domain up through validating resolvers.

- **OK**: the domain is signed and the chain of trust from the parent zone is intact.
- **Warning**: the domain is not signed. Or it publishes keys, but the DS record at the registrar is missing, so nobody can validate it.
- **Error**: validation fails. Resolvers that check signatures cannot resolve the domain at all, so mail to and from it can fail. The usual cause is a DS record at the registrar that no longer matches the keys at the DNS provider.
- **Not checked**: the lookup failed or the domain does not exist in DNS.

### DANE

The DANE check reads the MX hosts and their `_25._tcp.<mx-host>` TLSA records, then connects on port 25 to compare certificates.

- **OK**: the MX records, the TLSA records and the MX host addresses are DNSSEC-validated, and the certificate matches, or could not be compared, on every MX host.
- **Error**: DANE is active and a TLSA record does not match the certificate of an MX host. Senders that use DANE refuse to deliver to it. This usually happens after the certificate's key changed and the TLSA record was not updated.
- **Warning**: no TLSA records are published (DANE is optional); or they are published but not DNSSEC-validated, so senders ignore them; or a record does not match the certificate while DNSSEC is still off, which breaks mail as soon as DNSSEC is turned on. Also a warning when an MX host has no TLSA record, or when no record uses the recommended `3 1 1` form.
- **Not checked**: the domain has a null MX and accepts no mail, it has no MX records, or the lookups failed.

Comparison supports usage 3 (DANE-EE), including mailcow's `3 1 1`. An unreachable port 25 gives "not compared", not a mismatch.

### MTA-STS

The check reads `_mta-sts.<domain>`, fetches the HTTPS policy without redirects and checks its `mx:` patterns against the MX hosts. See [The MTA-STS policy](#the-mta-sts-policy) for the file path and syntax.

- **OK**: the policy is in `enforce` mode and covers every MX host.
- **Error**: more than one `v=STSv1` record; the record exists but the policy file cannot be fetched; the file has no `version: STSv1` or an unknown mode; or an MX host is missing from an enforced policy, so those senders refuse to deliver through it.
- **Warning**: no record (MTA-STS is optional), mode `testing` (failures are reported but delivery is not protected), mode `none`, or an MX host missing from a policy that is not enforced.

### TLS-RPT

The same checks also read the TLS-RPT record at `_smtp._tls.<domain>`. It has no card here; [DMARC & TLS](DMARC.md) shows it with the domain's TLS reports.

## DNS change alerts

Each check compares the records with the previous results. A change sends an alert with the old and new values to **Admin Email** and to the destinations that receive **DNS record changes**, for example `DNS records changed for example.com: SPF, DKIM`. An alert is sent when:

- An SPF, DKIM, DMARC, TLSA, MTA-STS or TLS-RPT record has a new value, appeared, or verifiably disappeared.
- DNSSEC stops validating for a domain that validated before.
- A DNSSEC-validated TLSA record stops matching the certificate of an MX host.

A failed lookup or a timeout never counts as a change, so a DNS hiccup does not raise an alarm. The first check of a domain has nothing to compare with and sends no alert. Alias domains are watched the same way.

**DNS Change Alerts Enabled** under **Settings** > **Notifications** is on by default. See [Notifications](../Notifications.md).

## The weekly summary

The weekly summary email has a **DNS issues** section that lists the active domains whose SPF, DKIM or DMARC check ended in an error at the last check. Warnings, such as `p=none`, are not listed. See [Notifications](../Notifications.md).

## When something is missing

- The page is not in the menu: the Domains feature is off. Turn it on under **Settings** > **Features**. While it is off, the DNS checks every 6 hours do not run.
- **Failed to load domains**: the app could not read the domain list from mailcow. The message under it gives the reason. Check the mailcow connection on the Status page. A read-only mailcow API key is enough for this page.
- **Not checked yet**: the first check has not run. It starts about a minute after the app starts; **Check Now** runs it at once.
- **DKIM not configured in mailcow**: mailcow has no DKIM key for the domain. Create one in mailcow under the domain's DKIM settings, then publish it.
- A message that ends with "Check the application logs.": something unexpected went wrong in the check. The app's log has the details.
- A record you changed still shows the old value: the public resolvers keep an answer until its TTL runs out. Wait for the record's TTL, then use **Check**.

## How the DNS records work

### The SPF record

SPF checks the connecting IP against the envelope sender domain's record, not the visible From address. For a server that sends directly:

```text
example.com.  TXT  "v=spf1 mx a -all"
```

Add an `include:` for each sending service you use, for example `include:spf.mailservice.example.net`. Mail sent through a relay needs the relay's IPs too.

Publish one SPF record. `-all` returns fail for unmatched IPs and `~all` softfail; neither passes DMARC through SPF, though aligned DKIM can still pass. `+all` authorizes every IP. Forwarding can break SPF because the connecting IP changes.

SPF allows 10 DNS-querying terms during evaluation, including nested terms. Exceeding that gives `permerror`; not every sending IP reaches the same terms. The app counts `include`, `a`, `mx`, `exists`, `ptr` and `redirect`, and the terms of the records they point to. See [RFC 7208, section 4.6.4](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4).

### The DKIM record

DKIM signs mail with a private key; receivers check the signature with the public key in DNS at `<selector>._domainkey.<domain>`. Publish the value from mailcow or **Expected Value**. Whitespace and quoted TXT fragments do not change the key.

Use a 2048-bit RSA key when your DNS provider supports it. Remove the test flag `t=y` after setup. The flag `t=s` requires the signature's `i=` domain to equal its `d=` domain; it does not prohibit mail from subdomains. See [RFC 6376, section 3.6.1](https://www.rfc-editor.org/rfc/rfc6376.html#section-3.6.1). To rotate a key, publish a new selector first, switch signing, then keep the old key long enough for queued mail to arrive.

### The DMARC record

DMARC connects SPF and DKIM to the visible From domain. Publish its record at `_dmarc.example.com`. The policies `none`, `quarantine` and `reject` request monitoring, suspicious-mail handling and rejection; receivers apply their own policies too. See [How DMARC works](DMARC.md#how-dmarc-works) for alignment, reporting and policy changes.

### DNSSEC signing

Your DNS provider signs the zone and publishes DNSKEY records; your registrar publishes the matching DS record in the parent zone. A missing DS leaves no chain of trust. A mismatched DS can break resolution and mail. Coordinate keys and DS records when moving DNS providers.

### DANE and TLSA records

DANE authenticates an MX host's TLS certificate through DNSSEC. For mailcow's usual public-key pin:

```text
_25._tcp.mail.example.com.  TLSA  3 1 1 <SHA-256 hash of the certificate's public key>
```

The values mean end-entity certificate (3), public key (1) and SHA-256 (1). Keeping the same key keeps the pin valid through certificate renewal. Publish records for every MX host. Before changing keys, publish both old and new pins and let caches update. A validated pin that matches no active key stops DANE delivery.

### The MTA-STS policy

MTA-STS requires TLS and a trusted certificate without DNSSEC. Unlike DANE, the first policy lookup can be blocked by an attacker. See [RFC 8461, section 10.2](https://www.rfc-editor.org/rfc/rfc8461.html#section-10.2).

Publish `v=STSv1; id=20260101T000000` at `_mta-sts.example.com` and serve this file at `https://mta-sts.example.com/.well-known/mta-sts.txt` without redirects:

```text
version: STSv1
mode: enforce
mx: mail.example.com
max_age: 604800
```

Start with `mode: testing` and read [TLS reports](DMARC.md#how-tls-rpt-and-mta-sts-work) before enforcing. Every MX must match a policy line; `*.example.com` matches one label. Change `id` when the policy changes. The HTTPS host needs a trusted certificate.
