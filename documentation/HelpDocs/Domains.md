# Domains Page - User Guide

## Overview
The Domains page displays all email domains configured in your mailcow server, along with comprehensive DNS validation and domain statistics.

## Key Features

### Domain Information
- **Domain Name**: Your email domain
- **Active Status**: Whether the domain is currently active
- **Mailboxes**: Current/Maximum mailbox count and available slots
- **Aliases**: Current/Maximum alias count and available slots  
- **Storage**: Total storage used and quota (if applicable)

### DNS Security Validation
The system automatically validates four critical DNS record types:

#### SPF (Sender Policy Framework)
- **Purpose**: Specifies which mail servers can send email on behalf of your domain
- **Source IP Validation**: The check does not only parse the record - it verifies that every IP your mail can actually leave from is authorized. Which IPs are validated is configurable under **Settings → Domains → SPF check sources**:
  - Auto-detected WAN IP (on by default)
  - Public IPs of active mailcow transports
  - Public IPs of active mailcow relayhosts
  - Manually configured IPs or hostnames
  - Source IPs observed with a passing SPF result in the last 30 days of imported DMARC aggregate reports (the DMARC history source)
- If **any** validated IP is not authorized by the record, the SPF check reports an error naming the offending IP(s)
- **Checked IPs**: The SPF card contains an expandable **Checked IPs** list showing every validated IP, where it came from (Auto-detected WAN, Transport, Relay host, Configured, DMARC history) and a per-IP **Authorized** / **Not authorized** verdict
- **Status Indicators**:
  - ✓ **Success**: SPF record exists and is properly configured
  - ⚠ **Warning**: SPF record exists but may need optimization
  - ✗ **Error**: SPF record is missing or incorrect
  - ? **Unknown**: Not yet checked

> [!NOTE]
> The DMARC history source is off by default. With relaxed alignment, an ESP subdomain IP can appear as an aligned pass in DMARC reports without being in your domain's own SPF record - enabling this source can then cause a false warning.

> [!NOTE]
> Settings are edited on the **Settings** page (requires `SETTINGS_EDIT_VIA_UI_ENABLED=true`). Every setting can also be provided as an environment variable - see [ENV_Settings.md](../ENV_Settings.md).

#### DKIM (DomainKeys Identified Mail)
- **Purpose**: Adds a digital signature to outgoing emails
- **Validation**: Compares your DNS record with mailcow's configured DKIM key
- **Status**: Same indicators as SPF

#### DMARC (Domain-based Message Authentication)
- **Purpose**: Defines how recipients should handle emails that fail authentication
- **Policy Levels**:
  - `reject`: Strongest protection (recommended)
  - `quarantine`: Moderate protection
  - `none`: Monitoring only (weakest)
- **Status**: Same indicators as SPF

### Alias Domains
Domains configured in mailcow as **alias domains** (a domain whose mail is delivered to the mailboxes of another domain) are shown inside their target domain's expanded view, each with its own DNS validation summary.
- Alias domains need their own SPF, DKIM and DMARC records - mail sent as `user@alias.tld` is authenticated against `alias.tld`, not against the target domain
- Alias domains are included in the scheduled and manual "Check All DNS" runs
- The mapping is synced from mailcow automatically (every 5 minutes, together with the domain list)

#### TLSA (DANE)
- **Purpose**: DANE lets senders verify your mail server's TLS certificate through DNS, preventing TLS downgrade and man-in-the-middle attacks
- **Where the records live**: For SMTP, TLSA records are published under each MX hostname (`_25._tcp.<mx-host>`), not under the domain itself - the check resolves your MX hosts and looks there
- **Validation**: Warns when some MX hosts have no TLSA record, or when no record uses the recommended `3 1 1` form (DANE-EE, SPKI, SHA-256 - mailcow's default)
- **Optional**: DANE requires a DNSSEC-signed zone. A domain without TLSA records gets an informational warning, never an error. Domains that do not accept mail (null MX) are skipped

#### MTA-STS
- **Purpose**: MTA-STS (RFC 8461) lets your domain tell sending servers to require TLS and verified certificates when delivering mail to you, closing the TLS-downgrade gap without DNSSEC
- **How it works**: A TXT record at `_mta-sts.<domain>` points senders at a policy file served from `https://mta-sts.<domain>/.well-known/mta-sts.txt`. The check validates both, and verifies that your MX hosts are covered by the policy
- **Statuses**: `enforce` mode with covered MX hosts is a pass. `testing` and `none` modes are warnings - the policy exists but does not protect delivery. A published record whose policy file cannot be fetched is an error, because enforcing senders treat that as a hard failure. An MX host missing from an enforced policy is an error - those senders will refuse to deliver through it
- **Optional**: A domain without MTA-STS gets an informational warning, never an error

---

## How to Use

### Viewing Domains
1. All domains are displayed in an expandable list
2. Quick overview shows domain name, status, and DNS validation summary
3. Click any domain row to expand and view detailed information

### DNS Validation
- **Automatic Checks**: DNS records are validated every 6 hours in the background
- **Manual Check**: Click the "Check DNS" button within any domain's details to force an immediate validation
- **Last Checked**: Timestamp shows when DNS was last validated

### Search & Filter
- **Search Box**: Filter domains by name
- **Issues Filter**: Check "Show DNS Issues Only" to display only domains with DNS problems

### Understanding DNS Status
When you expand a domain, the DNS Security section shows:
- Detailed status message for each record type
- The actual DNS record value (for DKIM and DMARC)
- The expandable **Checked IPs** list on the SPF card (every validated IP with its source and verdict)
- Specific warnings or recommendations
- Time of last validation

### DNS Change Alerts
When a scheduled or manual check finds that a domain's SPF, DKIM, DMARC, TLSA or MTA-STS record has **changed** since the previous check, an alert is sent by email and to your notification destinations (alert type "DNS record changes").
- Only definite changes trigger an alert: a value that is present and different, or a record that verifiably disappeared
- Failed lookups and timeouts are ignored, so a DNS hiccup never fires a false alarm
- Controlled by the **DNS Change Alerts Enabled** toggle under **Settings → Notifications → Alert types** (on by default)

---

## Best Practices

1. **Regular Monitoring**: Review DNS status regularly, especially after DNS changes
2. **Fix Issues Promptly**: Address DNS warnings and errors as soon as possible
3. **Strong DMARC Policy**: Aim for `quarantine` or `reject` policy
4. **SPF Optimization**: Keep SPF records concise (under 10 DNS lookups)
5. **DKIM Key Rotation**: Periodically rotate DKIM keys for security

---

## Troubleshooting

### DNS Changes Not Reflected
- DNS changes can take 24-72 hours to propagate globally
- Use the manual "Check DNS" button to verify after waiting
- Check your DNS provider's interface to confirm records are published

### "DNS Query Timeout" Errors
- Indicates temporary DNS server issues
- Wait a few minutes and try again
- If persistent, check your DNS provider's status

### "Record Mismatch" Warnings
- Compare the "Expected" vs "Actual" record values
- Update your DNS to match the expected value
- Wait for DNS propagation, then check again

## Related Resources
- [SPF Record Syntax](https://en.wikipedia.org/wiki/Sender_Policy_Framework)
- [DKIM Overview](https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail)
- [DMARC Policy Guide](https://dmarc.org/)