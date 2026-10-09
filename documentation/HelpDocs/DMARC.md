# DMARC Reports - User Guide

## Overview
The **DMARC & TLS** page provides detailed analysis of DMARC aggregate reports and TLS-RPT reports received from email service providers. These reports show how your domain's emails are being handled across the internet and help identify authentication issues and potential email spoofing attempts.

## What is DMARC?

**DMARC (Domain-based Message Authentication, Reporting & Conformance)** is an email authentication protocol that:
- Validates that emails claiming to be from your domain are legitimate
- Tells receiving servers what to do with emails that fail validation
- Provides reports about email authentication results

---

## Report Types

### Aggregate Reports (XML)
Most common type of DMARC report, containing:
- **Statistics**: How many emails passed/failed authentication
- **Sources**: IP addresses sending email claiming to be from your domain
- **Results**: SPF and DKIM authentication outcomes
- **Disposition**: How receiving servers handled the emails

### Report Organization

The page has a few levels; the breadcrumbs lead back from each:

#### 1. All Domains (Main Page)
- **Last 30 days**: domains with reports, messages reported, how many passed DMARC, and how many domains enforce a policy (quarantine or reject)
- **Messages per day** across every domain
- **Domains**: each with its DMARC policy, messages, DMARC pass rate, whether a TLS-RPT record is published, how much mail to it was encrypted, and how many senders fail DMARC. A row opens the domain
- **To do** (beside the list): what needs attention on every domain, the most important first, such as a missing DMARC record, senders that fail DMARC, a policy that only monitors, or a missing TLS-RPT record

#### 2. A Domain
- **Messages per day**: passed and failed DMARC; a day opens its reports
- **Mail flow**: your domain, the senders that sent mail as it, and the receivers that reported it. Line width is the volume, colour is the pass rate
- **Senders**: who sent mail as the domain, failing first. Senders are grouped by their network (ASN, from the MaxMind database); an address with no known network stands alone
- **Daily reports**: one row a day, with the senders and the receivers that reported it
- **Encryption of mail to you (TLS)**: from the TLS-RPT reports, with a row per receiver that reported
- **To do** and **Records** (beside the content): the records are DMARC, SPF, DKIM and TLS-RPT. A record opens a window with what is published, what it means, the three DMARC policies with whether the domain is ready for the next one, and a record to copy

#### 3. A Day of Reports
- What the receivers reported that day: messages, DMARC, SPF and DKIM pass rates, and a row per sender and receiver. A sender opens its details

#### 4. A Sender
- **Where it is**: country, city and network (ASN)
- **What it means**: a sender that fails DMARC is either a service you use that is not set up (set up SPF or DKIM for it), or someone sending as you (the policy handles it)
- **What receivers saw**: each address, envelope sender, SPF and DKIM result, and the reporting receiver

---

## Understanding Report Data

### DMARC Alignment
For an email to pass DMARC, it must pass either:
- **SPF alignment**: The sending domain passes SPF AND matches the From: header domain
- **DKIM alignment**: The email has a valid DKIM signature AND the domain matches the From: header

### Disposition
What the receiving server did with the email:
- **none**: Delivered normally (monitoring mode)
- **quarantine**: Moved to spam/junk folder
- **reject**: Bounced/blocked entirely

### Policy vs. Disposition
- **Policy**: What your DMARC record tells servers to do
- **Disposition**: What servers actually did (they may override your policy)

---

## Key Features

### Geographic Visualization
- Country flags show where emails are being sent from
- Hover over flags to see country names
- Click to filter by geographic region

### Trend Analysis
- Charts show authentication patterns over time
- Identify sudden changes in email volume or sources
- Spot potential spoofing attempts

### Source Identification
- IP addresses with reverse DNS lookup
- ISP/organization information
- Historical data per source

### Compliance Tracking
- Pass rate percentage for SPF and DKIM
- DMARC policy effectiveness
- Recommendations for policy adjustments

---

## Common Scenarios

### Legitimate Sources Failing
**Symptom**: Known good sources showing failures

**Causes**:
- Third-party email services not properly configured
- Marketing platforms lacking DKIM signatures
- Forwarded emails breaking SPF

**Solutions**:
- Add third-party IPs to SPF record
- Configure DKIM with third-party services
- Use SPF/DKIM alignment carefully

### Unknown Sources Appearing
**Symptom**: Unexpected IP addresses in reports

**Investigation**:
1. Check reverse DNS and ISP
2. Look for geographic anomalies
3. Compare message volume
4. Review authentication failures

**Action**: If suspicious, strengthen DMARC policy

### High Failure Rate
**Symptom**: Low DMARC pass percentage

**Diagnosis**:
- Review which sources are failing
- Check SPF record completeness
- Verify DKIM is configured on all sending systems
- Look for email forwarding issues

---

## 🚀 Implementation: Enabling DMARC Reporting

To leverage the monitoring capabilities, you must publish a DMARC record in your DNS. This triggers global receivers (Google, Microsoft, etc.) to generate and send aggregate reports (`rua`) to your system.

### 1. DNS Configuration

Create a **TXT** record at the `_dmarc` subdomain (e.g., `_dmarc.example.com`):

```text
v=DMARC1; p=none; rua=mailto:dmarc@example.net;

```

### 2. Parameter Details

* **`p=none` (Monitoring Mode):** The recommended starting point. It ensures no mail is blocked while you collect data to verify that all legitimate sources are correctly authenticated.
* **`rua=mailto:...`:** This is the feedback loop trigger. Ensure this address is the mailbox configured under **Settings → DMARC & TLS IMAP** in mailcow Logs Viewer.
* **`v=DMARC1`:** Required version prefix.

### 3. External Domain Reporting (Verification)

If you want to receive DMARC reports to a different domain from the one the record is set on (e.g., reports for `example.com` sent to `dmarc@example.net`), you must authorize (`example.net`) to receiving DMARC reports. 

Without this DNS record, major providers (like Google and Microsoft) will **not** send the reports to prevent spam.

#### Option 1: Specific Domain Authorization (Recommended for security)
Add a TXT record to the DNS of the **receiving domain** (`example.net`):

| Host / Name | Value |
| :--- | :--- |
| `example.com._report._dmarc.example.net` | `v=DMARC1;` |

#### Option 2: Wildcard Authorization (Recommended for multiple domains)
If the receiving domain handles reports for many different domains, or if you prefer not to add a record for every single domain, you can use a wildcard record to authorize **all** domains at once:

| Host / Name | Value |
| :--- | :--- |
| `*._report._dmarc.example.net` | `v=DMARC1;` |

*Note: Not all DNS provider support wildcard records. use Cloudflare / Route53.*

### 4. TLS Reports (TLS-RPT)

TLS-RPT reports (RFC 8460) tell you whether other mail servers could connect to yours over TLS, and why they failed when they could not. They matter most when the domain uses MTA-STS or DANE, because a TLS failure then means mail is not delivered.

To receive them, create a **TXT** record at the `_smtp._tls` subdomain (e.g., `_smtp._tls.example.com`):

```text
v=TLSRPTv1; rua=mailto:dmarc@example.net
```

* **`rua=`**: Where reports are sent. Use the mailbox configured under **Settings → DMARC & TLS IMAP**; the same sync imports DMARC and TLS reports. Senders deliver only to `mailto:` and `https:` addresses.
* Publish exactly one such record. Senders ignore the domain when there is more than one.

The reports appear on the domain, under **Encryption of mail to you (TLS)**, and a day opens its report. The **TLS-RPT** record in the domain's **Records** shows whether it is published and where reports go, and gives a record to copy when it is missing. A change to the record triggers a DNS change alert, like the other records.

---

## Best Practices

### Policy Progression
1. **Start**: `p=none` (monitoring only)
2. **Observe**: Collect reports for 2-4 weeks
3. **Identify**: Find all legitimate sending sources
4. **Fix**: Configure SPF/DKIM for all sources
5. **Upgrade**: Move to `p=quarantine`
6. **Monitor**: Watch for issues
7. **Final**: Move to `p=reject` for maximum protection

### Regular Review
- Check reports at least weekly
- Look for new sources or suspicious patterns
- Monitor DMARC compliance rate
- Update SPF/DKIM as infrastructure changes

### Third-Party Services
When using email services (marketing, support desk, etc.):
- Request DKIM signing
- Add their IPs to SPF record
- Test before going live
- Monitor their authentication success

---

## Troubleshooting

### No Reports Appearing
- **Check DMARC Record**: Verify `rua=` tag has correct email
- **No TLS reports**: Check the TLS-RPT record in the domain's **Records**; without a `_smtp._tls` record no TLS reports are sent
- **Wait**: Reports can take 24-48 hours to arrive
- **Email Access**: Ensure reporting email is accessible

### Reports Not Parsing
- **Format Issues**: Some providers send non-standard XML
- **Upload Manually**: Use upload button for problematic reports
- **Contact Support**: Report parsing issues

### Confusing Results
- **Multiple Sources**: Different email systems may show different results
- **Forwarding**: Email forwarding can break SPF
- **Subdomains**: Check if subdomain policy is needed

## Report Retention
- Reports are stored according to your configured retention period (**Settings → DMARC → Retention**)
- Default: 60 days

> [!NOTE]
> Settings are edited on the **Settings** page (requires `SETTINGS_EDIT_VIA_UI_ENABLED=true`). Every setting can also be provided as an environment variable - see [ENV_Settings.md](../ENV_Settings.md).
- Older DMARC and TLS reports are automatically deleted daily (cleanup job runs at 2:15 AM) to save space
- Export reports before they're deleted if long-term analysis is needed

### Deleting reports
**Manage Reports** on the DMARC & TLS page opens a window with two lists:
- **Reports by domain**: each domain with its number of DMARC and TLS reports and the date of its latest report. A click on a column header sorts by it. **Delete all** removes every DMARC and TLS report of that domain, for example a domain you no longer host. The confirmation shows how many reports will be deleted; this cannot be undone.
- **All reports**: every report, newest first, with **Delete** for a single report. A click on a column header sorts the whole list by it (a second click turns it around), across all pages. The search above it finds reports by domain or by reporter (the organization that sent the report), and the total shows how many match.

Deleting is off by default. Turn it on under **Settings → DMARC** (`DMARC_ALLOW_REPORT_DELETE=true`). A domain whose reports were deleted comes back if new reports for it arrive.

---

## Security Considerations

### Identifying Spoofing
Watch for:
- Unusual geographic sources
- High volume from unknown IPs
- 100% authentication failures from specific sources
- Mismatched reverse DNS

### Response to Threats
1. Document the suspicious activity
2. Strengthen DMARC policy if not already at `reject`
3. Review and tighten SPF records
4. Consider adding forensic reporting (`ruf=`)
5. Contact abuse departments at sending ISPs

## Additional Resources
- [DMARC Official Site](https://dmarc.org/)
- [DMARC Alignment Guide](https://dmarc.org/overview/)
- [RFC 7489 - DMARC Specification](https://tools.ietf.org/html/rfc7489)