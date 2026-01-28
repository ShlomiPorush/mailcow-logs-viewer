# DMARC Reports - User Guide

## Overview
The DMARC Reports page provides detailed analysis of DMARC aggregate reports received from email service providers. These reports show how your domain's emails are being handled across the internet and help identify authentication issues and potential email spoofing attempts.

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

The DMARC interface has multiple navigation levels:

#### 1. Domains View (Main Page)
- Lists all domains with DMARC reporting enabled
- Shows summary statistics:
  - Total reports received
  - Date range of reports
  - Overall DMARC compliance rate

#### 2. Domain Overview
Click a domain to see:
- **Report Timeline**: Graph showing reports over time
- **Top Sending Sources**: Most active IP addresses
- **Compliance Summary**: Pass/fail statistics
- **Policy Effectiveness**: How well your DMARC policy is working

#### 3. Individual Report Details
Click a specific report to view:
- **Report Metadata**:
  - Reporting organization (e.g., Gmail, Outlook)
  - Date range covered
  - Report ID
- **Authentication Results**:
  - SPF alignment status
  - DKIM alignment status
  - Overall DMARC result
- **Message Statistics**:
  - Total messages evaluated
  - Disposition applied (none/quarantine/reject)

#### 4. Source IP Details
Click an IP address to see:
- **Geographic Information**:
  - Country
  - Region/City
  - ISP/Organization
- **Authentication Details**:
  - SPF check result
  - DKIM check result
  - DMARC alignment status
- **Volume**: Number of messages from this source
- **Reverse DNS**: Hostname associated with the IP

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
* **`rua=mailto:...`:** This is the feedback loop trigger. Ensure this address is the one configured in the **IMAP Settings** of mailcow Logs Viewer.
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
- Reports are stored according to your configured retention period
- Default: 90 days
- Older reports are automatically deleted to save space
- Export reports before they're deleted if long-term analysis is needed

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