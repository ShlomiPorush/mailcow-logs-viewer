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
The system automatically validates three critical DNS records:

#### SPF (Sender Policy Framework)
- **Purpose**: Specifies which mail servers can send email on behalf of your domain
- **Status Indicators**:
  - ✓ **Success**: SPF record exists and is properly configured
  - ⚠ **Warning**: SPF record exists but may need optimization
  - ✗ **Error**: SPF record is missing or incorrect
  - ? **Unknown**: Not yet checked

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
- Specific warnings or recommendations
- Time of last validation

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