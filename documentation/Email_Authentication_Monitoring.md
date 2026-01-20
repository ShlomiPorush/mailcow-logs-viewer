# Technical Overview: Email Authentication & Monitoring

To maintain high deliverability and robust domain security, **mailcow-logs-viewer** provides deep inspection and automated monitoring of the three core email authentication protocols: **SPF**, **DKIM**, and **DMARC**.

## The Authentication Stack

| Protocol | Technical Purpose | System Validation Logic |
| --- | --- | --- |
| **SPF** | **Identity Authorization:** Defines which IP addresses/hosts are authorized to send mail for a domain. | Validates against **RFC 7208**, checking the **10-DNS lookup limit**, recursive `include:` mechanisms, and verifying if the Mailcow server IP is explicitly authorized. |
| **DKIM** | **Message Integrity:** Provides a cryptographic signature to ensure the email content hasn't been altered in transit. | Inspects public keys for **SHA1 (weak hash)**, detects **revoked keys**, and warns if the record is stuck in **Testing Mode (`t=y`)**. |
| **DMARC** | **Policy Enforcement:** Provides instructions to receivers on how to handle failed SPF/DKIM checks. | Aggregates XML reports via IMAP, performing **Identifier Alignment** analysis and visualizing global mail flow. |

---

## Advanced Monitoring & Intelligence

**mailcow-logs-viewer** goes beyond basic record checking by providing a comprehensive analysis of your mail flow:

* **GeoIP & ASN Enrichment:** Integrated with **MaxMind GeoLite2**, the system enriches source IPs from DMARC reports with city-level location and Autonomous System (ASN) data. This allows you to identify legitimate third-party senders (like SendGrid or M365) versus malicious spoofing attempts.
* **Automated Data Ingestion:** An automated **IMAP worker** polls your designated reporting mailbox, processes `zip/gz` attachments. 
* **SPF Recursion Analysis:** The validator simulates the receiver's evaluation process, detecting deep-nested includes that might cause the SPF check to fail due to the 10-lookup limit, a common issue in complex enterprise environments.
* **Compliance Dashboard:** Visualize a 30-day trend of your authentication pass rates. The UI provides color-coded compliance metrics (Green  95%) and immediate visibility into `quarantine` or `reject` policy effectiveness.

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
* **`rua=mailto:...`:** This is the feedback loop trigger. Ensure this address is the one configured in the **IMAP Settings** of Mailcow Logs Viewer.
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

### 4. Transitioning to Enforcement

Once the dashboard confirms that your legitimate traffic (including third-party SaaS) is passing SPF/DKIM alignment, you should update your policy to `p=quarantine` or `p=reject` to fully secure your domain against spoofing.

---