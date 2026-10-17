# DMARC & TLS

This page shows who sends mail in your domains' name and whether mail to your domains arrives encrypted. It reads the DMARC aggregate reports and TLS reports (TLS-RPT) that other mail servers send you, imported from a mailbox over IMAP or uploaded by hand, and the DMARC and TLS-RPT records of each domain.

The main report views cover the last 30 days; day views cover their selected day, and report management includes all retained reports. A message counts as **Passed DMARC** when the receiver reported an aligned SPF pass or an aligned DKIM pass for it. Rates show in green from 95%, in amber from 80% and in red below. A rate with no messages or sessions behind it shows `-`. What alignment means is explained in [How DMARC works](#how-dmarc-works).

## All domains

![DMARC & TLS, all domains](../../images/docs/dmarc-all-domains-light.webp#gh-light-mode-only)
![DMARC & TLS, all domains](../../images/docs/dmarc-all-domains-dark.webp#gh-dark-mode-only)

**Domains with reports** counts every domain that has a DMARC or TLS report. **Enforced (quarantine or reject)** counts the domains that publish a DMARC policy that acts on failing mail.

In the domain table, **Not on server** marks a domain that is not an active domain or alias domain on this mailcow server, for example a domain you removed from mailcow that still has reports. **Not checked** means the domain's DNS has not been checked yet. A domain with only TLS reports shows `-` under **Messages** and **Passed DMARC**. **Encrypted** is the share of TLS sessions to the domain that succeeded. **Failing senders** counts the sending addresses that failed DMARC for most of their mail. Records come from [Domains](Domains.md) DNS checks, or a page-load lookup for domains outside those checks.

### To do

The list shows up to 8 items, most urgent first, and the remaining count:

- **Publish a DMARC record**: the domain has no DMARC record. The record window offers one to publish.
- **N senders fail DMARC**: mail in your name failed SPF and DKIM.
- **The policy only monitors (p=none)**: mail that fails is still delivered. When the reports support a stricter policy, the item says so.
- **Publish a TLS-RPT record**: without one, receivers do not tell you when mail to you could not be encrypted.

## A domain

![A domain on DMARC & TLS](../../images/docs/dmarc-domain-light.webp#gh-light-mode-only)
![A domain on DMARC & TLS](../../images/docs/dmarc-domain-dark.webp#gh-dark-mode-only)

In **Mail flow**, each box's color follows its pass rate and each line is as wide as the volume it carries. It shows up to 8 senders and 8 receivers. On a phone it is left out, because the Senders table shows the same.

**Senders** group by network organization, failing groups first, then by volume. MaxMind supplies network and country. Unknown networks stay as individual IPs; without MaxMind every IP stands alone. See [Settings](Settings.md).

### To do

The same kinds of items as on the all-domains view, for this domain only, plus:

- **<sender> fails DMARC**: a sender that failed for most of its mail, with its SPF and DKIM rates. If it is yours, set up SPF or DKIM for it; if not, a stricter policy stops it.
- **<sender> passes on DKIM only**: at least 95% of its mail passes DMARC, but fewer than 50% pass aligned SPF; this does not prove it is missing from your SPF record.

### Records

- **DMARC** is tagged **Monitoring** (`p=none`), **Partial** (`p=quarantine`), **Enforced** (`p=reject`) or **Missing**.
- **SPF** is the share of mail that passed with SPF aligned, tagged **OK** from 95% and **Gaps** below.
- **DKIM** is **OK** when any reported mail passes aligned DKIM; **Missing** means none does.
- **TLS-RPT** is **OK** when a record is published at `_smtp._tls`, **Missing** when not.

Without mail in the last 30 days, SPF and DKIM say **No data**.

## The record windows

![The DMARC record window for a domain](../../images/docs/dmarc-record-window-light.webp#gh-light-mode-only)
![The DMARC record window for a domain](../../images/docs/dmarc-record-window-dark.webp#gh-dark-mode-only)

### DMARC record

The window takes the published record apart. A tag that is not set shows its default: **Subdomains** follow the domain's policy, **Applied to** (`pct=`) is 100% and **Alignment** is **relaxed**. Below are the notes of the DNS check, for example the advice to use a stricter policy.

**Policy** marks the policy in place with **Now** and picks the next stricter one when the window opens. Pick a policy to see what it would change:

- **Ready.** means that every sender group passing DMARC on most of its mail passes on 95% or more. Senders that fail on most of their mail are treated as not yours. **Not yet.** means such a group passes on under 95%, or no group passes on most of its mail. Without mail in the last 30 days, it says **No data.** Review known senders before changing policy.
- How many messages receivers would have sent to spam or refused in the last 30 days with that policy: every message that failed DMARC, from any sender.
- The record to publish: your current record with only `p=` changed, so all its other tags stay, for example `_dmarc.example.com  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com; adkim=s"`. Without a record, it is `v=DMARC1; p=<policy>; rua=mailto:dmarc@<domain>`.

### SPF and DKIM

The senders are listed with their aligned SPF or DKIM share, the weakest first. For a known sender below 95%, check SPF authorization or aligned DKIM signing before tightening your policy.

### TLS-RPT record

With a record, the window shows where reports go and any warnings, for example a report address that is not `mailto:` or `https:`. Without one, it offers a record with the address of the report mailbox this page reads, so the reports show up here. When IMAP is not set up, it suggests `tls-reports@<domain>`.

## A sender

![A sender that fails DMARC](../../images/docs/dmarc-sender-light.webp#gh-light-mode-only)
![A sender that fails DMARC](../../images/docs/dmarc-sender-dark.webp#gh-dark-mode-only)

**Fails DMARC** means the sender failed for more than half of its mail. The sender view uses **Passes on DKIM only** when at least half passes DMARC but fewer than half passes aligned SPF; the **To do** item above requires a 95% DMARC pass rate. Review unfamiliar senders before treating them as spoofing or tightening your policy.

In **What receivers saw**, **From** is the header From domain, and **SPF** and **DKIM** show **Aligned** or the result the receiver reported, such as `fail`.

## A day of TLS reports

**Policy** is the policy the receiver applied: `STS` for MTA-STS, `TLSA` for DANE, or `NO-POLICY-FOUND`. Each kind of failure has its own line with the number of sessions and the MX host, for example `certificate-expired: 3 sessions to mail.example.com`.

## Fetching reports from the mailbox

DMARC and TLS reports arrive by email at the addresses in the `rua=` tags of your records. The app reads them from that mailbox over IMAP. Set it up under **Settings** > **DMARC & TLS IMAP**; with **IMAP Enabled** on, the app imports every hour (**IMAP Interval**, 3600 seconds by default) and once 30 seconds after it starts (**IMAP Run On Startup**).

How the import works:

- It reads unread messages in **IMAP Folder** (`INBOX` by default) whose subject contains `Report Domain:`, `DMARC`, `Report-ID:`, `TLS-RPT` or `TLS Report`. With **IMAP Scan All Unseen** on, it reads every unread message, for reports with subjects in other languages.
- An XML attachment is read as a DMARC report, a JSON attachment as a TLS report; a ZIP is opened to see which one it holds. Each report must expand to 10 MB or less.
- A report that is already stored counts as a duplicate and is not imported twice.
- An imported message is deleted with **IMAP Delete After** on (the default) or marked as read with it off.
- Bounces and messages without a report are marked as read and skipped. They are not counted as failures and never deleted. mailcow sends its own DMARC reports from an address that often receives reports, so bounces of those reports land here.
- A message that cannot be imported is marked as read, left in the mailbox and counted as failed. Messages larger than 20 MB are not downloaded at all and count as failed.
- Messages are handled in batches of **IMAP Batch Size** (10 by default).

Reading a report in a mail client before import makes it ineligible until you mark it unread again.

> [!NOTE]
> Use a mailbox that receives only reports. With **IMAP Scan All Unseen** on, the import reads every unread message in the folder and marks it as read, reports or not.

**Fetch reports** starts an import and reloads the page after a few seconds. Only one import runs at a time: while one runs, **Fetch reports** says "Reports are already being fetched", and a scheduled import skips its turn. An import left `running` because the app stopped during it is marked `failed` when the next one starts.

**View History** shows the last 20 imports. An import whose connection failed has the status `error`. An import that finished with some failed emails has the status `success` and a number under **Failed**.

## Uploading a report

**Upload Report** imports one file:

- DMARC: a plain `.xml` file, a gzip file (`.xml.gz`) or a ZIP that holds the XML.
- TLS: `.json`, `.json.gz`, or a ZIP that holds the JSON, whatever its name.

The file may be at most 10 MB and must expand to 10 MB or less. The app tells XML, gzip and ZIP apart by their content, not by the file name. A report already stored is reported as a duplicate.

Upload is allowed by default. Turn it off with **Manual Upload Enabled** under **Settings** > **DMARC & TLS**; the button then disappears.

## Manage Reports

![Manage Reports](../../images/docs/dmarc-manage-reports-light.webp#gh-light-mode-only)
![Manage Reports](../../images/docs/dmarc-manage-reports-dark.webp#gh-dark-mode-only)

**Manage Reports** lists the stored reports by domain and one by one. **Delete all** removes all reports of a domain, **Delete** a single report. In **All reports**, the search finds reports by domain or reporter, and a click on a column header sorts the whole list, across all pages.

Deleting is off by default. Turn it on with **Allow Report Delete** under **Settings** > **DMARC & TLS** (`DMARC_ALLOW_REPORT_DELETE=true`). Deletion cannot be undone. New reports can recreate a deleted domain's entry.

## How long reports are kept

Every day at 02:15 the app deletes DMARC and TLS reports that were imported more than **Retention Days** ago (60 by default, under **Settings** > **DMARC & TLS**). The age counts from the import, not from the report's period.

## Emails from this page

- **Import errors.** When an import leaves messages it could not import, the app sends `DMARC & TLS: N report emails could not be imported`, with the subject, Message-ID and error of each message. It goes to **Report Import Error Email** (comma-separated addresses), or the **Admin Email** when that is empty (both under **Settings** > **Notifications**), and to the notification destinations that receive **DMARC processing errors**. Email needs SMTP; the other notification destinations receive the alert without it. Skipped bounces do not trigger it.
- **The weekly summary** has no figures from the reports. Its **DNS issues** section lists DMARC records with an error, from the DNS checks. See [Domains](Domains.md#the-weekly-summary).
- **DNS change alerts** cover the DMARC and TLS-RPT records. See [Domains](Domains.md#dns-change-alerts).

See [Notifications](../Notifications.md) for the destinations.

## Policy advice in the menu and on the Dashboard

The **DMARC & TLS** entry in the menu shows a count: the domains whose reports suggest a stricter policy, show a low pass rate, or show new addresses that fail DMARC. The Dashboard lists the same under its items that need attention.

Both use **Settings** > **DMARC & TLS** > **Insights (policy recommendations)**, not the 30 days of the report views. By default, with at least 100 messages (**DMARC Insights Min Volume**) over 28 days (**DMARC Insights Window Days**), they suggest a stricter policy at a pass rate of 99.5% or more (**DMARC Insights Pass Threshold**) and warn below 90%. The record window's **Ready.** is a separate calculation, described [above](#dmarc-record).

## When something is missing

- The page is not in the menu: the DMARC & TLS feature is off. Turn it on under **Settings** > **Features**. While it is off, the import and the daily cleanup do not run.
- **No reports yet**: nothing has been imported. Check that your DMARC records have a `rua=` address that ends up in the report mailbox, that IMAP is set up, and that the address may receive reports for the domain (see [Receiving reports at another domain](#receiving-reports-at-another-domain)). Receivers send aggregate reports about once a day, so the first ones take a day or two.
- A domain says it has no TLS reports: it has no TLS-RPT record, or no server has sent mail to it with TLS reporting turned on yet. The TLS-RPT record window shows a record to publish.
- **Fetch reports** is greyed out with **Not set up** under it: IMAP is not set up. **IMAP Enabled** is off by default; the connection defaults are port 993, SSL on and **IMAP Verify SSL** off.
- **Last fetch failed**: the import could not connect or log in. **View History** shows the import; the error is in the app's log. A certificate problem names the setting to change (**IMAP Verify SSL**).
- There is no **Manage Reports** button: there are no reports.
- **No location or network known** on a sender: the MaxMind databases are not set up, or the address is not in them.

## How DMARC works

DMARC connects authentication to the visible `From:` domain. SPF checks the connecting IP against the envelope sender domain; DKIM checks a signature from its `d=` domain. DMARC passes when at least one passes and is **aligned** with From.

Relaxed alignment (`aspf=r` and `adkim=r`, the defaults) accepts the same organizational domain, so `bounces.example.com` aligns with `example.com`. Strict alignment (`s`) needs an exact match. Forwarding can break SPF while a surviving aligned DKIM signature still passes DMARC.

### The policy

| Tag | Meaning |
|---|---|
| `p=none` | Request no DMARC enforcement; receivers still apply spam rules. |
| `p=quarantine` | Request suspicious-mail handling, usually a spam folder. |
| `p=reject` | Request rejection of failing mail. |
| `sp=` | Subdomain policy; otherwise subdomains inherit `p=`. |
| `pct=` | Policy sampling percentage, default 100. Unsampled failing mail gets the next weaker policy. |
| `rua=` | Aggregate-report destinations, separated by commas. |
| `ruf=`, `fo=` | Failure-report destinations and conditions. Few receivers send these reports; this page does not display them. |

Receivers choose the final disposition. See [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489.html).

### Aggregate reports

Receivers usually send daily XML reports, often compressed. They list sending IPs, message counts, authentication and alignment results, and dispositions, but no message content. Missing reports do not prove that no mail was sent.

### Receiving reports at another domain

When a destination is outside the policy's organizational domain, its operator must authorize reports. For `example.com` reporting to `dmarc-reports@example.net`, publish in the receiving domain:

| Name | TXT value |
|---|---|
| `example.com._report._dmarc.example.net` | `v=DMARC1` |

To authorize all domains, use `*._report._dmarc.example.net` if your DNS provider supports wildcard TXT records.

### From p=none to p=reject

1. Publish `v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com` and set up SPF and DKIM. See [Domains](Domains.md).
2. Collect reports through a full sending cycle, including monthly jobs.
3. Identify legitimate **Senders** and fix their aligned SPF or DKIM. Investigate unknown senders before classifying them as spoofing.
4. Move to `quarantine`, optionally increasing `pct=` in steps. **Ready.** is a prompt to review reports, not proof that all senders work.
5. Monitor the results before moving to `reject`.

## How TLS-RPT and MTA-STS work

Opportunistic STARTTLS can fall back to plain text and is open to downgrade attacks. MTA-STS and DANE require encrypted delivery for senders that support them. TLS-RPT reports delivery failures.

### TLS-RPT

TLS-RPT (RFC 8460) asks sending servers to send a daily report about their connections to your MX hosts: how many sessions were encrypted, how many failed and why, for example an expired certificate or a host name that does not match. The record is a TXT record at `_smtp._tls`:

```text
_smtp._tls.example.com.  TXT  "v=TLSRPTv1; rua=mailto:dmarc-reports@example.com"
```

- Use the report mailbox of this page; the same import reads DMARC and TLS reports.
- Senders deliver reports only to `mailto:` and `https:` addresses.
- Publish exactly one record. With more than one, senders ignore them.

The reports matter most with MTA-STS in `enforce` mode or DANE, where a TLS failure means the mail is not delivered.

### MTA-STS

Start MTA-STS in `testing`, review TLS reports, then use `enforce` when legitimate delivery works. For records, policy syntax and certificate requirements, see [Domains](Domains.md#the-mta-sts-policy).
