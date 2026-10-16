# DMARC & TLS

This page shows who sends mail in your domains' name and whether mail to your domains arrives encrypted. It reads the DMARC aggregate reports and TLS reports (TLS-RPT) that other mail servers send you, imported from a mailbox over IMAP or uploaded by hand, and the DMARC and TLS-RPT records of each domain.

The main report views cover the last 30 days; day views cover their selected day, and report management includes all retained reports. A message counts as **Passed DMARC** when the receiver reported an aligned SPF pass or an aligned DKIM pass for it. Rates show in green from 95%, in amber from 80% and in red below. A rate with no messages or sessions behind it shows `-`. What alignment means is explained in [How DMARC works](#how-dmarc-works).

Open a domain, then a sender or report day. Use the breadcrumbs to return.

## The page head

- **Fetch reports** imports new reports from the report mailbox now. Under it, the last import, for example **Last fetch done: 10 min ago**, and **View History**. See [Fetching reports from the mailbox](#fetching-reports-from-the-mailbox).
- **Upload Report** imports a report file from your computer. It shows only while manual upload is allowed. See [Uploading a report](#uploading-a-report).
- **Manage Reports (N)** opens the list of stored reports, with N the number of DMARC and TLS reports. It is hidden while there are none. See [Manage Reports](#manage-reports).

## All domains

![DMARC & TLS, all domains](../../images/docs/dmarc-all-domains-light.webp#gh-light-mode-only)
![DMARC & TLS, all domains](../../images/docs/dmarc-all-domains-dark.webp#gh-dark-mode-only)

### Last 30 days

- **Domains with reports**: every domain that has a DMARC or TLS report.
- **Messages reported**: the messages in all DMARC reports.
- **Passed DMARC**: the share of those messages that passed.
- **Enforced (quarantine or reject)**: how many of the domains publish a DMARC policy that acts on failing mail.

### Messages per day

A bar per day across every domain, passed in green and failed in red. Point at a bar to see the numbers for that day.

### Domains

Open a domain from the table, ordered by latest report.

- **Domain**: the name. A small **Not on server** note marks a domain that is not an active domain or alias domain on this mailcow server, for example a domain you removed from mailcow that still has reports.
- **DMARC policy**: the published policy, **Reject**, **Quarantine** or **None**; **No record** when the domain has none, or **Not checked** before its DNS check.
- **Messages** and **Passed DMARC**: from the DMARC reports. A domain with only TLS reports shows `-`.
- **TLS-RPT**: **Published**, **Missing** or **Not checked**.
- **Encrypted**: the share of TLS sessions to the domain that succeeded, from its TLS reports.
- **Failing senders**: how many sending addresses failed DMARC for most of their mail.

Records come from [Domains](Domains.md) DNS checks, or a page-load lookup for domains outside those checks.

### To do

Items name the domain and link to the next action, most urgent first:

- **Publish a DMARC record**: the domain has no DMARC record. **Show the record** opens the DMARC record window with a record to publish.
- **N senders fail DMARC**: mail in your name failed SPF and DKIM. **Look at it** opens the domain.
- **The policy only monitors (p=none)**: mail that fails is still delivered. When the reports support a stricter policy, the item says so. **See the policy** opens the DMARC record window.
- **Publish a TLS-RPT record**: without one, receivers do not tell you when mail to you could not be encrypted. **Show the record** opens the TLS-RPT record window.

The list shows up to 8 items and the remaining count. With none, it says "Nothing to do. The records are in place and every sender passes."

## A domain

![A domain on DMARC & TLS](../../images/docs/dmarc-domain-light.webp#gh-light-mode-only)
![A domain on DMARC & TLS](../../images/docs/dmarc-domain-dark.webp#gh-dark-mode-only)

The domain's name, with **Not on server** when it applies, and from top to bottom:

### Messages per day

Passed and failed messages per day. Click a day's bar to open that day's reports.

### Mail flow

Three columns: **Your domain**, **Sent by** (the senders) and **Reported by** (the receivers that sent reports). Each box shows its messages and pass rate, and its color follows the pass rate. The lines between the boxes are as wide as the volume they carry. Up to 8 senders and 8 receivers show. Click a sender to open it. On a phone the mail flow is left out, because the Senders table shows the same.

### Senders

Senders group by ASN, failing groups first, then by volume. MaxMind supplies network and country. Unknown networks stay as individual IPs; without MaxMind every IP stands alone. See [Settings](Settings.md).

Columns: **Sender**, **Messages**, **Passed DMARC**, **SPF aligned**, **DKIM aligned** and **Addresses**. Click a row to open the sender.

### Daily reports

One row per day: **Day**, **Messages**, **Senders**, **Reported by** and **Passed DMARC**. Click a row to open that day's reports. On a phone the list starts folded.

### Encryption of mail to you (TLS)

From the TLS reports of the domain: **Sessions**, **Encrypted**, **Failed** and **Reports**, a chart of encrypted and failed sessions per day (click a day to open its TLS reports), and a row per receiver that reported, with its sessions, failures and encrypted share. Without TLS reports in the last 30 days, the card says so and links to the TLS-RPT record.

### To do

The same kinds of items as on the all-domains view, for this domain only, plus:

- **<sender> fails DMARC**: a sender that failed for most of its mail, with its SPF and DKIM rates. If it is yours, set up SPF or DKIM for it; if not, a stricter policy stops it.
- **<sender> passes on DKIM only**: the sender passes DMARC but is not in your SPF record. That is fine for a newsletter service; add it to SPF if it should be there.

### Records

One row per record. Click a row to open its window.

- **DMARC**: the published policy, for example `p=quarantine`, tagged **Monitoring** (none), **Partial** (quarantine) or **Enforced** (reject); or **No record at _dmarc**, tagged **Missing**.
- **SPF**: the share of mail that passed with SPF aligned, tagged **OK** from 95% or **Gaps** below.
- **DKIM**: **Your mail is signed** (**OK**) or **No signed mail in the reports** (**Missing**).
- **TLS-RPT**: **Receivers report encryption** (**OK**) or **No record at _smtp._tls** (**Missing**).

Without mail in the last 30 days, SPF and DKIM say **No mail in the last 30 days** and **No data**.

## The record windows

Open record windows from **Records** or **To do**.

![The DMARC record window for a domain](../../images/docs/dmarc-record-window-light.webp#gh-light-mode-only)
![The DMARC record window for a domain](../../images/docs/dmarc-record-window-dark.webp#gh-dark-mode-only)

### DMARC record

With a record, the window shows:

- **Current record**: the record as published, with **Copy**.
- **Policy**, **Subdomains** (the `sp=` policy, or "same as the domain"), **Applied to** (the `pct=` share of mail, 100% when not set), **Reports go to** (the `rua=` addresses), **Failure reports go to** (the `ruf=` addresses, only when set) and **Alignment** for SPF and DKIM, **relaxed** or **strict** (relaxed when not set).
- The notes of the DNS check, for example the advice to use a stricter policy.

Without a record, it says **No DMARC record at _dmarc.<domain>.**

Below, two lines say how much of the domain's mail is aligned with SPF and whether it is signed with DKIM.

**Policy** offers **None**, **Quarantine** and **Reject**, each with what it does. **Now** marks the policy in place, and the next stricter one is picked when the window opens. Pick a policy to see what it would change:

- **Ready.** means that every sender group passing DMARC on most of its mail passes on 95% or more. Senders that fail on most of their mail are treated as not yours. **Not yet.** means such a group passes on under 95%, or no group passes on most of its mail. Without mail in the last 30 days, it says **No data.** Review known senders before changing policy.
- How many messages receivers would have sent to spam or refused in the last 30 days with that policy: every message that failed DMARC, from any sender.
- The record to publish, with **Copy**: your current record with only `p=` changed, so all its other tags stay, for example `_dmarc.example.com  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com; adkim=s"`. Without a record, it is `v=DMARC1; p=<policy>; rua=mailto:dmarc@<domain>`.

### SPF and DKIM

How much of the domain's mail passed SPF, or was signed with DKIM, in the last 30 days, and a table of the senders with their share, the weakest first. A sender of yours under 95% is missing from the SPF record or does not sign as your domain; a sender that is not yours should fail. Click a sender to open it.

### TLS-RPT record

With a record: the record with **Copy**, where reports go, and any warnings, for example a report address that is not `mailto:` or `https:`. Without one: a record to publish, with the address of the report mailbox this page reads, so the reports show up here. When IMAP is not set up, it suggests `tls-reports@<domain>`.

## A sender

![A sender that fails DMARC](../../images/docs/dmarc-sender-light.webp#gh-light-mode-only)
![A sender that fails DMARC](../../images/docs/dmarc-sender-dark.webp#gh-dark-mode-only)

The sender's name, its city, country and network, and a tag: **Fails DMARC** (it failed for more than half of its mail), **Passes on DKIM only** or **Passes**.

A failing sender has a box that says what receivers did with its mail (delivered, sent to spam or refused, depending on your policy) and what to do: if you know the sender (a CRM, a newsletter tool, a scanner), set up SPF or DKIM for it; if you do not, someone is sending as you, and a stricter policy stops it.

**Last 30 days** shows **Messages**, **Passed DMARC**, **SPF aligned**, **DKIM aligned** and **Addresses**. **What receivers saw** has a row per address, envelope sender and receiver: **Address**, **From** (the header From domain), **Envelope from**, **Messages**, **SPF** and **DKIM** (**Aligned**, or the result the receiver reported, such as `fail`) and **Reported by**.

## A day of reports

What the receivers reported for one day. **That day** shows **Messages**, **Passed DMARC**, **SPF aligned**, **DKIM aligned** and **Reported by**. **Who sent that day** has a row per sender and address, with the envelope sender, the rates and the receiver; click a row to open the sender. **Other days** shows the domain's chart.

## A day of TLS reports

What the receivers reported about encrypted delivery to the domain on one day. **That day** shows **Sessions**, **Encrypted**, **Failed** and **Receivers reporting**. **Who reported** has a row per receiver: its contact, the **Policy** it applied (`STS` for MTA-STS, `TLSA` for DANE, or `NO-POLICY-FOUND`), the **MX** hosts, **Sessions**, **Failed** and **Encrypted**. Each kind of failure has its own line with the number of sessions and the MX host, for example `certificate-expired: 3 sessions to mail.example.com`.

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

**View History** opens **Fetch history**, the last 20 imports: **Date**, **Type** (`auto` or `manual`), **Status** (`success`, `error`, `running` or `failed`), **Emails**, **Created**, **Duplicate**, **Failed** and **Duration**. An import whose connection failed has the status `error`. An import that finished with some failed emails has the status `success` and a number under **Failed**.

## Uploading a report

**Upload Report** imports one file:

- DMARC: a plain `.xml` file, a gzip file (`.xml.gz`) or a ZIP that holds the XML.
- TLS: `.json`, `.json.gz`, or a ZIP that holds the JSON, whatever its name.

The file may be at most 10 MB and must expand to 10 MB or less. The app tells XML, gzip and ZIP apart by their content, not by the file name.

Upload results give the record or policy count, identify duplicates, or show **Failed to upload report**. Successful imports reload the page.

Upload is allowed by default. Turn it off with **Manual Upload Enabled** under **Settings** > **DMARC & TLS**; the button then disappears.

## Manage Reports

![Manage Reports](../../images/docs/dmarc-manage-reports-light.webp#gh-light-mode-only)
![Manage Reports](../../images/docs/dmarc-manage-reports-dark.webp#gh-dark-mode-only)

**Manage Reports** opens a window with two lists.

**Reports by domain** lists **Domain**, **DMARC reports**, **TLS reports** and **Last report** (latest period end). Headers sort. **Delete all** confirms counts before removing that domain's reports.

**All reports** lists every report, newest import first, 50 to a page: **Import Date**, **Type** (`DMARC` or `TLS`), **Domain**, **Reporter** (the organization that sent the report), **Records** and **Period**. **Delete** removes a single report. The search finds reports by domain or reporter, and the total counts the matches. A click on a column header sorts the whole list by it, across all pages; a second click turns the order around.

Deletion defaults off; **Deleting reports is off** links to **Open Settings**. Enable **Allow Report Delete** under **Settings** > **DMARC & TLS** (`DMARC_ALLOW_REPORT_DELETE=true`). Deletion cannot be undone. New reports can recreate a deleted domain's entry.

## How long reports are kept

Every day at 02:15 the app deletes DMARC and TLS reports that were imported more than **Retention Days** ago (60 by default, under **Settings** > **DMARC & TLS**). The age counts from the import, not from the report's period.

## Emails from this page

- **Import errors.** When an import leaves messages it could not import, the app sends `DMARC & TLS: N report emails could not be imported`, with the subject, Message-ID and error of each message. It goes to **Report Import Error Email**, or the **Admin Email** when that is empty (both under **Settings** > **Notifications**), and to the notification destinations that receive **DMARC processing errors**. Email needs SMTP; the other notification destinations receive the alert without it. Skipped bounces do not trigger it.
- **The weekly summary** has no figures from the reports. Its **DNS issues** section lists DMARC records with an error, from the DNS checks. See [Domains](Domains.md#the-weekly-summary).
- **DNS change alerts** cover the DMARC and TLS-RPT records. See [Domains](Domains.md#dns-change-alerts).

See [Notifications](../Notifications.md) for the destinations.

## Elsewhere in the app

The **DMARC & TLS** entry in the menu shows a count: the domains whose reports suggest a stricter policy, show a low pass rate, or show new addresses that fail DMARC. The Dashboard lists the same under its items that need attention. Both use the settings under **Insights (policy recommendations)**.

## Addresses

Each screen has its own address, so it can be bookmarked, shared and reached with Back:

| Address | Opens |
|---|---|
| `/dmarc` | All domains |
| `/dmarc/example.com` | A domain |
| `/dmarc/example.com/source/192.0.2.10` | A sender, by one of its addresses |
| `/dmarc/example.com/report/2026-10-01` | A day of DMARC reports |
| `/dmarc/tls/example.com/2026-10-01` | A day of TLS reports |

Older addresses keep working: `/dmarc/tls` opens all domains, and `/dmarc/tls/example.com`, `/dmarc/example.com/reports`, `/dmarc/example.com/sources` and `/dmarc/example.com/tls` open the domain.

## Settings that change this page

The sections above describe import, upload, deletion and retention settings. [Settings](Settings.md) and [environment variables](../ENV_Settings.md) list their full controls.

- **Settings** > **DMARC & TLS** > **Insights (policy recommendations)**: **DMARC Insights Window Days** (28), **DMARC Insights Pass Threshold** (99.5%) and **DMARC Insights Min Volume** (100). These change sidebar and Dashboard advice; the main report views still use 30 days.
- **Settings** > **DMARC & TLS IMAP**: **IMAP Enabled** is off by default. Connection defaults are port 993, SSL on and **IMAP Verify SSL** off. **Test IMAP** checks the connection.
- **Settings** > **Notifications**: **Report Import Error Email** accepts comma-separated addresses and falls back to **Admin Email**.
- **Settings** > **Features** > **DMARC & TLS** controls the page, import and cleanup.

## When something is missing

- The page is not in the menu: the DMARC & TLS feature is off. Turn it on under **Settings** > **Features**. While it is off, the import and the daily cleanup do not run.
- **No reports yet**: nothing has been imported. Check that your DMARC records have a `rua=` address that ends up in the report mailbox, that IMAP is set up, and that the address may receive reports for the domain (see [Receiving reports at another domain](#receiving-reports-at-another-domain)). Receivers send aggregate reports about once a day, so the first ones take a day or two.
- A domain says it has no TLS reports: it has no TLS-RPT record, or no server has sent mail to it with TLS reporting turned on yet. The TLS-RPT record window shows a record to publish.
- **Fetch reports** is greyed out with **Not set up** under it: IMAP is not set up. **Set up IMAP** opens **Settings** > **DMARC & TLS IMAP**.
- **Last fetch failed**: the import could not connect or log in. **View History** shows the import; the error is in the app's log. A certificate problem names the setting to change (**IMAP Verify SSL**).
- There is no **Upload Report** button: manual upload is off.
- There is no **Manage Reports** button: there are no reports.
- **No location or network known** on a sender: the MaxMind databases are not set up, or the address is not in them.
- **Could not load this**: a request to the app failed. Try again in a moment.

## How DMARC works

DMARC connects authentication to the visible `From:` domain. SPF checks the connecting IP against the envelope sender domain; DKIM checks a signature from its `d=` domain. DMARC passes when at least one passes and is **aligned** with From.

Relaxed alignment (`aspf=r` and `adkim=r`, the defaults) accepts the same organizational domain. For example, `bounces.example.com` aligns with `example.com`. Strict alignment (`s`) needs an exact domain match. Forwarding can break SPF while a surviving aligned DKIM signature still passes DMARC.

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

Receivers usually send daily XML reports, often compressed. They list sending IPs, message counts, authentication and alignment results, and dispositions. They contain no message content. Missing reports do not prove that no mail was sent.

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

Sidebar and Dashboard advice uses **Insights (policy recommendations)**. Defaults suggest a stricter policy after at least 99.5% of 100 or more messages pass over 28 days, and warn below 90%. The record window's separate **Ready.** calculation is described [above](#dmarc-record).

## How TLS-RPT and MTA-STS work

Opportunistic STARTTLS can fall back to plain text and is vulnerable to downgrade attacks. MTA-STS and DANE require encrypted delivery for supporting senders. TLS-RPT reports delivery failures.

### TLS-RPT

TLS-RPT (RFC 8460) asks sending servers to send a daily report about their connections to your MX hosts: how many sessions were encrypted, how many failed and why, for example an expired certificate or a host name that does not match. The record is a TXT record at `_smtp._tls`:

```text
_smtp._tls.example.com.  TXT  "v=TLSRPTv1; rua=mailto:dmarc-reports@example.com"
```

- Use the report mailbox of this page; the same import reads DMARC and TLS reports.
- Senders deliver reports only to `mailto:` and `https:` addresses.
- Publish exactly one record. With more than one, senders ignore them.

A report names the policy the sender applied: `sts` for MTA-STS, `tlsa` for DANE, or `no-policy-found` when the domain has neither. The reports matter most with MTA-STS in `enforce` mode or DANE, where a TLS failure means the mail is not delivered.

### MTA-STS

Start MTA-STS in `testing`, review TLS reports, then use `enforce` when legitimate delivery works. For records, policy syntax and certificate requirements, see [Domains](Domains.md#the-mta-sts-policy).
