# Mailbox Statistics - User Guide

## Overview

This page provides a comprehensive dashboard for monitoring mailbox usage, traffic patterns etc.

### Summary Cards
The top section displays aggregated metrics for **all mailboxes** matching your current filters:
*   **MESSAGES SENT**: Total emails sent outbound.
*   **MESSAGES RECEIVED**: Total emails received inbound.
*   **FAILED**: Total messages that failed delivery (Bounced or Rejected).
*   **FAILURE RATE**: The percentage of sent messages that failed.

> **Note**: These numbers represent traffic processed by the system during the selected date range.

### Search & Filtering Toolbar
Use the toolbar to drill down into specific data:
1.  **Search**: Filter by email address, username, or alias.
2.  **Date Range**: Select a preset (Today, 7 Days, 30 Days) or define a custom range.
3.  **Domain**: Filter to show mailboxes from a specific domain only.
4.  **Sort**: Order the list by Sent count, Quota usage, Failure rate, etc.
5.  **Toggles**:
    *   **Active Only**: Hides deleted mailboxes that still have historical data.
    *   **Hide Zero Activity**: Hides mailboxes with no sent/received traffic in the selected period.

## 📧 Mailbox List

The list displays mailboxes in an expandable "accordion" view.

### Quick View (Collapsed)
Each row provides an immediate snapshot:
*   **Identity**: Mailbox address and status (Active/Inactive).
*   **Traffic Badges**:
    *   **Sent**: Total sent.
    *   **Received**: Total received.
    *   **Delivered**: Successfully delivered.
    *   **Failed**: Failed deliveries.
*   **Usage**: Detailed on the right side:
    *   **Aliases**: Count of linked alias addresses.
    *   **Storage**: Current storage usage (e.g., 10.4 KB).

### Detailed View (Expanded)
Clicking a row reveals comprehensive details split into three sections:

#### 1. Mailbox Status & Configuration
Synced directly from Mailcow (every 5 minutes):
*   **Quota**: Usage vs. Limit (e.g., 10.4 KB / 1.0 GB).
*   **Messages**: Current count of messages stored in the mailbox.
*   **Timestamps**: Created date, Modified date, and Last Login times for IMAP/SMTP/POP3.
*   **Permissions**: Color-coded status for protocols (IMAP, POP3, SMTP, Sieve, TLS Enforce).
    *   🟢 Green: Enabled/Active (may show last access time).
    *   🔴 Red: Disabled/Inactive.
    *   ⚪ Grey: Never accessed.

#### 2. Message Statistics (Traffic)
Colored cards showing the breakdown of message flow.
**✨ Interactive:** Click any card to jump to the **Messages** page filtered for those specific emails.

*   **Sent** (Blue): Total messages sent by this mailbox.
*   **Received** (Purple): Total messages received.
*   **Internal** (Teal): Messages sent internally between local domains.
*   **Delivered** (Green): Messages successfully handed off to the next hop.
*   **Deferred** (Yellow): Temporary failures (server will retry).
*   **Bounced** (Orange): Permanent failures (e.g., invalid recipient).
*   **Rejected** (Red): Blocked messages (e.g., policy violation, spam).

#### 3. Aliases Breakdown
A table listing all aliases associated with the mailbox, breaking down traffic per alias.
*   Columns: Sent, Received, Internal, Delivered, Deferred, Bounced, Rejected.
*   **Interactive**: Click the numbers to view the specific logs for that alias.

---

## ℹ️ Technical Notes

### How is data counted?
*   **Traffic Data** (Sent, Received, Failed, etc.): Aggregated locally from the **MessageCorrelation** table. This means it reflects logs processed by this viewer, offering historical data even if logs are rotated on the mail server. It is strictly tied to the selected **Date Range**.
*   **Mailbox Status** (Quota, Permissions, Login Times): Fetched directly from the **Mailcow API** via a background job running every 5 minutes. This data reflects the *current state* on the server.

### "Internal" vs "Sent"
*   **Sent**: Includes all outbound traffic.
*   **Internal**: A subset of "Sent". Refers to emails where both sender and recipient are hosted on this local system.

### Data Accuracy
*   Since traffic stats are based on logs, if the log retention period (e.g., 7 days) is shorter than your selected date range (e.g., 30 days), the older stats might be partial.
*   Quota and "Messages in Mailbox" are real-time values from the server and are not affected by the date range filter.
