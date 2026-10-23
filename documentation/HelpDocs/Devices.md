# Devices

**Devices** lists the phones, tablets and Outlook clients that sync with your mailcow server over ActiveSync. The app finds them in the SOGo log, which it reads through the mailcow API, and updates the list every minute. **Not checked yet** next to the title appears for about a minute after the app starts.

![Devices](../../images/docs/devices-list-light.webp#gh-light-mode-only)
![Devices](../../images/docs/devices-list-dark.webp#gh-dark-mode-only)

## Find a device

Search matches the user, device ID, device type and IP address. **New this week** in the **Last seen** filter means first recorded by this app in the last 7 days. The list starts with the most recent **Last seen** first.

## Read the list

| Column | What it means |
| --- | --- |
| **Device** | The reported type (for Samsung, the model, such as `SM-S918B`) and the mail app, when recognized. Hover for the device ID. **New**: first seen in the last 7 days. |
| **Last IP** | The address of the latest request, with country and city when GeoIP is set up. Hover the place for the network. |
| **Last request** | The latest ActiveSync command, such as `Ping`, `Sync`, `FolderSync` or `SendMail`, with a tag when it failed. |
| **First seen** | The earliest request this app recorded, which can be later than the day the device was set up. |
| **Last seen** | The latest recorded request, grayed out after 30 days. |

The app recognizes Outlook, Windows Mail, Apple Mail, Samsung Email and Gmail by the way they name the device. **Gmail** can also be another Android mail app that names devices the same way. Other apps get no label.

**Sign-in failed** means SOGo answered the last request with HTTP 401, **Refused** with 403, and **Error** plus the code for any other error. For a failed sign-in, check the password stored on the device and the SOGo log.

## Settings that change this page

**Retention Days** under **Settings** > **Devices** removes a device when its last request is older than that many days. The default is 90; `0` keeps devices forever. The cleanup runs daily at 03:30.

Country, city and network need the MaxMind keys under **Settings** > **MaxMind**. Without the GeoIP databases, **Location needs GeoIP** appears above the list.

Turning off **Devices** under **Settings** > **Features** hides the page, stops the updates and deletes the list. When you turn it on again, the app rebuilds the list from the SOGo log lines it still has; those are kept for **Raw Logs Retention Days** under **Settings** > **Logs**, 2 days by default. While Devices is on, the app collects the SOGo log even if the Logs page is off or SOGo is unticked there.

## When something is missing

**No ActiveSync devices yet** means no ActiveSync request has been recorded. Devices that use only IMAP, CalDAV or CardDAV never appear. Clients that send their requests in ActiveSync's encoded form have no user name in the log line and cannot be listed.

**The last check failed** next to the title means the update job failed: open [Status](Status.md#jobs) > **Jobs** and look at **ActiveSync Devices**.

## How ActiveSync works

Exchange ActiveSync is the protocol phones and Outlook use to sync mail, calendars and contacts. In mailcow, SOGo answers it at `/Microsoft-Server-ActiveSync`. This page only reads the log; it cannot remove or wipe a device.

A device keeps a `Ping` request open and waits for changes, in mailcow for up to almost an hour. SOGo writes the log line when the request ends, so a connected device can show a **Last seen** close to an hour old. The log has no device name or operating system version.
