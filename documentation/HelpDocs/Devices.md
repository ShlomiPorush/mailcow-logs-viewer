# Devices - User Guide

## Overview

The Devices page lists the phones, tablets and Outlook clients that sync mail, calendars and contacts with your server over **ActiveSync** (Exchange ActiveSync, served by SOGo in mailcow).

The list is built from the SOGo log, which the app reads through the mailcow API once a minute. Nothing is installed on the devices and nothing is changed in mailcow.

> **Note**: A device that syncs over IMAP, CalDAV or CardDAV does not use ActiveSync and is not listed here.

### Search & Filtering
1.  **Search**: User, device ID, device type or IP address.
2.  **Device type**: The type the device reports, such as `iPhone`, `iPad`, `Outlook` or a phone model.
3.  **Last seen**: Seen in 24 hours, new this week (first seen in the last 7 days), or not seen for 30 days, for example a replaced phone.

Click a column heading to sort by it.

## The List

*   **User**: The account the device signs in with.
*   **Device**: The device type and its ActiveSync device ID. A **New** tag marks a device first seen in the last 7 days.
*   **Last IP**: The address of the newest request, with its country and city. Hover the location to see the network (provider) it belongs to. The location needs the MaxMind GeoIP databases (Settings → MaxMind).
*   **Last request**: The newest ActiveSync command (`Ping`, `Sync`, `FolderSync`, `SendMail` ...). **Sign-in failed** means SOGo refused the password, which usually means the device still has an old password.
*   **First seen / Last seen**: Hover to see the exact time.

## Good to Know

*   **Last seen can be up to an hour old on a connected phone.** A phone waits for new mail with a long `Ping` request, and SOGo writes it to the log only when it ends. In mailcow that can take up to 59 minutes.
*   **First seen** is the first request this app saw, not the day the device was set up. Devices that synced before the app was installed show the day the app first read their requests.
*   A request in the older, encoded form of the protocol does not include the user name, so it cannot be listed. Current iOS, Android and Outlook clients use the plain form.
*   On a very busy server a single request can be missed. The device appears with its next request.

## Settings

*   **Settings → Devices → Retention Days** (`EAS_DEVICES_RETENTION_DAYS`): how long a device that stopped syncing is kept. Default 90 days. `0` keeps every device.
*   **Settings → Features**: turn the Devices page off. Its data is deleted when you do.
