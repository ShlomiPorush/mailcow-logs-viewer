# About

**About** shows whether everything the app relies on is working, how sign-in is set up and which version is running. Version information comes from the project's releases on GitHub.

![About](../../images/docs/about-page-light.webp#gh-light-mode-only)
![About](../../images/docs/about-page-dark.webp#gh-dark-mode-only)

## What the app relies on

Each card shows a state and a short line on what it means. Every card except **Database** has a **Settings** button that opens the matching category.

| Card | States | Notes |
| --- | --- | --- |
| **Database** | **Connected**, **Not connected** | Shows the PostgreSQL version. |
| **mailcow API** | **Connected**, **Not connected** | Shows the mailcow URL the app reads. |
| **Read-write API key** | **Configured**, **Not configured** | **Configured** only means a key is saved. The **Mailcow** category of [Settings](Settings.md#mailcow) shows whether mailcow accepts it. |
| **Email alerts (SMTP)** | **Configured**, **Not set up** | When configured, **Test SMTP** sends a test email. |
| **Report mailbox (IMAP)** | **Collecting**, **Not set up** | When collecting, **Test IMAP** checks the connection and the folder. |
| **MaxMind GeoIP** | **Working**, **License invalid**, **Database damaged**, **Not set up** | A failure says what MaxMind or the database reported. |
| **Rspamd** | **Configured**, **Not set up** | **Configured** means the Rspamd password is saved. |
| **Sign-in** | **Required**, **Open** | Names the Basic Auth user or the OAuth2 provider. |

**Unknown** on a card means the app could not check it. **Open** means anyone who can reach the app can see everything in it and use its actions; set up sign-in before you make the app reachable from outside. See [Sign-in configuration](../OAuth2_Configuration.md).

## Version

**Current Version** opens the release notes of the version you run. **Latest Version** shows the newest release, tagged **Up to Date** or **Update Available**, or **Not known** tagged **Check failed** when GitHub could not be reached. The app checks every 6 hours; **Check Now** checks at once and updates **Last checked**.

When an update is out, the panel shows its release notes and a **View release notes** link. Checking does not install anything; see [Updating](../GETTING_STARTED.md#updating).

## Configuration

**mailcow URL** is the mailcow server the app reads. **Server IP** is the public IPv4 address mailcow reports for itself, or **Not available** until the app has read it.

## When something is missing

- **Failed to load the app information. Refresh the page to try again.** The app could not load this page's data. Refresh; if it keeps failing, check the app's log with **View Container Logs**.
- **The version check fails.** When GitHub cannot be reached, **Latest Version** shows **Not known** with **Check failed**, the Dashboard's **This app** card says **Update check failed**, and **Check App Version** under **Status** > **Jobs** shows the error. The rest of the app works as usual. Check that the app can reach `api.github.com`, then use **Check Now**.
