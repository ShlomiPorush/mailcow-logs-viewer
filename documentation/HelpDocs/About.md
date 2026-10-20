# About

![About](../../images/docs/about-page-light.webp#gh-light-mode-only)
![About](../../images/docs/about-page-dark.webp#gh-dark-mode-only)

## What the app relies on

**Configured** on **Read-write API key** and **Rspamd** only means a key or password is saved; use **Validate** beside each credential under [Settings > Mailcow](Settings.md#mailcow) to check whether mailcow or Rspamd accepts it. **Unknown** on a card means the app could not check it.

**Open** on **Sign-in** means anyone who can reach the app can see everything in it and use its actions. Set up sign-in before you make the app reachable from outside; see [Sign-in configuration](../OAuth2_Configuration.md).

## Version

The app checks the project's releases on GitHub every 6 hours; **Check Now** checks at once. Checking does not install anything; see [Updating](../GETTING_STARTED.md#updating).

When GitHub cannot be reached, **Latest Version** shows **Not known** with **Check failed**, the Dashboard's **This app** card says **Update check failed**, and **Check App Version** under **Status** > **Jobs** shows the error. The rest of the app works as usual. Check that the app can reach `api.github.com`, then use **Check Now**.

## Configuration

**Server IP** is the public IPv4 address mailcow reports for itself, or **Not available** until the app has read it.
