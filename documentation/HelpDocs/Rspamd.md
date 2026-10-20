# Rspamd

The Rspamd maps that allow or block mail, incoming and outgoing. They are read from Rspamd and saved through mailcow's API.

![Rspamd, the maps](../../images/docs/rspamd-maps-light.webp#gh-light-mode-only)
![Rspamd, the maps](../../images/docs/rspamd-maps-dark.webp#gh-dark-mode-only)

Header-From and envelope-sender denylists add 2050 to the spam score; their allowlists subtract 2050. Recipient Denylist rejects matching recipients; Recipient Allowlist accepts them. Fishy TLDs and bad-word rules fire only together. Monitoring Hosts excludes matching hosts from logging.

**Auto-managed** on Recipient Denylist means the suppression list on [Outbound](Outbound.md#suppressions) writes to it. **Open in Rspamd**, in the **⋯** menu of **Suppressions**, opens this map.

## Edit a map

![Map editor for Recipient Denylist](../../images/docs/rspamd-map-editor-light.webp#gh-light-mode-only)
![Map editor for Recipient Denylist](../../images/docs/rspamd-map-editor-dark.webp#gh-dark-mode-only)

Lines starting with `#` are comments; blank lines do not count as entries. Validation checks slash-delimited regular expressions and warns about bare addresses. Other lines, including words, domains, header patterns and language codes, are accepted as entered.

Saving refuses invalid patterns, anchors bare addresses and writes the whole map through mailcow. Rspamd reloads it. **Discard** reloads from Rspamd. The editor does not refresh automatically while you edit.

> [!NOTE]
> In **Recipient Denylist**, the lines between `# === MANAGED BY MAILCOW LOGS VIEWER - DO NOT EDIT BELOW ===` and `# === END MANAGED SECTION ===` are the suppression list. An entry you add or delete there is added to or deleted from the list on the next read. Keep each marker line once.

## Regex Wizard

The wizard's **Domain** pattern includes subdomains, unlike a domain suppression. Its explanation says "Blocks", but the map determines the effect: the same pattern in an allowlist allows matching mail.

## Settings that change this page

Under **Settings** > **Mailcow**, set **Rspamd Password** to read the maps. Leave **Rspamd URL** empty to use mailcow's path; try a direct URL such as `http://rspamd-mailcow:11334` if that fails.

Under **Settings** > **Features**, **Rspamd** turns this page off. The old name `spam-filter` in `DISABLED_FEATURES` turns off both this page and Suppressions.

## When something is missing

- **No Rspamd password**: the maps cannot load.
- **No read-write API key**: the maps are read-only. See [Getting started](../GETTING_STARTED.md).
- **Rspamd cannot be reached**: check the application logs, password and **Rspamd URL**.

## How Rspamd maps work

Maps provide values for mail-filtering rules. In a regular-expression map, each line matches anywhere in the value: bare `ann@example.com` also matches `joann@example.com`. The app writes `/^ann@example\.com$/i` instead: `^` and `$` anchor the full value, and `i` ignores case.
