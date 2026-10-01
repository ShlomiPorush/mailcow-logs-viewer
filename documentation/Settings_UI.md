# Editing settings from the web UI

You can manage most application settings from the **Settings** tab in the web UI instead of (or in addition to) using environment variables.

## Enable the feature

Set in your `.env`:

```env
SETTINGS_EDIT_VIA_UI_ENABLED=true
```

Restart the application. The Settings tab will then show an **Edit configuration** section.

## First step: migrate settings from ENV

The first time you open it, the form is read-only and the section shows a **Migrate Settings from ENV** button instead of **Save changes**. Click it once: it copies the current effective configuration (defaults + ENV) into the database. The form then becomes editable and the **Save changes** button appears.

You only do this once. After that, you can remove ENV variables and manage those settings from the UI.

## Priority order

Configuration is resolved in this order (later overrides earlier):

1. **Defaults** (from the application)
2. **DB** (values stored via the web UI)
3. **ENV** (environment variables — **always win** when set)

So: ENV overrides DB, and DB overrides defaults. If an environment variable is explicitly set, it takes precedence over the value stored in the database. This prevents lockout: if you make a configuration mistake in the UI, you can always fix it by setting the correct value in your `.env` / `docker-compose.yml` and restarting.

Fields where an ENV variable is active are marked with a 🔒 lock icon and cannot be edited in the UI. To manage such a setting from the UI, remove its ENV variable and restart the application.

## Lockout recovery

If you accidentally lock yourself out (e.g., wrong OIDC URL or password typo):

1. Set the correct value in your `.env` file or `docker-compose.yml`
2. Restart the application (`docker compose up -d`)
3. The ENV value will override the bad DB value and restore access

## What can be edited

All settings are editable from the UI **except** database connection settings (`POSTGRES_*`). Those must stay in ENV.

Sensitive fields (passwords, API key, etc.) are shown as masked in the form. Leave the field empty to keep the current value; enter a new value only when you want to change it.

## Scheduler / intervals

Changes to **fetch interval**, **correlation check interval**, **DMARC & TLS IMAP interval**, and **scheduler workers** take effect immediately after you save. The application reschedules the relevant background jobs and updates the thread pool without requiring a restart.

## Disabling UI editing

Set `SETTINGS_EDIT_VIA_UI_ENABLED=false` (or remove it) and restart. The Edit configuration section will disappear and all configuration will again come only from ENV/defaults.
