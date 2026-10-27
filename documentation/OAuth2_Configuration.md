# Sign-in configuration

The app can ask for a username and password (Basic authentication), send users to an identity provider (OAuth2/OIDC), or offer both. You set this up in **Settings** > **Authentication** or with environment variables.

> [!WARNING]
> Everyone who signs in can see everything and use every action the app's mailcow API keys allow. The app has no user roles and no list of allowed OAuth2 users, so limit who can use the app at your identity provider.

## Basic authentication

Add these lines to `.env` and run `docker compose up -d`:

```dotenv
BASIC_AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_PASSWORD=replace-with-a-long-random-password
```

To set it up in the app instead, fill in **Auth Username** and **Auth Password** in **Settings** > **Authentication**, turn on **Basic Auth Enabled** and save. The app asks you to type the username and password again, so you cannot lock yourself out with a typo, and it does not let you clear the password while Basic authentication is on.

Scripts and API clients can send an `Authorization: Basic` header with every request instead of signing in.

![Login page](../images/docs/authentication-login-light.webp#gh-light-mode-only)
![Login page](../images/docs/authentication-login-dark.webp#gh-dark-mode-only)

After 10 failed attempts within 15 minutes, the app refuses further Basic sign-in attempts from that address ("Too many login attempts") until the oldest failures are more than 15 minutes old. IPv6 addresses are counted per `/64` network. Users who are already signed in are not affected.

Behind a reverse proxy, the app must know the real visitor address, or all visitors share one counter. See [Reverse proxy](Reverse_Proxy.md). **Auth Max Failure Clients** (`AUTH_MAX_FAILURE_CLIENTS`, default 10,000) caps how many addresses the app tracks.

## OAuth2/OIDC

1. At your identity provider, register a confidential web client (one with a client secret) that uses the authorization code flow. Set its redirect or callback URL to your app address followed by `/api/auth/callback`, for example `https://logs.example.com/api/auth/callback`.
2. Copy the client ID and the client secret.
3. Generate a session secret with `openssl rand -hex 32`.
4. Add the lines below to `.env`, plus the provider lines from one of the [recipes](#provider-recipes).
5. Run `docker compose up -d`. The login page now shows a **Login with** button with your provider name.

```dotenv
OAUTH2_ENABLED=true
OAUTH2_PROVIDER_NAME=Company sign-in
OAUTH2_CLIENT_ID=replace-with-client-id
OAUTH2_CLIENT_SECRET=replace-with-client-secret
OAUTH2_REDIRECT_URI=https://logs.example.com/api/auth/callback
OAUTH2_SCOPES=openid profile email
SESSION_SECRET_KEY=replace-with-the-generated-secret
SESSION_EXPIRY_HOURS=24
```

The app uses PKCE (`S256`) on every login and sends the client secret when it exchanges the code. After sign-in it reads the user's details from the provider's UserInfo endpoint, so the access token must be allowed to call it.

### Discovery or manual endpoints

With discovery on (the default), set `OAUTH2_ISSUER_URL` to the base address of the provider. The app adds `/.well-known/openid-configuration` and reads the three endpoints from there, so do not include that part yourself:

```dotenv
OAUTH2_USE_OIDC_DISCOVERY=true
OAUTH2_ISSUER_URL=https://identity.example.com
```

If the provider has no discovery document, turn discovery off and set the three endpoints:

```dotenv
OAUTH2_USE_OIDC_DISCOVERY=false
OAUTH2_AUTHORIZATION_URL=https://identity.example.com/oauth/authorize
OAUTH2_TOKEN_URL=https://identity.example.com/oauth/token
OAUTH2_USERINFO_URL=https://identity.example.com/oauth/userinfo
```

If discovery fails and all three endpoints are set, the app uses them.

## Provider recipes

### Authentik

Create an OAuth2/OIDC provider (confidential client, your callback URL, the `openid`, `profile` and `email` scope mappings) and an application that uses it. Bind a policy or group to the application so only mail administrators can use it. See [Authentik's provider setup](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/create-oauth2-provider).

```dotenv
OAUTH2_PROVIDER_NAME=Authentik
OAUTH2_USE_OIDC_DISCOVERY=true
OAUTH2_ISSUER_URL=https://identity.example.com/application/o/mailcow-logs-viewer/
OAUTH2_SCOPES=openid profile email
```

Replace `mailcow-logs-viewer` with your application's slug. See [Authentik's OAuth2 endpoints](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/).

### mailcow

<!-- VERIFY: Test this manual-endpoint recipe against the supported mailcow release, including which mailbox or administrator accounts can authorize the client. Provider implementation is outside this checkout. -->
Add an OAuth2 client in mailcow with your callback URL, then use these lines:

```dotenv
OAUTH2_PROVIDER_NAME=mailcow
OAUTH2_USE_OIDC_DISCOVERY=false
OAUTH2_AUTHORIZATION_URL=https://mail.example.com/oauth/authorize
OAUTH2_TOKEN_URL=https://mail.example.com/oauth/token
OAUTH2_USERINFO_URL=https://mail.example.com/oauth/profile
OAUTH2_SCOPES=profile
```

Do not assume that only mailcow administrators can sign in this way. If you cannot limit who uses this client, choose a provider with access control or use Basic authentication.

### Keycloak

Create an OpenID Connect client in the realm, turn on client authentication and the standard (authorization code) flow, add your callback URL and copy the client secret. To keep other users out, use an authentication flow or policy that denies them; a role on its own does nothing here, because the app does not check roles.

```dotenv
OAUTH2_PROVIDER_NAME=Keycloak
OAUTH2_USE_OIDC_DISCOVERY=true
OAUTH2_ISSUER_URL=https://identity.example.com/realms/mail-admin
OAUTH2_SCOPES=openid profile email
```

Replace `mail-admin` with your realm. See [Keycloak's OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers).

### Google

Create an OAuth client of type web application, add your callback URL and copy the client ID and secret. See [Google's OpenID Connect setup](https://developers.google.com/identity/openid-connect/openid-connect).

```dotenv
OAUTH2_PROVIDER_NAME=Google
OAUTH2_USE_OIDC_DISCOVERY=true
OAUTH2_ISSUER_URL=https://accounts.google.com
OAUTH2_SCOPES=openid profile email
```

Limit access at Google. Even an internal audience usually includes more people than your mail administrators, and the app does not check groups or email domains.

### Microsoft Entra ID

Register a single-tenant web application with your callback URL and create a client secret. In the enterprise application, turn on assignment required and assign the users who may sign in. See [Microsoft's OIDC documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc).

```dotenv
OAUTH2_PROVIDER_NAME=Microsoft
OAUTH2_USE_OIDC_DISCOVERY=true
OAUTH2_ISSUER_URL=https://login.microsoftonline.com/replace-with-tenant-id/v2.0
OAUTH2_SCOPES=openid profile email
```

Use your own tenant ID. Do not use the shared multi-tenant address unless you limit who can use the client some other way.

## Sessions and signing out

Both sign-in methods give the browser a cookie named `session_id` (`HttpOnly`, `SameSite=Lax`). The cookie is marked `Secure` when the request came over HTTPS, directly or through a proxy that sends `X-Forwarded-Proto: https`. Use HTTPS for anything outside a private network.

- A session lasts at most **Longest session** (`SESSION_EXPIRY_HOURS`, default 24), counted from sign-in whatever the activity. Five minutes before, the page says so. A shorter value applies to open sessions at once; a longer one from the next sign-in.
- **Sign out after inactivity** (`SESSION_IDLE_ENABLED`, off by default) ends a session after **Inactivity limit** minutes without activity (`SESSION_IDLE_TIMEOUT_MINUTES`, default 60, from 5 to 1440). Typing, clicking, scrolling with the wheel and touching count as activity; pages that refresh by themselves do not, so a dashboard left open on a screen is signed out too. A minute before, the page asks whether you are still there. Turning it on does not sign out people who are already signed in: their inactivity time starts then.
- After a session ends this way, the login page says why. Both limits apply to Basic Auth and OAuth2 sign-ins alike. AI agents and API calls with a username and password are not affected.
- Sessions are kept in memory, so every restart of the app signs everyone out.
- **Session Max Entries** (`SESSION_MAX_ENTRIES`, default 50) caps open sessions. When it is reached, existing sessions keep working and new sign-ins fail with "Login capacity reached" until a session expires or someone signs out.
- **Logout** ends the session in this app only. It does not sign you out of your identity provider.
- Saving a change to the sign-in settings signs everyone out. The person who saved gets a new session and stays signed in.

## Apply changes and recover access

A variable set in `.env` always wins over the value saved in the app. After you change `.env`, run `docker compose up -d`. Changes saved in **Settings** apply right away.

If you lock yourself out:

1. Add `BASIC_AUTH_ENABLED=true`, `AUTH_USERNAME` and `AUTH_PASSWORD` to `.env`.
2. Run `docker compose up -d` and sign in with those values.
3. Fix the sign-in settings in **Settings** > **Authentication**.
4. Remove the lines from `.env` again and run `docker compose up -d`.

## When sign-in fails

| Problem | What to check |
| --- | --- |
| No **Login with** button | `OAUTH2_ENABLED` and the values in **Settings** > **Authentication**. **About** shows whether sign-in is required. |
| The provider button fails at once | The issuer URL (the app adds `/.well-known/openid-configuration`), network access from the app to the provider, and the provider's certificate. The reason is in the app's log. |
| The provider rejects the callback | The callback URL must be identical at the provider and in `OAUTH2_REDIRECT_URI`: scheme, host, port and path. |
| "Invalid authentication state" | Start the login again in the same browser and finish it within 10 minutes. |
| "Login capacity reached" | Sign out unused sessions or wait for them to expire, or raise **Session Max Entries**. |
| Everyone gets "Too many login attempts" at once | The app sees the proxy's address instead of the visitor's. Check `FORWARDED_ALLOW_IPS` in [Reverse proxy](Reverse_Proxy.md). |
