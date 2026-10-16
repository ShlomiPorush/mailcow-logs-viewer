# OAuth2/OIDC Authentication Configuration Guide

This guide provides step-by-step instructions and examples for configuring OAuth2/OIDC authentication with various identity providers.

---

## Table of Contents

1. [Overview](#overview)
2. [Configuration Methods](#configuration-methods)
3. [Provider-Specific Examples](#provider-specific-examples)
   - [Authentik](#authentik)
   - [Mailcow](#mailcow)
   - [Keycloak](#keycloak)
   - [Google](#google)
   - [Microsoft Azure AD](#microsoft-azure-ad)
4. [Troubleshooting](#troubleshooting)

---

## Overview

mailcow-logs-viewer supports OAuth2/OIDC authentication with any standard OAuth2/OIDC provider. You can use:

- **OIDC Discovery** (recommended) - Automatically discovers endpoints from the provider
- **Manual Configuration** - Manually specify all endpoints (for providers without discovery support)

The login always uses PKCE (RFC 7636, `S256`): the app sends a code challenge with the authorization request and the matching verifier when it exchanges the code, so an intercepted authorization code is useless on its own. There is nothing to configure. Google, Microsoft, Authentik and Keycloak check it; the mailcow OAuth2 server does not support PKCE and ignores the extra parameters, as the OAuth2 standard requires. The app keeps the client secret as well, so it stays a confidential client.

> **Who can sign in is decided by your provider.** Every account your provider lets sign in to this application gets full access to the dashboard, including settings and the actions that change mailcow. mailcow-logs-viewer does not keep its own list of allowed users, so restrict access in the provider:
>
> - **mailcow** - mailcow's OAuth2 server signs in mailbox users. Unless you have confirmed that only administrators can authorize this app on your server, assume every mailbox user can, and use a provider that can limit access instead.
> - **Google** - set the OAuth consent screen to **Internal** so only accounts in your Google Workspace can sign in.
> - **Microsoft Azure AD** - register the app as **single tenant** and turn on **Assignment required** for its enterprise application, then assign only the users who need access.
> - **Authentik / Keycloak** - bind the application to a policy, group or role that only the intended users have.

### Basic Configuration

Enable OAuth2 authentication in your `.env` file:

```env
# Enable OAuth2 authentication
OAUTH2_ENABLED=true

# Provider display name (shown on login button)
OAUTH2_PROVIDER_NAME=Your Provider Name

# OAuth2 Client ID and Secret (from your provider)
OAUTH2_CLIENT_ID=your-client-id
OAUTH2_CLIENT_SECRET=your-client-secret

# Redirect URI (must match provider configuration)
OAUTH2_REDIRECT_URI=https://your-logs-viewer.example.com/api/auth/callback

# Session secret key (generate with: openssl rand -hex 32)
SESSION_SECRET_KEY=your-random-secret-key

# Session expiration (hours)
SESSION_EXPIRY_HOURS=24
```

---

## Configuration Methods

### Method 1: OIDC Discovery (Recommended)

If your provider supports OIDC Discovery (most modern providers do), you only need to set the issuer URL:

```env
# OIDC Discovery Configuration
OAUTH2_ISSUER_URL=https://your-provider.example.com
OAUTH2_USE_OIDC_DISCOVERY=true
OAUTH2_SCOPES=openid profile email
```

The application will automatically discover:
- Authorization endpoint
- Token endpoint
- UserInfo endpoint

### Method 2: Manual Configuration

For providers that don't support OIDC Discovery, manually configure all endpoints:

```env
# Manual Endpoint Configuration
OAUTH2_USE_OIDC_DISCOVERY=false
OAUTH2_AUTHORIZATION_URL=https://provider.example.com/oauth/authorize
OAUTH2_TOKEN_URL=https://provider.example.com/oauth/token
OAUTH2_USERINFO_URL=https://provider.example.com/oauth/userinfo
OAUTH2_SCOPES=profile email
```

**Note:** When using manual configuration, do NOT set `OAUTH2_ISSUER_URL`.

---

## Provider-Specific Examples

### Authentik

Authentik supports OIDC Discovery and works out of the box.

#### Step 1: Create OAuth2 Provider in Authentik

1. Log in to Authentik admin panel
2. Navigate to **Applications** → **Providers**
3. Click **Create** → **OAuth2/OpenID Provider**
4. Configure:
   - **Name**: mailcow-logs-viewer
   - **Client type**: Confidential
   - **Redirect URIs**: `https://your-logs-viewer.example.com/api/auth/callback`
   - **Scopes**: `openid`, `profile`, `email`
5. Save and note the **Client ID** and **Client Secret**

#### Step 2: Create Application in Authentik

1. Navigate to **Applications** → **Applications**
2. Click **Create**
3. Configure:
   - **Name**: mailcow-logs-viewer
   - **Slug**: mailcow-logs-viewer
   - **Provider**: Select the provider created in Step 1
4. Save

#### Step 3: Configure mailcow-logs-viewer

Add to your `.env` file:

```env
# Enable OAuth2
OAUTH2_ENABLED=true
OAUTH2_PROVIDER_NAME=Authentik

# OIDC Discovery (Authentik supports this)
OAUTH2_ISSUER_URL=https://authentik.yourdomain.com/application/o/mailcow-logs-viewer/
OAUTH2_USE_OIDC_DISCOVERY=true
OAUTH2_SCOPES=openid profile email

# Client credentials from Authentik
OAUTH2_CLIENT_ID=your-client-id-from-authentik
OAUTH2_CLIENT_SECRET=your-client-secret-from-authentik

# Redirect URI (must match Authentik configuration)
OAUTH2_REDIRECT_URI=https://your-logs-viewer.example.com/api/auth/callback

# Session configuration
SESSION_SECRET_KEY=your-random-secret-key
SESSION_EXPIRY_HOURS=24
```

**Important Notes:**
- The issuer URL should point to your Authentik application endpoint
- Authentik automatically provides all required endpoints via discovery
- No need to manually configure authorization/token/userinfo URLs

---

### Mailcow

Mailcow's OAuth2 implementation does not support OIDC Discovery, so manual endpoint configuration is required.

#### Step 1: Create OAuth2 App in Mailcow

1. Log in to Mailcow admin panel
2. Navigate to **System** → **Configuration** → **Access** → **OAuth2 Apps**
3. Click **Add OAuth2 App**
4. Configure:
   - **Name**: mailcow-logs-viewer
   - **Redirect URI**: `https://your-logs-viewer.example.com/api/auth/callback`
5. Save and note the **Client ID** and **Client Secret**

#### Step 2: Configure mailcow-logs-viewer

Add to your `.env` file:

```env
# Enable OAuth2
OAUTH2_ENABLED=true
OAUTH2_PROVIDER_NAME=Mailcow

# Manual Configuration (Mailcow doesn't support OIDC Discovery)
OAUTH2_USE_OIDC_DISCOVERY=false
OAUTH2_AUTHORIZATION_URL=https://mail.yourdomain.com/oauth/authorize
OAUTH2_TOKEN_URL=https://mail.yourdomain.com/oauth/token
OAUTH2_USERINFO_URL=https://mail.yourdomain.com/oauth/profile

# Scopes (Mailcow typically only supports 'profile')
OAUTH2_SCOPES=profile

# Client credentials from Mailcow
OAUTH2_CLIENT_ID=your-client-id-from-mailcow
OAUTH2_CLIENT_SECRET=your-client-secret-from-mailcow

# Redirect URI (must match Mailcow configuration)
OAUTH2_REDIRECT_URI=https://your-logs-viewer.example.com/api/auth/callback

# Session configuration
SESSION_SECRET_KEY=your-random-secret-key
SESSION_EXPIRY_HOURS=24
```

**Important Notes:**
- **Do NOT** set `OAUTH2_ISSUER_URL` when using manual configuration
- Mailcow typically only supports the `profile` scope (not `openid` or `email`)
- Replace `https://mail.yourdomain.com` with your actual Mailcow URL

---

### Keycloak

Keycloak supports OIDC Discovery and works well with discovery mode.

#### Step 1: Create OAuth2 Client in Keycloak

1. Log in to Keycloak admin console
2. Select your realm
3. Navigate to **Clients** → **Create**
4. Configure:
   - **Client ID**: mailcow-logs-viewer
   - **Client Protocol**: openid-connect
   - **Access Type**: confidential
   - **Valid Redirect URIs**: `https://your-logs-viewer.example.com/api/auth/callback`
   - **Web Origins**: `https://your-logs-viewer.example.com`
5. Go to **Credentials** tab and note the **Secret**

#### Step 2: Configure mailcow-logs-viewer

Add to your `.env` file:

```env
# Enable OAuth2
OAUTH2_ENABLED=true
OAUTH2_PROVIDER_NAME=Keycloak

# OIDC Discovery (Keycloak supports this)
OAUTH2_ISSUER_URL=https://keycloak.yourdomain.com/realms/your-realm
OAUTH2_USE_OIDC_DISCOVERY=true
OAUTH2_SCOPES=openid profile email

# Client credentials from Keycloak
OAUTH2_CLIENT_ID=mailcow-logs-viewer
OAUTH2_CLIENT_SECRET=your-client-secret-from-keycloak

# Redirect URI (must match Keycloak configuration)
OAUTH2_REDIRECT_URI=https://your-logs-viewer.example.com/api/auth/callback

# Session configuration
SESSION_SECRET_KEY=your-random-secret-key
SESSION_EXPIRY_HOURS=24
```

**Important Notes:**
- The issuer URL format is: `https://keycloak.domain.com/realms/realm-name`
- Keycloak supports full OIDC Discovery
- All standard scopes are supported

---

### Google

Google supports OIDC Discovery and can be used as an identity provider.

#### Step 1: Create OAuth2 Credentials in Google Cloud

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Select your project
3. Navigate to **APIs & Services** → **Credentials**
4. Click **Create Credentials** → **OAuth client ID**
5. Configure:
   - **Application type**: Web application
   - **Name**: mailcow-logs-viewer
   - **Authorized redirect URIs**: `https://your-logs-viewer.example.com/api/auth/callback`
6. Save and note the **Client ID** and **Client Secret**

#### Step 2: Configure mailcow-logs-viewer

Add to your `.env` file:

```env
# Enable OAuth2
OAUTH2_ENABLED=true
OAUTH2_PROVIDER_NAME=Google

# OIDC Discovery (Google supports this)
OAUTH2_ISSUER_URL=https://accounts.google.com
OAUTH2_USE_OIDC_DISCOVERY=true
OAUTH2_SCOPES=openid profile email

# Client credentials from Google Cloud
OAUTH2_CLIENT_ID=your-google-client-id
OAUTH2_CLIENT_SECRET=your-google-client-secret

# Redirect URI (must match Google configuration)
OAUTH2_REDIRECT_URI=https://your-logs-viewer.example.com/api/auth/callback

# Session configuration
SESSION_SECRET_KEY=your-random-secret-key
SESSION_EXPIRY_HOURS=24
```

**Important Notes:**
- Google's issuer URL is always `https://accounts.google.com`
- Full OIDC Discovery is supported
- All standard scopes work with Google

---

### Microsoft Azure AD

Azure AD supports OIDC Discovery.

#### Step 1: Register Application in Azure AD

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Configure:
   - **Name**: mailcow-logs-viewer
   - **Supported account types**: Your choice
   - **Redirect URI**: Web → `https://your-logs-viewer.example.com/api/auth/callback`
5. Go to **Certificates & secrets** → **New client secret**
6. Note the **Application (client) ID** and **Client secret value**

#### Step 2: Configure mailcow-logs-viewer

Add to your `.env` file:

```env
# Enable OAuth2
OAUTH2_ENABLED=true
OAUTH2_PROVIDER_NAME=Microsoft

# OIDC Discovery (Azure AD supports this)
OAUTH2_ISSUER_URL=https://login.microsoftonline.com/your-tenant-id/v2.0
OAUTH2_USE_OIDC_DISCOVERY=true
OAUTH2_SCOPES=openid profile email

# Client credentials from Azure AD
OAUTH2_CLIENT_ID=your-azure-client-id
OAUTH2_CLIENT_SECRET=your-azure-client-secret

# Redirect URI (must match Azure configuration)
OAUTH2_REDIRECT_URI=https://your-logs-viewer.example.com/api/auth/callback

# Session configuration
SESSION_SECRET_KEY=your-random-secret-key
SESSION_EXPIRY_HOURS=24
```

**Important Notes:**
- Replace `your-tenant-id` with your Azure AD tenant ID
- Azure AD supports full OIDC Discovery
- Standard scopes work with Azure AD

---

## Troubleshooting

### Common Issues

#### 1. "OIDC discovery failed"

**Symptoms:** Error message about discovery failure

**Solutions:**
- Verify `OAUTH2_ISSUER_URL` is correct and accessible
- Check if provider supports OIDC Discovery
- If not supported, use manual configuration instead
- Ensure network connectivity to the provider

#### 2. "Invalid redirect URI"

**Symptoms:** Provider rejects the redirect URI

**Solutions:**
- Ensure `OAUTH2_REDIRECT_URI` matches exactly what's configured in the provider
- Check for trailing slashes (should match exactly)
- Verify the URL uses HTTPS (required by most providers)
- Check provider logs for specific error messages

#### 3. "Invalid client credentials"

**Symptoms:** Authentication fails with credential errors

**Solutions:**
- Verify `OAUTH2_CLIENT_ID` and `OAUTH2_CLIENT_SECRET` are correct
- Check if client secret has expired (some providers rotate secrets)
- Ensure the client is enabled in the provider
- Verify the client has correct permissions/scopes

#### 4. "Scope not supported"

**Symptoms:** Provider rejects requested scopes

**Solutions:**
- Check provider documentation for supported scopes
- Try minimal scopes first (e.g., just `profile`)
- Some providers (like Mailcow) only support specific scopes
- Remove unsupported scopes from `OAUTH2_SCOPES`

#### 5. Session expires immediately

**Symptoms:** User gets logged out right after login

**Solutions:**
- Verify `SESSION_SECRET_KEY` is set and not empty
- Ensure `SESSION_SECRET_KEY` is a strong random value
- Check `SESSION_EXPIRY_HOURS` is set to a reasonable value
- Verify cookies are being set (check browser dev tools)

### Debugging Tips

1. **Check Application Logs:**
   ```bash
   docker compose logs app | grep -i oauth
   ```

2. **Verify Provider Configuration:**
   - Test OIDC Discovery endpoint: `https://your-provider/.well-known/openid-configuration`
   - Verify all endpoints are accessible
   - Check provider admin panel for client status

3. **Browser Developer Tools:**
   - Check Network tab for OAuth2 redirects
   - Verify cookies are being set
   - Check for CORS errors

4. **Test OIDC Discovery:**
   ```bash
   curl https://your-provider/.well-known/openid-configuration
   ```
   Should return JSON with `authorization_endpoint`, `token_endpoint`, and `userinfo_endpoint`.

---

## Quick Reference

### OIDC Discovery Providers

These providers support automatic endpoint discovery:

- ✅ Authentik
- ✅ Keycloak
- ✅ Google
- ✅ Microsoft Azure AD
- ✅ Auth0
- ✅ Okta
- ✅ Most modern OIDC providers

### Manual Configuration Required

These providers require manual endpoint configuration:

- ❌ Mailcow
- ❌ Some custom/legacy OAuth2 implementations

### Scope Recommendations

| Provider | Recommended Scopes |
|----------|-------------------|
| Authentik | `openid profile email` |
| Mailcow | `profile` |
| Keycloak | `openid profile email` |
| Google | `openid profile email` |
| Microsoft | `openid profile email` |

---

## Security Best Practices

1. **Use HTTPS:** Always use HTTPS for production deployments
2. **Strong Secrets:** Generate strong random values for `SESSION_SECRET_KEY`
   ```bash
   openssl rand -hex 32
   ```
3. **Secure Cookies:** The application automatically uses secure cookies when HTTPS is detected
4. **Regular Rotation:** Rotate client secrets and session keys periodically
5. **Minimal Scopes:** Request only the scopes you actually need
6. **Provider Security:** Follow your provider's security recommendations
7. **PKCE:** Every login uses PKCE (S256). If your provider can require PKCE for a client (in Keycloak: the client's PKCE Method set to S256), you can turn that on
8. **Limit Who Can Sign In:** Every account the provider lets sign in gets full access to the dashboard. Restrict the application to the intended users in the provider (see the [Overview](#overview))

---

## Additional Resources

- [OAuth 2.0 Specification](https://oauth.net/2/)
- [OpenID Connect Specification](https://openid.net/connect/)
- [OIDC Discovery Specification](https://openid.net/specs/openid-connect-discovery-1_0.html)

---

**Need Help?** Check the main [Getting Started Guide](/documentation/GETTING_STARTED.md) or open an issue on GitHub.
