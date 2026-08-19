# Calendar external sync — Google & Outlook OAuth setup

One-time setup to enable two-way calendar sync (Phase 4). Create one OAuth app per
provider, then hand the credentials to the deploy (Vercel env). The sync engine is built
around the fixed values below — **use these exact redirect URIs and scopes.**

Production host: `https://communications.citrate.ai`

## Contract (what the code expects)

| Provider | Redirect URI | Scopes | Env vars |
|---|---|---|---|
| Google | `https://communications.citrate.ai/api/calendar/oauth/google/callback` | `openid`, `email`, `https://www.googleapis.com/auth/calendar.events` | `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` |
| Microsoft | `https://communications.citrate.ai/api/calendar/oauth/microsoft/callback` | `openid`, `email`, `offline_access`, `Calendars.ReadWrite` | `MS_OAUTH_CLIENT_ID`, `MS_OAUTH_CLIENT_SECRET`, `MS_OAUTH_TENANT` |

Each user connects their own calendar (per-member OAuth), tokens stored **encrypted** in
`calendar_connections`. Nothing works until both the OAuth app *and* the env vars are set.

---

## Google Calendar

1. **Google Cloud Console** → https://console.cloud.google.com/ → create (or pick) a
   project, e.g. "Citrate Comms".
2. **Enable the API**: APIs & Services → Library → search **"Google Calendar API"** →
   **Enable**.
3. **OAuth consent screen** (APIs & Services → OAuth consent screen):
   - User type: **External** (unless everyone is in one Google Workspace org, then Internal).
   - App name: `Citrate Comms`; support email + developer email: yours.
   - **Scopes** → Add → add `.../auth/calendar.events` (plus `openid`, `email` if listed).
   - **Test users**: while the app is in "Testing", add every teammate's Google address
     (only listed testers can connect). To skip this, **Publish** the app (a Google
     verification review may apply for sensitive scopes; for internal team use, Testing +
     test users is usually fine).
4. **Create the OAuth client**: APIs & Services → Credentials → **Create Credentials →
   OAuth client ID**:
   - Application type: **Web application**.
   - Name: `Citrate Comms Web`.
   - **Authorized redirect URIs** → add exactly:
     `https://communications.citrate.ai/api/calendar/oauth/google/callback`
   - Create → copy the **Client ID** and **Client secret**.
5. Give me those two values → they become `GOOGLE_OAUTH_CLIENT_ID` /
   `GOOGLE_OAUTH_CLIENT_SECRET` (Vercel, Production).

> The auth request will use `access_type=offline` + `prompt=consent` so Google returns a
> refresh token (needed for background sync).

---

## Microsoft / Outlook (Azure)

1. **Azure Portal** → https://portal.azure.com/ → **Microsoft Entra ID** (formerly Azure
   AD) → **App registrations** → **New registration**.
   - Name: `Citrate Comms`.
   - **Supported account types**: pick based on who connects:
     - Work/school + personal Microsoft accounts → *"Accounts in any org directory and
       personal Microsoft accounts"* → set `MS_OAUTH_TENANT=common`.
     - Only your org → *"Single tenant"* → set `MS_OAUTH_TENANT=<your tenant ID>`.
   - **Redirect URI**: platform **Web**, value exactly:
     `https://communications.citrate.ai/api/calendar/oauth/microsoft/callback`
   - Register.
2. **API permissions** → Add a permission → **Microsoft Graph** → **Delegated
   permissions** → add:
   - `Calendars.ReadWrite`
   - `offline_access`
   - `openid`, `email` (usually present by default)
   - (Optional) **Grant admin consent** for your org so users aren't each prompted.
3. **Certificates & secrets** → **New client secret** → description + expiry (24 months) →
   **Add** → copy the secret **Value** immediately (shown once).
4. From **Overview**, copy the **Application (client) ID** and the **Directory (tenant)
   ID**.
5. Give me: client ID, client secret Value, and tenant (`common` or the tenant ID) → they
   become `MS_OAUTH_CLIENT_ID` / `MS_OAUTH_CLIENT_SECRET` / `MS_OAUTH_TENANT` (Vercel,
   Production).

---

## Handing over the secrets

Same method as the DigitalOcean token — don't paste secrets into chat. Save them to a file
in your own terminal and tell me the path, e.g.:

```
printf 'GOOGLE_OAUTH_CLIENT_ID=...\nGOOGLE_OAUTH_CLIENT_SECRET=...\nMS_OAUTH_CLIENT_ID=...\nMS_OAUTH_CLIENT_SECRET=...\nMS_OAUTH_TENANT=common\n' > ~/.config/citrate-cal-oauth && chmod 600 ~/.config/citrate-cal-oauth
```

I'll read it, set the Vercel env, build the connect/callback/sync engine, and verify a
round-trip (connect an account → an event created in-app appears in Google/Outlook and
vice-versa). No droplet involvement — this is entirely webapp/Vercel.
