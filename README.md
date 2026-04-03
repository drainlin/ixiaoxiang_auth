# Auth Worker (Cloudflare)

This worker provides a reusable account system for one or more apps.

Supported routes:

- `POST /auth/send-code`
- `POST /auth/verify-code`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`
- `POST /auth/profile`
- `POST /auth/passkey/register/start`
- `POST /auth/passkey/register/finish`
- `POST /auth/passkey/login/start`
- `POST /auth/passkey/login/finish`
- `GET /auth/passkey/settings`
- `PATCH /auth/passkey/settings`
- `GET /auth/passkey/credentials`
- `PATCH /auth/passkey/credential`
- `DELETE /auth/passkey/credential`

## 1) Install

```bash
cd auth-worker
npm install
```

## 2) Log in to Cloudflare

```bash
npx wrangler login
```

## 3) Create Cloudflare resources

### D1

```bash
npx wrangler d1 create auth-worker
```

Copy the `database_id` into `wrangler.toml`.

Apply migrations:

```bash
npx wrangler d1 migrations apply auth-worker --remote
```

### KV

```bash
npx wrangler kv namespace create OTP_KV
```

Copy the namespace `id` into `wrangler.toml`.

## 4) Set secrets

```bash
npx wrangler secret put JWT_SECRET
npx wrangler secret put MAIL_GATEWAY_SIGNING_SECRET
```

Optional:

```bash
npx wrangler secret put MAIL_GATEWAY_TOKEN
npx wrangler secret put DEFAULT_EMAIL_SUBJECT
npx wrangler secret put APP_EMAIL_SUBJECTS
```

- `MAIL_GATEWAY_SIGNING_SECRET` is the HMAC key shared with `mail-gateway`.
- `MAIL_GATEWAY_TOKEN` is an optional fallback auth token.
- `MAIL_GATEWAY` is configured as a Cloudflare service binding in `wrangler.toml`.
- `APP_BUNDLE_ID` is forwarded as `X-Bundle-Id` for single-app setups.
- `DEFAULT_EMAIL_SUBJECT` is the fallback subject template, for example `{app_name} Login Code`.
- `APP_EMAIL_SUBJECTS` is a JSON map keyed by `appId`.

## 5) Configure apps

The worker can serve multiple apps behind one auth backend.

- Shared across all apps:
  - `users`
  - OTP login
  - Passkey credentials
- Isolated by `appId`:
  - sessions and JWT audience
  - sync settings
  - library profiles

Clients should send:

```http
X-App-Id: app1
```

Environment variables:

- `DEFAULT_APP_ID`: fallback app id when the header is missing
- `APP_CONFIGS`: JSON map of per-app config

Example:

```json
{
  "app1": {
    "appName": "App One",
    "appOrigin": "https://app1.example.com",
    "appBundleId": "com.example.app1",
    "passkeyRpId": "auth.example.com",
    "passkeyRpName": "App One",
    "passkeyExpectedOrigins": ["https://app1.example.com"]
  },
  "app2": {
    "appName": "App Two",
    "appOrigin": "https://app2.example.com",
    "appBundleId": "com.example.app2",
    "passkeyRpId": "auth.example.com",
    "passkeyRpName": "App Two",
    "passkeyExpectedOrigins": ["https://app2.example.com"]
  }
}
```

Recommended per-app fields:

- `appName`: display name used in emails and UI payloads
- `appOrigin`: canonical web origin for CORS and passkey checks
- `appBundleId`: bundle identifier sent to the mail gateway
- `passkeyRpId`: relying-party domain for WebAuthn
- `passkeyRpName`: passkey prompt display name
- `passkeyExpectedOrigins`: allowed passkey origins

If you only have one app, you can also set the global fallbacks in `wrangler.toml`:

- `APP_NAME`
- `APP_ORIGIN`
- `APP_BUNDLE_ID`
- `PASSKEY_RP_ID`
- `PASSKEY_RP_NAME`
- `PASSKEY_EXPECTED_ORIGINS`

## 6) Deploy

```bash
npx wrangler deploy
```

## Examples

### Send code

```bash
curl -X POST "$WORKER_URL/auth/send-code" \
  -H 'content-type: application/json' \
  -H 'x-app-id: app1' \
  -d '{"email":"you@example.com","purpose":"login"}'
```

### Verify code

```bash
curl -X POST "$WORKER_URL/auth/verify-code" \
  -H 'content-type: application/json' \
  -H 'x-app-id: app1' \
  -d '{"email":"you@example.com","code":"123456","purpose":"login"}'
```

### List passkeys

```bash
curl "$WORKER_URL/auth/passkey/credentials" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'x-app-id: app1'
```

### Read passkey login setting

```bash
curl "$WORKER_URL/auth/passkey/settings" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'x-app-id: app1'
```

### Toggle passkey login

```bash
curl -X PATCH "$WORKER_URL/auth/passkey/settings" \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'x-app-id: app1' \
  -d '{"passkeyLoginEnabled":true}'
```

### Update passkey alias

```bash
curl -X PATCH "$WORKER_URL/auth/passkey/credential" \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'x-app-id: app1' \
  -d '{"credentialId":"abc123","alias":"MacBook Pro"}'
```

### Delete passkey

```bash
curl -X DELETE "$WORKER_URL/auth/passkey/credential" \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'x-app-id: app1' \
  -d '{"credentialId":"abc123"}'
```

Legacy clients may omit `credentialId` to delete all passkeys for the current user.

## Notes

- OTP is stored in KV with TTL.
- Refresh tokens are hashed and stored in D1.
- Access tokens are signed with `JWT_SECRET`.
- Email delivery is delegated to `mail-gateway`.
- Passkey start/finish routes use WebAuthn verification and persist credentials in D1.
- `GET /auth/me` returns the current user's passkey list and `passkey_login_enabled`.
- `GET /auth/passkey/settings` reads the current user's passkey login toggle.
- `PATCH /auth/passkey/settings` updates the current user's passkey login toggle.
- `GET /auth/passkey/credentials` returns the current user's passkey list for the frontend.
- `PATCH /auth/passkey/credential` updates a single passkey alias.
- `DELETE /auth/passkey/credential` deletes a single passkey by `credentialId`.
- Each passkey item includes `addedAt` as the creation timestamp.
- Passkeys are account-level credentials and can be reused across apps when the RP/origin config allows it.
- Before passkeys work on mobile, complete domain association:
  - iOS: `apple-app-site-association` + Associated Domains (`webcredentials:`)
  - Android: `assetlinks.json` + Digital Asset Links verification

## Suggested setup pattern

For each new app:

- add an entry in `APP_CONFIGS`
- send `X-App-Id` from the client
- keep the app's bundle id, origin, and passkey config in that app entry
- reuse the same worker and user database

The shared mail-gateway contract is documented in the mail gateway repository.
