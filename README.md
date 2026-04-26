# Auth Worker (Cloudflare)

This worker powers the shared auth system for multiple apps.

Current built-in app configs:

- `cinedock` for ivideo
- `echospace` for imusic
- `echoshelf` for EchoShelf

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

## Install

```bash
cd auth-worker
npm install
```

## Cloudflare Login

```bash
npx wrangler login
```

## Resources

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

## Secrets

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
- `APP_EMAIL_SUBJECTS` is a JSON map keyed by `appId`.
- `DEFAULT_EMAIL_SUBJECT` is the fallback subject template, for example `{app_name} Login Code`.

## App Config

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
X-App-Id: cinedock
```

Built-in app ids:

- `cinedock` for ivideo
- `echospace` for imusic
- `echoshelf` for EchoShelf

Recommended config shape:

```json
{
  "cinedock": {
    "appName": "CineDock",
    "appOrigin": "https://ixiaoxiang.cn",
    "appBundleId": "cn.ixiaoxiang.video",
    "passkeyRpId": "ixiaoxiang.cn",
    "passkeyRpName": "CineDock",
    "passkeyExpectedOrigins": ["https://ixiaoxiang.cn"]
  },
  "echospace": {
    "appName": "EchoSpace",
    "appOrigin": "https://ixiaoxiang.cn",
    "appBundleId": "cn.ixiaoxiang.music",
    "passkeyRpId": "ixiaoxiang.cn",
    "passkeyRpName": "EchoSpace",
    "passkeyExpectedOrigins": ["https://ixiaoxiang.cn"]
  },
  "echoshelf": {
    "appName": "EchoShelf",
    "appOrigin": "https://ixiaoxiang.cn",
    "appBundleId": "cn.ixiaoxiang.listen",
    "passkeyRpId": "ixiaoxiang.cn",
    "passkeyRpName": "EchoShelf",
    "passkeyExpectedOrigins": [
      "https://ixiaoxiang.cn",
      "android:apk-key-hash:kfEqXSUFM3so8dtWFvCM8tzenXuwfP6btE_U4qRic1s",
      "android:apk-key-hash:_YsTiSH_CC0qlpSXGGhlXnVeL1ft077adRSFeI1wXw4"
    ]
  }
}
```

Environment variables:

- `DEFAULT_APP_ID`: fallback app id when the header is missing
- `APP_CONFIGS`: JSON map for per-app config
- `APP_NAME`: fallback app name if an app entry is missing
- `APP_ORIGIN`: fallback origin if an app entry is missing
- `APP_BUNDLE_ID`: fallback bundle id if an app entry is missing
- `PASSKEY_RP_ID`: fallback relying-party domain if an app entry is missing
- `PASSKEY_RP_NAME`: fallback passkey display name if an app entry is missing
- `PASSKEY_EXPECTED_ORIGINS`: fallback list of allowed origins
- `ACCESS_TOKEN_TTL_SECONDS`: access token lifetime in seconds, default `86400` (1 day)
- `REFRESH_TOKEN_TTL_SECONDS`: refresh token lifetime in seconds, default `1209600` (2 weeks)

## Deploy

```bash
npx wrangler deploy
```

## Examples

### Send code

```bash
curl -X POST "$WORKER_URL/auth/send-code" \
  -H 'content-type: application/json' \
  -H 'x-app-id: cinedock' \
  -d '{"email":"you@example.com","purpose":"login"}'
```

### Verify code

```bash
curl -X POST "$WORKER_URL/auth/verify-code" \
  -H 'content-type: application/json' \
  -H 'x-app-id: cinedock' \
  -d '{"email":"you@example.com","code":"123456","purpose":"login"}'
```

### List passkeys

```bash
curl "$WORKER_URL/auth/passkey/credentials" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'x-app-id: cinedock'
```

### Read passkey login setting

```bash
curl "$WORKER_URL/auth/passkey/settings" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'x-app-id: cinedock'
```

### Toggle passkey login

```bash
curl -X PATCH "$WORKER_URL/auth/passkey/settings" \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'x-app-id: cinedock' \
  -d '{"passkeyLoginEnabled":true}'
```

### Update passkey alias

```bash
curl -X PATCH "$WORKER_URL/auth/passkey/credential" \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'x-app-id: cinedock' \
  -d '{"credentialId":"abc123","alias":"MacBook Pro"}'
```

### Delete passkey

```bash
curl -X DELETE "$WORKER_URL/auth/passkey/credential" \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'x-app-id: cinedock' \
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
