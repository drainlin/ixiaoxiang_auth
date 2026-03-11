# CineDock Auth Worker (Cloudflare)

This worker provides a serverless auth flow for your app account system:

- `POST /auth/send-code`
- `POST /auth/verify-code`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`
- `POST /auth/passkey/register/start`
- `POST /auth/passkey/register/finish`
- `POST /auth/passkey/login/start`
- `POST /auth/passkey/login/finish`
- `DELETE /auth/passkey/credential`

## 1) Install

```bash
cd worker
npm install
```

## 2) Login to Cloudflare

```bash
npx wrangler login
```

A browser window will open for authorization.

## 3) Create Cloudflare resources

### D1

```bash
npx wrangler d1 create ivideo-auth
```

Copy `database_id` and replace it in `wrangler.toml`.

Apply migration:

```bash
npx wrangler d1 migrations apply ivideo-auth --remote
```

### KV

```bash
npx wrangler kv namespace create OTP_KV
```

Copy namespace `id` and replace it in `wrangler.toml`.

## 4) Set secrets

```bash
npx wrangler secret put JWT_SECRET
npx wrangler secret put MAIL_GATEWAY_URL
npx wrangler secret put MAIL_GATEWAY_TOKEN
```

## 4.1) Passkey variables

Set these in `wrangler.toml` (or via dashboard):

- `PASSKEY_RP_ID`: your relying-party domain (e.g. `ixiaoxiang.cn`)
- `PASSKEY_EXPECTED_ORIGINS`: comma-separated allowed origins (e.g. `https://ixiaoxiang.cn`)
- `PASSKEY_RP_NAME`: display name in passkey prompt, default `CineDock`
- `PASSKEY_CHALLENGE_TTL_SECONDS`: challenge validity, default `300`

## 4.2) Multi-app support

The worker supports multiple apps sharing one account system.

- Shared across all apps:
  - `users`
  - OTP login email
  - Passkey credentials
- Isolated by `appId`:
  - sessions (refresh/access token audience)
  - user settings and library profiles (prepare via migration)

Client requests should include header:

```http
X-App-Id: cinedock
```

Environment variables:

- `DEFAULT_APP_ID`: fallback app id when header is missing (default `cinedock`)
- `APP_CONFIGS`: JSON map for per-app config (name/origin/passkey rp)

Example:

```json
{
  "cinedock": {
    "appName": "CineDock",
    "appOrigin": "https://cinedock.example.com",
    "passkeyRpId": "example.com",
    "passkeyRpName": "CineDock",
    "passkeyExpectedOrigins": ["https://cinedock.example.com"]
  },
  "anotherapp": {
    "appName": "Another App",
    "appOrigin": "https://another.example.com",
    "passkeyRpId": "example.com",
    "passkeyRpName": "Another App",
    "passkeyExpectedOrigins": ["https://another.example.com"]
  }
}
```

## 5) Deploy

```bash
npx wrangler deploy
```

## Request examples

### Send code

```bash
curl -X POST "$WORKER_URL/auth/send-code" \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","purpose":"login"}'
```

### Verify code

```bash
curl -X POST "$WORKER_URL/auth/verify-code" \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","code":"123456","purpose":"login"}'
```

## Notes

- OTP is stored in KV with TTL.
- Refresh token is hashed and stored in D1.
- Access token is signed with `JWT_SECRET`.
- Email sending is delegated to your self-hosted mail gateway API (`mail-gateway/`).
- Passkey start/finish routes use WebAuthn verification and persist credentials in D1.
- Passkeys are global account credentials and can be used across app ids (if RP/origin configuration allows it).
- Before passkeys work on mobile, complete domain association:
  - iOS: `apple-app-site-association` + Associated Domains (`webcredentials:`)
  - Android: `assetlinks.json` + Digital Asset Links verification
