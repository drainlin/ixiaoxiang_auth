# CineDock Auth Worker (Cloudflare)

This worker provides a serverless auth flow for your app account system:

- `POST /auth/send-code`
- `POST /auth/verify-code`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`

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
- This is intentionally minimal and suitable as a base for adding passkey + sync APIs.
