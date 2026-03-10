interface Env {
  DB: D1Database;
  OTP_KV: KVNamespace;
  JWT_SECRET: string;
  MAIL_GATEWAY_URL: string;
  MAIL_GATEWAY_TOKEN: string;
  APP_NAME?: string;
  APP_ORIGIN?: string;
  ACCESS_TOKEN_TTL_SECONDS?: string;
  REFRESH_TOKEN_TTL_SECONDS?: string;
  OTP_TTL_SECONDS?: string;
  OTP_MAX_ATTEMPTS?: string;
}

type JsonRecord = Record<string, unknown>;

const encoder = new TextEncoder();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders(env) });
      }

      const url = new URL(request.url);
      const path = url.pathname.replace(/\/+$/, '') || '/';

      if (request.method === 'POST' && path === '/auth/send-code') {
        return withCors(await handleSendCode(request, env), env);
      }
      if (request.method === 'POST' && path === '/auth/verify-code') {
        return withCors(await handleVerifyCode(request, env), env);
      }
      if (request.method === 'POST' && path === '/auth/refresh') {
        return withCors(await handleRefresh(request, env), env);
      }
      if (request.method === 'POST' && path === '/auth/logout') {
        return withCors(await handleLogout(request, env), env);
      }
      if (request.method === 'GET' && path === '/auth/me') {
        return withCors(await handleMe(request, env), env);
      }

      return withCors(json({ error: 'not_found' }, 404), env);
    } catch (error) {
      console.error('worker-error', error);
      return withCors(json({ error: 'internal_error' }, 500), env);
    }
  },
};

async function handleSendCode(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  if (!isValidEmail(email)) {
    return json({ error: 'invalid_email' }, 400);
  }

  const purpose = normalizePurpose(body.purpose);
  const otpTtl = intVar(env.OTP_TTL_SECONDS, 300);
  const maxAttempts = intVar(env.OTP_MAX_ATTEMPTS, 5);
  const code = generateOtp();
  const now = nowSeconds();
  const expiresAt = now + otpTtl;

  const value = {
    codeHash: await sha256(`${email}:${purpose}:${code}`),
    attempts: 0,
    maxAttempts,
    expiresAt,
  };

  await env.OTP_KV.put(otpKey(email, purpose), JSON.stringify(value), {
    expirationTtl: otpTtl,
  });

  await sendOtpEmail({ env, email, code, ttlSeconds: otpTtl });

  return json({ ok: true, expiresAt });
}

async function handleVerifyCode(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const code = `${body.code ?? ''}`.trim();
  const purpose = normalizePurpose(body.purpose);
  if (!isValidEmail(email) || !/^\d{6}$/.test(code)) {
    return json({ error: 'invalid_payload' }, 400);
  }

  const key = otpKey(email, purpose);
  const raw = await env.OTP_KV.get(key);
  if (!raw) {
    return json({ error: 'otp_expired' }, 400);
  }

  const otp = parseJson(raw);
  if (!otp || typeof otp.codeHash !== 'string') {
    return json({ error: 'otp_invalid_state' }, 400);
  }

  const now = nowSeconds();
  if (typeof otp.expiresAt !== 'number' || otp.expiresAt <= now) {
    await env.OTP_KV.delete(key);
    return json({ error: 'otp_expired' }, 400);
  }

  const attempts = Number(otp.attempts ?? 0);
  const maxAttempts = Number(otp.maxAttempts ?? 5);
  if (attempts >= maxAttempts) {
    await env.OTP_KV.delete(key);
    return json({ error: 'otp_locked' }, 429);
  }

  const inputHash = await sha256(`${email}:${purpose}:${code}`);
  if (inputHash !== otp.codeHash) {
    const remainingTtl = Math.max(1, otp.expiresAt - now);
    await env.OTP_KV.put(
      key,
      JSON.stringify({ ...otp, attempts: attempts + 1 }),
      { expirationTtl: remainingTtl },
    );
    return json({ error: 'otp_mismatch', attemptsLeft: maxAttempts - attempts - 1 }, 400);
  }

  await env.OTP_KV.delete(key);

  const user = await upsertUserByEmail(env.DB, email);
  const tokens = await issueSessionTokens(env, user.id, user.email);

  return json({
    ok: true,
    user,
    tokens,
  });
}

async function handleRefresh(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const refreshToken = `${body.refreshToken ?? ''}`.trim();
  if (!refreshToken) {
    return json({ error: 'missing_refresh_token' }, 400);
  }

  const refreshHash = await sha256(refreshToken);
  const now = nowSeconds();

  const sessionRow = await env.DB.prepare(
    `SELECT s.id AS session_id, s.user_id, s.expires_at, s.revoked_at, u.email
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.refresh_hash = ?1 LIMIT 1`,
  )
    .bind(refreshHash)
    .first<{
      session_id: string;
      user_id: string;
      expires_at: number;
      revoked_at: number | null;
      email: string;
    }>();

  if (!sessionRow) {
    return json({ error: 'invalid_refresh_token' }, 401);
  }
  if (sessionRow.revoked_at != null || sessionRow.expires_at <= now) {
    return json({ error: 'refresh_token_expired' }, 401);
  }

  await env.DB.prepare(
    'UPDATE sessions SET revoked_at = ?1, updated_at = ?1 WHERE id = ?2',
  )
    .bind(now, sessionRow.session_id)
    .run();

  const tokens = await issueSessionTokens(env, sessionRow.user_id, sessionRow.email);
  return json({ ok: true, tokens });
}

async function handleLogout(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const refreshToken = `${body.refreshToken ?? ''}`.trim();
  if (!refreshToken) {
    return json({ ok: true });
  }
  const refreshHash = await sha256(refreshToken);
  const now = nowSeconds();

  await env.DB.prepare(
    'UPDATE sessions SET revoked_at = ?1, updated_at = ?1 WHERE refresh_hash = ?2',
  )
    .bind(now, refreshHash)
    .run();

  return json({ ok: true });
}

async function handleMe(request: Request, env: Env): Promise<Response> {
  const auth = request.headers.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) {
    return json({ error: 'missing_access_token' }, 401);
  }

  const payload = await verifyJwt(token, env.JWT_SECRET);
  if (!payload || typeof payload.sub !== 'string') {
    return json({ error: 'invalid_access_token' }, 401);
  }

  const user = await env.DB.prepare(
    'SELECT id, email, status, created_at FROM users WHERE id = ?1 LIMIT 1',
  )
    .bind(payload.sub)
    .first<{ id: string; email: string; status: string; created_at: number }>();

  if (!user) {
    return json({ error: 'user_not_found' }, 404);
  }

  return json({ ok: true, user });
}

async function issueSessionTokens(env: Env, userId: string, email: string) {
  const now = nowSeconds();
  const accessTtl = intVar(env.ACCESS_TOKEN_TTL_SECONDS, 900);
  const refreshTtl = intVar(env.REFRESH_TOKEN_TTL_SECONDS, 2_592_000);

  const accessToken = await signJwt(
    {
      sub: userId,
      email,
      iat: now,
      exp: now + accessTtl,
      scope: 'user',
    },
    env.JWT_SECRET,
  );

  const refreshToken = `${crypto.randomUUID()}.${crypto.randomUUID()}`;
  const refreshHash = await sha256(refreshToken);
  const sessionId = crypto.randomUUID();

  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, refresh_hash, expires_at, revoked_at, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?5)`,
  )
    .bind(sessionId, userId, refreshHash, now + refreshTtl, now)
    .run();

  return {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: accessTtl,
  };
}

async function upsertUserByEmail(db: D1Database, email: string) {
  const now = nowSeconds();
  const id = crypto.randomUUID();

  await db.prepare(
    `INSERT INTO users (id, email, email_verified_at, status, created_at, updated_at)
     VALUES (?1, ?2, ?3, 'active', ?3, ?3)
     ON CONFLICT(email)
     DO UPDATE SET email_verified_at = excluded.email_verified_at, updated_at = excluded.updated_at`,
  )
    .bind(id, email, now)
    .run();

  const user = await db
    .prepare('SELECT id, email, status, created_at FROM users WHERE email = ?1 LIMIT 1')
    .bind(email)
    .first<{ id: string; email: string; status: string; created_at: number }>();

  if (!user) {
    throw new Error('failed_to_load_user_after_upsert');
  }

  return user;
}

async function sendOtpEmail(args: {
  env: Env;
  email: string;
  code: string;
  ttlSeconds: number;
}) {
  const appName = args.env.APP_NAME ?? 'CineDock';
  const gatewayUrl = `${args.env.MAIL_GATEWAY_URL}`.trim().replace(/\/+$/, '');
  const token = `${args.env.MAIL_GATEWAY_TOKEN}`.trim();
  if (!gatewayUrl || !token) {
    throw new Error('mail_gateway_not_configured');
  }
  const response = await fetch(`${gatewayUrl}/send-otp`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email: args.email,
      code: args.code,
      ttl_seconds: args.ttlSeconds,
      app_name: appName,
    }),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`send_email_via_gateway_failed:${response.status}:${detail}`);
  }
}

async function readJson(request: Request): Promise<JsonRecord> {
  const text = await request.text();
  if (!text) return {};
  const parsed = parseJson(text);
  return (parsed && typeof parsed === 'object' ? parsed : {}) as JsonRecord;
}

function parseJson(input: string): JsonRecord | null {
  try {
    const parsed = JSON.parse(input);
    if (parsed && typeof parsed === 'object') {
      return parsed as JsonRecord;
    }
    return null;
  } catch {
    return null;
  }
}

function normalizeEmail(value: unknown): string {
  return `${value ?? ''}`.trim().toLowerCase();
}

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function normalizePurpose(value: unknown): string {
  const text = `${value ?? ''}`.trim().toLowerCase();
  return text || 'login';
}

function generateOtp(): string {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000;
  return `${n}`.padStart(6, '0');
}

function otpKey(email: string, purpose: string): string {
  return `otp:${purpose}:${email}`;
}

function intVar(raw: string | undefined, fallback: number): number {
  const n = Number.parseInt(`${raw ?? ''}`, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
  });
}

function withCors(response: Response, env: Env): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(env))) {
    headers.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function corsHeaders(env: Env): Record<string, string> {
  const origin = env.APP_ORIGIN ?? '*';
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type,authorization',
    'access-control-max-age': '86400',
  };
}

async function sha256(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return base64UrlEncode(digest);
}

async function signJwt(payload: JsonRecord, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = await hmacSha256(data, secret);
  return `${data}.${signature}`;
}

async function verifyJwt(token: string, secret: string): Promise<JsonRecord | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, sig] = parts;
  const data = `${h}.${p}`;
  const expected = await hmacSha256(data, secret);
  if (sig !== expected) return null;

  const payloadRaw = base64UrlDecodeToString(p);
  if (!payloadRaw) return null;
  const payload = parseJson(payloadRaw);
  if (!payload) return null;
  const exp = Number(payload.exp ?? 0);
  if (!Number.isFinite(exp) || exp <= nowSeconds()) {
    return null;
  }
  return payload;
}

async function hmacSha256(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return base64UrlEncode(signature);
}

function base64UrlEncode(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecodeToString(input: string): string | null {
  try {
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
    const binary = atob(normalized + padding);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}
