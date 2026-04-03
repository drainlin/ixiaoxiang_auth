import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type VerifiedRegistrationResponse,
} from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/types';

interface Env {
  DB: D1Database;
  OTP_KV: KVNamespace;
  MAIL_GATEWAY?: Fetcher;
  JWT_SECRET: string;
  MAIL_GATEWAY_URL?: string;
  MAIL_GATEWAY_TOKEN?: string;
  MAIL_GATEWAY_SIGNING_SECRET?: string;
  DEFAULT_EMAIL_SUBJECT?: string;
  APP_EMAIL_SUBJECTS?: string;
  APP_NAME?: string;
  APP_ORIGIN?: string;
  APP_BUNDLE_ID?: string;
  DEFAULT_APP_NAME?: string;
  DEFAULT_APP_ORIGIN?: string;
  DEFAULT_APP_BUNDLE_ID?: string;
  ACCESS_TOKEN_TTL_SECONDS?: string;
  REFRESH_TOKEN_TTL_SECONDS?: string;
  OTP_TTL_SECONDS?: string;
  OTP_MAX_ATTEMPTS?: string;
  DEFAULT_APP_ID?: string;
  APP_CONFIGS?: string;
  PASSKEY_RP_ID?: string;
  PASSKEY_RP_NAME?: string;
  PASSKEY_EXPECTED_ORIGINS?: string;
  PASSKEY_CHALLENGE_TTL_SECONDS?: string;
}

type JsonRecord = Record<string, unknown>;
type AppConfig = {
  appName?: unknown;
  appOrigin?: unknown;
  appBundleId?: unknown;
  passkeyRpId?: unknown;
  passkeyRpName?: unknown;
  passkeyExpectedOrigins?: unknown;
};
type AppConfigRecord = Record<string, AppConfig>;

type AppContext = {
  appId: string;
  appName: string;
  appOrigin?: string;
  appBundleId: string;
  passkeyRpId?: string;
  passkeyRpName?: string;
  passkeyExpectedOrigins: string[];
};

const encoder = new TextEncoder();
const DEFAULT_APP_ID = 'default';

class HttpError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: corsHeaders(env, resolveAppContextSafe(request, env)),
        });
      }

      const url = new URL(request.url);
      const path = normalizeApiPath(url.pathname);

      if (request.method === 'POST' && path === '/auth/send-code') {
        return withCors(await handleSendCode(request, env), env, request);
      }
      if (request.method === 'POST' && path === '/auth/verify-code') {
        return withCors(await handleVerifyCode(request, env), env, request);
      }
      if (request.method === 'POST' && path === '/auth/refresh') {
        return withCors(await handleRefresh(request, env), env, request);
      }
      if (request.method === 'POST' && path === '/auth/logout') {
        return withCors(await handleLogout(request, env), env, request);
      }
      if (request.method === 'GET' && path === '/auth/me') {
        return withCors(await handleMe(request, env), env, request);
      }
      if (request.method === 'POST' && path === '/auth/profile') {
        return withCors(await handleUpdateProfile(request, env), env, request);
      }
      if (request.method === 'GET' && path === '/sync/bootstrap') {
        return withCors(await handleSyncBootstrap(request, env), env, request);
      }
      if (request.method === 'GET' && path === '/sync/settings') {
        return withCors(await handleGetSyncSettings(request, env), env, request);
      }
      if (request.method === 'PUT' && path === '/sync/settings') {
        return withCors(await handlePutSyncSettings(request, env), env, request);
      }
      if (request.method === 'GET' && path === '/sync/libraries') {
        return withCors(await handleGetSyncLibraries(request, env), env, request);
      }
      if (request.method === 'PUT' && path === '/sync/libraries') {
        return withCors(await handlePutSyncLibraries(request, env), env, request);
      }
      if (request.method === 'POST' && path === '/auth/passkey/register/start') {
        return withCors(await handlePasskeyRegisterStart(request, env), env, request);
      }
      if (request.method === 'POST' && path === '/auth/passkey/register/finish') {
        return withCors(await handlePasskeyRegisterFinish(request, env), env, request);
      }
      if (request.method === 'POST' && path === '/auth/passkey/login/start') {
        return withCors(await handlePasskeyLoginStart(request, env), env, request);
      }
      if (request.method === 'POST' && path === '/auth/passkey/login/finish') {
        return withCors(await handlePasskeyLoginFinish(request, env), env, request);
      }
      if (request.method === 'GET' && path === '/auth/passkey/settings') {
        return withCors(await handleGetPasskeySettings(request, env), env, request);
      }
      if (request.method === 'PATCH' && path === '/auth/passkey/settings') {
        return withCors(await handlePatchPasskeySettings(request, env), env, request);
      }
      if (request.method === 'GET' && path === '/auth/passkey/credentials') {
        return withCors(await handlePasskeyCredentialsList(request, env), env, request);
      }
      if (request.method === 'PATCH' && path === '/auth/passkey/credential') {
        return withCors(await handlePasskeyCredentialUpdate(request, env), env, request);
      }
      if (request.method === 'DELETE' && path === '/auth/passkey/credential') {
        return withCors(await handlePasskeyCredentialDelete(request, env), env, request);
      }

      return withCors(json({ error: 'not_found' }, 404), env, request);
    } catch (error) {
      if (error instanceof HttpError) {
        return withCors(json({ error: error.code }, error.status), env, request);
      }
      console.error('worker-error', error);
      return withCors(json({ error: 'internal_error' }, 500), env, request);
    }
  },
};

async function handleSendCode(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
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

  await env.OTP_KV.put(otpKey(email, purpose, app.appId), JSON.stringify(value), {
    expirationTtl: otpTtl,
  });

  await sendOtpEmail({ env, app, email, code, ttlSeconds: otpTtl });

  return json({ ok: true, expiresAt });
}

async function handleVerifyCode(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const code = `${body.code ?? ''}`.trim();
  const purpose = normalizePurpose(body.purpose);
  if (!isValidEmail(email) || !/^\d{6}$/.test(code)) {
    return json({ error: 'invalid_payload' }, 400);
  }

  const key = otpKey(email, purpose, app.appId);
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
  const tokens = await issueSessionTokens(env, app, user.id, user.email);

  return json({
    ok: true,
    user,
    tokens,
  });
}

async function handleRefresh(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const body = await readJson(request);
  const refreshToken = `${body.refreshToken ?? ''}`.trim();
  if (!refreshToken) {
    return json({ error: 'missing_refresh_token' }, 400);
  }

  const refreshHash = await sha256(refreshToken);
  const now = nowSeconds();

  const sessionRow = await env.DB.prepare(
    `SELECT s.id AS session_id, s.user_id, s.expires_at, s.revoked_at, s.app_id, u.email
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.refresh_hash = ?1 AND s.app_id = ?2 LIMIT 1`,
  )
    .bind(refreshHash, app.appId)
    .first<{
      session_id: string;
      user_id: string;
      expires_at: number;
      revoked_at: number | null;
      app_id: string;
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

  const tokens = await issueSessionTokens(
    env,
    app,
    sessionRow.user_id,
    sessionRow.email,
  );
  return json({ ok: true, tokens });
}

async function handleLogout(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const body = await readJson(request);
  const refreshToken = `${body.refreshToken ?? ''}`.trim();
  if (!refreshToken) {
    return json({ ok: true });
  }
  const refreshHash = await sha256(refreshToken);
  const now = nowSeconds();

  await env.DB.prepare(
    'UPDATE sessions SET revoked_at = ?1, updated_at = ?1 WHERE refresh_hash = ?2 AND app_id = ?3',
  )
    .bind(now, refreshHash, app.appId)
    .run();

  return json({ ok: true });
}

async function handleMe(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const auth = request.headers.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) {
    return json({ error: 'missing_access_token' }, 401);
  }

  const payload = await verifyJwt(token, env.JWT_SECRET, app.appId);
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

  const profile = await readUserProfile(env.DB, user.id);
  const displayName = profile?.displayName ?? '';
  const avatarDataUrl = profile?.avatarDataUrl ?? '';
  const passkeyLoginEnabled = profile?.passkeyLoginEnabled ?? true;
  const passkeys = await listUserPasskeyCredentials(env.DB, user.id);

  return json({
    ok: true,
    user: {
      ...user,
      display_name: displayName || user.email.split('@')[0] || `${app.appName} User`,
      avatar_url: avatarDataUrl,
      passkey_login_enabled: passkeyLoginEnabled,
    },
    passkeys: passkeys.map(serializePasskeyCredential),
  });
}

async function handleUpdateProfile(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const body = await readJson(request);
  const displayName = `${body.displayName ?? ''}`.trim();
  const avatarDataUrl = `${body.avatarDataUrl ?? ''}`.trim();
  if (!displayName) return json({ error: 'invalid_payload' }, 400);
  if (displayName.length > 80) return json({ error: 'invalid_payload' }, 400);
  const avatarError = validateAvatarDataUrl(avatarDataUrl);
  if (avatarError != null) {
    return json({ error: avatarError }, 400);
  }

  await writeUserProfile(env.DB, authUser.id, {
    displayName,
    avatarDataUrl,
  });

  return json({
    ok: true,
    profile: {
      displayName,
      avatarUrl: avatarDataUrl,
    },
  });
}

async function handleGetPasskeySettings(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const profile = await readUserProfile(env.DB, authUser.id);
  return json({
    ok: true,
    passkeyLoginEnabled: profile?.passkeyLoginEnabled ?? true,
  });
}

async function handlePatchPasskeySettings(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const body = await readJson(request);
  const enabled = body.passkeyLoginEnabled;
  if (typeof enabled !== 'boolean') {
    return json({ error: 'invalid_payload' }, 400);
  }

  await upsertPasskeyLoginEnabled(env.DB, authUser.id, enabled);
  return json({
    ok: true,
    passkeyLoginEnabled: enabled,
  });
}

async function handleSyncBootstrap(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const settings = await readSyncSettings(env.DB, authUser.id, app.appId);
  const libraries = await readLibraryProfiles(env, authUser.id, app.appId);
  return json({
    ok: true,
    settings,
    libraries,
  });
}

async function handleGetSyncSettings(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);
  return json({
    ok: true,
    ...(await readSyncSettings(env.DB, authUser.id, app.appId)),
  });
}

async function handlePutSyncSettings(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const body = await readJson(request);
  const payload = body.payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return json({ error: 'invalid_payload' }, 400);
  }
  const normalizedPayload = payload as JsonRecord;
  const updatedAt = parseTimestamp(body.updatedAt) ?? Date.now();
  const current = await readUserSettings(env.DB, authUser.id, app.appId);
  await writeUserSettings(env.DB, authUser.id, app.appId, {
    ...current,
    sync: {
      schemaVersion: Number(body.schemaVersion ?? 1),
      updatedAt,
      deviceId: `${body.deviceId ?? ''}`.trim(),
      appVersion: `${body.appVersion ?? ''}`.trim(),
      payload: normalizedPayload,
    },
  });
  return json({
    ok: true,
    updatedAt,
  });
}

async function handleGetSyncLibraries(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);
  return json({
    ok: true,
    ...(await readLibraryProfiles(env, authUser.id, app.appId)),
  });
}

async function handlePutSyncLibraries(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const body = await readJson(request);
  const itemsRaw = body.items;
  if (!Array.isArray(itemsRaw)) {
    return json({ error: 'invalid_payload' }, 400);
  }
  const updatedAt = parseTimestamp(body.updatedAt) ?? Date.now();
  const items = itemsRaw
    .map((item) => (item && typeof item === 'object' && !Array.isArray(item)
      ? item as JsonRecord
      : null))
    .filter((item): item is JsonRecord => item !== null);

  await replaceLibraryProfiles(env, authUser.id, app.appId, items, updatedAt);
  return json({
    ok: true,
    updatedAt,
  });
}

function validateAvatarDataUrl(input: string): string | null {
  if (!input) return null;
  if (!input.startsWith('data:image/')) return 'invalid_payload';
  const marker = ';base64,';
  const idx = input.indexOf(marker);
  if (idx <= 0) return 'invalid_payload';
  const base64 = input.substring(idx + marker.length);
  if (!base64) return 'invalid_payload';
  // ~1.5MB base64 payload hard limit to prevent oversized DB writes.
  if (base64.length > 2_000_000) return 'avatar_too_large';
  return null;
}

async function readUserSettings(
  db: D1Database,
  userId: string,
  appId: string,
): Promise<JsonRecord> {
  const row = await db
    .prepare(
      'SELECT payload_json FROM user_settings WHERE user_id = ?1 AND app_id = ?2 LIMIT 1',
    )
    .bind(userId, appId)
    .first<{ payload_json: string }>();
  if (!row?.payload_json) return {};
  const parsed = parseJson(row.payload_json);
  return parsed ?? {};
}

async function readUserProfile(
  db: D1Database,
  userId: string,
): Promise<{ displayName: string; avatarDataUrl: string; passkeyLoginEnabled: boolean } | null> {
  const row = await db
    .prepare(
      'SELECT display_name, avatar_data_url, passkey_login_enabled FROM user_profiles WHERE user_id = ?1 LIMIT 1',
    )
    .bind(userId)
    .first<{
      display_name: string | null;
      avatar_data_url: string | null;
      passkey_login_enabled: number | null;
    }>();
  if (!row) return null;
  return {
    displayName: `${row.display_name ?? ''}`.trim(),
    avatarDataUrl: `${row.avatar_data_url ?? ''}`.trim(),
    passkeyLoginEnabled: Number(row.passkey_login_enabled ?? 1) === 1,
  };
}

async function readSyncSettings(
  db: D1Database,
  userId: string,
  appId: string,
): Promise<JsonRecord> {
  const current = await readUserSettings(db, userId, appId);
  const sync = current.sync;
  if (!sync || typeof sync !== 'object' || Array.isArray(sync)) {
    return {
      payload: {},
      updatedAt: 0,
      schemaVersion: 1,
    };
  }
  const map = sync as JsonRecord;
  return {
    payload:
      map.payload && typeof map.payload === 'object' && !Array.isArray(map.payload)
        ? map.payload
        : {},
    updatedAt: parseTimestamp(map.updatedAt) ?? 0,
    schemaVersion: Number(map.schemaVersion ?? 1),
  };
}

async function writeUserSettings(
  db: D1Database,
  userId: string,
  appId: string,
  payload: JsonRecord,
): Promise<void> {
  const now = nowSeconds();
  await db
    .prepare(
      `INSERT INTO user_settings (user_id, app_id, payload_json, updated_at)
       VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT(user_id, app_id) DO UPDATE SET
         payload_json = excluded.payload_json,
         updated_at = excluded.updated_at`,
    )
    .bind(userId, appId, JSON.stringify(payload), now)
    .run();
}

async function writeUserProfile(
  db: D1Database,
  userId: string,
  profile: { displayName: string; avatarDataUrl: string },
): Promise<void> {
  const now = nowSeconds();
  await db
    .prepare(
      `INSERT INTO user_profiles (user_id, display_name, avatar_data_url, updated_at)
       VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT(user_id) DO UPDATE SET
         display_name = excluded.display_name,
         avatar_data_url = excluded.avatar_data_url,
         updated_at = excluded.updated_at`,
    )
    .bind(userId, profile.displayName, profile.avatarDataUrl, now)
    .run();
}

async function upsertPasskeyLoginEnabled(
  db: D1Database,
  userId: string,
  enabled: boolean,
): Promise<void> {
  const now = nowSeconds();
  await db
    .prepare(
      `INSERT INTO user_profiles (user_id, display_name, avatar_data_url, passkey_login_enabled, updated_at)
       VALUES (?1, NULL, NULL, ?2, ?3)
       ON CONFLICT(user_id) DO UPDATE SET
         passkey_login_enabled = excluded.passkey_login_enabled,
         updated_at = excluded.updated_at`,
    )
    .bind(userId, enabled ? 1 : 0, now)
    .run();
}

async function readLibraryProfiles(
  env: Env,
  userId: string,
  appId: string,
): Promise<JsonRecord> {
  const rows = await env.DB
    .prepare(
      `SELECT id, display_name, provider_type, server_url, username, encrypted_secret, meta_json, updated_at
         FROM library_profiles
        WHERE user_id = ?1 AND app_id = ?2
        ORDER BY updated_at DESC, id ASC`,
    )
    .bind(userId, appId)
    .all<{
      id: string;
      display_name: string;
      provider_type: string;
      server_url: string;
      username: string | null;
      encrypted_secret: string | null;
      meta_json: string | null;
      updated_at: number;
    }>();
  const items = await Promise.all(
    (rows.results ?? []).map(async (row: {
      id: string;
      display_name: string;
      provider_type: string;
      server_url: string;
      username: string | null;
      encrypted_secret: string | null;
      meta_json: string | null;
      updated_at: number;
    }) => {
      const meta = row.meta_json ? parseJson(row.meta_json) ?? {} : {};
      const secret = row.encrypted_secret
        ? await decryptJsonRecord(env, appId, row.encrypted_secret)
        : {};
      return {
        id: row.id,
        displayName: row.display_name,
        providerType: row.provider_type,
        serverUrl: row.server_url,
        username: row.username ?? '',
        meta,
        secret,
        updatedAt: row.updated_at,
        createdAt: `${(meta.createdAt ?? '')}`.trim(),
      };
    }),
  );
  const updatedAt = items.reduce<number>(
    (max: number, item: { updatedAt: number }) =>
      Math.max(max, parseTimestamp(item.updatedAt) ?? 0),
    0,
  );
  return {
    items,
    updatedAt,
    schemaVersion: 1,
  };
}

async function replaceLibraryProfiles(
  env: Env,
  userId: string,
  appId: string,
  items: JsonRecord[],
  updatedAt: number,
): Promise<void> {
  await env.DB
    .prepare('DELETE FROM library_profiles WHERE user_id = ?1 AND app_id = ?2')
    .bind(userId, appId)
    .run();

  for (const item of items) {
    const id = `${item.id ?? ''}`.trim();
    const displayName = `${item.displayName ?? ''}`.trim();
    const providerType = `${item.providerType ?? ''}`.trim() || 'emby';
    const serverUrl = `${item.serverUrl ?? ''}`.trim();
    const username = `${item.username ?? ''}`.trim();
    if (!id || !displayName || !serverUrl) {
      continue;
    }
    const meta = item.meta && typeof item.meta === 'object' && !Array.isArray(item.meta)
      ? { ...(item.meta as JsonRecord), createdAt: `${item.createdAt ?? ''}`.trim() }
      : { createdAt: `${item.createdAt ?? ''}`.trim() };
    const secret = item.secret && typeof item.secret === 'object' && !Array.isArray(item.secret)
      ? item.secret as JsonRecord
      : {};
    const encryptedSecret = await encryptJsonRecord(env, appId, secret);
    await env.DB
      .prepare(
        `INSERT INTO library_profiles (
            id, user_id, app_id, provider_type, display_name, server_url,
            username, encrypted_secret, meta_json, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
      )
      .bind(
        id,
        userId,
        appId,
        providerType,
        displayName,
        serverUrl,
        username,
        encryptedSecret,
        JSON.stringify(meta),
        Math.floor(updatedAt / 1000),
      )
      .run();
  }
}

type AuthUser = { id: string; email: string };

type StoredPasskeyCredential = {
  id: string;
  user_id: string;
  credential_id: string;
  alias: string;
  public_key_b64url: string;
  counter: number;
  transports_json: string | null;
  device_type: string | null;
  backed_up: number | null;
  created_at: number;
  updated_at: number;
  last_used_at: number | null;
};

type PasskeyCredentialItem = {
  credentialId: string;
  alias: string;
  addedAt: number;
  deviceType: string | null;
  backedUp: boolean;
  transports: AuthenticatorTransportFuture[];
  counter: number;
  createdAt: number;
  updatedAt: number;
  lastUsedAt: number | null;
};

async function handlePasskeyRegisterStart(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const body = await readJson(request);
  const userId = `${body.userId ?? authUser.id}`.trim();
  const userName = normalizeEmail(body.email ?? authUser.email);
  const userDisplayName = `${body.displayName ?? userName}`.trim();
  if (!userId || !isValidEmail(userName) || userId !== authUser.id) {
    return json({ error: 'invalid_payload' }, 400);
  }

  const rpID = resolvePasskeyRpId(env, app);
  const rpName = app.passkeyRpName ?? app.appName;
  const challengeTtl = intVar(env.PASSKEY_CHALLENGE_TTL_SECONDS, 300);
  const credentials = await listUserPasskeyCredentials(env.DB, userId);

  const options = await generateRegistrationOptions({
    rpID,
    rpName,
    userName,
    userDisplayName: userDisplayName || userName,
    userID: encoder.encode(userId),
    timeout: 60_000,
    attestationType: 'none',
    excludeCredentials: credentials.map((item) => ({
      id: item.credential_id,
      transports: parseTransports(item.transports_json),
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  await env.OTP_KV.put(
    passkeyRegisterChallengeKey(app.appId, userId),
    JSON.stringify({
      challenge: options.challenge,
      userId,
      email: userName,
      appId: app.appId,
      expiresAt: nowSeconds() + challengeTtl,
    }),
    { expirationTtl: challengeTtl },
  );

  return json({ ok: true, options });
}

async function handlePasskeyRegisterFinish(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const body = await readJson(request);
  const credential = body.credential;
  if (!credential || typeof credential !== 'object') {
    return json({ error: 'invalid_payload' }, 400);
  }

  const challengeRaw = await env.OTP_KV.get(passkeyRegisterChallengeKey(app.appId, authUser.id));
  if (!challengeRaw) return json({ error: 'passkey_challenge_expired' }, 400);
  const challengeState = parseJson(challengeRaw);
  if (
    !challengeState ||
    `${challengeState.userId ?? ''}`.trim() !== authUser.id ||
    `${challengeState.appId ?? ''}`.trim() !== app.appId
  ) {
    return json({ error: 'passkey_challenge_invalid' }, 400);
  }

  const expectedOrigin = resolvePasskeyExpectedOrigins(env, app);
  const expectedRPID = resolvePasskeyRpId(env, app);

  let verification: VerifiedRegistrationResponse;
  try {
    verification = await verifyRegistrationResponse({
      response: credential as Parameters<typeof verifyRegistrationResponse>[0]['response'],
      expectedChallenge: `${challengeState.challenge ?? ''}`,
      expectedOrigin,
      expectedRPID,
      requireUserVerification: false,
    });
  } catch (error) {
    console.error('passkey-register-verify-error', error);
    return json({ error: 'passkey_verification_failed' }, 400);
  }

  if (!verification.verified || !verification.registrationInfo) {
    return json({ error: 'passkey_verification_failed' }, 400);
  }

  const info = verification.registrationInfo;
  const responsePayload = (credential as { response?: { transports?: unknown } }).response;
  const transports =
    responsePayload && Array.isArray(responsePayload.transports)
      ? responsePayload.transports.map((item) => `${item ?? ''}`.trim()).filter(Boolean)
      : [];
  const now = nowSeconds();
  await env.DB.prepare(
    `INSERT INTO passkey_credentials
      (id, user_id, credential_id, alias, public_key_b64url, counter, transports_json, device_type, backed_up, created_at, updated_at, last_used_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?10)
     ON CONFLICT(credential_id) DO UPDATE SET
      user_id = excluded.user_id,
      alias = COALESCE(NULLIF(alias, ''), excluded.alias),
      public_key_b64url = excluded.public_key_b64url,
      counter = excluded.counter,
      transports_json = excluded.transports_json,
      device_type = excluded.device_type,
      backed_up = excluded.backed_up,
      updated_at = excluded.updated_at,
      last_used_at = excluded.last_used_at`,
  )
    .bind(
      crypto.randomUUID(),
      authUser.id,
      info.credentialID,
      '',
      base64UrlEncode(info.credentialPublicKey),
      info.counter,
      JSON.stringify(transports),
      info.credentialDeviceType,
      info.credentialBackedUp ? 1 : 0,
      now,
    )
    .run();

  await env.OTP_KV.delete(passkeyRegisterChallengeKey(app.appId, authUser.id));
  return json({ ok: true });
}

async function handlePasskeyCredentialsList(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const credentials = await listUserPasskeyCredentials(env.DB, authUser.id);
  return json({
    ok: true,
    items: credentials.map(serializePasskeyCredential),
  });
}

async function handlePasskeyCredentialUpdate(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const body = await readJson(request);
  const credentialId = `${body.credentialId ?? ''}`.trim();
  const alias = `${body.alias ?? ''}`.trim();
  if (!credentialId || alias.length > 80) {
    return json({ error: 'invalid_payload' }, 400);
  }

  const now = nowSeconds();
  const result = await env.DB.prepare(
    `UPDATE passkey_credentials
        SET alias = ?1,
            updated_at = ?2
      WHERE user_id = ?3 AND credential_id = ?4`,
  )
    .bind(alias, now, authUser.id, credentialId)
    .run();

  return json({
    ok: true,
    updated: result.meta?.changes ?? 0,
  });
}

async function handlePasskeyLoginStart(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const body = await readJson(request);
  const email = normalizeEmail(body.email);

  const rpID = resolvePasskeyRpId(env, app);
  const challengeTtl = intVar(env.PASSKEY_CHALLENGE_TTL_SECONDS, 300);
  let loginUserId: string | undefined;
  let loginEmail: string | undefined;
  let options: Awaited<ReturnType<typeof generateAuthenticationOptions>>;

  if (isValidEmail(email)) {
    const user = await env.DB
      .prepare('SELECT id, email FROM users WHERE email = ?1 LIMIT 1')
      .bind(email)
      .first<{ id: string; email: string }>();
    if (!user) {
      return json({ error: 'passkey_no_credentials' }, 404);
    }

    const passkeyLoginEnabled = await isPasskeyLoginEnabled(env.DB, user.id);
    if (!passkeyLoginEnabled) {
      return json({ error: 'passkey_login_disabled' }, 403);
    }

    const credentials = await listUserPasskeyCredentials(env.DB, user.id);
    if (credentials.length === 0) {
      return json({ error: 'passkey_no_credentials' }, 404);
    }

    loginUserId = user.id;
    loginEmail = user.email;
    options = await generateAuthenticationOptions({
      rpID,
      timeout: 60_000,
      userVerification: 'preferred',
      allowCredentials: credentials.map((item) => ({
        id: item.credential_id,
        transports: parseTransports(item.transports_json),
      })),
    });
  } else {
    options = await generateAuthenticationOptions({
      rpID,
      timeout: 60_000,
      userVerification: 'preferred',
    });
  }

  await env.OTP_KV.put(
    passkeyLoginChallengeKey(app.appId, options.challenge),
    JSON.stringify({
      challenge: options.challenge,
      userId: loginUserId,
      email: loginEmail,
      appId: app.appId,
      expiresAt: nowSeconds() + challengeTtl,
    }),
    { expirationTtl: challengeTtl },
  );

  return json({ ok: true, options });
}

async function handlePasskeyLoginFinish(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const body = await readJson(request);
  const credential = body.credential;
  if (!credential || typeof credential !== 'object') {
    return json({ error: 'invalid_payload' }, 400);
  }

  const challenge = extractChallengeFromCredential(credential as JsonRecord);
  if (!challenge) return json({ error: 'passkey_challenge_invalid' }, 400);
  const challengeRaw = await env.OTP_KV.get(passkeyLoginChallengeKey(app.appId, challenge));
  if (!challengeRaw) return json({ error: 'passkey_challenge_expired' }, 400);
  const challengeState = parseJson(challengeRaw);
  if (!challengeState) return json({ error: 'passkey_challenge_invalid' }, 400);

  const credentialId = `${(credential as JsonRecord).id ?? ''}`.trim();
  if (!credentialId) return json({ error: 'invalid_payload' }, 400);

  const dbCredential = await env.DB.prepare(
    `SELECT id, user_id, credential_id, alias, public_key_b64url, counter, transports_json, device_type, backed_up, created_at, updated_at, last_used_at
       FROM passkey_credentials
      WHERE credential_id = ?1 LIMIT 1`,
  )
    .bind(credentialId)
    .first<StoredPasskeyCredential>();
  if (!dbCredential) return json({ error: 'passkey_no_credentials' }, 404);

  const passkeyLoginEnabled = await isPasskeyLoginEnabled(env.DB, dbCredential.user_id);
  if (!passkeyLoginEnabled) {
    return json({ error: 'passkey_login_disabled' }, 403);
  }

  const challengeUserId = `${challengeState.userId ?? ''}`.trim();
  const challengeAppId = `${challengeState.appId ?? ''}`.trim();
  if (challengeAppId !== app.appId) {
    return json({ error: 'passkey_challenge_invalid' }, 400);
  }
  // For discoverable passkey flow (no email on start), challenge userId may be empty.
  // Only enforce userId match when start step already resolved a specific user.
  if (challengeUserId.length > 0 && challengeUserId !== dbCredential.user_id) {
    return json({ error: 'passkey_challenge_invalid' }, 400);
  }

  const expectedOrigin = resolvePasskeyExpectedOrigins(env, app);
  const expectedRPID = resolvePasskeyRpId(env, app);

  try {
    const verification = await verifyAuthenticationResponse({
      response: credential as Parameters<typeof verifyAuthenticationResponse>[0]['response'],
      expectedChallenge: `${challengeState.challenge ?? ''}`,
      expectedOrigin,
      expectedRPID,
      requireUserVerification: false,
      authenticator: {
        credentialID: dbCredential.credential_id,
        credentialPublicKey: base64UrlDecode(dbCredential.public_key_b64url),
        counter: Number(dbCredential.counter || 0),
        transports: parseTransports(dbCredential.transports_json),
      },
    });

    if (!verification.verified) {
      return json({ error: 'passkey_verification_failed' }, 400);
    }

    const now = nowSeconds();
    await env.DB.prepare(
      'UPDATE passkey_credentials SET counter = ?1, updated_at = ?2, last_used_at = ?2 WHERE credential_id = ?3',
    )
      .bind(verification.authenticationInfo.newCounter, now, dbCredential.credential_id)
      .run();

    const user = await env.DB
      .prepare('SELECT id, email, status, created_at FROM users WHERE id = ?1 LIMIT 1')
      .bind(dbCredential.user_id)
      .first<{ id: string; email: string; status: string; created_at: number }>();
    if (!user) return json({ error: 'user_not_found' }, 404);

    const tokens = await issueSessionTokens(env, app, user.id, user.email);
    await env.OTP_KV.delete(passkeyLoginChallengeKey(app.appId, challenge));
    return json({ ok: true, user, tokens });
  } catch (error) {
    console.error('passkey-login-verify-error', error);
    return json({ error: 'passkey_verification_failed' }, 400);
  }
}

async function handlePasskeyCredentialDelete(request: Request, env: Env): Promise<Response> {
  const app = resolveAppContext(request, env);
  const authUser = await requireAuthUser(request, env, app);
  if (!authUser) return json({ error: 'invalid_access_token' }, 401);

  const body = await readJson(request);
  const credentialId = `${body.credentialId ?? ''}`.trim();
  const deleted = credentialId
    ? await env.DB
        .prepare('DELETE FROM passkey_credentials WHERE user_id = ?1 AND credential_id = ?2')
        .bind(authUser.id, credentialId)
        .run()
    : await env.DB.prepare('DELETE FROM passkey_credentials WHERE user_id = ?1')
        .bind(authUser.id)
        .run();

  return json({ ok: true, deleted: deleted.meta?.changes ?? 0 });
}

async function issueSessionTokens(env: Env, app: AppContext, userId: string, email: string) {
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
      aud: app.appId,
    },
    env.JWT_SECRET,
  );

  const refreshToken = `${crypto.randomUUID()}.${crypto.randomUUID()}`;
  const refreshHash = await sha256(refreshToken);
  const sessionId = crypto.randomUUID();

  await env.DB.prepare(
    `INSERT INTO sessions (id, app_id, user_id, refresh_hash, expires_at, revoked_at, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?6)`,
  )
    .bind(sessionId, app.appId, userId, refreshHash, now + refreshTtl, now)
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
  app: AppContext;
  email: string;
  code: string;
  ttlSeconds: number;
}) {
  const appName = args.app.appName;
  const signingSecret = `${args.env.MAIL_GATEWAY_SIGNING_SECRET ?? ''}`.trim();
  const token = `${args.env.MAIL_GATEWAY_TOKEN ?? ''}`.trim();
  const bundleId = `${args.app.appBundleId ?? ''}`.trim();
  if (!signingSecret || !bundleId) {
    throw new Error('mail_gateway_not_configured');
  }
  const subject = resolveEmailSubject(args.env, args.app.appId, appName);
  const safeAppName = escapeHtml(appName);
  const safeCode = escapeHtml(args.code);
  const minutes = Math.max(1, Math.floor(args.ttlSeconds / 60));
  const text = [
    `${appName} verification code: ${args.code}`,
    `Expires in ${minutes} minute(s).`,
    'If you did not request this code, please ignore this email.',
  ].join('\n');
  const html = [
    '<!doctype html>',
    '<html lang="en">',
    '  <head>',
    '    <meta charset="utf-8" />',
    '    <meta name="viewport" content="width=device-width, initial-scale=1" />',
    `    <title>${safeAppName} Verification Code</title>`,
    '  </head>',
    "  <body style=\"margin:0;padding:0;background:#f3f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;color:#111827;\">",
    '    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f5f9;padding:24px 12px;">',
    '      <tr>',
    '        <td align="center">',
    '          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #e5e7eb;">',
    '            <tr>',
    '              <td style="background:linear-gradient(135deg,#1d4ed8 0%,#0ea5e9 100%);padding:20px 24px;">',
    `                <div style="font-size:13px;letter-spacing:0.08em;text-transform:uppercase;color:#bfdbfe;">${safeAppName}</div>`,
    '                <div style="margin-top:6px;font-size:22px;font-weight:700;color:#ffffff;">Verification Code</div>',
    '              </td>',
    '            </tr>',
    '            <tr>',
    '              <td style="padding:24px;">',
    `                <p style="margin:0 0 12px 0;font-size:15px;line-height:1.6;color:#374151;">Use this code to continue signing in to <strong>${safeAppName}</strong>.</p>`,
    '                <div style="margin:18px 0 12px 0;padding:14px 16px;border:1px dashed #93c5fd;border-radius:12px;background:#eff6ff;text-align:center;">',
    `                  <span style="font-size:34px;line-height:1;font-weight:800;letter-spacing:0.35em;color:#1d4ed8;">${safeCode}</span>`,
    '                </div>',
    `                <p style="margin:0 0 10px 0;font-size:14px;line-height:1.6;color:#4b5563;">This code expires in <strong>${minutes} minute(s)</strong>.</p>`,
    '                <p style="margin:0;font-size:13px;line-height:1.6;color:#6b7280;">If you did not request this email, you can safely ignore it.</p>',
    '              </td>',
    '            </tr>',
    '            <tr>',
    '              <td style="padding:14px 24px;background:#f9fafb;border-top:1px solid #f3f4f6;">',
    `                <p style="margin:0;font-size:12px;color:#9ca3af;">&copy; ${safeAppName} • Automated security message</p>`,
    '              </td>',
    '            </tr>',
    '          </table>',
    '        </td>',
    '      </tr>',
    '    </table>',
    '  </body>',
    '</html>',
  ].join('');
  const body: JsonRecord = {
    app_id: args.app.appId,
    to: [args.email],
    subject,
    html,
    text,
  };
  const serializedBody = JSON.stringify(body);
  const timestamp = `${nowSeconds()}`;
  const nonce = crypto.randomUUID();
  const bodyHash = await sha256Hex(serializedBody);
  const canonical = [
    'POST',
    '/v1/email/send',
    args.app.appId,
    bundleId,
    timestamp,
    nonce,
    bodyHash,
  ].join('\n');
  const signature = await hmacSha256Hex(signingSecret, canonical);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-App-Id': args.app.appId,
    'X-Bundle-Id': bundleId,
    'X-Timestamp': timestamp,
    'X-Nonce': nonce,
    'X-Signature': signature,
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const requestInit: RequestInit = {
    method: 'POST',
    headers,
    body: serializedBody,
  };
  const response = args.env.MAIL_GATEWAY
    ? await args.env.MAIL_GATEWAY.fetch('https://mail-gateway.internal/v1/email/send', requestInit)
    : await fetch(
        `${`${args.env.MAIL_GATEWAY_URL ?? ''}`.trim().replace(/\/+$/, '')}/v1/email/send`,
        requestInit,
      );

  if (!response.ok) {
    const detail = (await response.text()).slice(0, 500);
    throw new Error(`send_email_via_mail_gateway_failed:${response.status}:${detail}`);
  }
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function resolveEmailSubject(env: Env, appId: string, appName: string): string {
  const defaultTemplate = `${env.DEFAULT_EMAIL_SUBJECT ?? '{app_name} Verification Code'}`.trim()
    || '{app_name} Verification Code';
  const mapRaw = `${env.APP_EMAIL_SUBJECTS ?? ''}`.trim();
  if (!mapRaw) {
    return renderSubjectTemplate(defaultTemplate, appId, appName);
  }

  try {
    const parsed = JSON.parse(mapRaw) as Record<string, unknown>;
    if (parsed && typeof parsed === 'object') {
      const appTemplate = `${parsed[appId] ?? ''}`.trim();
      const template = appTemplate || defaultTemplate;
      return renderSubjectTemplate(template, appId, appName);
    }
  } catch {
    // no-op: fallback to default template
  }

  return renderSubjectTemplate(defaultTemplate, appId, appName);
}

function renderSubjectTemplate(template: string, appId: string, appName: string): string {
  return template
    .replaceAll('{app_name}', appName)
    .replaceAll('{app_id}', appId || 'default');
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

function otpKey(email: string, purpose: string, appId: string): string {
  return `otp:${appId}:${purpose}:${email}`;
}

function passkeyRegisterChallengeKey(appId: string, userId: string): string {
  return `passkey:${appId}:register:${userId}`;
}

function passkeyLoginChallengeKey(appId: string, challenge: string): string {
  return `passkey:${appId}:login:${challenge}`;
}

function extractChallengeFromCredential(credential: JsonRecord): string | null {
  const response = credential.response;
  if (!response || typeof response !== 'object') return null;
  const clientDataJSON = `${(response as JsonRecord).clientDataJSON ?? ''}`.trim();
  if (!clientDataJSON) return null;
  try {
    const decoded = base64UrlDecodeToString(clientDataJSON);
    if (!decoded) return null;
    const parsed = parseJson(decoded);
    if (!parsed || typeof parsed !== 'object') return null;
    const challenge = `${(parsed as JsonRecord).challenge ?? ''}`.trim();
    return challenge || null;
  } catch {
    return null;
  }
}

async function requireAuthUser(
  request: Request,
  env: Env,
  app: AppContext,
): Promise<AuthUser | null> {
  const auth = request.headers.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) return null;

  const payload = await verifyJwt(token, env.JWT_SECRET, app.appId);
  if (!payload || typeof payload.sub !== 'string') return null;

  const user = await env.DB
    .prepare('SELECT id, email FROM users WHERE id = ?1 LIMIT 1')
    .bind(payload.sub)
    .first<AuthUser>();
  return user ?? null;
}

function resolvePasskeyRpId(env: Env, app: AppContext): string {
  const configured = `${app.passkeyRpId ?? ''}`.trim();
  if (configured) return configured;

  const globalConfigured = `${env.PASSKEY_RP_ID ?? ''}`.trim();
  if (globalConfigured) return globalConfigured;

  const appOrigin = `${app.appOrigin ?? ''}`.trim();
  if (appOrigin) {
    try {
      return new URL(appOrigin).hostname;
    } catch {
      // no-op
    }
  }
  throw new HttpError(501, 'passkey_not_supported_server');
}

function resolvePasskeyExpectedOrigins(env: Env, app: AppContext): string[] {
  if (app.passkeyExpectedOrigins.length > 0) {
    return app.passkeyExpectedOrigins;
  }

  const explicit = `${env.PASSKEY_EXPECTED_ORIGINS ?? ''}`
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (explicit.length > 0) return explicit;

  const appOrigin = `${app.appOrigin ?? ''}`.trim();
  if (appOrigin) return [appOrigin];

  const rpID = `${env.PASSKEY_RP_ID ?? ''}`.trim();
  if (rpID) return [`https://${rpID}`];

  throw new HttpError(501, 'passkey_not_supported_server');
}

function parseTransports(raw: string | null): AuthenticatorTransportFuture[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((item) => `${item ?? ''}`.trim())
      .filter(Boolean) as AuthenticatorTransportFuture[];
  } catch {
    return [];
  }
}

async function listUserPasskeyCredentials(
  db: D1Database,
  userId: string,
): Promise<StoredPasskeyCredential[]> {
  const rows = await db
    .prepare(
      `SELECT id, user_id, credential_id, alias, public_key_b64url, counter, transports_json, device_type, backed_up, created_at, updated_at, last_used_at
         FROM passkey_credentials
        WHERE user_id = ?1
        ORDER BY updated_at DESC, created_at DESC, credential_id ASC`,
    )
    .bind(userId)
    .all<StoredPasskeyCredential>();
  return rows.results ?? [];
}

function serializePasskeyCredential(item: StoredPasskeyCredential): PasskeyCredentialItem {
  return {
    credentialId: item.credential_id,
    alias: `${item.alias ?? ''}`.trim(),
    addedAt: Number(item.created_at ?? 0),
    deviceType: `${item.device_type ?? ''}`.trim() || null,
    backedUp: Number(item.backed_up ?? 0) === 1,
    transports: parseTransports(item.transports_json),
    counter: Number(item.counter ?? 0),
    createdAt: Number(item.created_at ?? 0),
    updatedAt: Number(item.updated_at ?? 0),
    lastUsedAt: item.last_used_at == null ? null : Number(item.last_used_at),
  };
}

async function isPasskeyLoginEnabled(db: D1Database, userId: string): Promise<boolean> {
  const row = await db
    .prepare('SELECT passkey_login_enabled FROM user_profiles WHERE user_id = ?1 LIMIT 1')
    .bind(userId)
    .first<{ passkey_login_enabled: number | null }>();
  return Number(row?.passkey_login_enabled ?? 1) === 1;
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

function withCors(response: Response, env: Env, request: Request): Response {
  const app = resolveAppContextSafe(request, env);
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(env, app, request))) {
    headers.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function corsHeaders(env: Env, app?: AppContext, request?: Request): Record<string, string> {
  const requestOrigin = request?.headers.get('origin')?.trim();
  const allowList = new Set<string>();
  if (app?.appOrigin) allowList.add(app.appOrigin);
  for (const item of app?.passkeyExpectedOrigins ?? []) {
    allowList.add(item);
  }
  if (allowList.size === 0) {
    const legacyOrigin = `${env.APP_ORIGIN ?? ''}`.trim();
    if (legacyOrigin) allowList.add(legacyOrigin);
  }

  const allowOrigin = (() => {
    if (!requestOrigin) {
      return allowList.values().next().value ?? '*';
    }
    if (allowList.size === 0 || allowList.has(requestOrigin)) {
      return requestOrigin;
    }
    return allowList.values().next().value ?? '*';
  })();

  return {
    'access-control-allow-origin': allowOrigin,
    'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'access-control-allow-headers': 'content-type,authorization,x-app-id',
    'access-control-max-age': '86400',
    vary: 'Origin, X-App-Id',
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

async function verifyJwt(
  token: string,
  secret: string,
  expectedAud?: string,
): Promise<JsonRecord | null> {
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
  if (expectedAud) {
    const aud = payload.aud;
    if (aud == null) {
      // Backward compatibility: tokens issued before audience support.
      return payload;
    }
    if (typeof aud === 'string') {
      if (aud !== expectedAud) return null;
    } else if (Array.isArray(aud)) {
      const matched = aud.some((item) => `${item ?? ''}`.trim() === expectedAud);
      if (!matched) return null;
    } else {
      return null;
    }
  }
  return payload;
}

function resolveAppContextSafe(request: Request, env: Env): AppContext | undefined {
  try {
    return resolveAppContext(request, env);
  } catch {
    return undefined;
  }
}

function resolveAppContext(request: Request, env: Env): AppContext {
  const appConfigs = readAppConfigs(env.APP_CONFIGS);
  const defaultAppId = `${env.DEFAULT_APP_ID ?? ''}`.trim().toLowerCase() || DEFAULT_APP_ID;
  const requested = resolveRequestedAppId(request, defaultAppId);

  if (appConfigs && !appConfigs[requested]) {
    throw new HttpError(400, 'unknown_app');
  }
  const selected = appConfigs?.[requested] ?? {};

  const appName =
    `${selected.appName ?? env.APP_NAME ?? env.DEFAULT_APP_NAME ?? 'Auth Service'}`
      .trim() || 'Auth Service';
  const appOrigin = normalizeOptionalString(
    selected.appOrigin ?? env.APP_ORIGIN ?? env.DEFAULT_APP_ORIGIN,
  );
  const appBundleId =
    `${selected.appBundleId ?? env.APP_BUNDLE_ID ?? env.DEFAULT_APP_BUNDLE_ID ?? 'com.example.auth'}`
      .trim() || 'com.example.auth';
  const passkeyRpId = normalizeOptionalString(selected.passkeyRpId ?? env.PASSKEY_RP_ID);
  const passkeyRpName = `${selected.passkeyRpName ?? env.PASSKEY_RP_NAME ?? appName}`.trim() || appName;
  const passkeyExpectedOrigins = normalizeStringArray(
    selected.passkeyExpectedOrigins ?? env.PASSKEY_EXPECTED_ORIGINS,
  );

  return {
    appId: requested,
    appName,
    appOrigin,
    appBundleId,
    passkeyRpId,
    passkeyRpName,
    passkeyExpectedOrigins,
  };
}

function resolveRequestedAppId(request: Request, fallback: string): string {
  const fromHeader = `${request.headers.get('x-app-id') ?? ''}`.trim().toLowerCase();
  const fromQuery = new URL(request.url).searchParams.get('app_id')?.trim().toLowerCase() ?? '';
  const appId = fromHeader || fromQuery || fallback;
  if (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(appId)) {
    throw new HttpError(400, 'invalid_app_id');
  }
  return appId;
}

function normalizeApiPath(pathname: string): string {
  const normalized = pathname.replace(/\/+$/, '') || '/';
  if (normalized === '/video') return '/';
  if (normalized.startsWith('/video/')) {
    return normalized.slice('/video'.length) || '/';
  }
  return normalized;
}

function readAppConfigs(raw: string | undefined): AppConfigRecord | null {
  const text = `${raw ?? ''}`.trim();
  if (!text) return null;
  try {
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('invalid_app_configs');
    }
    return parsed as AppConfigRecord;
  } catch (error) {
    console.error('invalid-app-configs', error);
    throw new HttpError(500, 'invalid_app_configs');
  }
}

function normalizeOptionalString(value: unknown): string | undefined {
  const text = `${value ?? ''}`.trim();
  return text || undefined;
}

function normalizeStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .map((item) => `${item ?? ''}`.trim())
      .filter(Boolean);
  }
  const text = `${value ?? ''}`.trim();
  if (!text) return [];
  return text
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
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

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return toHex(new Uint8Array(signature));
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return toHex(new Uint8Array(digest));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((value) => value.toString(16).padStart(2, '0'))
    .join('');
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

function base64UrlDecode(input: string): Uint8Array {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const binary = atob(normalized + padding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function parseTimestamp(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  const parsed = Number.parseInt(`${value ?? ''}`, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

async function deriveSyncKey(secret: string, appId: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(`${secret}:${appId}:sync`),
  );
  return crypto.subtle.importKey('raw', digest, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encryptJsonRecord(
  env: Env,
  appId: string,
  payload: JsonRecord,
): Promise<string> {
  const key = await deriveSyncKey(env.JWT_SECRET, appId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = encoder.encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded,
  );
  return `${base64UrlEncode(iv)}.${base64UrlEncode(ciphertext)}`;
}

async function decryptJsonRecord(
  env: Env,
  appId: string,
  value: string,
): Promise<JsonRecord> {
  const [ivRaw, dataRaw] = value.split('.', 2);
  if (!ivRaw || !dataRaw) return {};
  try {
    const key = await deriveSyncKey(env.JWT_SECRET, appId);
    const iv = base64UrlDecode(ivRaw);
    const ivBuffer = iv.buffer.slice(
      iv.byteOffset,
      iv.byteOffset + iv.byteLength,
    ) as ArrayBuffer;
    const data = base64UrlDecode(dataRaw);
    const dataBuffer = data.buffer.slice(
      data.byteOffset,
      data.byteOffset + data.byteLength,
    ) as ArrayBuffer;
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBuffer },
      key,
      dataBuffer,
    );
    const decoded = new TextDecoder().decode(plaintext);
    return parseJson(decoded) ?? {};
  } catch {
    return {};
  }
}
