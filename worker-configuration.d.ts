interface D1Result<T = unknown> {
  results?: T[];
}

interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = unknown>(): Promise<T | null>;
  all<T = unknown>(): Promise<D1Result<T>>;
  run(): Promise<{ meta?: { changes?: number } }>;
}

interface D1Database {
  prepare(query: string): D1PreparedStatement;
}

interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(
    key: string,
    value: string,
    options?: { expirationTtl?: number },
  ): Promise<void>;
  delete(key: string): Promise<void>;
}

interface Fetcher {
  fetch(input: string | Request, init?: RequestInit): Promise<Response>;
}

declare namespace Cloudflare {
  interface GlobalProps {
    mainModule: typeof import('./src/index');
  }

  interface Env {
    OTP_KV: KVNamespace;
    DB: D1Database;
    APP_NAME: 'CineDock';
    DEFAULT_APP_ID: 'cinedock';
    APP_BUNDLE_ID: 'cn.ixiaoxiang.video';
    ACCESS_TOKEN_TTL_SECONDS: '900';
    REFRESH_TOKEN_TTL_SECONDS: '2592000';
    OTP_TTL_SECONDS: '300';
    OTP_MAX_ATTEMPTS: '5';
    PASSKEY_RP_NAME: 'CineDock';
    PASSKEY_CHALLENGE_TTL_SECONDS: '300';
    PASSKEY_RP_ID: 'ixiaoxiang.cn';
    PASSKEY_EXPECTED_ORIGINS: 'https://ixiaoxiang.cn';
    MAIL_GATEWAY: Fetcher;
  }
}

interface Env extends Cloudflare.Env {}
