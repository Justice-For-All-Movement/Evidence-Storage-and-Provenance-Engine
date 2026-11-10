// Standalone server for the evidence engine: reads env, migrates, serves HTTP and runs the job worker loop.
import { readFileSync } from 'node:fs';
import type { Server } from 'node:http';
import pg from 'pg';
import { DomainError, invariant } from '../contracts.ts';
import { createHttpHandler, createTokenVerifier, objectStoreFromEnv, pgSql, serve } from '../service-kit.ts';
import { ClamScanner, createEngine, manifest, migrate, routes } from './index.ts';
import type { EncryptionConfig, EvidenceConfig, EvidenceEngine } from './index.ts';

type Env = Readonly<Record<string, string | undefined>>;
const key = (value: string, label: string): Uint8Array => {
  const bytes = /^[0-9a-f]{64}$/i.test(value) ? Buffer.from(value, 'hex') : Buffer.from(value, 'base64');
  invariant(bytes.byteLength === 32, 'invalid_config', `${label} must be 32 bytes (base64 or hex)`);
  return new Uint8Array(bytes);
};
/** EVIDENCE_MASTER_KEY (+ _VERSION, default v1) and optional EVIDENCE_PREVIOUS_KEYS = JSON {version: key}. */
export function encryptionFromEnv(env: Env): EncryptionConfig | undefined {
  if (env.EVIDENCE_MASTER_KEY === undefined || env.EVIDENCE_MASTER_KEY === '') {
    invariant(env.EVIDENCE_ALLOW_PLAINTEXT === '1', 'invalid_config', 'EVIDENCE_MASTER_KEY is required (set EVIDENCE_ALLOW_PLAINTEXT=1 only for development)');
    return undefined;
  }
  const current = env.EVIDENCE_MASTER_KEY_VERSION ?? 'v1';
  const keys: Record<string, Uint8Array> = {};
  if (env.EVIDENCE_PREVIOUS_KEYS !== undefined && env.EVIDENCE_PREVIOUS_KEYS !== '') {
    let parsed: unknown;
    try { parsed = JSON.parse(env.EVIDENCE_PREVIOUS_KEYS); } catch { throw new DomainError('invalid_config', 'EVIDENCE_PREVIOUS_KEYS must be JSON'); }
    invariant(parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed), 'invalid_config', 'EVIDENCE_PREVIOUS_KEYS must be a JSON object');
    for (const [version, value] of Object.entries(parsed as Record<string, unknown>)) keys[version] = key(String(value), `EVIDENCE_PREVIOUS_KEYS.${version}`);
  }
  keys[current] = key(env.EVIDENCE_MASTER_KEY, 'EVIDENCE_MASTER_KEY');
  return { currentKeyVersion: current, keys };
}
export function publicKeysFromEnv(env: Env): Record<string, string> {
  const raw = env.IDENTITY_PUBLIC_KEYS ?? (env.IDENTITY_JWKS_FILE === undefined ? undefined : readFileSync(env.IDENTITY_JWKS_FILE, 'utf8'));
  invariant(raw !== undefined && raw !== '', 'invalid_config', 'IDENTITY_PUBLIC_KEYS (JSON map kid→PEM) or IDENTITY_JWKS_FILE is required');
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new DomainError('invalid_config', 'Identity public keys must be JSON'); }
  invariant(parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) && Object.values(parsed).every((v) => typeof v === 'string'), 'invalid_config', 'Identity public keys must be a JSON map of key id to PEM');
  return parsed as Record<string, string>;
}
export type Running = Readonly<{ server: Server; engine: EvidenceEngine; port: number; close(): Promise<void> }>;

export async function start(env: Env = process.env): Promise<Running> {
  invariant(typeof env.DATABASE_URL === 'string' && env.DATABASE_URL !== '', 'invalid_config', 'DATABASE_URL is required');
  const pool = new pg.Pool({ connectionString: env.DATABASE_URL, max: Number(env.DATABASE_POOL_MAX ?? 10) });
  const sql = pgSql(pool);
  await migrate(sql);
  const encryption = encryptionFromEnv(env);
  invariant(env.EVIDENCE_SCAN_POLICY === undefined || env.EVIDENCE_SCAN_POLICY === '' || env.EVIDENCE_SCAN_POLICY === 'structural_only', 'invalid_config', 'EVIDENCE_SCAN_POLICY may only be structural_only');
  const config: EvidenceConfig = {
    ...(encryption === undefined ? {} : { encryption }),
    ...(env.EVIDENCE_SCAN_POLICY === 'structural_only' ? { scanPolicy: 'structural_only' as const } : {}),
    ...(env.EVIDENCE_REPRODUCTION_WITHOUT_PORT === 'allow' ? { reproductionWithoutPort: 'allow' as const } : {}),
    ...(env.EVIDENCE_MAX_BYTES === undefined ? {} : { limits: { maxBytes: Number(env.EVIDENCE_MAX_BYTES) } }),
  };
  const scanner = env.CLAMAV_DATABASE_DIR === undefined || env.CLAMAV_DATABASE_DIR === '' ? undefined : new ClamScanner({ databaseDir: env.CLAMAV_DATABASE_DIR, ...(env.CLAMSCAN_BINARY === undefined ? {} : { binary: env.CLAMSCAN_BINARY }) });
  const engine = createEngine({ sql, objects: objectStoreFromEnv(env, './data/evidence-objects'), ports: scanner === undefined ? {} : { scanner }, config });
  const maxBody = Math.ceil((config.limits?.maxBytes ?? 256 * 1024 * 1024) * 4 / 3) + 1024 * 1024; // base64 JSON uploads
  const handler = createHttpHandler({
    name: manifest.name, version: manifest.version, routes: routes(engine), verify: createTokenVerifier({ publicKeys: publicKeysFromEnv(env), ...(env.IDENTITY_ISSUER === undefined ? {} : { issuer: env.IDENTITY_ISSUER }) }),
    maxBodyBytes: maxBody, health: () => engine.health(),
    onError: (error, info) => { console.error(JSON.stringify({ level: 'error', requestId: info.requestId, method: info.method, path: info.path, error: error instanceof Error ? error.name : 'unknown' })); },
  });
  const server = await serve(handler, Number(env.PORT ?? 8080), env.HOST ?? '127.0.0.1');
  let stopped = false; let timer: NodeJS.Timeout | undefined; let active: Promise<unknown> = Promise.resolve();
  const tick = (): void => {
    if (stopped) return;
    active = engine.runJobsOnce().catch(() => 0).then((n) => { if (!stopped) timer = setTimeout(tick, n === 0 ? Number(env.EVIDENCE_WORKER_IDLE_MS ?? 1000) : 0); });
  };
  if (env.EVIDENCE_WORKER !== 'off') tick();
  const address = server.address();
  return { server, engine, port: typeof address === 'object' && address !== null ? address.port : Number(env.PORT ?? 8080), async close() { stopped = true; if (timer !== undefined) clearTimeout(timer); await active; await new Promise<void>((r) => server.close(() => r())); await pool.end(); } };
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  start().then((running) => {
    console.log(JSON.stringify({ level: 'info', message: 'evidence engine listening', port: running.port }));
    for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => { void running.close().then(() => process.exit(0)); });
  }).catch((error: unknown) => { console.error(JSON.stringify({ level: 'fatal', error: error instanceof Error ? error.message : 'startup failed' })); process.exit(1); });
}
