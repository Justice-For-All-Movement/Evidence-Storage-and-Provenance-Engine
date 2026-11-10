// Shared fixtures for the engine tests: real PostgreSQL, real filesystem object store, real tools. All content is fictional.
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { DomainError } from '../src/contracts.ts';
import { FsObjectStore, withDisposableDatabase } from '../src/service-kit.ts';
import type { ServiceContext, Sql } from '../src/service-kit.ts';
import { ClamScanner, createEngine, migrate } from '../src/engine/index.ts';
import type { EvidenceConfig, EvidenceDeps, EvidenceEngine } from '../src/engine/index.ts';

export const ADMIN = process.env.TEST_DATABASE_URL;
export const needsPg = { skip: ADMIN === undefined ? 'TEST_DATABASE_URL is not set' : false } as const;
export const ALL_CAPS = ['evidence:*', 'evidence:export', 'evidence:admin', 'evidence:events'];
export const code = (expected: string) => (error: unknown): boolean => error instanceof DomainError && error.code === expected;

export function ctx(overrides: Partial<ServiceContext> = {}): ServiceContext {
  return { tenantId: 'tenant-a', projectId: 'project-1', purpose: 'investigate', requestId: randomUUID(), now: new Date().toISOString(), actor: { id: 'researcher-1', kind: 'human', roles: ['researcher'] }, capabilities: ALL_CAPS, compartments: [], ...overrides };
}
export const HARMLESS_MARKER = 'HARMLESS-PAM-TEST-SIGNATURE';
/** Writes a locally authored ClamAV signature that matches only the harmless marker string above. */
export async function signatureDb(dir: string): Promise<string> {
  const db = join(dir, 'clamdb'); await mkdir(db, { recursive: true });
  await writeFile(join(db, 'local-test.ndb'), `Pam.Test.Harmless:0:*:${Buffer.from(HARMLESS_MARKER).toString('hex')}\n`);
  return db;
}
export type Fixture = { sql: Sql; url: string; dir: string; objectRoot: string; objects: FsObjectStore; engine: EvidenceEngine; keys: Record<string, Uint8Array>; make: (over?: { config?: EvidenceConfig; ports?: EvidenceDeps['ports']; objects?: FsObjectStore }) => EvidenceEngine };
export async function withEngine(options: { config?: EvidenceConfig; ports?: EvidenceDeps['ports']; scanner?: 'clam' | 'none' }, fn: (f: Fixture) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), 'e05-test-'));
  try {
    await withDisposableDatabase(pg, ADMIN as string, async (url, sql) => {
      await migrate(sql);
      const objectRoot = join(dir, 'objects'); const objects = new FsObjectStore(objectRoot);
      const keys = { k1: new Uint8Array(randomBytes(32)) };
      const scanner = options.scanner === 'none' ? undefined : new ClamScanner({ databaseDir: await signatureDb(dir) });
      const make: Fixture['make'] = (over = {}) => createEngine({ sql, objects: over.objects ?? objects, ports: { ...(scanner === undefined ? {} : { scanner }), ...options.ports, ...over.ports }, config: { encryption: { currentKeyVersion: 'k1', keys }, scanInline: true, ...options.config, ...over.config } });
      await fn({ sql, url, dir, objectRoot, objects, keys, engine: make(), make });
    });
  } finally { await rm(dir, { recursive: true, force: true }); }
}
export const utf8 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'utf8'));
export const manual = { kind: 'manual_import', collectedBy: 'researcher-1', acquiredAt: '2026-01-05T10:00:00Z', source: 'https://records.example.org/fictional/notice-17' };

/** A small real text PDF (Helvetica), one string per line per page, so pdftotext can extract it. */
export function textPdf(pages: readonly (readonly string[])[]): Uint8Array {
  const objs: string[] = [];
  const kids = pages.map((_, i) => `${4 + i * 2} 0 R`).join(' ');
  objs.push('<< /Type /Catalog /Pages 2 0 R >>', `<< /Type /Pages /Count ${pages.length} /Kids [${kids}] >>`, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  pages.forEach((lines, i) => {
    const content = `BT /F1 18 Tf ${lines.map((line, n) => `1 0 0 1 72 ${700 - n * 60} Tm (${line.replace(/[()\\]/g, '\\$&')}) Tj`).join(' ')} ET`;
    objs.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${5 + i * 2} 0 R >>`, `<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
  });
  let out = '%PDF-1.4\n'; const offsets: number[] = [];
  objs.forEach((body, i) => { offsets.push(out.length); out += `${i + 1} 0 obj\n${body}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}trailer\n<< /Size ${objs.length + 1} /Root 1 0 R /Info << /Author (Fictional Clerk) >> >>\nstartxref\n${xref}\n%%EOF\n`;
  return new Uint8Array(Buffer.from(out, 'latin1'));
}
