// E05 Evidence storage and provenance — service layer (engine service convention v1).
// A SHA-256 digest recorded here establishes byte consistency only. It never establishes authenticity or truth.
import { randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DomainError, canonical, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import {
  appendAudit, controlJob, emitEvent, enqueueJob, getJob, idempotent, listAudit, listJobs, parseUref, readEvents, requireCapability,
  requireCompartment, runJobsOnce, runMigrations, standardRoutes, uref, urefMatches, validObjectKey,
} from '../service-kit.ts';
import type {
  AuditRecord, AuthorizationPort, EngineEvent, EngineManifestV1, EvidencePort, EvidenceVersionInfo, Inspection, Job, Migration, ObjectStore,
  Route, SearchHit, ServiceContext, Sql, StandardEngine, UpstreamChange, UseAction, UseDecisionPort,
} from '../service-kit.ts';
import {
  DEFAULT_LIMITS, baseMediaType, boxToPixels, decodeText, imageSize, isTextMedia, mediaDurationMs, openObject, pdfPageCount, pdfPageWords,
  readZip, redactImage, redactPdf, redactText, renderPdfPage, rewrapKey, sealObject, sha256Hex, structuralCheck, toolVersion, validBox,
  validateEncryption, withTempDir, writeZip,
} from './tools.ts';
import type { Box, EncryptionConfig, PageRegion, PdfWord, ScannerPort, StructuralLimits, TextRange } from './tools.ts';
import { readFile } from 'node:fs/promises';

export { ClamScanner, structuralCheck, sniff, writeZip, readZip, listZip, writeImagePdf, sealObject, openObject, rewrapKey } from './tools.ts';
export type { ScannerPort, ScanVerdict, EncryptionConfig, StructuralLimits, StructuralReport, Box, PageRegion, TextRange } from './tools.ts';

export const SCHEMA = 'e05_evidence';
const S = SCHEMA;
export const DIGEST_MEANING = 'SHA-256 establishes byte consistency with the preserved version only; it does not establish authenticity or truth.';

export const manifest: EngineManifestV1 = {
  id: 'E05', name: 'evidence', version: '1.0.0', kit: '1.0.1',
  capabilities: ['evidence:read', 'evidence:write', 'evidence:cite', 'evidence:verify', 'evidence:redact', 'evidence:retain', 'evidence:assess', 'evidence:upstream', 'evidence:audit', 'evidence:export', 'evidence:admin', 'evidence:events'],
  emits: ['evidence.accepted', 'evidence.version_added', 'evidence.derivative_added', 'evidence.released', 'evidence.blocked', 'evidence.integrity_failed', 'evidence.integrity_restored', 'evidence.retention_changed', 'evidence.redaction_created', 'evidence.restricted', 'evidence.restriction_lifted', 'evidence.stale'],
  consumes: ['permission_withdrawn', 'permission_changed', 'rights_changed', 'source_corrected', 'source_superseded', 'source_removed'],
};

export const migrations: readonly Migration[] = [{ id: '001_evidence_service', sql: `
create table {s}.evidence (
  id uuid primary key, tenant_id text not null, project_id text not null,
  kind text not null check (kind in ('original','derivative')),
  title text not null, compartment text, current_revision int not null,
  restricted boolean not null default false, restrictions jsonb not null default '[]',
  stale boolean not null default false, stale_reasons jsonb not null default '[]',
  hold boolean not null default false, retention jsonb not null default '{}',
  sources text[] not null default '{}', source_bases text[] not null default '{}',
  created_by text not null, created_at timestamptz not null
);
create index evidence_scope on {s}.evidence (tenant_id, project_id, created_at);
create index evidence_sources on {s}.evidence using gin (source_bases);
create table {s}.versions (
  evidence_id uuid not null references {s}.evidence(id), revision int not null check (revision > 0),
  tenant_id text not null, project_id text not null,
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'), size bigint not null, media_type text not null, filename text not null,
  object_key text not null, stored_sha256 text not null, key_version text not null, wrapped_key text,
  scan_state text not null check (scan_state in ('quarantined','released','blocked')), scan jsonb not null default '{}', scan_attempt int not null default 1,
  bytes_state text not null check (bytes_state in ('present','disposed','missing','corrupt')),
  integrity jsonb, authenticity jsonb, cause text not null, dedupe_key text,
  created_by text not null, created_at timestamptz not null,
  primary key (evidence_id, revision)
);
create unique index versions_dedupe on {s}.versions (tenant_id, project_id, dedupe_key) where dedupe_key is not null;
create index versions_scope on {s}.versions (tenant_id, project_id, sha256);
create table {s}.acquisitions (
  id uuid primary key, tenant_id text not null, project_id text not null, evidence_id uuid not null, revision int not null,
  origin_kind text not null, origin jsonb not null, original_owner text, handling_history jsonb not null default '[]', gaps jsonb not null default '[]',
  actor_id text not null, at timestamptz not null
);
create index acquisitions_evidence on {s}.acquisitions (evidence_id, at);
create table {s}.custody (
  evidence_id uuid not null, seq int not null, tenant_id text not null, project_id text not null, revision int,
  action text not null, detail jsonb not null, actor_id text not null, actor_kind text not null, purpose text not null, request_id text not null,
  at timestamptz not null, previous_hash text not null, hash text not null,
  primary key (evidence_id, seq)
);
create table {s}.derivations (
  tenant_id text not null, project_id text not null,
  parent_id uuid not null, parent_revision int not null, child_id uuid not null, child_revision int not null,
  relation text not null, tool jsonb not null, actor_id text not null, at timestamptz not null,
  primary key (child_id, child_revision, parent_id, parent_revision)
);
create index derivations_parent on {s}.derivations (parent_id);
create table {s}.citations (
  id uuid primary key, tenant_id text not null, project_id text not null, evidence_id uuid not null, revision int not null,
  sha256 text not null, selector jsonb not null, note text not null default '', validation jsonb not null,
  created_by text not null, created_at timestamptz not null
);
create index citations_evidence on {s}.citations (evidence_id, revision);
create table {s}.retention_decisions (
  id uuid primary key, tenant_id text not null, project_id text not null, evidence_id uuid not null, revision int,
  action text not null, reason text not null, dispose_after timestamptz, authorization_record jsonb not null,
  actor_id text not null, at timestamptz not null
);
create index retention_evidence on {s}.retention_decisions (evidence_id, at);
create table {s}.integrity_checks (
  id uuid primary key, tenant_id text not null, project_id text not null, evidence_id uuid not null, revision int not null,
  expected_sha256 text not null, observed_sha256 text, stored_sha256 text, status text not null, detail text,
  actor_id text not null, at timestamptz not null
);
create index integrity_evidence on {s}.integrity_checks (evidence_id, revision, at);
create table {s}.upstream_changes (
  tenant_id text not null, project_id text not null, event_id text not null, kind text not null, affected jsonb not null default '[]', at timestamptz not null,
  primary key (tenant_id, project_id, event_id)
);
` }];
export const migrate = (sql: Sql): Promise<string[]> => runMigrations(sql, SCHEMA, migrations);

// ───────────────────────────── Types ─────────────────────────────
export type Authorization = Readonly<{ authorizedBy: string; basis: string; reference?: string }>;
export type Gap = Readonly<{ code: string; detail: string; revision?: number }>;
export type Selector =
  | Readonly<{ kind: 'whole' }>
  | Readonly<{ kind: 'page'; page: number; box?: Box }>
  | Readonly<{ kind: 'text'; start: number; end: number; quote?: string }>
  | Readonly<{ kind: 'time'; startMs: number; endMs: number }>;
export type AuthenticityStatus = 'not_assessed' | Readonly<{ status: 'assessed_elsewhere'; assessmentRef: string; claimedOutcome: string; recordedAt: string; recordedBy: string }>;
export type VersionDetail = EvidenceVersionInfo & Readonly<{
  evidenceRef: string; kind: 'original' | 'derivative'; title: string; isCurrent: boolean; currentRef: string;
  state: 'quarantined' | 'released' | 'blocked'; bytesState: 'present' | 'disposed' | 'missing' | 'corrupt';
  restricted: boolean; restrictions: readonly Json[]; stale: boolean; staleReasons: readonly string[]; hold: boolean; retention: Json;
  scan: Json; integrity: Json | null; keyVersion: string; cause: string; createdAt: string; createdBy: string;
  authenticity: AuthenticityStatus; digestMeaning: string;
}>;
export type CustodyEntry = Readonly<{ evidenceId: string; seq: number; revision: number | null; action: string; detail: Json; actorId: string; actorKind: string; purpose: string; requestId: string; at: string; previousHash: string; hash: string }>;
export type IntegrityResult = Readonly<{ ref: string; sha256: string; status: 'matched' | 'mismatch' | 'missing' | 'disposed' | 'disposed_bytes_present' | 'key_unavailable'; observedSha256: string | null; detail: string | null; checkedAt: string; meaning: string }>;
export type IntegrityReport = Readonly<{
  checkedAt: string; checked: number; matched: number; failed: number; disposed: number; hiddenChecked: number; hiddenFailed: number;
  results: readonly IntegrityResult[]; orphanObjects: readonly string[]; ok: boolean; meaning: string;
}>;
export type Citation = Readonly<{ ref: string; id: string; version: string; sha256: string; selector: Selector; note: string; validation: Json; createdAt: string; createdBy: string }>;
export type CitationResolution = Readonly<{
  citation: Citation; state: 'resolved' | 'gap'; version: VersionDetail; isCurrentVersion: boolean; currentRef: string;
  gap: Gap | null; authenticity: AuthenticityStatus; digestMeaning: string;
}>;
export type Highlight = Readonly<{ kind: 'box'; page: number; box: Box; pixels: { x: number; y: number; w: number; h: number } } | { kind: 'text'; start: number; end: number; quote: string } | { kind: 'time'; startMs: number; endMs: number }>;
export type ViewData = Readonly<{ ref: string; sha256: string; mediaType: string; authenticity: AuthenticityStatus; digestMeaning: string; highlights: readonly Highlight[] }> & (
  | Readonly<{ kind: 'pdf_page'; page: number; pageCount: number; image: Uint8Array; imageMediaType: 'image/png'; widthPx: number; heightPx: number; pageWidthPt: number; pageHeightPt: number; words: readonly PdfWord[] }>
  | Readonly<{ kind: 'image'; image: Uint8Array; imageMediaType: string; widthPx: number; heightPx: number }>
  | Readonly<{ kind: 'media'; durationMs: number | null; totalBytes: number; range: { start: number; end: number }; bytes: Uint8Array; seekMs: number }>
  | Readonly<{ kind: 'text'; text: string }>
  | Readonly<{ kind: 'unsupported'; reason: string }>);
export type Provenance = Readonly<{
  evidence: string; title: string; kind: string; compartment: string | null; versions: readonly VersionDetail[];
  acquisitions: readonly Json[]; custody: readonly CustodyEntry[]; custodyChainValid: boolean;
  derivedFrom: readonly Json[]; derivatives: readonly Json[]; citations: readonly Citation[]; retention: readonly Json[]; integrityChecks: readonly Json[];
  gaps: readonly Gap[]; authenticity: AuthenticityStatus; digestMeaning: string;
}>;
export type PackageVerification = Readonly<{ ok: boolean; files: readonly { path: string; ok: boolean; detail: string }[]; custody: readonly { evidence: string; ok: boolean; entries: number }[]; gaps: readonly Json[]; errors: readonly string[]; meaning: string }>;

export type EvidenceConfig = Readonly<{
  /** Envelope encryption at rest. Omit only for development: objects are then stored in plaintext and say so. */
  encryption?: EncryptionConfig;
  /** Applies only when no scanner port is configured. Default: items stay quarantined. */
  scanPolicy?: 'structural_only';
  /** Run the scan job in-process right after accept (the durable job is still the mechanism). */
  scanInline?: boolean;
  limits?: Partial<StructuralLimits>;
  /** Standalone mode: allow reproduce/export without a UseDecisionPort. Default denies. */
  reproductionWithoutPort?: 'allow';
  redaction?: Readonly<{ dpi?: number; maxPages?: number }>;
  workerId?: string;
}>;
export type EvidenceDeps = Readonly<{
  sql: Sql; objects: ObjectStore;
  ports?: Readonly<{ scanner?: ScannerPort; useDecisions?: UseDecisionPort; authorization?: AuthorizationPort }>;
  config?: EvidenceConfig;
}>;

type VRow = {
  evidence_id: string; revision: number; tenant_id: string; project_id: string; sha256: string; size: string; media_type: string; filename: string;
  object_key: string; stored_sha256: string; key_version: string; wrapped_key: string | null; scan_state: 'quarantined' | 'released' | 'blocked'; scan: Json; scan_attempt: number;
  bytes_state: 'present' | 'disposed' | 'missing' | 'corrupt'; integrity: Json | null; authenticity: Json | null; cause: string; created_by: string; created_at: Date;
  e_kind: 'original' | 'derivative'; title: string; compartment: string | null; current_revision: number; restricted: boolean; restrictions: Json[];
  stale: boolean; stale_reasons: string[]; hold: boolean; retention: Json; sources: string[];
};
const VSEL = `select v.*, e.kind as e_kind, e.title, e.compartment, e.current_revision, e.restricted, e.restrictions, e.stale, e.stale_reasons, e.hold, e.retention, e.sources
  from ${S}.versions v join ${S}.evidence e on e.id = v.evidence_id`;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const REPRODUCTION: readonly UseAction[] = ['reproduce', 'adapt', 'publish', 'license'];
const iso = (d: Date | string): string => new Date(d).toISOString();
const versionRef = (id: string, revision?: number): string => uref('E05', 'evidence_version', id, revision);
const evidenceRef = (id: string): string => uref('E05', 'evidence', id);
const json = (v: unknown): Json => JSON.parse(JSON.stringify(v ?? null)) as Json;
const text = (value: unknown, label: string, max = 2000): string => { invariant(typeof value === 'string' && value.trim().length > 0 && value.length <= max, 'invalid_input', `${label} is required (at most ${max} characters)`); return value; };
const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

function authenticityOf(raw: Json | null): AuthenticityStatus {
  return isObject(raw) && raw.status === 'assessed_elsewhere' ? raw as unknown as AuthenticityStatus : 'not_assessed';
}
function infoOf(v: VRow): EvidenceVersionInfo {
  return { ref: versionRef(v.evidence_id, v.revision), evidenceId: v.evidence_id, revision: v.revision, sha256: v.sha256, size: Number(v.size), mediaType: v.media_type, filename: v.filename, compartment: v.compartment, available: v.bytes_state === 'present' && v.scan_state === 'released' };
}
function detailOf(v: VRow): VersionDetail {
  return {
    ...infoOf(v), evidenceRef: evidenceRef(v.evidence_id), kind: v.e_kind, title: v.title, isCurrent: v.revision === v.current_revision, currentRef: versionRef(v.evidence_id, v.current_revision),
    state: v.scan_state, bytesState: v.bytes_state, restricted: v.restricted, restrictions: v.restrictions, stale: v.stale, staleReasons: v.stale_reasons, hold: v.hold, retention: v.retention,
    scan: v.scan, integrity: v.integrity, keyVersion: v.key_version, cause: v.cause, createdAt: iso(v.created_at), createdBy: v.created_by,
    authenticity: authenticityOf(v.authenticity), digestMeaning: DIGEST_MEANING,
  };
}
function bytesGap(v: VRow): Gap | null {
  if (v.bytes_state === 'disposed') return { code: 'bytes_disposed', revision: v.revision, detail: `Bytes of revision ${v.revision} were removed by a recorded retention decision; the digest ${v.sha256} is retained as a tombstone` };
  if (v.bytes_state === 'missing') return { code: 'bytes_missing', revision: v.revision, detail: `Stored bytes of revision ${v.revision} are missing from object storage; retained digest ${v.sha256}` };
  if (v.bytes_state === 'corrupt') return { code: 'bytes_corrupt', revision: v.revision, detail: `Stored bytes of revision ${v.revision} no longer match the retained digest ${v.sha256}` };
  return null;
}

/** Derives the acquisition record and its explicit provenance gaps from caller-supplied origin JSON. */
export function analyzeOrigin(origin: Json): { kind: string; originalOwner: string | null; handlingHistory: Json[]; gaps: Gap[]; sources: string[] } {
  const o = isObject(origin) ? origin : {};
  const gaps: Gap[] = [];
  const known = ['intake_attachment', 'intake_submission', 'discovery_receipt', 'correspondence_message', 'manual_import', 'derivative', 'refresh'];
  const kind = typeof o.kind === 'string' && known.includes(o.kind) ? o.kind : 'unknown';
  if (kind === 'unknown') gaps.push({ code: 'origin_unknown', detail: 'No recognised origin kind was supplied; how this content was obtained is not recorded' });
  const sources = new Set<string>();
  const walk = (v: unknown, depth: number): void => {
    if (depth > 6) return;
    if (typeof v === 'string') { if (v.length <= 300) { try { parseUref(v); sources.add(v); } catch { /* not a reference */ } } }
    else if (Array.isArray(v)) v.slice(0, 200).forEach((x) => walk(x, depth + 1));
    else if (isObject(v)) Object.values(v).slice(0, 200).forEach((x) => walk(x, depth + 1));
  };
  walk(o, 0);
  const hasRef = typeof o.ref === 'string' && sources.has(o.ref);
  const originalOwner = typeof o.originalOwner === 'string' && o.originalOwner.trim() !== '' ? o.originalOwner.slice(0, 300) : null;
  const handlingHistory = Array.isArray(o.handlingHistory) ? (o.handlingHistory as Json[]).slice(0, 500) : [];
  if (kind === 'intake_attachment' || kind === 'intake_submission') {
    if (!hasRef) gaps.push({ code: 'intake_reference_missing', detail: 'The intake submission or attachment reference was not supplied' });
    if (originalOwner === null) gaps.push({ code: 'original_owner_unknown', detail: 'The intake owner of the original was not handed over' });
    if (!Array.isArray(o.handlingHistory)) gaps.push({ code: 'prior_handling_history_missing', detail: 'Handling history before acceptance was not handed over' });
  } else if (kind === 'discovery_receipt') {
    if (!hasRef) gaps.push({ code: 'discovery_receipt_missing', detail: 'No discovery acquisition receipt reference was supplied' });
  } else if (kind === 'correspondence_message') {
    if (!hasRef) gaps.push({ code: 'correspondence_reference_missing', detail: 'No correspondence message reference was supplied' });
  } else if (kind === 'manual_import') {
    if (typeof o.collectedBy !== 'string' || o.collectedBy.trim() === '') gaps.push({ code: 'collector_unknown', detail: 'Who collected this content is not recorded' });
    if (typeof o.acquiredAt !== 'string' || !Number.isFinite(Date.parse(o.acquiredAt))) gaps.push({ code: 'acquisition_time_unknown', detail: 'When this content was obtained is not recorded' });
    if (typeof o.source !== 'string' || o.source.trim() === '') gaps.push({ code: 'source_unknown', detail: 'Where this content came from is not recorded' });
  }
  return { kind, originalOwner, handlingHistory, gaps, sources: [...sources].slice(0, 200) };
}

const custodyHash = (e: Omit<CustodyEntry, 'hash'>): string => sha256Hex(canonical({ evidenceId: e.evidenceId, seq: e.seq, revision: e.revision, action: e.action, detail: e.detail, actorId: e.actorId, actorKind: e.actorKind, purpose: e.purpose, requestId: e.requestId, at: e.at, previousHash: e.previousHash }));
/** Verifies a complete per-evidence custody chain (ordered from seq 1). */
export function verifyCustodyChain(entries: readonly CustodyEntry[]): boolean {
  let previous = '';
  for (const [i, e] of entries.entries()) { if (e.seq !== i + 1 || e.previousHash !== previous || custodyHash(e) !== e.hash) return false; previous = e.hash; }
  return true;
}
function validSelector(raw: unknown): Selector {
  invariant(isObject(raw), 'invalid_input', 'Selector object required');
  const int = (v: unknown, min: number): number => { invariant(Number.isSafeInteger(v) && (v as number) >= min, 'invalid_input', 'Selector value out of range'); return v as number; };
  if (raw.kind === 'whole') return { kind: 'whole' };
  if (raw.kind === 'page') return { kind: 'page', page: int(raw.page, 1), ...(raw.box === undefined || raw.box === null ? {} : { box: validBox(raw.box) }) };
  if (raw.kind === 'text') { const start = int(raw.start, 0), end = int(raw.end, 1); invariant(end > start, 'invalid_input', 'Text selector is empty'); if (raw.quote !== undefined) text(raw.quote, 'quote', 20_000); return { kind: 'text', start, end, ...(raw.quote === undefined ? {} : { quote: raw.quote as string }) }; }
  if (raw.kind === 'time') { const startMs = int(raw.startMs, 0), endMs = int(raw.endMs, 0); invariant(endMs >= startMs, 'invalid_input', 'Time selector is reversed'); return { kind: 'time', startMs, endMs }; }
  throw new DomainError('invalid_input', 'Unsupported selector kind');
}

const README = `PROVENANCE PACKAGE
==================

This archive was exported by the evidence storage and provenance engine.

Contents
  manifest.json   Versions, SHA-256 digests, acquisition records, custody chains, derivation edges, retention decisions and
                  every known provenance gap for the exported items.
  objects/...     Preserved bytes, present only when the export included them. The path of each file is listed in
                  manifest.json under "files" together with its SHA-256 digest and size.

How to verify without this software
  1. For every entry in manifest.json "files", compute the SHA-256 of the file at "path" and compare it with "sha256".
  2. For every item, walk "custody" in order: each entry's "previousHash" must equal the previous entry's "hash" (the
     first is the empty string) and "hash" must equal the SHA-256 of the canonical JSON (keys sorted, no whitespace) of
     {actorId, actorKind, action, at, detail, evidenceId, previousHash, purpose, requestId, revision, seq}.
  3. Read "gaps". A gap is a statement that something is missing, withheld, disposed, or was never recorded.

What a matching digest means
  A matching SHA-256 shows that the bytes are identical to the bytes that were preserved. It does not show that the
  content is authentic, unaltered before acquisition, or true. Authenticity is "not_assessed" unless the manifest names
  an assessment recorded by another system.

The package itself is not signed. To detect replacement of the whole package, compare its SHA-256 with the package
digest recorded in the exporting system's custody log at the time of export.
`;

/** Re-checks a provenance package: file digests, custody chains and declared gaps. Needs no database or credentials. */
export async function verifyPackage(bytes: Uint8Array): Promise<PackageVerification> {
  const errors: string[] = []; const files: { path: string; ok: boolean; detail: string }[] = []; const custody: { evidence: string; ok: boolean; entries: number }[] = []; let gaps: Json[] = [];
  const done = (): PackageVerification => ({ ok: errors.length === 0 && files.every((f) => f.ok) && custody.every((c) => c.ok), files, custody, gaps, errors, meaning: DIGEST_MEANING });
  let entries: Map<string, Uint8Array>;
  try { entries = await readZip(bytes); } catch (error) { errors.push(`Archive unreadable: ${error instanceof Error ? error.message : 'unknown error'}`); return done(); }
  const raw = entries.get('manifest.json');
  if (raw === undefined) { errors.push('manifest.json is missing'); return done(); }
  let m: Record<string, unknown>;
  try { m = JSON.parse(Buffer.from(raw).toString('utf8')) as Record<string, unknown>; invariant(isObject(m) && m.schema === 'evidence.provenance-package/1' && Array.isArray(m.files) && Array.isArray(m.items), 'invalid_input', 'bad manifest'); }
  catch { errors.push('manifest.json is not a valid provenance manifest'); return done(); }
  const listed = new Set<string>();
  for (const f of m.files as { path?: unknown; sha256?: unknown; size?: unknown }[]) {
    const path = String(f.path); listed.add(path);
    const data = entries.get(path);
    if (data === undefined) files.push({ path, ok: false, detail: 'file listed in the manifest is missing from the archive' });
    else if (sha256Hex(data) !== f.sha256 || data.byteLength !== f.size) files.push({ path, ok: false, detail: 'bytes do not match the manifest digest' });
    else files.push({ path, ok: true, detail: 'digest matches' });
  }
  for (const name of entries.keys()) if (name !== 'manifest.json' && name !== 'README.txt' && !listed.has(name)) errors.push(`Unlisted file in archive: ${name}`);
  for (const item of m.items as { ref?: unknown; evidence?: unknown; sha256?: unknown; file?: unknown; custody?: unknown }[]) {
    const chain = Array.isArray(item.custody) ? item.custody as CustodyEntry[] : [];
    let ok = false; try { ok = chain.length > 0 && verifyCustodyChain(chain); } catch { ok = false; }
    custody.push({ evidence: String(item.evidence), ok, entries: chain.length });
    if (typeof item.file === 'string') { const listedFile = (m.files as { path?: unknown; sha256?: unknown }[]).find((f) => f.path === item.file); if (listedFile === undefined || listedFile.sha256 !== item.sha256) errors.push(`Item ${String(item.ref)} does not agree with its file entry`); }
  }
  gaps = Array.isArray(m.gaps) ? m.gaps as Json[] : [];
  return done();
}

// ───────────────────────────── Engine ─────────────────────────────
export interface EvidenceEngine extends StandardEngine, EvidencePort {
  getBytes(ctx: ServiceContext, ref: string, options?: { use?: UseAction; reason?: string }): Promise<Uint8Array>;
  describeVersion(ctx: ServiceContext, ref: string): Promise<VersionDetail | null>;
  list(ctx: ServiceContext, options?: { limit?: number; before?: string }): Promise<VersionDetail[]>;
  versions(ctx: ServiceContext, ref: string): Promise<VersionDetail[]>;
  addVersion(ctx: ServiceContext, input: { evidence: string; bytes: Uint8Array; mediaType: string; filename: string; origin: Json; cause?: 'refresh' | 'correction'; idempotencyKey?: string }): Promise<EvidenceVersionInfo>;
  rescan(ctx: ServiceContext, ref: string): Promise<{ jobId: string }>;
  recordHandling(ctx: ServiceContext, ref: string, input: { action: 'referenced' | 'copied' | 'transferred' | 'viewed' | 'note'; reason: string; destination?: string; idempotencyKey?: string }): Promise<CustodyEntry>;
  custody(ctx: ServiceContext, ref: string): Promise<{ entries: CustodyEntry[]; chainValid: boolean }>;
  provenance(ctx: ServiceContext, ref: string): Promise<Provenance>;
  createCitation(ctx: ServiceContext, input: { version: string; selector: Selector; note?: string; idempotencyKey?: string }): Promise<Citation>;
  resolveCitation(ctx: ServiceContext, citation: string): Promise<CitationResolution>;
  renderView(ctx: ServiceContext, ref: string, options?: { page?: number; timeMs?: number; range?: { start: number; end?: number }; dpi?: number; citation?: string; selector?: Selector }): Promise<ViewData>;
  redact(ctx: ServiceContext, ref: string, input: { regions?: readonly (PageRegion | (Box & { page?: number }))[]; textRanges?: readonly TextRange[]; reason: string; compartment?: string | null; dpi?: number; idempotencyKey?: string }): Promise<{ derivative: EvidenceVersionInfo; manifest: Json }>;
  setRetention(ctx: ServiceContext, ref: string, input: { action: 'hold' | 'release_hold' | 'schedule' | 'clear_schedule'; reason: string; disposeAfter?: string; authorization: Authorization; idempotencyKey?: string }): Promise<VersionDetail>;
  dueForDisposal(ctx: ServiceContext, options?: { at?: string }): Promise<VersionDetail[]>;
  dispose(ctx: ServiceContext, ref: string, input: { reason: string; authorization: Authorization; idempotencyKey?: string }): Promise<VersionDetail[]>;
  verifyIntegrity(ctx: ServiceContext, ref: string): Promise<IntegrityResult>;
  verifyAll(ctx: ServiceContext): Promise<IntegrityReport>;
  startIntegrityBatch(ctx: ServiceContext, options?: { idempotencyKey?: string }): Promise<{ jobId: string }>;
  restoreBytes(ctx: ServiceContext, ref: string, bytes: Uint8Array, input: { reason: string }): Promise<VersionDetail>;
  recordAssessment(ctx: ServiceContext, ref: string, input: { assessmentRef: string; claimedOutcome: string }): Promise<VersionDetail>;
  liftRestriction(ctx: ServiceContext, ref: string, input: { reason: string; authorization: Authorization }): Promise<VersionDetail>;
  exportPackage(ctx: ServiceContext, refs: readonly string[], options?: { includeOriginals?: boolean; redactedOnly?: boolean; reason?: string }): Promise<{ bytes: Uint8Array; sha256: string; filename: string; manifest: Json }>;
  verifyPackage(bytes: Uint8Array): Promise<PackageVerification>;
  rotateKeys(ctx: ServiceContext, options?: { limit?: number }): Promise<{ rewrapped: number; remaining: number; unavailable: number; currentKeyVersion: string }>;
  job(ctx: ServiceContext, id: string): Promise<Job | null>;
  jobs(ctx: ServiceContext, options?: { kind?: string; limit?: number }): Promise<Job[]>;
  controlJob(ctx: ServiceContext, id: string, action: 'cancel' | 'pause' | 'resume' | 'retry'): Promise<Job>;
  /** One polling pass of the engine's job worker (scan and integrity batch jobs). */
  runJobsOnce(options?: { worker?: string; limit?: number; leaseMs?: number }): Promise<number>;
}

type Loaded = { status: 'matched'; bytes: Buffer } | { status: 'missing' | 'mismatch' | 'key_unavailable' | 'disposed'; observed: string | null; detail: string };
type IngestInput = {
  bytes: Uint8Array; mediaType: string; filename: string; origin: Json; compartment: string | null; idempotencyKey: string | undefined;
  mode: 'original' | 'version' | 'derivative'; into?: string; parent?: VRow; relation?: string; tool?: Json; cause: string; extraEvent?: { type: string; payload: Json };
};

export function createEngine(deps: EvidenceDeps): EvidenceEngine {
  const { sql, objects } = deps;
  invariant(sql !== undefined && objects !== undefined, 'invalid_config', 'Evidence engine requires sql and an object store');
  const config = deps.config ?? {}; const ports = deps.ports ?? {};
  if (config.encryption !== undefined) validateEncryption(config.encryption);
  const limits: StructuralLimits = { ...DEFAULT_LIMITS, ...config.limits };
  const worker = config.workerId ?? `evidence-${randomUUID()}`;

  const scopeKey = (ctx: { tenantId: string; projectId: string }): string => {
    invariant(SAFE_ID.test(ctx.tenantId) && SAFE_ID.test(ctx.projectId), 'invalid_input', 'Tenant and project identifiers must be storage-safe ([A-Za-z0-9._-])');
    return `${ctx.tenantId}/${ctx.projectId}/`;
  };
  const visible = (ctx: ServiceContext, compartment: string | null): boolean => { try { requireCompartment(ctx, compartment); return true; } catch { return false; } };
  const parseRef = (ref: string): { id: string; revision: number | undefined; kind: string } | null => {
    try { const p = parseUref(ref); if (p.engine !== 'E05' || !UUID.test(p.id)) return null; return { id: p.id, revision: p.revision, kind: p.kind }; } catch { return null; }
  };
  /** Loads one version by evidence or evidence_version reference; null when unknown, foreign or compartment-hidden. */
  async function find(q: Sql, ctx: ServiceContext, ref: string, options: { system?: boolean } = {}): Promise<VRow | null> {
    const p = typeof ref === 'string' ? parseRef(ref) : null;
    if (p === null || (p.kind !== 'evidence' && p.kind !== 'evidence_version')) return null;
    const rows = await q.query<VRow>(`${VSEL} where v.evidence_id=$1 and v.tenant_id=$2 and v.project_id=$3 and v.revision = coalesce($4::int, e.current_revision)`, [p.id, ctx.tenantId, ctx.projectId, p.revision ?? null]);
    const row = rows[0];
    if (row === undefined || (options.system !== true && !visible(ctx, row.compartment))) return null;
    return row;
  }
  async function need(q: Sql, ctx: ServiceContext, ref: string): Promise<VRow> {
    const row = await find(q, ctx, ref);
    if (row === null) throw new DomainError('not_found', 'Not found');
    return row;
  }
  async function custody(tx: Sql, ctx: ServiceContext, evidenceId: string, revision: number | null, action: string, detail: Json = {}): Promise<CustodyEntry> {
    await tx.query(`select id from ${S}.evidence where id=$1 and tenant_id=$2 and project_id=$3 for update`, [evidenceId, ctx.tenantId, ctx.projectId]);
    const last = (await tx.query<{ seq: number; hash: string }>(`select seq, hash from ${S}.custody where evidence_id=$1 order by seq desc limit 1`, [evidenceId]))[0];
    const base = { evidenceId, seq: (last?.seq ?? 0) + 1, revision, action, detail: json(detail), actorId: ctx.actor.id, actorKind: ctx.actor.kind, purpose: ctx.purpose, requestId: ctx.requestId, at: iso(ctx.now), previousHash: last?.hash ?? '' };
    const entry: CustodyEntry = { ...base, hash: custodyHash(base) };
    await tx.query(`insert into ${S}.custody (evidence_id, seq, tenant_id, project_id, revision, action, detail, actor_id, actor_kind, purpose, request_id, at, previous_hash, hash) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12,$13,$14)`,
      [evidenceId, entry.seq, ctx.tenantId, ctx.projectId, revision, action, JSON.stringify(entry.detail), entry.actorId, entry.actorKind, entry.purpose, entry.requestId, entry.at, entry.previousHash, entry.hash]);
    await appendAudit(tx, SCHEMA, ctx, `evidence.${action}`, revision === null ? evidenceRef(evidenceId) : versionRef(evidenceId, revision), { custodySeq: entry.seq, custodyHash: entry.hash, ...(isObject(entry.detail) ? entry.detail : {}) });
    return entry;
  }
  async function custodyOf(q: Sql, evidenceId: string): Promise<CustodyEntry[]> {
    const rows = await q.query<Record<string, unknown>>(`select * from ${S}.custody where evidence_id=$1 order by seq`, [evidenceId]);
    return rows.map((r) => ({ evidenceId: r.evidence_id as string, seq: r.seq as number, revision: (r.revision as number | null) ?? null, action: r.action as string, detail: r.detail as Json, actorId: r.actor_id as string, actorKind: r.actor_kind as string, purpose: r.purpose as string, requestId: r.request_id as string, at: iso(r.at as Date), previousHash: r.previous_hash as string, hash: r.hash as string }));
  }
  async function recheck(ctx: ServiceContext, capability: string, resource?: string): Promise<void> {
    requireCapability(ctx, capability);
    if (ports.authorization === undefined) return;
    const decision = await ports.authorization.authorize(ctx, { capability, ...(resource === undefined ? {} : { resource }) });
    if (decision.allowed !== true) throw new DomainError('forbidden', 'Authorization was refused');
  }
  function seal(ctx: { tenantId: string; projectId: string }, sha256: string, bytes: Uint8Array): { stored: Uint8Array; wrappedKey: string | null; keyVersion: string } {
    if (config.encryption === undefined) return { stored: bytes, wrappedKey: null, keyVersion: 'none' };
    return sealObject(config.encryption, { tenantId: ctx.tenantId, projectId: ctx.projectId, sha256 }, bytes);
  }
  /** Reads the ACTUAL stored object, decrypts it and compares its SHA-256 with the retained digest. */
  async function load(v: VRow): Promise<Loaded> {
    if (v.bytes_state === 'disposed') return { status: 'disposed', observed: null, detail: 'Bytes were disposed by a recorded retention decision' };
    let stored: Uint8Array;
    try { stored = await objects.get(v.object_key); }
    catch (error) { if (error instanceof DomainError && error.code === 'not_found') return { status: 'missing', observed: null, detail: 'Object is absent from storage' }; throw error; }
    let plain: Buffer;
    if (v.key_version === 'none') plain = Buffer.from(stored.buffer, stored.byteOffset, stored.byteLength);
    else {
      if (config.encryption === undefined || config.encryption.keys[v.key_version] === undefined || v.wrapped_key === null) return { status: 'key_unavailable', observed: null, detail: `Master key version ${v.key_version} is not configured` };
      try { plain = openObject(config.encryption, { tenantId: v.tenant_id, projectId: v.project_id, sha256: v.sha256 }, stored, v.wrapped_key, v.key_version); }
      catch { return { status: 'mismatch', observed: null, detail: `Stored object failed authenticated decryption (stored bytes digest ${sha256Hex(stored)}, expected ${v.stored_sha256})` }; }
    }
    const observed = sha256Hex(plain);
    if (observed !== v.sha256 || plain.byteLength !== Number(v.size)) return { status: 'mismatch', observed, detail: 'Stored bytes do not match the retained digest' };
    return { status: 'matched', bytes: plain };
  }
  /** Records an integrity observation and makes failures visible state; emits on state transitions. */
  async function recordIntegrity(ctx: ServiceContext, v: VRow, loaded: Loaded, extra?: { objectPresent?: boolean }): Promise<IntegrityResult> {
    const at = iso(ctx.now);
    let status: IntegrityResult['status'] = loaded.status; let detail: string | null = loaded.status === 'matched' ? null : loaded.detail;
    if (loaded.status === 'disposed' && extra?.objectPresent === true) { status = 'disposed_bytes_present'; detail = 'Version is recorded as disposed but an object is still present in storage'; }
    const observed = loaded.status === 'matched' ? v.sha256 : loaded.observed;
    const result: IntegrityResult = { ref: versionRef(v.evidence_id, v.revision), sha256: v.sha256, status, observedSha256: observed, detail, checkedAt: at, meaning: DIGEST_MEANING };
    await sql.tx(async (tx) => {
      await tx.query(`insert into ${S}.integrity_checks (id, tenant_id, project_id, evidence_id, revision, expected_sha256, observed_sha256, stored_sha256, status, detail, actor_id, at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [randomUUID(), v.tenant_id, v.project_id, v.evidence_id, v.revision, v.sha256, observed, v.stored_sha256, status, detail, ctx.actor.id, at]);
      const summary = JSON.stringify({ status, at, detail, observedSha256: observed });
      const next = status === 'matched' ? 'present' : status === 'missing' ? 'missing' : status === 'mismatch' ? 'corrupt' : null;
      if (next === null) { await tx.query(`update ${S}.versions set integrity=$3::jsonb where evidence_id=$1 and revision=$2`, [v.evidence_id, v.revision, summary]); return; }
      const changed = await tx.query(`update ${S}.versions set integrity=$3::jsonb, bytes_state=$4 where evidence_id=$1 and revision=$2 and bytes_state <> 'disposed' returning (select bytes_state from ${S}.versions where evidence_id=$1 and revision=$2) as previous`, [v.evidence_id, v.revision, summary, next]);
      const previous = (changed[0] as { previous?: string } | undefined)?.previous;
      if (previous === undefined || previous === next) return;
      if (next === 'present') { await custody(tx, ctx, v.evidence_id, v.revision, 'integrity_restored', { sha256: v.sha256 }); await emitEvent(tx, SCHEMA, ctx, 'evidence.integrity_restored', result.ref, { sha256: v.sha256 }); }
      else { await custody(tx, ctx, v.evidence_id, v.revision, 'integrity_failed', { status, expectedSha256: v.sha256, observedSha256: observed }); await emitEvent(tx, SCHEMA, ctx, 'evidence.integrity_failed', result.ref, { status, expectedSha256: v.sha256, observedSha256: observed, evidence: evidenceRef(v.evidence_id) }); }
    });
    return result;
  }
  /** Loads verified bytes for an authorised read or throws a visible-state error. */
  async function readVerified(ctx: ServiceContext, v: VRow): Promise<Buffer> {
    if (v.scan_state !== 'released') throw new DomainError('invalid_state', v.scan_state === 'blocked' ? 'Evidence version is blocked and cannot be retrieved' : 'Evidence version is quarantined pending scan');
    if (v.bytes_state === 'disposed') throw new DomainError('invalid_state', 'Bytes were disposed by a recorded retention decision; only the tombstone digest remains');
    const loaded = await load(v);
    if (loaded.status === 'matched') { if (v.bytes_state !== 'present') await recordIntegrity(ctx, v, loaded); return loaded.bytes; }
    if (loaded.status === 'key_unavailable') throw new DomainError('unavailable', loaded.detail);
    await recordIntegrity(ctx, v, loaded);
    throw new DomainError('invalid_state', loaded.status === 'missing' ? 'Preserved bytes are missing from storage; a provenance gap is recorded' : 'Preserved bytes failed integrity verification; a provenance gap is recorded');
  }
  async function requireUse(ctx: ServiceContext, rows: readonly VRow[], action: UseAction, destination: string): Promise<Json> {
    for (const v of rows) if (v.restricted) throw new DomainError('consent_denied', 'Evidence is restricted: reproduction and export are blocked while preservation continues');
    if (ports.useDecisions === undefined) {
      if (config.reproductionWithoutPort === 'allow') return { mode: 'standalone_allow', note: 'No use-decision port configured; standalone mode explicitly allows reproduction' };
      throw new DomainError('consent_denied', 'Reproduction requires a use decision and no use-decision port is configured');
    }
    const decision = await ports.useDecisions.decide(ctx, { subjects: rows.map((v) => versionRef(v.evidence_id, v.revision)), action, purpose: ctx.purpose, destination });
    if (decision.decision !== 'allow') throw new DomainError('consent_denied', `Use decision is ${decision.decision === 'review' ? 'pending review' : 'deny'}`);
    return { mode: 'use_decision', decision: decision.decision, permissionRefs: [...decision.permissionRefs], restrictions: [...decision.restrictions], decidedAt: decision.decidedAt };
  }
  function validContent(input: { bytes: Uint8Array; mediaType: string; filename: string }): { bytes: Uint8Array; mediaType: string; filename: string } {
    invariant(input !== null && typeof input === 'object' && input.bytes instanceof Uint8Array, 'invalid_input', 'bytes must be a Uint8Array');
    if (input.bytes.byteLength > limits.maxBytes) throw new DomainError('payload_too_large', `Content exceeds ${limits.maxBytes} bytes`);
    invariant(typeof input.mediaType === 'string' && /^[a-z0-9][a-z0-9!#$&^_.+-]{0,100}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,100}(\s*;\s*[A-Za-z0-9_.-]+=[A-Za-z0-9_."-]+)*$/i.test(input.mediaType), 'invalid_input', 'Invalid media type');
    const filename = text(input.filename, 'filename', 255).replace(/[\u0000-\u001f\u007f/\\]/g, '_');
    return { bytes: Uint8Array.from(input.bytes), mediaType: input.mediaType.toLowerCase(), filename };
  }

  async function ingest(ctx: ServiceContext, input: IngestInput): Promise<EvidenceVersionInfo> {
    const prefix = scopeKey(ctx);
    const sha256 = sha256Hex(input.bytes);
    const objectKey = validObjectKey(`${prefix}objects/${sha256.slice(0, 2)}/${randomUUID()}`);
    const sealed = seal(ctx, sha256, input.bytes);
    const storedSha = sha256Hex(sealed.stored);
    const analysis = analyzeOrigin(input.origin);
    const now = iso(ctx.now);
    const dedupeKey = input.mode === 'original' ? `o:${sha256}:${input.compartment ?? ''}`
      : input.mode === 'derivative' ? `d:${(input.parent as VRow).evidence_id}@${(input.parent as VRow).revision}:${input.relation}:${sha256}:${input.compartment ?? ''}` : null;
    await objects.put(objectKey, sealed.stored);
    let out: { ref: string; objectKey: string };
    try {
      out = await sql.tx((tx) => idempotent(tx, SCHEMA, ctx, input.idempotencyKey, { op: input.mode, sha256, mediaType: input.mediaType, filename: input.filename, origin: input.origin, compartment: input.compartment, into: input.into ?? null, parent: input.parent === undefined ? null : versionRef(input.parent.evidence_id, input.parent.revision), relation: input.relation ?? null, tool: input.tool ?? null }, async () => {
        const acquisition = async (evidenceId: string, revision: number): Promise<void> => {
          await tx.query(`insert into ${S}.acquisitions (id, tenant_id, project_id, evidence_id, revision, origin_kind, origin, original_owner, handling_history, gaps, actor_id, at) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9::jsonb,$10::jsonb,$11,$12)`,
            [randomUUID(), ctx.tenantId, ctx.projectId, evidenceId, revision, input.mode === 'derivative' ? 'derivative' : analysis.kind, JSON.stringify(input.origin ?? null), analysis.originalOwner, JSON.stringify(analysis.handlingHistory), JSON.stringify(input.mode === 'derivative' ? [] : analysis.gaps), ctx.actor.id, now]);
        };
        if (dedupeKey !== null) {
          await tx.query('select pg_advisory_xact_lock(hashtext($1))', [`e05:${ctx.tenantId}:${ctx.projectId}:${dedupeKey}`]);
          const prior = (await tx.query<VRow>(`${VSEL} where v.tenant_id=$1 and v.project_id=$2 and v.dedupe_key=$3`, [ctx.tenantId, ctx.projectId, dedupeKey]))[0];
          if (prior !== undefined) {
            let used = prior.object_key;
            if (prior.bytes_state === 'missing' || prior.bytes_state === 'corrupt') {
              await tx.query(`update ${S}.versions set object_key=$3, stored_sha256=$4, key_version=$5, wrapped_key=$6, bytes_state='present' where evidence_id=$1 and revision=$2`, [prior.evidence_id, prior.revision, objectKey, storedSha, sealed.keyVersion, sealed.wrappedKey]);
              await custody(tx, ctx, prior.evidence_id, prior.revision, 'bytes_restored', { sha256, via: 'duplicate_acquisition' });
              await emitEvent(tx, SCHEMA, ctx, 'evidence.integrity_restored', versionRef(prior.evidence_id, prior.revision), { sha256 });
              used = objectKey;
            }
            if (input.mode === 'original') await acquisition(prior.evidence_id, prior.revision);
            await custody(tx, ctx, prior.evidence_id, prior.revision, input.mode === 'original' ? 'duplicate_acquisition' : 'duplicate_derivative', { sha256, originKind: analysis.kind });
            return { ref: versionRef(prior.evidence_id, prior.revision), objectKey: used };
          }
        }
        let evidenceId = input.into ?? randomUUID(); let revision = 1;
        const bases = analysis.sources.map((s) => s.replace(/@\d+$/, ''));
        if (input.mode === 'version') {
          const current = (await tx.query<VRow>(`${VSEL} where e.id=$1 and e.tenant_id=$2 and e.project_id=$3 and v.revision=e.current_revision for update of e`, [evidenceId, ctx.tenantId, ctx.projectId]))[0];
          if (current === undefined) throw new DomainError('not_found', 'Not found');
          if (current.sha256 === sha256) {
            await acquisition(evidenceId, current.revision);
            await custody(tx, ctx, evidenceId, current.revision, 'refresh_unchanged', { sha256 });
            return { ref: versionRef(evidenceId, current.revision), objectKey: current.object_key };
          }
          revision = current.current_revision + 1;
          await tx.query(`update ${S}.evidence set current_revision=$2, stale=false, stale_reasons='[]'::jsonb, sources=(select array(select distinct unnest(sources || $3::text[]))), source_bases=(select array(select distinct unnest(source_bases || $4::text[]))) where id=$1`, [evidenceId, revision, analysis.sources, bases]);
        } else {
          evidenceId = randomUUID();
          const parent = input.parent;
          const sources = parent === undefined ? analysis.sources : [versionRef(parent.evidence_id, parent.revision), ...parent.sources];
          await tx.query(`insert into ${S}.evidence (id, tenant_id, project_id, kind, title, compartment, current_revision, restricted, restrictions, sources, source_bases, created_by, created_at) values ($1,$2,$3,$4,$5,$6,1,$7,$8::jsonb,$9,$10,$11,$12)`,
            [evidenceId, ctx.tenantId, ctx.projectId, input.mode === 'derivative' ? 'derivative' : 'original', input.filename, input.compartment, parent?.restricted ?? false, JSON.stringify(parent?.restricted === true ? [{ inheritedFrom: evidenceRef(parent.evidence_id), at: now }] : []), sources, sources.map((s) => s.replace(/@\d+$/, '')), ctx.actor.id, now]);
        }
        await tx.query(`insert into ${S}.versions (evidence_id, revision, tenant_id, project_id, sha256, size, media_type, filename, object_key, stored_sha256, key_version, wrapped_key, scan_state, scan, bytes_state, cause, dedupe_key, created_by, created_at)
          values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'quarantined',$13::jsonb,'present',$14,$15,$16,$17)`,
          [evidenceId, revision, ctx.tenantId, ctx.projectId, sha256, input.bytes.byteLength, input.mediaType, input.filename, objectKey, storedSha, sealed.keyVersion, sealed.wrappedKey, JSON.stringify({ status: 'pending' }), input.cause, dedupeKey, ctx.actor.id, now]);
        await acquisition(evidenceId, revision);
        const ref = versionRef(evidenceId, revision);
        if (input.mode === 'derivative') {
          const parent = input.parent as VRow;
          await tx.query(`insert into ${S}.derivations (tenant_id, project_id, parent_id, parent_revision, child_id, child_revision, relation, tool, actor_id, at) values ($1,$2,$3,$4,$5,1,$6,$7::jsonb,$8,$9)`,
            [ctx.tenantId, ctx.projectId, parent.evidence_id, parent.revision, evidenceId, input.relation, JSON.stringify(input.tool ?? {}), ctx.actor.id, now]);
          await custody(tx, ctx, parent.evidence_id, parent.revision, 'derived', { derivative: ref, relation: input.relation as string, derivativeSha256: sha256 });
          await custody(tx, ctx, evidenceId, 1, 'derivative_added', { parent: versionRef(parent.evidence_id, parent.revision), relation: input.relation as string, sha256, keyVersion: sealed.keyVersion });
          await emitEvent(tx, SCHEMA, ctx, 'evidence.derivative_added', ref, { parent: versionRef(parent.evidence_id, parent.revision), relation: input.relation as string, sha256 });
        } else if (input.mode === 'version') {
          await custody(tx, ctx, evidenceId, revision, 'version_added', { sha256, cause: input.cause, originKind: analysis.kind, previous: versionRef(evidenceId, revision - 1), keyVersion: sealed.keyVersion });
          await emitEvent(tx, SCHEMA, ctx, 'evidence.version_added', ref, { evidence: evidenceRef(evidenceId), previous: versionRef(evidenceId, revision - 1), sha256, cause: input.cause === 'correction' ? 'source_corrected' : 'source_superseded' });
        } else {
          await custody(tx, ctx, evidenceId, 1, 'accepted', { sha256, size: input.bytes.byteLength, originKind: analysis.kind, originalOwner: analysis.originalOwner, priorHandlingEntries: analysis.handlingHistory.length, gaps: analysis.gaps.map((g) => g.code), keyVersion: sealed.keyVersion });
          await emitEvent(tx, SCHEMA, ctx, 'evidence.accepted', ref, { evidence: evidenceRef(evidenceId), sha256, originKind: analysis.kind, gaps: analysis.gaps.map((g) => g.code) });
        }
        if (input.extraEvent !== undefined) await emitEvent(tx, SCHEMA, ctx, input.extraEvent.type, ref, input.extraEvent.payload);
        await enqueueJob(tx, SCHEMA, ctx, { kind: 'evidence.scan', payload: { evidenceId, revision, attempt: 1 }, dedupeKey: `${evidenceId}@${revision}#1` });
        return { ref, objectKey };
      }));
    } catch (error) { try { await objects.delete(objectKey); } catch { /* an orphan object is reported by verifyAll */ } throw error; }
    if (out.objectKey !== objectKey) { try { await objects.delete(objectKey); } catch { /* reported as orphan by verifyAll */ } }
    if (config.scanInline === true) await engine.runJobsOnce();
    const row = await find(sql, ctx, out.ref, { system: true });
    invariant(row !== null, 'conflict', 'Accepted version could not be read back');
    return infoOf(row);
  }

  // ── jobs ──
  async function scanJob(job: Job): Promise<Json> {
    const ctx: ServiceContext = { ...job.ctx, now: new Date().toISOString() };
    await recheck(ctx, 'evidence:write');
    const p = job.payload as { evidenceId: string; revision: number; attempt: number };
    const ref = versionRef(p.evidenceId, p.revision);
    const v = await find(sql, ctx, ref, { system: true });
    if (v === null || v.scan_state !== 'quarantined' || v.scan_attempt !== p.attempt) return { ref, skipped: true };
    const loaded = await load(v);
    if (loaded.status !== 'matched') { if (loaded.status !== 'key_unavailable') await recordIntegrity(ctx, v, loaded); return { ref, state: 'quarantined', reason: `bytes_${loaded.status}` }; }
    const structural = await structuralCheck(loaded.bytes, { mediaType: v.media_type }, limits);
    const finish = async (state: 'released' | 'blocked', scan: Json, reason: string): Promise<Json> => {
      await sql.tx(async (tx) => {
        const rows = await tx.query(`update ${S}.versions set scan_state=$3, scan=$4::jsonb where evidence_id=$1 and revision=$2 and scan_state='quarantined' and scan_attempt=$5 returning revision`, [p.evidenceId, p.revision, state, JSON.stringify(scan), p.attempt]);
        if (rows.length === 0) return; // another worker already settled this version
        await custody(tx, ctx, p.evidenceId, p.revision, state, { reason, jobId: job.id });
        await emitEvent(tx, SCHEMA, ctx, `evidence.${state}`, ref, { evidence: evidenceRef(p.evidenceId), sha256: v.sha256, reason });
      });
      return { ref, state, reason };
    };
    const base = { at: ctx.now, attempt: p.attempt, structural: json(structural) };
    if (!structural.ok) return finish('blocked', { ...base, status: 'blocked', reason: 'structural_check_failed', malwareScan: 'not_performed' }, structural.findings.filter((f) => f.blocking).map((f) => f.code).join(','));
    if (ports.scanner !== undefined) {
      const verdict = await ports.scanner.scan({ bytes: loaded.bytes, sha256: v.sha256, filename: v.filename, mediaType: v.media_type });
      if (verdict.verdict === 'infected') return finish('blocked', { ...base, status: 'blocked', reason: 'malware_signature_matched', malwareScan: json(verdict), scanner: ports.scanner.name }, `malware:${verdict.signature ?? 'unknown'}`);
      if (verdict.verdict === 'clean') return finish('released', { ...base, status: 'released', policy: 'scanner', malwareScan: json(verdict), scanner: ports.scanner.name }, 'scanner_clean');
      await sql.query(`update ${S}.versions set scan=$3::jsonb where evidence_id=$1 and revision=$2 and scan_state='quarantined'`, [p.evidenceId, p.revision, JSON.stringify({ ...base, status: 'scan_failed', malwareScan: json(verdict), scanner: ports.scanner.name })]);
      throw new DomainError('unavailable', `Scanner ${verdict.verdict}: ${verdict.detail ?? 'no detail'}`);
    }
    if (config.scanPolicy === 'structural_only') return finish('released', { ...base, status: 'released', policy: 'structural_only', malwareScan: 'not_performed', note: 'Released on structural checks only; no malware scanner is configured' }, 'structural_only_policy');
    await sql.query(`update ${S}.versions set scan=$3::jsonb where evidence_id=$1 and revision=$2 and scan_state='quarantined'`, [p.evidenceId, p.revision, JSON.stringify({ ...base, status: 'awaiting_scanner', malwareScan: 'not_performed', note: 'No scanner is configured and no structural-only policy is set; the version stays quarantined' })]);
    return { ref, state: 'quarantined', reason: 'no_scanner_configured' };
  }
  async function integrityJob(job: Job): Promise<Json> {
    const ctx: ServiceContext = { ...job.ctx, now: new Date().toISOString() };
    await recheck(ctx, 'evidence:verify');
    return json(await verifyAllImpl(ctx));
  }
  async function verifyAllImpl(ctx: ServiceContext): Promise<IntegrityReport> {
    const prefix = scopeKey(ctx);
    const rows = await sql.query<VRow>(`${VSEL} where v.tenant_id=$1 and v.project_id=$2 order by v.created_at, v.evidence_id, v.revision`, [ctx.tenantId, ctx.projectId]);
    const results: IntegrityResult[] = []; let matched = 0, failed = 0, disposed = 0, hiddenChecked = 0, hiddenFailed = 0;
    const referenced = new Set<string>();
    for (const v of rows) {
      if (v.bytes_state !== 'disposed') referenced.add(v.object_key);
      const loaded = await load(v);
      const present = loaded.status === 'disposed' ? (await objects.head(v.object_key)) !== null : undefined;
      const result = await recordIntegrity(ctx, v, loaded, present === undefined ? {} : { objectPresent: present });
      const bad = result.status !== 'matched' && result.status !== 'disposed';
      if (result.status === 'matched') matched++; else if (result.status === 'disposed') disposed++; else failed++;
      if (visible(ctx, v.compartment)) results.push(result); else { hiddenChecked++; if (bad) hiddenFailed++; }
    }
    const orphanObjects = (await objects.list(prefix)).filter((k) => !referenced.has(k) && !rows.some((v) => v.bytes_state === 'disposed' && v.object_key === k));
    await sql.tx((tx) => appendAudit(tx, SCHEMA, ctx, 'evidence.integrity_batch', uref('E05', 'integrity_batch', randomUUID()), { checked: rows.length, matched, failed, disposed, orphanObjects: orphanObjects.length }));
    return { checkedAt: iso(ctx.now), checked: rows.length, matched, failed, disposed, hiddenChecked, hiddenFailed, results, orphanObjects, ok: failed === 0, meaning: DIGEST_MEANING };
  }

  async function citationOf(ctx: ServiceContext, citation: string): Promise<{ c: Citation; v: VRow }> {
    const p = typeof citation === 'string' ? (UUID.test(citation) ? { id: citation, kind: 'citation' } : parseRef(citation)) : null;
    if (p === null || p.kind !== 'citation') throw new DomainError('not_found', 'Not found');
    const row = (await sql.query<Record<string, unknown>>(`select * from ${S}.citations where id=$1 and tenant_id=$2 and project_id=$3`, [p.id, ctx.tenantId, ctx.projectId]))[0];
    if (row === undefined) throw new DomainError('not_found', 'Not found');
    const v = await need(sql, ctx, versionRef(row.evidence_id as string, row.revision as number));
    return { v, c: { ref: uref('E05', 'citation', row.id as string), id: row.id as string, version: versionRef(v.evidence_id, v.revision), sha256: row.sha256 as string, selector: row.selector as Selector, note: row.note as string, validation: row.validation as Json, createdAt: iso(row.created_at as Date), createdBy: row.created_by as string } };
  }
  function highlightsFor(selector: Selector | undefined, page: number, size: { width: number; height: number } | null, body: string | null): Highlight[] {
    if (selector === undefined) return [];
    if (selector.kind === 'page' && selector.page === page && size !== null) { const box = selector.box ?? { x: 0, y: 0, w: 1, h: 1 }; return [{ kind: 'box', page, box, pixels: boxToPixels(box, size.width, size.height) }]; }
    if (selector.kind === 'text' && body !== null) return [{ kind: 'text', start: selector.start, end: Math.min(selector.end, body.length), quote: body.slice(selector.start, selector.end) }];
    if (selector.kind === 'time') return [{ kind: 'time', startMs: selector.startMs, endMs: selector.endMs }];
    return [];
  }

  const engine: EvidenceEngine = {
    manifest,

    // ── EvidencePort ──
    async describe(ctx, ref) { requireCapability(ctx, 'evidence:read'); const v = await find(sql, ctx, ref); return v === null ? null : infoOf(v); },
    async describeVersion(ctx, ref) { requireCapability(ctx, 'evidence:read'); const v = await find(sql, ctx, ref); return v === null ? null : detailOf(v); },
    async getBytes(ctx, ref, options = {}) {
      requireCapability(ctx, 'evidence:read');
      const v = await need(sql, ctx, ref);
      const use: UseAction = options.use ?? ((REPRODUCTION as readonly string[]).includes(ctx.purpose) ? ctx.purpose as UseAction : 'investigate');
      invariant(['investigate', 'preserve', 'cite', 'reproduce', 'adapt', 'publish', 'license', 'process'].includes(use), 'invalid_input', 'Unsupported use');
      // Research reads and citation never treat unknown reproduction rights as a prohibition; reproduction-type uses ask.
      const decision = REPRODUCTION.includes(use) ? await requireUse(ctx, [v], use, 'retrieval') : null;
      const bytes = await readVerified(ctx, v);
      await sql.tx((tx) => custody(tx, ctx, v.evidence_id, v.revision, 'accessed', { use, sha256: v.sha256, ...(options.reason === undefined ? {} : { reason: text(options.reason, 'reason') }), ...(decision === null ? {} : { useDecision: decision }) }));
      return new Uint8Array(bytes);
    },
    async accept(ctx, input) {
      requireCapability(ctx, 'evidence:write');
      const content = validContent(input);
      const compartment = input.compartment === undefined || input.compartment === '' ? null : text(input.compartment, 'compartment', 128);
      if (compartment !== null && !ctx.compartments.includes(compartment)) throw new DomainError('forbidden', 'Caller does not hold the target compartment');
      invariant(input.origin === null || typeof input.origin === 'object', 'invalid_input', 'origin must be a JSON object');
      return ingest(ctx, { ...content, origin: json(input.origin), compartment, idempotencyKey: input.idempotencyKey, mode: 'original', cause: 'accept' });
    },
    async addDerivative(ctx, input) {
      requireCapability(ctx, 'evidence:write');
      const content = validContent(input);
      const relation = text(input.relation, 'relation', 64);
      invariant(/^[a-z][a-z0-9_]*$/.test(relation), 'invalid_input', 'relation must be a lowercase identifier');
      const parent = await need(sql, ctx, input.parent);
      if (parent.scan_state === 'blocked') throw new DomainError('invalid_state', 'Parent version is blocked');
      return ingest(ctx, { ...content, origin: { kind: 'derivative', parent: versionRef(parent.evidence_id, parent.revision), relation }, compartment: parent.compartment, idempotencyKey: input.idempotencyKey, mode: 'derivative', parent, relation, tool: json(input.tool), cause: 'derivative' });
    },

    // ── versions, listing ──
    async addVersion(ctx, input) {
      requireCapability(ctx, 'evidence:write');
      const content = validContent(input);
      const current = await need(sql, ctx, input.evidence);
      const cause = input.cause ?? 'refresh';
      invariant(cause === 'refresh' || cause === 'correction', 'invalid_input', 'cause must be refresh or correction');
      return ingest(ctx, { ...content, origin: json(input.origin), compartment: current.compartment, idempotencyKey: input.idempotencyKey, mode: 'version', into: current.evidence_id, cause });
    },
    async versions(ctx, ref) {
      requireCapability(ctx, 'evidence:read');
      const v = await need(sql, ctx, ref);
      return (await sql.query<VRow>(`${VSEL} where v.evidence_id=$1 and v.tenant_id=$2 and v.project_id=$3 order by v.revision`, [v.evidence_id, ctx.tenantId, ctx.projectId])).map(detailOf);
    },
    async list(ctx, options = {}) {
      requireCapability(ctx, 'evidence:read');
      const limit = Math.min(Math.max(Number(options.limit ?? 50) || 50, 1), 200);
      const before = options.before !== undefined && Number.isFinite(Date.parse(options.before)) ? iso(options.before) : null;
      return (await sql.query<VRow>(`${VSEL} where v.tenant_id=$1 and v.project_id=$2 and v.revision=e.current_revision and (e.compartment is null or e.compartment = any($3)) and ($4::timestamptz is null or e.created_at < $4) order by e.created_at desc, e.id limit ${limit}`, [ctx.tenantId, ctx.projectId, [...ctx.compartments], before])).map(detailOf);
    },
    async rescan(ctx, ref) {
      requireCapability(ctx, 'evidence:write');
      const v = await need(sql, ctx, ref);
      if (v.scan_state !== 'quarantined') throw new DomainError('invalid_state', `Version is ${v.scan_state}; only quarantined versions can be rescanned`);
      return sql.tx(async (tx) => {
        const row = (await tx.query<{ scan_attempt: number }>(`update ${S}.versions set scan_attempt=scan_attempt+1 where evidence_id=$1 and revision=$2 and scan_state='quarantined' returning scan_attempt`, [v.evidence_id, v.revision]))[0];
        if (row === undefined) throw new DomainError('invalid_state', 'Version is no longer quarantined');
        await custody(tx, ctx, v.evidence_id, v.revision, 'rescan_requested', { attempt: row.scan_attempt });
        const job = await enqueueJob(tx, SCHEMA, ctx, { kind: 'evidence.scan', payload: { evidenceId: v.evidence_id, revision: v.revision, attempt: row.scan_attempt }, dedupeKey: `${v.evidence_id}@${v.revision}#${row.scan_attempt}` });
        return { jobId: job.id };
      });
    },

    // ── custody & provenance ──
    async recordHandling(ctx, ref, input) {
      requireCapability(ctx, 'evidence:write');
      invariant(isObject(input) && ['referenced', 'copied', 'transferred', 'viewed', 'note'].includes(input.action), 'invalid_input', 'Unsupported handling action');
      const reason = text(input.reason, 'reason'); const destination = input.destination === undefined ? undefined : text(input.destination, 'destination', 500);
      const v = await need(sql, ctx, ref);
      return sql.tx((tx) => idempotent(tx, SCHEMA, ctx, input.idempotencyKey, { op: 'handling', ref, action: input.action, reason, destination: destination ?? null }, async () =>
        json(await custody(tx, ctx, v.evidence_id, v.revision, input.action, { reason, sha256: v.sha256, ...(destination === undefined ? {} : { destination }) })))) as unknown as Promise<CustodyEntry>;
    },
    async custody(ctx, ref) {
      requireCapability(ctx, 'evidence:read');
      const v = await need(sql, ctx, ref);
      const entries = await custodyOf(sql, v.evidence_id);
      return { entries, chainValid: verifyCustodyChain(entries) };
    },
    async provenance(ctx, ref) {
      requireCapability(ctx, 'evidence:read');
      const v = await need(sql, ctx, ref);
      const scope = [v.evidence_id, ctx.tenantId, ctx.projectId];
      const versions = await sql.query<VRow>(`${VSEL} where v.evidence_id=$1 and v.tenant_id=$2 and v.project_id=$3 order by v.revision`, scope);
      const acquisitions = await sql.query<Record<string, unknown>>(`select * from ${S}.acquisitions where evidence_id=$1 and tenant_id=$2 and project_id=$3 order by at, id`, scope);
      const entries = await custodyOf(sql, v.evidence_id);
      const edge = (r: Record<string, unknown>, side: 'parent' | 'child'): Json => {
        const id = r[`${side}_id`] as string, revision = r[`${side}_revision`] as number;
        if (!visible(ctx, (r.other_compartment as string | null) ?? null)) return { hidden: true, relation: r.relation as string, note: 'The related version is outside the caller\'s compartments' };
        return { ref: versionRef(id, revision), relation: r.relation as string, tool: r.tool as Json, sha256: r.other_sha256 as string, at: iso(r.at as Date), actorId: r.actor_id as string, bytesState: r.other_bytes_state as string };
      };
      const parents = await sql.query<Record<string, unknown>>(`select d.*, e.compartment as other_compartment, pv.sha256 as other_sha256, pv.bytes_state as other_bytes_state from ${S}.derivations d join ${S}.evidence e on e.id=d.parent_id join ${S}.versions pv on pv.evidence_id=d.parent_id and pv.revision=d.parent_revision where d.child_id=$1 and d.tenant_id=$2 and d.project_id=$3 order by d.at`, scope);
      const children = await sql.query<Record<string, unknown>>(`select d.*, e.compartment as other_compartment, cv.sha256 as other_sha256, cv.bytes_state as other_bytes_state from ${S}.derivations d join ${S}.evidence e on e.id=d.child_id join ${S}.versions cv on cv.evidence_id=d.child_id and cv.revision=d.child_revision where d.parent_id=$1 and d.tenant_id=$2 and d.project_id=$3 order by d.at`, scope);
      const hideSource = parents.some((r) => !visible(ctx, (r.other_compartment as string | null) ?? null));
      const citations = await sql.query<Record<string, unknown>>(`select * from ${S}.citations where evidence_id=$1 and tenant_id=$2 and project_id=$3 order by created_at`, scope);
      const retention = await sql.query<Record<string, unknown>>(`select * from ${S}.retention_decisions where evidence_id=$1 and tenant_id=$2 and project_id=$3 order by at`, scope);
      const checks = await sql.query<Record<string, unknown>>(`select * from ${S}.integrity_checks where evidence_id=$1 and tenant_id=$2 and project_id=$3 order by at desc limit 100`, scope);
      const gaps: Gap[] = [];
      for (const a of acquisitions) for (const g of a.gaps as Gap[]) gaps.push({ ...g, revision: a.revision as number });
      for (const ver of versions) { const g = bytesGap(ver); if (g !== null) gaps.push(g); if (!acquisitions.some((a) => a.revision === ver.revision)) gaps.push({ code: 'acquisition_record_missing', revision: ver.revision, detail: 'No acquisition record exists for this revision' }); }
      if (hideSource) gaps.push({ code: 'source_not_visible', detail: 'This is a derivative; its source is preserved but is outside the caller\'s compartments' });
      for (const r of parents) if (visible(ctx, (r.other_compartment as string | null) ?? null) && r.other_bytes_state !== 'present') gaps.push({ code: 'source_bytes_unavailable', detail: `The source version ${versionRef(r.parent_id as string, r.parent_revision as number)} is ${String(r.other_bytes_state)}` });
      if (v.stale) for (const reason of v.stale_reasons) gaps.push({ code: 'upstream_changed', detail: reason });
      const scrub = (detail: Json): Json => hideSource && isObject(detail) ? Object.fromEntries(Object.entries(detail).filter(([k]) => k !== 'parent')) as Json : detail;
      const custodyOut = hideSource ? entries : entries; // hashes cover the stored detail, so entries are returned unmodified
      return {
        evidence: evidenceRef(v.evidence_id), title: v.title, kind: v.e_kind, compartment: v.compartment, versions: versions.map(detailOf),
        acquisitions: acquisitions.map((a) => ({ revision: a.revision as number, originKind: a.origin_kind as string, origin: scrub(a.origin as Json), originalOwner: (a.original_owner as string | null) ?? null, handlingHistory: a.handling_history as Json, gaps: a.gaps as Json, actorId: a.actor_id as string, at: iso(a.at as Date) })),
        custody: custodyOut, custodyChainValid: verifyCustodyChain(entries),
        derivedFrom: parents.map((r) => edge(r, 'parent')), derivatives: children.map((r) => edge(r, 'child')),
        citations: citations.map((row) => ({ ref: uref('E05', 'citation', row.id as string), id: row.id as string, version: versionRef(row.evidence_id as string, row.revision as number), sha256: row.sha256 as string, selector: row.selector as Selector, note: row.note as string, validation: row.validation as Json, createdAt: iso(row.created_at as Date), createdBy: row.created_by as string })),
        retention: retention.map((r) => ({ id: r.id as string, revision: (r.revision as number | null) ?? null, action: r.action as string, reason: r.reason as string, disposeAfter: r.dispose_after ? iso(r.dispose_after as Date) : null, authorization: r.authorization_record as Json, actorId: r.actor_id as string, at: iso(r.at as Date) })),
        integrityChecks: checks.map((r) => ({ revision: r.revision as number, status: r.status as string, expectedSha256: r.expected_sha256 as string, observedSha256: (r.observed_sha256 as string | null) ?? null, detail: (r.detail as string | null) ?? null, at: iso(r.at as Date) })),
        gaps, authenticity: authenticityOf(v.authenticity), digestMeaning: DIGEST_MEANING,
      };
    },

    // ── citations ──
    async createCitation(ctx, input) {
      requireCapability(ctx, 'evidence:cite');
      invariant(isObject(input) && typeof input.version === 'string', 'invalid_input', 'version reference required');
      const pinned = parseRef(input.version);
      invariant(pinned !== null && pinned.kind === 'evidence_version' && pinned.revision !== undefined, 'invalid_input', 'A citation must pin an exact evidence version (E05:evidence_version:<id>@<revision>)');
      const selector = validSelector(input.selector);
      const note = input.note === undefined ? '' : text(input.note, 'note', 4000);
      const v = await need(sql, ctx, input.version);
      if (v.scan_state !== 'released') throw new DomainError('invalid_state', 'Only released versions can be cited');
      // Validate the selector against the actual preserved bytes where a tool can do so.
      let validation: Json = { checked: false, reason: 'selector kind not checked against content' };
      if (selector.kind !== 'whole' && v.bytes_state === 'present') {
        const bytes = await readVerified(ctx, v); const type = baseMediaType(v.media_type);
        if (selector.kind === 'text' && isTextMedia(type)) {
          const body = decodeText(bytes);
          invariant(selector.end <= body.length, 'invalid_input', 'Text selector is outside the content');
          invariant(selector.quote === undefined || body.slice(selector.start, selector.end) === selector.quote, 'invalid_input', 'Quote does not match the content at the selected offsets');
          validation = { checked: true, basis: 'text offsets verified against preserved bytes' };
        } else if (selector.kind === 'page' && type === 'application/pdf') {
          try { const pages = await withTempDir(async (dir) => { const f = join(dir, 'source.pdf'); await writeFile(f, bytes, { mode: 0o600 }); return pdfPageCount(f); }); invariant(selector.page <= pages, 'invalid_input', 'Page selector is beyond the last page'); validation = { checked: true, basis: `page exists (document has ${pages} pages)` }; }
          catch (error) { if (error instanceof DomainError && error.code === 'unavailable') validation = { checked: false, reason: error.message }; else throw error; }
        } else if (selector.kind === 'time' && /^(audio|video)\//.test(type)) {
          try { const duration = await withTempDir(async (dir) => { const f = join(dir, 'source.media'); await writeFile(f, bytes, { mode: 0o600 }); return mediaDurationMs(f); }); if (duration !== null) { invariant(selector.endMs <= duration + 500, 'invalid_input', 'Time selector is beyond the end of the recording'); validation = { checked: true, basis: `within duration ${duration} ms` }; } }
          catch (error) { if (error instanceof DomainError && error.code === 'unavailable') validation = { checked: false, reason: error.message }; else throw error; }
        } else if (selector.kind === 'page' && type.startsWith('image/')) { invariant(selector.page === 1, 'invalid_input', 'Images have a single page'); validation = { checked: true, basis: 'single-page image' }; }
      }
      return sql.tx((tx) => idempotent(tx, SCHEMA, ctx, input.idempotencyKey, { op: 'cite', version: input.version, selector, note }, async () => {
        const id = randomUUID(); const now = iso(ctx.now);
        await tx.query(`insert into ${S}.citations (id, tenant_id, project_id, evidence_id, revision, sha256, selector, note, validation, created_by, created_at) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9::jsonb,$10,$11)`, [id, ctx.tenantId, ctx.projectId, v.evidence_id, v.revision, v.sha256, JSON.stringify(selector), note, JSON.stringify(validation), ctx.actor.id, now]);
        await custody(tx, ctx, v.evidence_id, v.revision, 'cited', { citation: uref('E05', 'citation', id), sha256: v.sha256, selectorKind: selector.kind });
        return json({ ref: uref('E05', 'citation', id), id, version: versionRef(v.evidence_id, v.revision), sha256: v.sha256, selector, note, validation, createdAt: now, createdBy: ctx.actor.id });
      })) as unknown as Promise<Citation>;
    },
    async resolveCitation(ctx, citation) {
      requireCapability(ctx, 'evidence:read');
      const { c, v } = await citationOf(ctx, citation);
      let gap: Gap | null = null; let current = v;
      if (v.scan_state !== 'released') gap = { code: `version_${v.scan_state}`, revision: v.revision, detail: `The cited version is ${v.scan_state}` };
      else {
        const loaded = await load(v);
        if (loaded.status === 'key_unavailable') throw new DomainError('unavailable', loaded.detail);
        if (loaded.status !== 'matched' || v.bytes_state !== 'present') { if (loaded.status !== 'disposed') await recordIntegrity(ctx, v, loaded); current = await need(sql, ctx, c.version); gap = bytesGap(current); }
      }
      invariant(c.sha256 === v.sha256, 'conflict', 'Citation digest does not match the preserved version');
      return { citation: c, state: gap === null ? 'resolved' : 'gap', version: detailOf(current), isCurrentVersion: v.revision === v.current_revision, currentRef: versionRef(v.evidence_id, v.current_revision), gap, authenticity: authenticityOf(v.authenticity), digestMeaning: DIGEST_MEANING };
    },

    // ── source viewer ──
    async renderView(ctx, ref, options = {}) {
      requireCapability(ctx, 'evidence:read');
      let selector = options.selector === undefined ? undefined : validSelector(options.selector);
      let target = ref;
      if (options.citation !== undefined) { const { c } = await citationOf(ctx, options.citation); const p = parseRef(ref), q = parseRef(c.version); invariant(p !== null && q !== null && p.id === q.id && (p.revision === undefined || p.revision === q.revision), 'invalid_input', 'Citation is bound to a different version'); selector = c.selector; target = c.version; }
      const v = await need(sql, ctx, target);
      const bytes = await readVerified(ctx, v);
      const type = baseMediaType(v.media_type);
      const common = { ref: versionRef(v.evidence_id, v.revision), sha256: v.sha256, mediaType: v.media_type, authenticity: authenticityOf(v.authenticity), digestMeaning: DIGEST_MEANING };
      const dpi = Math.min(Math.max(Math.floor(Number(options.dpi ?? 110)) || 110, 36), 300);
      let view: ViewData;
      if (type === 'application/pdf') {
        const page = options.page ?? (selector?.kind === 'page' ? selector.page : 1);
        invariant(Number.isSafeInteger(page) && page >= 1, 'invalid_input', 'Invalid page');
        view = await withTempDir(async (dir) => {
          const file = join(dir, 'source.pdf'); await writeFile(file, bytes, { mode: 0o600 });
          const pageCount = await pdfPageCount(file);
          invariant(page <= pageCount, 'invalid_input', 'Page is beyond the last page');
          const png = await renderPdfPage(dir, file, page, dpi);
          const size = await imageSize(png); const words = await pdfPageWords(file, page);
          return { ...common, kind: 'pdf_page' as const, page, pageCount, image: new Uint8Array(await readFile(png)), imageMediaType: 'image/png' as const, widthPx: size.width, heightPx: size.height, pageWidthPt: words.widthPt, pageHeightPt: words.heightPt, words: words.words, highlights: highlightsFor(selector, page, size, null) };
        });
      } else if (['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(type)) {
        const size = await withTempDir(async (dir) => { const file = join(dir, 'source.img'); await writeFile(file, bytes, { mode: 0o600 }); return imageSize(file); });
        view = { ...common, kind: 'image', image: new Uint8Array(bytes), imageMediaType: type, widthPx: size.width, heightPx: size.height, highlights: highlightsFor(selector, 1, size, null) };
      } else if (/^(audio|video)\//.test(type)) {
        const durationMs = await withTempDir(async (dir) => { const file = join(dir, 'source.media'); await writeFile(file, bytes, { mode: 0o600 }); return mediaDurationMs(file); });
        const start = Math.floor(Number(options.range?.start ?? 0)); const end = Math.min(bytes.byteLength - 1, Math.floor(Number(options.range?.end ?? Math.min(bytes.byteLength - 1, start + 4 * 1024 * 1024 - 1))));
        invariant(Number.isSafeInteger(start) && start >= 0 && (bytes.byteLength === 0 || (start < bytes.byteLength && end >= start)), 'invalid_input', 'Byte range is not satisfiable');
        view = { ...common, kind: 'media', durationMs, totalBytes: bytes.byteLength, range: { start, end }, bytes: new Uint8Array(bytes.subarray(start, end + 1)), seekMs: options.timeMs ?? (selector?.kind === 'time' ? selector.startMs : 0), highlights: highlightsFor(selector, 1, null, null) };
      } else if (isTextMedia(type)) {
        const body = decodeText(bytes);
        view = { ...common, kind: 'text', text: body, highlights: highlightsFor(selector, 1, null, body) };
      } else view = { ...common, kind: 'unsupported', reason: `No viewer for ${type}`, highlights: [] };
      await sql.tx((tx) => custody(tx, ctx, v.evidence_id, v.revision, 'viewed', { sha256: v.sha256, view: view.kind, ...(view.kind === 'pdf_page' ? { page: view.page } : {}), ...(options.citation === undefined ? {} : { citation: options.citation }) }));
      return view;
    },

    // ── redaction ──
    async redact(ctx, ref, input) {
      requireCapability(ctx, 'evidence:redact');
      invariant(isObject(input), 'invalid_input', 'Redaction input required');
      const reason = text(input.reason, 'reason');
      const source = await need(sql, ctx, ref);
      const compartment = input.compartment === undefined ? source.compartment : input.compartment === null || input.compartment === '' ? null : text(input.compartment, 'compartment', 128);
      if (compartment !== null && compartment !== source.compartment && !ctx.compartments.includes(compartment)) throw new DomainError('forbidden', 'Caller does not hold the target compartment');
      const bytes = await readVerified(ctx, source);
      const type = baseMediaType(source.media_type);
      const dpi = Math.min(Math.max(Math.floor(Number(input.dpi ?? config.redaction?.dpi ?? 150)) || 150, 72), 300);
      const sourceRef = versionRef(source.evidence_id, source.revision);
      const stem = source.filename.replace(/\.[A-Za-z0-9]{1,8}$/, '');
      let out: { bytes: Uint8Array; mediaType: string; filename: string; method: Json };
      if (type === 'application/pdf') {
        invariant(Array.isArray(input.regions) && input.regions.length > 0 && input.regions.length <= 2000 && input.textRanges === undefined, 'invalid_input', 'PDF redaction requires page regions');
        const regions: PageRegion[] = input.regions.map((r) => ({ page: Number((r as PageRegion).page), ...validBox(r) }));
        const result = await redactPdf(bytes, regions, { dpi, maxPages: config.redaction?.maxPages ?? 200 });
        out = { bytes: result.bytes, mediaType: 'application/pdf', filename: `${stem}.redacted.pdf`, method: { method: 'rasterize_and_remove_pixels', dpi, pageCount: result.pageCount, regions: json(regions), textLayer: 'none (every page is an image; no text, annotations or metadata are carried over)', tools: { pdftoppm: await toolVersion('pdftoppm'), convert: await toolVersion('convert', ['-version']) } } };
      } else if (['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(type)) {
        invariant(Array.isArray(input.regions) && input.regions.length > 0 && input.regions.length <= 2000 && input.textRanges === undefined, 'invalid_input', 'Image redaction requires regions');
        const boxes = input.regions.map((r) => validBox(r));
        const result = await redactImage(bytes, boxes);
        out = { bytes: result.bytes, mediaType: 'image/png', filename: `${stem}.redacted.png`, method: { method: 'rasterize_and_remove_pixels', widthPx: result.width, heightPx: result.height, regions: json(boxes.map((b) => ({ page: 1, ...b }))), metadata: 'stripped (re-encoded from raw pixels, then exiftool -all=)', tools: { convert: await toolVersion('convert', ['-version']), exiftool: await toolVersion('exiftool', ['-ver']) } } };
      } else if (isTextMedia(type)) {
        invariant(Array.isArray(input.textRanges) && input.textRanges.length > 0 && input.textRanges.length <= 5000 && input.regions === undefined, 'invalid_input', 'Text redaction requires text ranges');
        const ranges = input.textRanges.map((r) => ({ start: r.start, end: r.end }));
        out = { bytes: new Uint8Array(Buffer.from(redactText(decodeText(bytes), ranges), 'utf8')), mediaType: source.media_type, filename: `${stem}.redacted.txt`, method: { method: 'text_offsets_replaced', ranges: json(ranges), offsetUnit: 'UTF-16 code units of the UTF-8 decoded text', replacement: 'U+2588 per code unit (offsets preserved)' } };
      } else throw new DomainError('unsupported_media_type', `Redaction is not supported for ${type}`);
      const manifestJson: Json = { schema: 'evidence.redaction/1', source: sourceRef, sourceSha256: source.sha256, reason, redactedBy: ctx.actor.id, at: iso(ctx.now), outputSha256: sha256Hex(out.bytes), ...(out.method as Record<string, Json>), note: 'The original is preserved unchanged. The removed content is absent from the derivative, not covered by an overlay.' };
      const derivative = await ingest(ctx, { bytes: out.bytes, mediaType: out.mediaType, filename: out.filename, origin: { kind: 'derivative', parent: sourceRef, relation: 'redacted' }, compartment, idempotencyKey: input.idempotencyKey, mode: 'derivative', parent: source, relation: 'redacted', tool: manifestJson, cause: 'derivative', extraEvent: { type: 'evidence.redaction_created', payload: { source: sourceRef, outputSha256: sha256Hex(out.bytes), compartment } } });
      return { derivative, manifest: manifestJson };
    },

    // ── retention ──
    async setRetention(ctx, ref, input) {
      requireCapability(ctx, 'evidence:retain');
      invariant(isObject(input) && ['hold', 'release_hold', 'schedule', 'clear_schedule'].includes(input.action), 'invalid_input', 'Unsupported retention action');
      const reason = text(input.reason, 'reason'); const authorization = validAuthorization(input.authorization);
      const disposeAfter = input.action === 'schedule' ? (() => { invariant(typeof input.disposeAfter === 'string' && Number.isFinite(Date.parse(input.disposeAfter)), 'invalid_input', 'disposeAfter timestamp required'); return iso(input.disposeAfter); })() : null;
      const v = await need(sql, ctx, ref);
      await sql.tx((tx) => idempotent(tx, SCHEMA, ctx, input.idempotencyKey, { op: 'retention', ref, action: input.action, reason, disposeAfter, authorization }, async () => {
        const cur = (await tx.query<{ hold: boolean; retention: Record<string, Json> }>(`select hold, retention from ${S}.evidence where id=$1 for update`, [v.evidence_id]))[0] as { hold: boolean; retention: Record<string, Json> };
        const retention: Record<string, Json> = { ...cur.retention };
        let hold = cur.hold;
        if (input.action === 'hold') { hold = true; retention.hold = { reason, since: iso(ctx.now), authorization }; }
        if (input.action === 'release_hold') { invariant(cur.hold, 'invalid_state', 'No hold is active'); hold = false; delete retention.hold; }
        if (input.action === 'schedule') retention.schedule = { disposeAfter, reason, authorization };
        if (input.action === 'clear_schedule') delete retention.schedule;
        await tx.query(`update ${S}.evidence set hold=$2, retention=$3::jsonb where id=$1`, [v.evidence_id, hold, JSON.stringify(retention)]);
        await tx.query(`insert into ${S}.retention_decisions (id, tenant_id, project_id, evidence_id, revision, action, reason, dispose_after, authorization_record, actor_id, at) values ($1,$2,$3,$4,null,$5,$6,$7,$8::jsonb,$9,$10)`, [randomUUID(), ctx.tenantId, ctx.projectId, v.evidence_id, input.action, reason, disposeAfter, JSON.stringify(authorization), ctx.actor.id, iso(ctx.now)]);
        await custody(tx, ctx, v.evidence_id, null, `retention_${input.action}`, { reason, authorization, ...(disposeAfter === null ? {} : { disposeAfter }) });
        await emitEvent(tx, SCHEMA, ctx, 'evidence.retention_changed', versionRef(v.evidence_id), { evidence: evidenceRef(v.evidence_id), action: input.action, hold, ...(disposeAfter === null ? {} : { disposeAfter }) });
        return { ok: true };
      }));
      return detailOf(await need(sql, ctx, ref));
    },
    async dueForDisposal(ctx, options = {}) {
      requireCapability(ctx, 'evidence:retain');
      const at = iso(options.at ?? ctx.now);
      return (await sql.query<VRow>(`${VSEL} where v.tenant_id=$1 and v.project_id=$2 and e.hold=false and v.bytes_state <> 'disposed' and (e.retention->'schedule'->>'disposeAfter')::timestamptz <= $3 and (e.compartment is null or e.compartment = any($4)) order by e.created_at, v.revision`, [ctx.tenantId, ctx.projectId, at, [...ctx.compartments]])).map(detailOf);
    },
    async dispose(ctx, ref, input) {
      invariant(isObject(input), 'invalid_input', 'Disposal input required');
      const reason = text(input.reason, 'reason'); const authorization = validAuthorization(input.authorization);
      requireCapability(ctx, 'evidence:admin');
      const v = await need(sql, ctx, ref);
      await recheck(ctx, 'evidence:admin', versionRef(v.evidence_id, v.revision));
      const pinned = parseRef(ref)?.revision !== undefined;
      const keys = await sql.tx((tx) => idempotent(tx, SCHEMA, ctx, input.idempotencyKey, { op: 'dispose', ref, reason, authorization }, async () => {
        const ev = (await tx.query<{ hold: boolean }>(`select hold from ${S}.evidence where id=$1 for update`, [v.evidence_id]))[0] as { hold: boolean };
        if (ev.hold) throw new DomainError('invalid_state', 'A retention hold is active; disposal is refused');
        const targets = await tx.query<{ revision: number; object_key: string; sha256: string; bytes_state: string }>(`select revision, object_key, sha256, bytes_state from ${S}.versions where evidence_id=$1 and ($2::int is null or revision=$2) order by revision`, [v.evidence_id, pinned ? v.revision : null]);
        const out: string[] = [];
        for (const t of targets) {
          out.push(t.object_key);
          if (t.bytes_state === 'disposed') continue;
          await tx.query(`update ${S}.versions set bytes_state='disposed', wrapped_key=null, dedupe_key=null where evidence_id=$1 and revision=$2`, [v.evidence_id, t.revision]);
          await tx.query(`insert into ${S}.retention_decisions (id, tenant_id, project_id, evidence_id, revision, action, reason, dispose_after, authorization_record, actor_id, at) values ($1,$2,$3,$4,$5,'disposal',$6,null,$7::jsonb,$8,$9)`, [randomUUID(), ctx.tenantId, ctx.projectId, v.evidence_id, t.revision, reason, JSON.stringify(authorization), ctx.actor.id, iso(ctx.now)]);
          await custody(tx, ctx, v.evidence_id, t.revision, 'disposed', { reason, authorization, tombstoneSha256: t.sha256 });
          await emitEvent(tx, SCHEMA, ctx, 'evidence.retention_changed', versionRef(v.evidence_id, t.revision), { evidence: evidenceRef(v.evidence_id), action: 'disposal', tombstoneSha256: t.sha256 });
        }
        return out;
      }));
      // Bytes are removed after the decision is durable. A failed delete is retried by calling dispose again and is
      // reported by verifyAll as `disposed_bytes_present`.
      for (const key of keys) await objects.delete(key);
      return (await sql.query<VRow>(`${VSEL} where v.evidence_id=$1 and v.tenant_id=$2 and v.project_id=$3 and ($4::int is null or v.revision=$4) order by v.revision`, [v.evidence_id, ctx.tenantId, ctx.projectId, pinned ? v.revision : null])).map(detailOf);
    },

    // ── integrity ──
    async verifyIntegrity(ctx, ref) {
      requireCapability(ctx, 'evidence:verify');
      const v = await need(sql, ctx, ref);
      const loaded = await load(v);
      const present = loaded.status === 'disposed' ? (await objects.head(v.object_key)) !== null : undefined;
      return recordIntegrity(ctx, v, loaded, present === undefined ? {} : { objectPresent: present });
    },
    async verifyAll(ctx) { requireCapability(ctx, 'evidence:verify'); return verifyAllImpl(ctx); },
    async startIntegrityBatch(ctx, options = {}) {
      requireCapability(ctx, 'evidence:verify');
      const job = await sql.tx((tx) => enqueueJob(tx, SCHEMA, ctx, { kind: 'evidence.integrity_batch', payload: {}, ...(options.idempotencyKey === undefined ? {} : { dedupeKey: text(options.idempotencyKey, 'idempotencyKey', 200) }), maxAttempts: 3 }));
      return { jobId: job.id };
    },
    async restoreBytes(ctx, ref, bytes, input) {
      requireCapability(ctx, 'evidence:admin');
      invariant(bytes instanceof Uint8Array, 'invalid_input', 'bytes must be a Uint8Array');
      const reason = text(input?.reason, 'reason');
      const v = await need(sql, ctx, ref);
      if (v.bytes_state === 'disposed') throw new DomainError('invalid_state', 'Disposed versions cannot be restored; accept the content again as a new acquisition');
      if (sha256Hex(bytes) !== v.sha256 || bytes.byteLength !== Number(v.size)) throw new DomainError('invalid_input', 'Supplied bytes do not match the retained digest');
      const objectKey = validObjectKey(`${scopeKey(ctx)}objects/${v.sha256.slice(0, 2)}/${randomUUID()}`);
      const sealed = seal(ctx, v.sha256, Uint8Array.from(bytes));
      await objects.put(objectKey, sealed.stored);
      await sql.tx(async (tx) => {
        await tx.query(`update ${S}.versions set object_key=$3, stored_sha256=$4, key_version=$5, wrapped_key=$6, bytes_state='present', integrity=$7::jsonb where evidence_id=$1 and revision=$2`, [v.evidence_id, v.revision, objectKey, sha256Hex(sealed.stored), sealed.keyVersion, sealed.wrappedKey, JSON.stringify({ status: 'matched', at: iso(ctx.now), detail: 'restored from supplied bytes matching the retained digest' })]);
        await custody(tx, ctx, v.evidence_id, v.revision, 'bytes_restored', { reason, sha256: v.sha256, previousState: v.bytes_state });
        await emitEvent(tx, SCHEMA, ctx, 'evidence.integrity_restored', versionRef(v.evidence_id, v.revision), { sha256: v.sha256 });
      });
      if (v.object_key !== objectKey) { try { await objects.delete(v.object_key); } catch { /* reported as orphan */ } }
      return detailOf(await need(sql, ctx, ref));
    },
    async recordAssessment(ctx, ref, input) {
      requireCapability(ctx, 'evidence:assess');
      invariant(isObject(input), 'invalid_input', 'Assessment input required');
      const assessment = parseUref(text(input.assessmentRef, 'assessmentRef', 300));
      invariant(assessment.engine !== 'E05', 'invalid_input', 'An authenticity assessment must be recorded by another engine; this engine does not assess authenticity');
      const claimedOutcome = text(input.claimedOutcome, 'claimedOutcome', 200);
      const v = await need(sql, ctx, ref);
      await sql.tx(async (tx) => {
        await tx.query(`update ${S}.versions set authenticity=$3::jsonb where evidence_id=$1 and revision=$2`, [v.evidence_id, v.revision, JSON.stringify({ status: 'assessed_elsewhere', assessmentRef: input.assessmentRef, claimedOutcome, recordedAt: iso(ctx.now), recordedBy: ctx.actor.id })]);
        await custody(tx, ctx, v.evidence_id, v.revision, 'assessment_recorded', { assessmentRef: input.assessmentRef, claimedOutcome });
      });
      return detailOf(await need(sql, ctx, ref));
    },
    async liftRestriction(ctx, ref, input) {
      requireCapability(ctx, 'evidence:admin');
      invariant(isObject(input), 'invalid_input', 'Input required');
      const reason = text(input.reason, 'reason'); const authorization = validAuthorization(input.authorization);
      const v = await need(sql, ctx, ref);
      await recheck(ctx, 'evidence:admin', evidenceRef(v.evidence_id));
      if (!v.restricted) throw new DomainError('invalid_state', 'Evidence is not restricted');
      await sql.tx(async (tx) => {
        await tx.query(`update ${S}.evidence set restricted=false, restrictions = restrictions || $2::jsonb where id=$1`, [v.evidence_id, JSON.stringify([{ lifted: true, reason, authorization, at: iso(ctx.now), actorId: ctx.actor.id }])]);
        await custody(tx, ctx, v.evidence_id, null, 'restriction_lifted', { reason, authorization });
        await emitEvent(tx, SCHEMA, ctx, 'evidence.restriction_lifted', versionRef(v.evidence_id), { evidence: evidenceRef(v.evidence_id), reason });
      });
      return detailOf(await need(sql, ctx, ref));
    },

    // ── export ──
    async exportPackage(ctx, refs, options = {}) {
      requireCapability(ctx, 'evidence:export');
      invariant(Array.isArray(refs) && refs.length > 0 && refs.length <= 500 && new Set(refs).size === refs.length, 'invalid_input', 'One to 500 distinct references required');
      const redactedOnly = options.redactedOnly === true; const includeBytes = redactedOnly || options.includeOriginals === true;
      const reason = options.reason === undefined ? null : text(options.reason, 'reason');
      const rows: VRow[] = [];
      for (const ref of refs) rows.push(await need(sql, ctx, ref));
      await recheck(ctx, 'evidence:export');
      for (const v of rows) if (v.restricted) throw new DomainError('consent_denied', 'Evidence is restricted: reproduction and export are blocked while preservation continues');
      const redactedParents = new Map<string, Record<string, unknown>[]>();
      for (const v of rows) {
        const parents = await sql.query<Record<string, unknown>>(`select d.*, e.compartment as other_compartment, pv.sha256 as other_sha256, pv.bytes_state as other_bytes_state from ${S}.derivations d join ${S}.evidence e on e.id=d.parent_id join ${S}.versions pv on pv.evidence_id=d.parent_id and pv.revision=d.parent_revision where d.child_id=$1 and d.child_revision=$2 and d.tenant_id=$3 and d.project_id=$4`, [v.evidence_id, v.revision, ctx.tenantId, ctx.projectId]);
        redactedParents.set(versionRef(v.evidence_id, v.revision), parents);
        if (redactedOnly) invariant(v.e_kind === 'derivative' && parents.some((p) => p.relation === 'redacted'), 'invalid_input', 'redactedOnly exports accept only redacted derivatives');
      }
      const decision = includeBytes ? await requireUse(ctx, rows, 'reproduce', 'provenance_package') : null;
      const files: { name: string; data: Uint8Array }[] = []; const fileList: Json[] = []; const items: Json[] = []; const allGaps: Json[] = [];
      for (const v of rows) {
        const ref = versionRef(v.evidence_id, v.revision);
        const gaps: Gap[] = [];
        const acquisitions = await sql.query<Record<string, unknown>>(`select * from ${S}.acquisitions where evidence_id=$1 and revision <= $2 order by at, id`, [v.evidence_id, v.revision]);
        for (const a of acquisitions) for (const g of a.gaps as Gap[]) gaps.push({ ...g, revision: a.revision as number });
        const bg = bytesGap(v); if (bg !== null) gaps.push(bg);
        if (v.scan_state !== 'released') gaps.push({ code: `version_${v.scan_state}`, revision: v.revision, detail: `This version is ${v.scan_state}; its bytes are not exported` });
        let file: string | null = null;
        if (includeBytes && v.scan_state === 'released' && v.bytes_state !== 'disposed') {
          const loaded = await load(v);
          if (loaded.status === 'key_unavailable') throw new DomainError('unavailable', loaded.detail);
          if (loaded.status === 'matched') { file = `objects/${v.sha256}/${v.filename.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120) || 'content'}`; if (!files.some((f) => f.name === file)) { files.push({ name: file, data: loaded.bytes }); fileList.push({ path: file, sha256: v.sha256, size: Number(v.size) }); } }
          else { await recordIntegrity(ctx, v, loaded); const g: Gap = { code: loaded.status === 'missing' ? 'bytes_missing' : 'bytes_corrupt', revision: v.revision, detail: loaded.detail }; if (!gaps.some((x) => x.code === g.code)) gaps.push(g); }
        } else if (!includeBytes) gaps.push({ code: 'bytes_not_included', revision: v.revision, detail: 'This package was exported without preserved bytes' });
        const parents = redactedParents.get(ref) ?? [];
        const derivedFrom: Json[] = parents.map((p) => {
          const hidden = !visible(ctx, (p.other_compartment as string | null) ?? null);
          if (redactedOnly || hidden) { return { withheld: true, relation: p.relation as string, tool: p.relation === 'redacted' && isObject(p.tool) ? Object.fromEntries(Object.entries(p.tool as Record<string, Json>).filter(([k]) => !['source', 'sourceSha256'].includes(k))) as Json : {}, note: 'The source is preserved by the exporting system and withheld from this package' }; }
          return { ref: versionRef(p.parent_id as string, p.parent_revision as number), sha256: p.other_sha256 as string, relation: p.relation as string, tool: p.tool as Json, bytesState: p.other_bytes_state as string };
        });
        if (derivedFrom.some((d) => isObject(d) && d.withheld === true)) gaps.push({ code: 'source_withheld', detail: 'The source of this derivative is not part of this package' });
        const withheld = derivedFrom.some((d) => isObject(d) && d.withheld === true);
        const chain = await custodyOf(sql, v.evidence_id);
        const retention = await sql.query<Record<string, unknown>>(`select * from ${S}.retention_decisions where evidence_id=$1 order by at`, [v.evidence_id]);
        items.push(json({
          ref, evidence: evidenceRef(v.evidence_id), revision: v.revision, kind: v.e_kind, sha256: v.sha256, size: Number(v.size), mediaType: v.media_type, filename: v.filename,
          state: v.scan_state, bytesState: v.bytes_state, isCurrentVersion: v.revision === v.current_revision, authenticity: authenticityOf(v.authenticity), scan: v.scan, file,
          acquisition: acquisitions.map((a) => ({ revision: a.revision, originKind: a.origin_kind, origin: withheld ? { kind: 'derivative', relation: 'redacted' } : a.origin, originalOwner: a.original_owner ?? null, handlingHistory: a.handling_history, gaps: a.gaps, actorId: a.actor_id, at: iso(a.at as Date) })),
          custody: chain, custodyHead: chain.at(-1)?.hash ?? '', derivedFrom,
          retention: retention.map((r) => ({ revision: r.revision ?? null, action: r.action, reason: r.reason, authorization: r.authorization_record, at: iso(r.at as Date) })),
          integrity: v.integrity, gaps,
        }));
        for (const g of gaps) allGaps.push({ ref, ...g });
      }
      const manifestJson = json({
        schema: 'evidence.provenance-package/1', generatedAt: iso(ctx.now), generatedBy: ctx.actor.id, purpose: ctx.purpose, reason,
        options: { includeOriginals: options.includeOriginals === true, redactedOnly }, statement: DIGEST_MEANING, useDecision: decision,
        custodyNote: redactedOnly ? 'Custody entries of a derivative name its source by opaque reference; source bytes and digests are withheld.' : 'Custody entries are complete up to the time of export; the export itself is recorded afterwards in the exporting system.',
        items, files: fileList, gaps: allGaps,
      });
      const zip = writeZip([{ name: 'manifest.json', data: Buffer.from(JSON.stringify(manifestJson, null, 2)) }, { name: 'README.txt', data: Buffer.from(README) }, ...files]);
      const packageSha = sha256Hex(zip);
      await sql.tx(async (tx) => { for (const v of rows) await custody(tx, ctx, v.evidence_id, v.revision, 'exported', { packageSha256: packageSha, includedBytes: includeBytes, redactedOnly, ...(reason === null ? {} : { reason }), ...(decision === null ? {} : { useDecision: decision }) }); });
      return { bytes: zip, sha256: packageSha, filename: `provenance-${packageSha.slice(0, 12)}.zip`, manifest: manifestJson };
    },
    verifyPackage,

    async rotateKeys(ctx, options = {}) {
      requireCapability(ctx, 'evidence:admin');
      if (config.encryption === undefined) throw new DomainError('invalid_state', 'Encryption at rest is not configured');
      const enc = config.encryption; const limit = Math.min(Math.max(Number(options.limit ?? 500) || 500, 1), 5000);
      const rows = await sql.query<VRow>(`${VSEL} where v.tenant_id=$1 and v.project_id=$2 and v.key_version <> $3 and v.key_version <> 'none' and v.wrapped_key is not null order by v.created_at limit ${limit}`, [ctx.tenantId, ctx.projectId, enc.currentKeyVersion]);
      let rewrapped = 0, unavailable = 0;
      for (const v of rows) {
        let next: { wrappedKey: string; keyVersion: string };
        try { next = rewrapKey(enc, { tenantId: v.tenant_id, projectId: v.project_id, sha256: v.sha256 }, v.wrapped_key as string, v.key_version); } catch { unavailable++; continue; }
        const done = await sql.query(`update ${S}.versions set wrapped_key=$3, key_version=$4 where evidence_id=$1 and revision=$2 and key_version=$5 and wrapped_key=$6 returning revision`, [v.evidence_id, v.revision, next.wrappedKey, next.keyVersion, v.key_version, v.wrapped_key]);
        rewrapped += done.length;
      }
      const remaining = Number(((await sql.query<{ n: string }>(`select count(*)::text as n from ${S}.versions where tenant_id=$1 and project_id=$2 and key_version <> $3 and key_version <> 'none' and wrapped_key is not null`, [ctx.tenantId, ctx.projectId, enc.currentKeyVersion]))[0] as { n: string }).n);
      await sql.tx((tx) => appendAudit(tx, SCHEMA, ctx, 'evidence.keys_rotated', uref('E05', 'key_rotation', randomUUID()), { rewrapped, remaining, unavailable, currentKeyVersion: enc.currentKeyVersion }));
      return { rewrapped, remaining, unavailable, currentKeyVersion: enc.currentKeyVersion };
    },

    // ── jobs ──
    async job(ctx, id) { requireCapability(ctx, 'evidence:read'); return UUID.test(String(id)) ? getJob(sql, SCHEMA, ctx, id) : null; },
    async jobs(ctx, options = {}) { requireCapability(ctx, 'evidence:read'); return listJobs(sql, SCHEMA, ctx, options); },
    async controlJob(ctx, id, action) { requireCapability(ctx, 'evidence:admin'); if (!UUID.test(String(id))) throw new DomainError('not_found', 'Not found'); return controlJob(sql, SCHEMA, ctx, id, action); },
    runJobsOnce(options = {}) { return runJobsOnce(sql, SCHEMA, { 'evidence.scan': scanJob, 'evidence.integrity_batch': integrityJob }, { worker: options.worker ?? worker, limit: options.limit ?? 10, ...(options.leaseMs === undefined ? {} : { leaseMs: options.leaseMs }) }); },

    // ── StandardEngine ──
    async inspect(ctx, ref) {
      requireCapability(ctx, 'evidence:read');
      const p = typeof ref === 'string' ? parseRef(ref) : null;
      if (p === null) return null;
      if (p.kind === 'citation') {
        let found: { c: Citation; v: VRow };
        try { found = await citationOf(ctx, ref); } catch (error) { if (error instanceof DomainError && error.code === 'not_found') return null; throw error; }
        const { c, v } = found; const gap = bytesGap(v);
        return { ref: c.ref, kind: 'citation', title: `Citation of ${v.filename}`, state: gap === null ? 'bound' : 'gap', stale: v.revision !== v.current_revision, blocked: v.restricted, staleReasons: [...(v.revision !== v.current_revision ? [`A newer version exists (${versionRef(v.evidence_id, v.current_revision)}); this citation still resolves to the exact cited version`] : []), ...(gap === null ? [] : [gap.detail])],
          versions: [{ revision: 1, at: c.createdAt, actorId: c.createdBy }], sources: [c.version], dependents: [], permissions: [], decisions: [], history: [{ at: c.createdAt, actorId: c.createdBy, action: 'cited' }], data: json({ ...c, authenticity: authenticityOf(v.authenticity), digestMeaning: DIGEST_MEANING }) };
      }
      const v = await find(sql, ctx, ref);
      if (v === null) return null;
      const prov = await engine.provenance(ctx, ref);
      const d = detailOf(v);
      const reasons = [...v.stale_reasons, ...(v.restricted ? v.restrictions.filter((r) => isObject(r) && typeof r.reason === 'string' && r.lifted !== true).map((r) => `restricted: ${(r as { reason: string }).reason}`) : []), ...(v.scan_state === 'blocked' ? [`blocked: ${isObject(v.scan) ? String(v.scan.reason ?? 'scan') : 'scan'}`] : []), ...prov.gaps.filter((g) => g.code.startsWith('bytes_')).map((g) => g.detail)];
      const state = v.bytes_state !== 'present' ? `bytes_${v.bytes_state}` : v.restricted ? 'restricted' : v.scan_state;
      return {
        ref: p.kind === 'evidence' ? evidenceRef(v.evidence_id) : versionRef(v.evidence_id, v.revision), kind: p.kind, title: v.title, state, stale: v.stale, blocked: v.restricted || v.scan_state === 'blocked', staleReasons: reasons,
        versions: prov.versions.map((x) => ({ revision: x.revision, at: x.createdAt, actorId: x.createdBy, summary: `${x.cause}: sha256 ${x.sha256} (${x.state}, bytes ${x.bytesState})` })),
        sources: [...prov.derivedFrom.filter((e) => isObject(e) && typeof e.ref === 'string').map((e) => (e as { ref: string }).ref), ...(prov.derivedFrom.length === 0 ? v.sources : [])],
        dependents: [...prov.derivatives.filter((e) => isObject(e) && typeof e.ref === 'string').map((e) => (e as { ref: string }).ref), ...prov.citations.map((c) => c.ref)],
        permissions: v.restrictions, decisions: prov.retention,
        history: prov.custody.map((e) => ({ at: e.at, actorId: e.actorId, action: e.action, detail: e.detail })),
        data: json({ version: d, gaps: prov.gaps, acquisitions: prov.acquisitions, custodyChainValid: prov.custodyChainValid, authenticity: d.authenticity, digestMeaning: DIGEST_MEANING }),
      } satisfies Inspection;
    },
    async search(ctx, query) {
      requireCapability(ctx, 'evidence:read');
      const q = typeof query?.q === 'string' ? query.q.trim().slice(0, 200) : '';
      if (q === '') return [];
      const limit = Math.min(Math.max(Number(query.limit ?? 20) || 20, 1), 100);
      const like = `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      const rows = await sql.query<VRow>(`${VSEL} where v.tenant_id=$1 and v.project_id=$2 and (e.compartment is null or e.compartment = any($3)) and (v.filename ilike $4 or e.title ilike $4 or v.sha256 like $5 or v.media_type ilike $4
        or exists (select 1 from ${S}.acquisitions a where a.evidence_id=v.evidence_id and a.revision=v.revision and a.origin::text ilike $4)) order by v.created_at desc limit ${limit}`, [ctx.tenantId, ctx.projectId, [...ctx.compartments], like, `${q.toLowerCase().replace(/[^0-9a-f]/g, '') || 'x'}%`]);
      return rows.map((v): SearchHit => ({ ref: versionRef(v.evidence_id, v.revision), kind: 'evidence_version', title: v.filename, snippet: `${v.media_type}, ${v.size} bytes, sha256 ${v.sha256.slice(0, 16)}…, revision ${v.revision}${v.revision === v.current_revision ? ' (current)' : ''}`, state: v.bytes_state !== 'present' ? `bytes_${v.bytes_state}` : v.scan_state }));
    },
    async audit(ctx, options = {}) {
      requireCapability(ctx, 'evidence:audit');
      const records = await listAudit(sql, SCHEMA, ctx, options);
      const ids = [...new Set(records.map((r) => { try { return parseUref(r.subject).id; } catch { return ''; } }).filter((id) => UUID.test(id)))];
      const hidden = new Set((await sql.query<{ id: string }>(`select id from ${S}.evidence where id = any($1::uuid[]) and compartment is not null and not (compartment = any($2))`, [ids, [...ctx.compartments]])).map((r) => r.id));
      return records.filter((r: AuditRecord) => { try { return !hidden.has(parseUref(r.subject).id); } catch { return true; } });
    },
    async events(ctx, options = {}): Promise<EngineEvent[]> {
      requireCapability(ctx, 'evidence:events');
      return (await readEvents(sql, SCHEMA, { ...options, tenantId: ctx.tenantId })).map((e) => ({ ...e, engine: 'E05' }));
    },
    async applyUpstreamChange(ctx, change) {
      requireCapability(ctx, 'evidence:upstream');
      invariant(isObject(change) && typeof change.eventId === 'string' && change.eventId.length > 0 && change.eventId.length <= 200 && Array.isArray(change.refs) && change.refs.length <= 1000 && typeof change.kind === 'string', 'invalid_input', 'Invalid upstream change');
      const reason = text(change.reason, 'reason');
      const refs = change.refs.filter((r) => { try { parseUref(r); return true; } catch { return false; } });
      return sql.tx(async (tx) => {
        const fresh = await tx.query(`insert into ${S}.upstream_changes (tenant_id, project_id, event_id, kind, at) values ($1,$2,$3,$4,$5) on conflict do nothing returning event_id`, [ctx.tenantId, ctx.projectId, change.eventId, change.kind, iso(ctx.now)]);
        if (fresh.length === 0) return { affected: ((await tx.query<{ affected: string[] }>(`select affected from ${S}.upstream_changes where tenant_id=$1 and project_id=$2 and event_id=$3`, [ctx.tenantId, ctx.projectId, change.eventId]))[0] as { affected: string[] }).affected };
        const bases = refs.map((r) => r.replace(/@\d+$/, ''));
        const own = refs.map(parseRef).filter((p): p is NonNullable<typeof p> => p !== null && (p.kind === 'evidence' || p.kind === 'evidence_version')).map((p) => p.id);
        const direct = await tx.query<{ id: string; sources: string[] }>(`select id, sources from ${S}.evidence where tenant_id=$1 and project_id=$2 and (id = any($3::uuid[]) or source_bases && $4::text[])`, [ctx.tenantId, ctx.projectId, own, bases]);
        const hit = new Set(direct.filter((e) => own.includes(e.id) || e.sources.some((s) => refs.some((r) => { try { return urefMatches(r, s); } catch { return false; } }))).map((e) => e.id));
        for (let frontier = [...hit]; frontier.length > 0;) {
          const kids = await tx.query<{ child_id: string }>(`select distinct child_id from ${S}.derivations where tenant_id=$1 and project_id=$2 and parent_id = any($3::uuid[])`, [ctx.tenantId, ctx.projectId, frontier]);
          frontier = kids.map((k) => k.child_id).filter((id) => !hit.has(id)); frontier.forEach((id) => hit.add(id));
        }
        const restrict = change.kind === 'permission_withdrawn';
        const affected: string[] = [];
        for (const id of [...hit].sort()) {
          const ref = versionRef(id);
          if (restrict) {
            await tx.query(`update ${S}.evidence set restricted=true, restrictions = restrictions || $2::jsonb where id=$1`, [id, JSON.stringify([{ eventId: change.eventId, kind: change.kind, reason, refs, at: iso(ctx.now) }])]);
            await custody(tx, ctx, id, null, 'restricted', { cause: change.eventId, kind: change.kind, reason });
            await emitEvent(tx, SCHEMA, ctx, 'evidence.restricted', ref, { evidence: evidenceRef(id), reason, cause: change.eventId, blocks: ['reproduce', 'export'], preserved: true });
          } else {
            await tx.query(`update ${S}.evidence set stale=true, stale_reasons = stale_reasons || $2::jsonb where id=$1`, [id, JSON.stringify([`${change.kind}: ${reason} (cause ${change.eventId})`])]);
            await custody(tx, ctx, id, null, 'marked_stale', { cause: change.eventId, kind: change.kind, reason });
            await emitEvent(tx, SCHEMA, ctx, 'evidence.stale', ref, { evidence: evidenceRef(id), reason, cause: change.eventId, kind: change.kind });
          }
          affected.push(ref);
        }
        await tx.query(`update ${S}.upstream_changes set affected=$4::jsonb where tenant_id=$1 and project_id=$2 and event_id=$3`, [ctx.tenantId, ctx.projectId, change.eventId, JSON.stringify(affected)]);
        return { affected };
      });
    },
    async health() {
      const detail: Record<string, Json> = { encryption: config.encryption === undefined ? 'disabled (plaintext objects)' : `enabled (current key version ${config.encryption.currentKeyVersion})`, scanner: ports.scanner?.name ?? (config.scanPolicy === 'structural_only' ? 'none (structural_only policy)' : 'none (versions stay quarantined)'), useDecisions: ports.useDecisions === undefined ? (config.reproductionWithoutPort === 'allow' ? 'absent (standalone allow)' : 'absent (reproduction denied)') : 'configured' };
      let ok = true;
      try { await sql.query('select 1'); detail.database = 'ok'; } catch { ok = false; detail.database = 'unavailable'; }
      try { await objects.head('healthcheck/probe'); detail.objects = 'ok'; } catch { ok = false; detail.objects = 'unavailable'; }
      const tools: Record<string, Json> = {};
      for (const [name, args] of [['pdftoppm', ['-v']], ['pdftotext', ['-v']], ['pdfinfo', ['-v']], ['convert', ['-version']], ['identify', ['-version']], ['exiftool', ['-ver']], ['ffprobe', ['-version']]] as const) tools[name] = await toolVersion(name, args);
      detail.tools = tools;
      return { ok, detail };
    },
  };
  return engine;
}

function validAuthorization(raw: unknown): Authorization {
  invariant(isObject(raw), 'invalid_input', 'A recorded authorization is required');
  const out: Authorization = { authorizedBy: text(raw.authorizedBy, 'authorization.authorizedBy', 300), basis: text(raw.basis, 'authorization.basis', 2000), ...(raw.reference === undefined ? {} : { reference: text(raw.reference, 'authorization.reference', 500) }) };
  return out;
}

// ───────────────────────────── HTTP ─────────────────────────────
const INLINE_TYPES = ['application/pdf', 'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'text/plain'];
const b64 = (bytes: Uint8Array): string => Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
function bodyOf(r: { body: unknown }): Record<string, unknown> { invariant(isObject(r.body), 'invalid_input', 'JSON body required'); return r.body; }
function contentOf(body: Record<string, unknown>): Uint8Array {
  invariant(typeof body.contentBase64 === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(body.contentBase64), 'invalid_input', 'contentBase64 is required');
  return new Uint8Array(Buffer.from(body.contentBase64, 'base64'));
}
const refOf = (query: URLSearchParams): string => { const ref = query.get('ref'); invariant(ref !== null && ref !== '', 'invalid_input', 'ref query parameter required'); return ref; };
const viewJson = (view: ViewData): Json => {
  const { ...rest } = view as unknown as Record<string, unknown>;
  for (const key of ['image', 'bytes']) if (rest[key] instanceof Uint8Array) { rest[`${key}Base64`] = b64(rest[key] as Uint8Array); delete rest[key]; }
  return rest as Json;
};

export function routes(engine: EvidenceEngine): Route[] {
  const idRef = (id: string): string => UUID.test(id) ? uref('E05', 'evidence', id) : id;
  return [
    ...standardRoutes(engine),
    { method: 'POST', path: '/v1/evidence/accept', handler: async (r) => { const b = bodyOf(r); return { status: 201, json: await engine.accept(r.ctx, { bytes: contentOf(b), mediaType: b.mediaType as string, filename: b.filename as string, origin: (b.origin ?? null) as Json, ...(typeof b.compartment === 'string' ? { compartment: b.compartment } : {}), ...(typeof b.idempotencyKey === 'string' ? { idempotencyKey: b.idempotencyKey } : {}) }) }; } },
    { method: 'POST', path: '/v1/evidence/derivatives', handler: async (r) => { const b = bodyOf(r); return { status: 201, json: await engine.addDerivative(r.ctx, { parent: b.parent as string, bytes: contentOf(b), mediaType: b.mediaType as string, filename: b.filename as string, relation: b.relation as string, tool: (b.tool ?? {}) as Json, ...(typeof b.idempotencyKey === 'string' ? { idempotencyKey: b.idempotencyKey } : {}) }) }; } },
    { method: 'GET', path: '/v1/evidence', handler: async (r) => { const limit = r.query.get('limit'); const before = r.query.get('before'); return (await engine.list(r.ctx, { ...(limit === null ? {} : { limit: Number(limit) }), ...(before === null ? {} : { before }) })) as unknown as Json; } },
    { method: 'GET', path: '/v1/evidence/describe', handler: async (r) => { const out = await engine.describeVersion(r.ctx, refOf(r.query)); if (out === null) throw new DomainError('not_found', 'Not found'); return out as unknown as Json; } },
    { method: 'GET', path: '/v1/evidence/content', handler: async (r) => {
      const ref = refOf(r.query); const use = r.query.get('use');
      const info = await engine.describe(r.ctx, ref);
      if (info === null) throw new DomainError('not_found', 'Not found');
      const bytes = await engine.getBytes(r.ctx, ref, use === null ? {} : { use: use as UseAction });
      const type = baseMediaType(info.mediaType); const inline = INLINE_TYPES.includes(type) || /^(audio|video)\//.test(type);
      const headers: Record<string, string> = { 'content-type': inline ? type : 'application/octet-stream', 'content-disposition': `${inline ? 'inline' : 'attachment'}; filename="${info.filename.replace(/[^A-Za-z0-9._-]/g, '_')}"`, 'content-security-policy': "sandbox; default-src 'none'", 'accept-ranges': 'bytes', 'x-evidence-sha256': info.sha256, 'x-evidence-authenticity': 'not_assessed' };
      const range = /^bytes=(\d+)-(\d*)$/.exec(String(r.headers.range ?? ''));
      if (range !== null) {
        const start = Number(range[1]); const end = Math.min(range[2] === '' ? bytes.byteLength - 1 : Number(range[2]), bytes.byteLength - 1);
        if (start >= bytes.byteLength || end < start) return { status: 416, bytes: new Uint8Array(), headers: { ...headers, 'content-range': `bytes */${bytes.byteLength}` } };
        return { status: 206, bytes: bytes.subarray(start, end + 1), headers: { ...headers, 'content-range': `bytes ${start}-${end}/${bytes.byteLength}` } };
      }
      return { bytes, headers };
    } },
    { method: 'POST', path: '/v1/evidence/:id/versions', handler: async (r) => { const b = bodyOf(r); return { status: 201, json: await engine.addVersion(r.ctx, { evidence: idRef(r.params.id as string), bytes: contentOf(b), mediaType: b.mediaType as string, filename: b.filename as string, origin: (b.origin ?? null) as Json, ...(b.cause === undefined ? {} : { cause: b.cause as 'refresh' | 'correction' }), ...(typeof b.idempotencyKey === 'string' ? { idempotencyKey: b.idempotencyKey } : {}) }) }; } },
    { method: 'GET', path: '/v1/evidence/:id/versions', handler: async (r) => (await engine.versions(r.ctx, idRef(r.params.id as string))) as unknown as Json },
    { method: 'POST', path: '/v1/evidence/:id/verify', handler: async (r) => { const rev = isObject(r.body) && Number.isSafeInteger(r.body.revision) ? r.body.revision as number : undefined; const id = r.params.id as string; return (await engine.verifyIntegrity(r.ctx, UUID.test(id) ? uref('E05', 'evidence_version', id, rev) : id)) as unknown as Json; } },
    { method: 'GET', path: '/v1/provenance/:id', handler: async (r) => (await engine.provenance(r.ctx, idRef(r.params.id as string))) as unknown as Json },
    { method: 'GET', path: '/v1/evidence/custody', handler: async (r) => (await engine.custody(r.ctx, refOf(r.query))) as unknown as Json },
    { method: 'POST', path: '/v1/evidence/handling', handler: async (r) => { const b = bodyOf(r); return (await engine.recordHandling(r.ctx, b.ref as string, b as never)) as unknown as Json; } },
    { method: 'POST', path: '/v1/evidence/rescan', handler: async (r) => (await engine.rescan(r.ctx, bodyOf(r).ref as string)) as unknown as Json },
    { method: 'POST', path: '/v1/citations', handler: async (r) => { const b = bodyOf(r); return { status: 201, json: await engine.createCitation(r.ctx, b as never) }; } },
    { method: 'GET', path: '/v1/citations/:id', handler: async (r) => (await engine.resolveCitation(r.ctx, r.params.id as string)) as unknown as Json },
    { method: 'POST', path: '/v1/evidence/view', handler: async (r) => { const b = bodyOf(r); return viewJson(await engine.renderView(r.ctx, b.ref as string, b as never)); } },
    { method: 'POST', path: '/v1/evidence/redactions', handler: async (r) => { const b = bodyOf(r); return { status: 201, json: await engine.redact(r.ctx, b.ref as string, b as never) }; } },
    { method: 'POST', path: '/v1/evidence/retention', handler: async (r) => { const b = bodyOf(r); return (await engine.setRetention(r.ctx, b.ref as string, b as never)) as unknown as Json; } },
    { method: 'GET', path: '/v1/evidence/retention/due', handler: async (r) => (await engine.dueForDisposal(r.ctx)) as unknown as Json },
    { method: 'POST', path: '/v1/evidence/disposals', handler: async (r) => { const b = bodyOf(r); return (await engine.dispose(r.ctx, b.ref as string, b as never)) as unknown as Json; } },
    { method: 'POST', path: '/v1/evidence/restore', handler: async (r) => { const b = bodyOf(r); return (await engine.restoreBytes(r.ctx, b.ref as string, contentOf(b), { reason: b.reason as string })) as unknown as Json; } },
    { method: 'POST', path: '/v1/evidence/assessments', handler: async (r) => { const b = bodyOf(r); return (await engine.recordAssessment(r.ctx, b.ref as string, b as never)) as unknown as Json; } },
    { method: 'POST', path: '/v1/evidence/restrictions/lift', handler: async (r) => { const b = bodyOf(r); return (await engine.liftRestriction(r.ctx, b.ref as string, b as never)) as unknown as Json; } },
    { method: 'POST', path: '/v1/integrity/verify-all', handler: async (r) => (await engine.verifyAll(r.ctx)) as unknown as Json },
    { method: 'POST', path: '/v1/integrity/batches', handler: async (r) => ({ status: 202, json: await engine.startIntegrityBatch(r.ctx, isObject(r.body) && typeof r.body.idempotencyKey === 'string' ? { idempotencyKey: r.body.idempotencyKey } : {}) }) },
    { method: 'POST', path: '/v1/packages', handler: async (r) => { const b = bodyOf(r); const out = await engine.exportPackage(r.ctx, b.refs as string[], { includeOriginals: b.includeOriginals === true, redactedOnly: b.redactedOnly === true, ...(typeof b.reason === 'string' ? { reason: b.reason } : {}) }); return { bytes: out.bytes, headers: { 'content-type': 'application/zip', 'content-disposition': `attachment; filename="${out.filename}"`, 'x-package-sha256': out.sha256 } }; } },
    { method: 'POST', path: '/v1/packages/verify', handler: async (r) => { requireCapability(r.ctx, 'evidence:read'); return (await engine.verifyPackage(r.raw)) as unknown as Json; } },
    { method: 'POST', path: '/v1/keys/rotate', handler: async (r) => (await engine.rotateKeys(r.ctx, isObject(r.body) && typeof r.body.limit === 'number' ? { limit: r.body.limit } : {})) as unknown as Json },
    { method: 'GET', path: '/v1/jobs', handler: async (r) => { const kind = r.query.get('kind'); return (await engine.jobs(r.ctx, kind === null ? {} : { kind })) as unknown as Json; } },
    { method: 'GET', path: '/v1/jobs/:id', handler: async (r) => { const job = await engine.job(r.ctx, r.params.id as string); if (job === null) throw new DomainError('not_found', 'Not found'); const { ctx: _ctx, ...rest } = job; return rest as unknown as Json; } },
    { method: 'POST', path: '/v1/jobs/:id/:action', handler: async (r) => { invariant(['cancel', 'pause', 'resume', 'retry'].includes(r.params.action as string), 'invalid_input', 'Unsupported job action'); const { ctx: _ctx, ...rest } = await engine.controlJob(r.ctx, r.params.id as string, r.params.action as 'cancel'); return rest as unknown as Json; } },
  ];
}
