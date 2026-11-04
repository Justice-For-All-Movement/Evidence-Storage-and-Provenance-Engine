import {captureSelectors, assertReviewBudget, reviewSelectors, captureSelectorLinks, type SelectorLinkCapture, type SelectorReview} from './selector-review.ts';
export type {SelectorReview, SelectorLinkCapture} from './selector-review.ts';
import { authenticate, authorize, type Identity } from './identity-sdk.ts';
import { DomainError, digest, hashBytes, invariant, nonempty, requireScope, validTime, type Context, type Json } from './contracts.ts';
import { scoped, type Database, type LeasedJob, type UnitOfWork } from './database.ts';
import { PrivateObjectStore, type ObjectReceipt } from './objects.ts';
import {
  acquireEvidence, addRepresentation, assertEvidenceState, beginScan, completeScan, createEvidenceState,
  getEvidenceVersion, getScanStatus, quarantineEvidence, requireEvidenceUsable,
  type EvidenceState, type EvidenceRef, type EvidenceVersion, type Representation, type EvidenceSelector,
} from './index.ts';
export type { Identity } from './identity-sdk.ts';

export type EvidenceRequest = Readonly<{ token: string; purpose: string; requestId: string }>;
export type AcquireCommand = Readonly<{
  id: string; acquisitionId: string; bytes: Uint8Array; mediaType: string; capturedAt: string;
  originalLanguage: string; supersedes: EvidenceRef | null; expectedRevision: number; idempotencyKey: string;
}>;
export type ScanInput = Readonly<{
  attemptId: string; evidence: EvidenceRef; sha256: string; bytes: Uint8Array; mediaType: string;
  deadline: string; signal: AbortSignal;
}>;
export type ExtractedRepresentation = Readonly<{
  sourceSha256: string; text: string | null; pages: readonly string[] | null; durationMs: number | null; toolVersion: string;
}>;
export type ScanReply = Readonly<{
  attemptId: string; sha256: string; engineVersion: string; verdict: 'clean' | 'infected' | 'failed';
  representation?: ExtractedRepresentation;
}>;
/** Deployment port, not a verdict accepted from application commands. No default scanner exists. */
export interface ScannerPort { readonly version: string; scan(input: ScanInput): Promise<ScanReply>; }
export interface EvidenceServiceOptions {
  database: Database; objects: PrivateObjectStore; identities: () => Promise<readonly Identity[]>; now: () => string;
  scanner: ScannerPort; leaseMs?: number; scanTimeoutMs?: number; uploadTtlMs?: number; maxScanAttempts?: number;
}
export type AcquisitionResult = Readonly<{ ref: EvidenceRef; revision: number }>;
export type ScanOutcome = Readonly<{ attemptId: string; ref: EvidenceRef; verdict: 'clean' | 'infected' | 'failed' | 'stale'; revision: number }>;
type ObjectBinding = Readonly<{ evidence: EvidenceRef; receipt: ObjectReceipt }>;
type ActiveScan = Readonly<{ attemptId: string; evidence: EvidenceRef; sha256: string; job: LeasedJob; deadline: string }>;
type Aggregate = Readonly<{ domain: EvidenceState; objects: readonly ObjectBinding[]; activeScans: readonly ActiveScan[] }>;
type UploadIntent = Readonly<{
  receipt: ObjectReceipt; fingerprint: string; expiresAt: string; status: 'pending' | 'referenced' | 'retired'; evidence: EvidenceRef | null;
}>;
type ScanAttempt = ActiveScan & Readonly<{ status: 'scanning' | 'clean' | 'infected' | 'failed'; reason: string }>;
type StartedScan = ActiveScan & Readonly<{ receipt: ObjectReceipt; mediaType: string }>;
const KIND = 'evidence.aggregate', ID = 'project', UPLOAD = 'evidence.upload', ATTEMPT = 'evidence.scan-attempt', TOPIC = 'evidence.scan';
const sameRef = (a: EvidenceRef, b: EvidenceRef): boolean => digest(a) === digest(b);
const attemptKey = (attemptId: string): string => digest({ attemptId });

/** Typed application boundary. Dependencies/identity directory/clock/ports are trusted deployment configuration. */
export class EvidenceService {
  #db: Database; #objects: PrivateObjectStore; #identities: EvidenceServiceOptions['identities']; #now: () => string;
  #scanner: ScannerPort; #scannerVersion: string; #leaseMs: number; #timeoutMs: number; #uploadTtl: number; #maxAttempts: number;
  constructor(options: EvidenceServiceOptions) {
    this.#db = options.database; this.#objects = options.objects; this.#identities = options.identities; this.#now = options.now;
    invariant(options.scanner && typeof options.scanner.scan === 'function', 'scanner_required', 'A deployment scanner port is required');
    nonempty(options.scanner.version, 'scanner version', 128);
    this.#scanner = options.scanner; this.#scannerVersion = options.scanner.version; this.#leaseMs = options.leaseMs ?? 30000; this.#timeoutMs = options.scanTimeoutMs ?? 20000;
    this.#uploadTtl = options.uploadTtlMs ?? 900000; this.#maxAttempts = options.maxScanAttempts ?? 5;
    invariant(Number.isSafeInteger(this.#leaseMs) && this.#leaseMs >= 1000 && this.#leaseMs <= 300000, 'invalid_lease', 'Lease must be 1-300 seconds');
    invariant(Number.isSafeInteger(this.#timeoutMs) && this.#timeoutMs > 0 && this.#timeoutMs < this.#leaseMs, 'invalid_timeout', 'Scanner timeout must fit inside its lease');
    invariant(Number.isSafeInteger(this.#uploadTtl) && this.#uploadTtl >= 1000 && this.#uploadTtl <= 86400000, 'invalid_expiry', 'Upload intent lifetime must be 1 second-1 day');
    invariant(Number.isSafeInteger(this.#maxAttempts) && this.#maxAttempts > 0 && this.#maxAttempts <= 100, 'invalid_attempts', 'Maximum scan attempts must be 1-100');
  }
  async #context(request: EvidenceRequest, action: 'read' | 'investigate' | 'process', workerRole?: string): Promise<Context> {
    // Capture request fields before awaiting directory lookup. Credentials never enter persistence fingerprints/audits.
    const input = structuredClone(request);
    invariant(Object.keys(input).every(key => ['token', 'purpose', 'requestId'].includes(key)), 'invalid_input', 'Only credentials, purpose and request ID are accepted');
    nonempty(input.token, 'credential', 512); nonempty(input.purpose, 'purpose', 128); nonempty(input.requestId, 'requestId', 128);
    const identity = authenticate(input.token, await this.#identities());
    const ctx = { tenantId: identity.tenantId, projectId: identity.projectId, actor: identity.actor, purpose: input.purpose, requestId: input.requestId, now: this.#now() };
    validTime(ctx.now); authorize(ctx, action);
    if (workerRole) invariant(ctx.actor.kind === 'service' && ctx.actor.roles.includes(workerRole), 'worker_required', 'A configured service worker role is required');
    return ctx;
  }
  async #load(tx: UnitOfWork, ctx: Context): Promise<{ value: Aggregate; revision: number }> {
    const record = await tx.get<Aggregate>(KIND, ID);
    if (!record) return { value: { domain: createEvidenceState(ctx), objects: [], activeScans: [] }, revision: 0 };
    requireScope(ctx, record.value.domain); assertEvidenceState(record.value.domain);
    return { value: record.value, revision: record.revision };
  }
  #binding(aggregate: Aggregate, ref: EvidenceRef): ObjectBinding {
    const binding = aggregate.objects.find(item => sameRef(item.evidence, ref));
    invariant(binding, 'not_found', 'Object receipt missing');
    const version = aggregate.domain.versions.find(item => sameRef(item.ref, ref));
    invariant(version && version.storageVersionRef === digest(binding.receipt) && version.sha256 === binding.receipt.plaintextHash && version.byteLength === binding.receipt.size, 'integrity_failure', 'Object receipt does not match immutable acquisition');
    return binding;
  }
  async acquire(request: EvidenceRequest, command: AcquireCommand): Promise<AcquisitionResult> {
    const input = structuredClone(command);
    invariant(Object.keys(input).every(key => ['id','acquisitionId','bytes','mediaType','capturedAt','originalLanguage','supersedes','expectedRevision','idempotencyKey'].includes(key)), 'invalid_input', 'Unknown acquisition property');
    invariant(input.bytes instanceof Uint8Array, 'invalid_input', 'Exact acquisition bytes required');
    nonempty(input.idempotencyKey, 'idempotencyKey', 128);
    const ctx = await this.#context(request, 'investigate');
    if (input.supersedes) requireScope(ctx, input.supersedes);
    const sha256 = hashBytes(input.bytes);
    const receipt: ObjectReceipt = { key: `${digest({ tenantId: ctx.tenantId, projectId: ctx.projectId })}/${sha256}`, plaintextHash: sha256, size: input.bytes.byteLength, keyVersion: this.#objects.keyVersion };
    const fingerprint: Json = { id: input.id, acquisitionId: input.acquisitionId, sha256, size: receipt.size, mediaType: input.mediaType, capturedAt: input.capturedAt, originalLanguage: input.originalLanguage, supersedes: input.supersedes, expectedRevision: input.expectedRevision, purpose: ctx.purpose };
    const intentId = digest({ actorId: ctx.actor.id, key: input.idempotencyKey });
    // Durable intent survives rollback of publication, so cleanup never relies on a best-effort catch handler.
    await scoped(this.#db, ctx, tx => tx.idempotent(`stage:${input.idempotencyKey}`, fingerprint, async () => {
      const intent: UploadIntent = { receipt, fingerprint: digest(fingerprint), expiresAt: new Date(validTime(ctx.now) + this.#uploadTtl).toISOString(), status: 'pending', evidence: null };
      await tx.put(UPLOAD, intentId, 0, intent); return { intentId };
    }));
    return scoped(this.#db, ctx, tx => tx.idempotent(`acquire:${input.idempotencyKey}`, fingerprint, async () => {
      const staged = await tx.get<UploadIntent>(UPLOAD, intentId);
      invariant(staged?.value.status === 'pending' && validTime(this.#now()) < validTime(staged.value.expiresAt), 'upload_expired', 'Upload intent was retired or expired');
      invariant(staged.value.fingerprint === digest(fingerprint) && digest(staged.value.receipt) === digest(receipt), 'integrity_failure', 'Upload intent changed');
      const aggregate = await this.#load(tx, ctx);
      invariant(aggregate.revision === input.expectedRevision, 'revision_conflict', 'Evidence aggregate changed');
      const domain = acquireEvidence(aggregate.value.domain, ctx, {
        id: input.id, acquisitionId: input.acquisitionId, bytes: input.bytes, mediaType: input.mediaType, storageVersionRef: digest(receipt),
        sourceFamilyId: null, capturedAt: input.capturedAt, originalLanguage: input.originalLanguage, allowedPurposes: [ctx.purpose], supersedes: input.supersedes,
      });
      const ref = domain.versions.at(-1)!.ref;
      // Hold the project lock across filesystem publication/verification. Reconciliation uses that same lock.
      const stored = await this.#objects.put(ctx, input.bytes);
      invariant(digest(stored) === digest(receipt), 'integrity_failure', 'Stored object receipt differs from the intent');
      await this.#objects.get(ctx, receipt);
      invariant(validTime(this.#now()) < validTime(staged.value.expiresAt), 'upload_expired', 'Upload intent expired before publication');
      const next = await tx.put(KIND, ID, aggregate.revision, { ...aggregate.value, domain, objects: [...aggregate.value.objects, { evidence: ref, receipt }] });
      await tx.enqueue(TOPIC, { evidence: ref, sha256 }, `scan:${digest(ref)}`, this.#maxAttempts);
      await tx.put(UPLOAD, intentId, staged.revision, { ...staged.value, status: 'referenced', evidence: ref });
      return { ref, revision: next.revision };
    }));
  }
  async inspect(request: EvidenceRequest, ref: EvidenceRef): Promise<{ version: EvidenceVersion; scan: ReturnType<typeof getScanStatus>; revision: number }> {
    const captured = structuredClone(ref); const ctx = await this.#context(request, 'read'); authorize(ctx, 'read', captured);
    return scoped(this.#db, ctx, async tx => { const aggregate = await this.#load(tx, ctx); return { version: getEvidenceVersion(aggregate.value.domain, ctx, captured), scan: getScanStatus(aggregate.value.domain, ctx, captured), revision: aggregate.revision }; });
  }
  /** Authenticated owning metadata review; no source bytes, raw histories or effect authority. */
  async reviewSelectors(request: EvidenceRequest, selectors: readonly EvidenceSelector[]): Promise<SelectorReview> {
    return this.#observeSelectors(request, selectors, 'evidence.selectors.review_checked', reviewSelectors);
  }
  /** Current owning compact family/selector capture; does not create Knowledge links or grant use. */
  async captureSelectorLinks(request: EvidenceRequest, selectors: readonly EvidenceSelector[]): Promise<SelectorLinkCapture> {
    return this.#observeSelectors(request, selectors, 'evidence.selectors.capture_checked', captureSelectorLinks);
  }
  async #observeSelectors<T>(request: EvidenceRequest, selectors: readonly EvidenceSelector[],
    auditType: 'evidence.selectors.review_checked' | 'evidence.selectors.capture_checked',
    project: (state: EvidenceState, context: Context, selected: readonly EvidenceSelector[], revision: number) => T): Promise<T> {
    const captured = captureSelectors(selectors), credential = structuredClone(request);
    const ctx = await this.#context(credential, 'read');
    for (const selector of captured) authorize(ctx, 'read', selector.evidence);
    return scoped(this.#db, ctx, async tx => {
      // Acquire owning project lock BEFORE current directory observation and aggregate read.
      await tx.audit(auditType, {selectorCount: captured.length});
      const current = await this.#context(credential, 'read');
      requireScope(ctx, current);
      invariant(current.actor.id === ctx.actor.id && current.actor.kind === ctx.actor.kind,
        'unauthenticated', 'Authenticated principal changed');
      for (const selector of captured) authorize(current, 'read', selector.evidence);
      const stored = await tx.get<Aggregate>(KIND, ID);
      invariant(stored, 'not_found', 'Evidence aggregate missing');
      requireScope(current, stored.value.domain);
      assertReviewBudget(stored.value.domain);
      return project(stored.value.domain, current, captured, stored.revision);
    });
  }
  async read(request: EvidenceRequest, ref: EvidenceRef): Promise<Uint8Array> {
    const captured = structuredClone(ref); const ctx = await this.#context(request, 'read'); authorize(ctx, 'read', captured);
    const result = await scoped(this.#db, ctx, async tx => {
      // Audit acquires the project lock; any denied read rolls it back.
      await tx.audit('evidence.read_requested', { evidence: captured });
      const aggregate = await this.#load(tx, ctx); requireEvidenceUsable(aggregate.value.domain, ctx, captured);
      const binding = this.#binding(aggregate.value, captured);
      try { return { bytes: await this.#objects.get(ctx, binding.receipt) }; }
      catch {
        const domain = quarantineEvidence(aggregate.value.domain, ctx, { id: `read-integrity:${digest({ ref: captured, revision: aggregate.revision })}`, evidence: captured, reason: 'Encrypted object failed integrity or availability verification' });
        await tx.put(KIND, ID, aggregate.revision, { ...aggregate.value, domain }); return { bytes: null };
      }
    });
    invariant(result.bytes !== null, 'object_integrity_failure', 'Evidence object was quarantined');
    return result.bytes;
  }

  async representation(request: EvidenceRequest, ref: EvidenceRef, representationId: string): Promise<Representation> {
    const captured = structuredClone(ref); const ctx = await this.#context(request, 'read'); authorize(ctx, 'read', captured);
    return scoped(this.#db, ctx, async tx => {
      const aggregate = await this.#load(tx, ctx); requireEvidenceUsable(aggregate.value.domain, ctx, captured);
      const found = aggregate.value.domain.representations.find(r => r.id === representationId && sameRef(r.evidence, captured));
      invariant(found, 'not_found', 'Representation missing'); return structuredClone(found);
    });
  }
  async quarantine(request: EvidenceRequest, ref: EvidenceRef, expectedRevision: number, key: string): Promise<number> {
    const captured = structuredClone(ref); const ctx = await this.#context(request, 'process'); authorize(ctx, 'process', captured); nonempty(key, 'key', 128);
    const result = await scoped(this.#db, ctx, tx => tx.idempotent(`quarantine:${key}`, { ref: captured, expectedRevision }, async () => {
      const aggregate = await this.#load(tx, ctx); invariant(aggregate.revision === expectedRevision, 'revision_conflict', 'Evidence aggregate changed');
      const domain = quarantineEvidence(aggregate.value.domain, ctx, { id: `quarantine:${digest({ ref: captured, key, actor: ctx.actor.id })}`, evidence: captured, reason: 'Authorized safety quarantine' });
      const next = await tx.put(KIND, ID, aggregate.revision, { ...aggregate.value, domain }); return { revision: next.revision };
    })); return result.revision;
  }
  async #recover(tx: UnitOfWork, ctx: Context): Promise<number> {
    const aggregate = await this.#load(tx, ctx); let domain = aggregate.value.domain; let count = 0;
    const expired = aggregate.value.activeScans.filter(s => validTime(s.deadline) <= validTime(ctx.now));
    for (const scan of expired) {
      const current = domain.scans.findLast(s => sameRef(s.evidence, scan.evidence));
      if (current?.status === 'scanning' && current.attemptId === scan.attemptId) domain = quarantineEvidence(domain, ctx, { id: `expired:${attemptKey(scan.attemptId)}`, evidence: scan.evidence, reason: 'Scanner lease expired without a valid completion' });
      const attempt = await tx.get<ScanAttempt>(ATTEMPT, attemptKey(scan.attemptId));
      invariant(attempt, 'invalid_state', 'Durable scan attempt missing');
      await tx.put(ATTEMPT, attemptKey(scan.attemptId), attempt.revision, { ...attempt.value, status: 'failed', reason: 'lease_expired' }); count++;
    }
    if (count) await tx.put(KIND, ID, aggregate.revision, { ...aggregate.value, domain, activeScans: aggregate.value.activeScans.filter(s => !expired.includes(s)) });
    return count;
  }
  async recoverStalledScans(request: EvidenceRequest): Promise<number> {
    const ctx = await this.#context(request, 'process', 'evidence_scanner');
    const result = await scoped(this.#db, ctx, tx => tx.idempotent(`recover:${digest({ request: ctx.requestId, now: ctx.now })}`, {}, async () => ({ count: await this.#recover(tx, ctx) })));
    return result.count;
  }
  async runNextScan(request: EvidenceRequest): Promise<ScanOutcome | null> {
    let ctx = await this.#context(request, 'process', 'evidence_scanner');
    await this.recoverStalledScans(request);
    ctx = await this.#context(request, 'process', 'evidence_scanner');
    const started = await scoped(this.#db, ctx, async tx => {
      const job = await tx.claim(ctx.actor.id, this.#leaseMs, TOPIC); if (!job) return null;
      const payload = job.payload as { evidence: EvidenceRef; sha256: string };
      const aggregate = await this.#load(tx, ctx); const version = getEvidenceVersion(aggregate.value.domain, ctx, payload.evidence);
      invariant(payload.sha256 === version.sha256, 'integrity_failure', 'Scan job hash differs from acquisition');
      const binding = this.#binding(aggregate.value, version.ref);
      const attemptId = `${job.id}:${job.generation}`, deadline = new Date(validTime(ctx.now) + this.#leaseMs).toISOString();
      const active: ActiveScan = { attemptId, evidence: version.ref, sha256: version.sha256, job, deadline };
      const domain = beginScan(aggregate.value.domain, ctx, { id: `start:${attemptKey(attemptId)}`, evidence: version.ref, attemptId, engineVersion: this.#scannerVersion });
      await tx.put(ATTEMPT, attemptKey(attemptId), 0, { ...active, status: 'scanning', reason: 'started' } satisfies ScanAttempt);
      await tx.put(KIND, ID, aggregate.revision, { ...aggregate.value, domain, activeScans: [...aggregate.value.activeScans, active] });
      return { ...active, receipt: binding.receipt, mediaType: version.mediaType } satisfies StartedScan;
    });
    if (!started) return null;
    let reply: ScanReply | null = null; let failure = 'scanner_failure'; const controller = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const scan = (async () => {
        const bytes = await this.#objects.get(ctx, started.receipt);
        return this.#scanner.scan({ attemptId: started.attemptId, evidence: structuredClone(started.evidence), sha256: started.sha256, bytes, mediaType: started.mediaType, deadline: started.deadline, signal: controller.signal });
      })();
      reply = structuredClone(await Promise.race([scan, new Promise<never>((_, reject) => { timer = setTimeout(() => { failure = 'scanner_timeout'; controller.abort(); reject(new Error('scanner_timeout')); }, this.#timeoutMs); })]));
      invariant(reply.attemptId === started.attemptId && reply.sha256 === started.sha256 && reply.engineVersion === this.#scannerVersion && ['clean', 'infected', 'failed'].includes(reply.verdict), 'invalid_scanner_reply', 'Scanner response is not bound to this exact attempt/hash/version');
    } catch (error) { if (error instanceof DomainError && error.code === 'invalid_scanner_reply') failure = 'invalid_scanner_reply'; reply = null; }
    finally { if (timer !== undefined) clearTimeout(timer); }
    return this.#finish(request, started, reply, failure);
  }
  async #finish(request: EvidenceRequest, started: StartedScan, reply: ScanReply | null, failure: string): Promise<ScanOutcome> {
    // Refresh credential state/time after the deployment scanner returns.
    const ctx = await this.#context(request, 'process', 'evidence_scanner'); requireScope(ctx, started.evidence);
    invariant(ctx.actor.id === started.job.leaseOwner, 'worker_required', 'Scanner identity changed');
    try {
      return await scoped(this.#db, ctx, async tx => {
        await tx.audit('evidence.scan_completion_received', { attemptId: started.attemptId });
        const aggregate = await this.#load(tx, ctx);
        const active = aggregate.value.activeScans.find(a => a.attemptId === started.attemptId);
        const current = aggregate.value.domain.scans.findLast(s => sameRef(s.evidence, started.evidence));
        if (!active || current?.status !== 'scanning' || current.attemptId !== started.attemptId) {
          await tx.acknowledge(started.job);
          const attempt = await tx.get<ScanAttempt>(ATTEMPT, attemptKey(started.attemptId)); invariant(attempt, 'invalid_state', 'Durable scan attempt missing');
          await tx.put(ATTEMPT, attemptKey(started.attemptId), attempt.revision, { ...attempt.value, status: 'failed', reason: 'attempt_invalidated' });
          const next = await tx.put(KIND, ID, aggregate.revision, { ...aggregate.value, activeScans: aggregate.value.activeScans.filter(a => a.attemptId !== started.attemptId) });
          return { attemptId: started.attemptId, ref: started.evidence, verdict: 'stale' as const, revision: next.revision };
        }
        const newer = aggregate.value.domain.versions.some(v => v.ref.id === started.evidence.id && v.ref.revision > started.evidence.revision);
        let verdict: 'clean' | 'infected' | 'failed' = newer ? 'failed' : reply?.verdict ?? 'failed';
        let reason = newer ? 'source_superseded' : reply ? `scanner_${reply.verdict}` : failure;
        const complete = (status: 'clean' | 'infected' | 'failed', detail: string): EvidenceState => completeScan(aggregate.value.domain, ctx, { id: `finish:${attemptKey(started.attemptId)}`, evidence: started.evidence, attemptId: started.attemptId, sha256: started.sha256, status, reason: detail });
        let domain = complete(verdict, reason);
        if (verdict === 'clean' && reply?.representation) {
          try { domain = addRepresentation(domain, ctx, { ...reply.representation, id: `representation:${attemptKey(started.attemptId)}`, evidence: started.evidence }); }
          catch { verdict = 'failed'; reason = 'representation_rejected'; domain = complete(verdict, reason); }
        }
        if (verdict === 'failed' && !newer) await tx.fail(started.job, reason); else await tx.acknowledge(started.job);
        const attempt = await tx.get<ScanAttempt>(ATTEMPT, attemptKey(started.attemptId)); invariant(attempt, 'invalid_state', 'Durable scan attempt missing');
        await tx.put(ATTEMPT, attemptKey(started.attemptId), attempt.revision, { ...attempt.value, status: verdict, reason });
        const next = await tx.put(KIND, ID, aggregate.revision, { ...aggregate.value, domain, activeScans: aggregate.value.activeScans.filter(a => a.attemptId !== started.attemptId) });
        return { attemptId: started.attemptId, ref: started.evidence, verdict, revision: next.revision };
      });
    } catch (error) {
      if (!(error instanceof DomainError) || !['stale_lease', 'stale_scan'].includes(error.code)) throw error;
      await this.recoverStalledScans(request);
      const current = await this.inspect(request, started.evidence);
      return { attemptId: started.attemptId, ref: started.evidence, verdict: 'stale', revision: current.revision };
    }
  }
  async reconcileUploads(request: EvidenceRequest, after = '', limit = 100): Promise<{ removed: number; retained: number; next: string | null }> {
    const ctx = await this.#context(request, 'process', 'evidence_storage_maintenance');
    const result = await scoped(this.#db, ctx, tx => tx.idempotent(`cleanup:${digest({ request: ctx.requestId, now: ctx.now, after, limit })}`, {}, async () => {
      const aggregate = await this.#load(tx, ctx); const intents = await tx.list<UploadIntent>(UPLOAD, limit, after); let removed = 0, retained = 0;
      for (const record of intents) {
        if (record.value.status !== 'pending' || validTime(record.value.expiresAt) > validTime(ctx.now)) continue;
        const referenced = aggregate.value.objects.some(binding => binding.receipt.key === record.value.receipt.key);
        // Project lock excludes acquisition publication; all historical bindings count as references.
        if (referenced) retained++; else if (await this.#objects.removeUnreferenced(ctx, record.value.receipt)) removed++;
        await tx.put(UPLOAD, record.id, record.revision, { ...record.value, status: 'retired' });
      }
      await tx.audit('evidence.uploads_reconciled', { removed, retained });
      return { removed, retained, next: intents.length === limit ? intents.at(-1)!.id : null };
    })); return result;
  }
}
