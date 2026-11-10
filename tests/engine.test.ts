// Core evidence service: acceptance criteria, quarantine with real clamscan, citations, integrity, isolation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { leaseJobs, listAudit, verifyAuditChain } from '../src/service-kit.ts';
import type { EvidencePort, UseDecisionPort } from '../src/service-kit.ts';
import { SCHEMA, structuralCheck, verifyCustodyChain, writeZip } from '../src/engine/index.ts';
import { HARMLESS_MARKER, code, ctx, manual, needsPg, utf8, withEngine } from './engine-helpers.ts';

const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');
async function files(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true, recursive: true })) if (e.isFile()) out.push(join(e.parentPath, e.name));
  return out;
}

test('accept → quarantine → real clamscan release; describe/getBytes/addDerivative satisfy EvidencePort', needsPg, async () => {
  await withEngine({}, async ({ engine, objectRoot, sql }) => {
    const port: EvidencePort = engine; // structural conformance with the kit port
    const bytes = utf8('Minutes of the fictional harbour board, meeting 17.\n');
    const info = await port.accept(ctx(), { bytes, mediaType: 'text/plain', filename: 'minutes.txt', origin: manual });
    assert.match(info.ref, /^E05:evidence_version:[0-9a-f-]{36}@1$/);
    assert.equal(info.sha256, sha(bytes)); assert.equal(info.size, bytes.byteLength); assert.equal(info.available, true);
    const detail = await engine.describeVersion(ctx(), info.ref);
    assert.equal(detail?.state, 'released'); assert.equal(detail?.authenticity, 'not_assessed'); assert.match(detail?.digestMeaning ?? '', /byte consistency .* only; it does not establish authenticity or truth/);
    const scan = detail?.scan as { policy: string; malwareScan: { verdict: string; engineVersion: string } };
    assert.equal(scan.policy, 'scanner'); assert.equal(scan.malwareScan.verdict, 'clean'); assert.match(scan.malwareScan.engineVersion, /ClamAV/);
    assert.deepEqual(Buffer.from(await port.getBytes(ctx(), info.ref)), Buffer.from(bytes));
    assert.deepEqual(await port.describe(ctx(), info.ref), info);
    // Encrypted at rest: the plaintext never appears in the object store, and keys are tenant/project prefixed.
    const stored = await files(objectRoot);
    assert.equal(stored.length, 1); assert.ok(stored[0]!.includes(join('tenant-a', 'project-1')));
    assert.ok(!(await readFile(stored[0]!)).includes(Buffer.from('harbour board')));
    assert.equal(detail?.keyVersion, 'k1');
    // derivative
    const ocr = await port.addDerivative(ctx(), { parent: info.ref, bytes: utf8('MINUTES OF THE FICTIONAL HARBOUR BOARD'), mediaType: 'text/plain', filename: 'minutes.ocr.txt', relation: 'ocr_text', tool: { name: 'tesseract', lang: 'eng' } });
    assert.equal(ocr.available, true);
    const prov = await engine.provenance(ctx(), ocr.ref);
    assert.deepEqual((prov.derivedFrom[0] as { ref: string; relation: string; tool: unknown }).ref, info.ref);
    assert.deepEqual((prov.derivedFrom[0] as { tool: unknown }).tool, { name: 'tesseract', lang: 'eng' });
    const parentProv = await engine.provenance(ctx(), info.ref);
    assert.equal((parentProv.derivatives[0] as { ref: string }).ref, ocr.ref);
    assert.deepEqual(parentProv.gaps, []);
    // custody: per-evidence hash chain + kit audit chain
    const custody = await engine.custody(ctx(), info.ref);
    assert.deepEqual(custody.entries.map((e) => e.action), ['accepted', 'released', 'accessed', 'derived']);
    assert.ok(custody.chainValid);
    assert.ok(!verifyCustodyChain(custody.entries.map((e, i) => i === 1 ? { ...e, actorId: 'someone-else' } : e)));
    assert.equal(custody.entries[2]!.purpose, 'investigate'); assert.equal(custody.entries[2]!.actorId, 'researcher-1');
    assert.ok(verifyAuditChain(await listAudit(sql, SCHEMA, ctx(), { allProjects: true })));
    // events
    const events = await engine.events(ctx());
    assert.deepEqual(events.map((e) => e.type), ['evidence.accepted', 'evidence.released', 'evidence.derivative_added', 'evidence.released']);
    assert.equal(events[0]!.subject, info.ref);
    assert.equal((await engine.search(ctx(), { q: 'minutes' })).length, 2);
    assert.equal((await engine.search(ctx(), { q: info.sha256.slice(0, 12) }))[0]!.ref, info.ref);
    const inspection = await engine.inspect(ctx(), info.ref);
    assert.equal(inspection?.state, 'released'); assert.deepEqual(inspection?.dependents, [ocr.ref]);
  });
});

test('real clamscan with a locally authored signature blocks a harmless marked file; blocked bytes are not retrievable', needsPg, async () => {
  await withEngine({}, async ({ engine }) => {
    const info = await engine.accept(ctx(), { bytes: utf8(`fictional attachment ${HARMLESS_MARKER} end\n`), mediaType: 'text/plain', filename: 'marked.txt', origin: manual });
    assert.equal(info.available, false);
    const d = await engine.describeVersion(ctx(), info.ref);
    assert.equal(d?.state, 'blocked');
    assert.equal((d?.scan as { malwareScan: { signature: string } }).malwareScan.signature, 'Pam.Test.Harmless.UNOFFICIAL');
    await assert.rejects(engine.getBytes(ctx(), info.ref), code('invalid_state'));
    await assert.rejects(engine.createCitation(ctx(), { version: info.ref, selector: { kind: 'whole' } }), code('invalid_state'));
    assert.deepEqual((await engine.events(ctx())).map((e) => e.type), ['evidence.accepted', 'evidence.blocked']);
    assert.equal((await engine.inspect(ctx(), info.ref))?.blocked, true);
    // preserved all the same: integrity verification still reads the real bytes
    assert.equal((await engine.verifyIntegrity(ctx(), info.ref)).status, 'matched');
  });
});

test('structural checks: media-type mismatch, executables, archive bombs, size limit', needsPg, async () => {
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), randomBytes(32)]);
  assert.equal((await structuralCheck(png, { mediaType: 'application/pdf' })).findings[0]!.code, 'media_type_mismatch');
  assert.equal((await structuralCheck(Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), randomBytes(32)]), { mediaType: 'application/x-custom' })).findings[0]!.code, 'executable_content');
  assert.equal((await structuralCheck(png, { mediaType: 'text/plain' })).ok, false);
  assert.ok((await structuralCheck(png, { mediaType: 'image/png' })).ok);
  const big = Buffer.alloc(40 * 1024 * 1024); // highly compressible
  const bombZip = writeZip([{ name: 'zeros.bin', data: big }]);
  assert.ok(bombZip.byteLength < 100_000);
  assert.equal((await structuralCheck(bombZip, { mediaType: 'application/zip' })).findings.find((f) => f.blocking)?.code, 'archive_bomb');
  assert.equal((await structuralCheck(bombZip, { mediaType: 'application/zip' }, { maxBytes: 1e9, maxArchiveEntries: 10, maxArchiveUncompressedBytes: 1024 * 1024, maxArchiveRatio: 1e9 })).findings.find((f) => f.blocking)?.code, 'archive_bomb');
  assert.equal((await structuralCheck(gzipSync(big), { mediaType: 'application/gzip' })).findings.find((f) => f.blocking)?.code, 'archive_bomb');
  assert.ok((await structuralCheck(writeZip([{ name: 'a.txt', data: utf8('small') }]), { mediaType: 'application/zip' })).ok);
  // a header that lies about its size is still caught because entries are really inflated
  const lying = Buffer.from(bombZip); const cd = lying.lastIndexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])); lying.writeUInt32LE(10, cd + 24);
  assert.equal((await structuralCheck(lying, { mediaType: 'application/zip' })).findings.find((f) => f.blocking)?.code, 'archive_bomb');
  await withEngine({ config: { limits: { maxBytes: 1024 } } }, async ({ engine }) => {
    await assert.rejects(engine.accept(ctx(), { bytes: randomBytes(2048), mediaType: 'application/octet-stream', filename: 'big.bin', origin: manual }), code('payload_too_large'));
    const lie = await engine.accept(ctx(), { bytes: png, mediaType: 'application/pdf', filename: 'not-a.pdf', origin: manual });
    const d = await engine.describeVersion(ctx(), lie.ref);
    assert.equal(d?.state, 'blocked'); assert.equal((d?.scan as { reason: string }).reason, 'structural_check_failed');
  });
});

test('no scanner: versions stay quarantined; structural_only policy releases and says exactly that', needsPg, async () => {
  await withEngine({ scanner: 'none' }, async ({ engine, make }) => {
    const a = await engine.accept(ctx(), { bytes: utf8('first fictional note'), mediaType: 'text/plain', filename: 'a.txt', origin: manual });
    assert.equal(a.available, false);
    const d = await engine.describeVersion(ctx(), a.ref);
    assert.equal(d?.state, 'quarantined'); assert.equal((d?.scan as { status: string }).status, 'awaiting_scanner');
    await assert.rejects(engine.getBytes(ctx(), a.ref), code('invalid_state'));
    const lenient = make({ config: { scanPolicy: 'structural_only' } });
    await lenient.rescan(ctx(), a.ref); await lenient.runJobsOnce();
    const released = await lenient.describeVersion(ctx(), a.ref);
    assert.equal(released?.state, 'released');
    assert.deepEqual({ policy: (released?.scan as { policy: string }).policy, malwareScan: (released?.scan as { malwareScan: string }).malwareScan }, { policy: 'structural_only', malwareScan: 'not_performed' });
    await assert.rejects(lenient.rescan(ctx(), a.ref), code('invalid_state'));
  });
});

test('scan jobs are restart-safe: a crashed worker lease is taken over and the version settles exactly once', needsPg, async () => {
  await withEngine({ config: { scanInline: false } }, async ({ engine, sql }) => {
    const info = await engine.accept(ctx(), { bytes: utf8('pending fictional memo'), mediaType: 'text/plain', filename: 'memo.txt', origin: manual });
    assert.equal(info.available, false);
    assert.equal((await engine.describeVersion(ctx(), info.ref))?.state, 'quarantined');
    const crashed = await leaseJobs(sql, SCHEMA, { worker: 'crashed-worker', leaseMs: 1 }); // leases, then "dies"
    assert.equal(crashed.length, 1);
    await new Promise((r) => setTimeout(r, 20));
    const [n1, n2] = await Promise.all([engine.runJobsOnce({ worker: 'w1' }), engine.runJobsOnce({ worker: 'w2' })]);
    assert.equal(n1 + n2, 1);
    assert.equal(await engine.runJobsOnce(), 0);
    assert.equal((await engine.describe(ctx(), info.ref))?.available, true);
    assert.equal((await engine.events(ctx())).filter((e) => e.type === 'evidence.released').length, 1);
    const job = (await engine.jobs(ctx(), { kind: 'evidence.scan' }))[0]!;
    assert.equal(job.state, 'done'); assert.equal(job.attempts, 2);
    assert.equal(await engine.job(ctx({ tenantId: 'tenant-b' }), job.id), null);
  });
});

test('idempotent accept, duplicate bytes and concurrent accepts of the same bytes', needsPg, async () => {
  await withEngine({}, async ({ engine, objectRoot }) => {
    const bytes = utf8('the same fictional bytes');
    const input = { bytes, mediaType: 'text/plain', filename: 'same.txt', origin: manual, idempotencyKey: 'accept-1' };
    const first = await engine.accept(ctx(), input);
    assert.deepEqual(await engine.accept(ctx(), input), first);
    await assert.rejects(engine.accept(ctx(), { ...input, filename: 'other.txt' }), code('idempotency_conflict'));
    assert.equal((await engine.custody(ctx(), first.ref)).entries.filter((e) => e.action === 'accepted').length, 1);
    // same bytes from a second origin: one preserved version, a second acquisition record, a visible custody event
    const again = await engine.accept(ctx(), { bytes, mediaType: 'text/plain', filename: 'copy.txt', origin: { kind: 'discovery_receipt', ref: 'E04:receipt:r-77@1' } });
    assert.equal(again.ref, first.ref);
    const prov = await engine.provenance(ctx(), first.ref);
    assert.deepEqual(prov.acquisitions.map((a) => (a as { originKind: string }).originKind), ['manual_import', 'discovery_receipt']);
    assert.ok(prov.custody.some((e) => e.action === 'duplicate_acquisition'));
    // concurrency
    const other = utf8('raced fictional bytes');
    const raced = await Promise.all(Array.from({ length: 6 }, () => engine.accept(ctx(), { bytes: other, mediaType: 'text/plain', filename: 'race.txt', origin: manual })));
    assert.equal(new Set(raced.map((r) => r.ref)).size, 1);
    assert.equal((await engine.list(ctx())).length, 2);
    assert.equal((await files(objectRoot)).length, 2); // no orphan objects left behind
    assert.deepEqual((await engine.verifyAll(ctx())).orphanObjects, []);
  });
});

test('catalog acceptance: restored original matches digest, mutated bytes detected, old citation opens exact version, missing original shows a gap', needsPg, async () => {
  await withEngine({}, async ({ engine, objectRoot }) => {
    const v1Bytes = utf8('Register entry 4: the fictional ferry licence was granted on the first day.\n');
    const v1 = await engine.accept(ctx(), { bytes: v1Bytes, mediaType: 'text/plain', filename: 'register.txt', origin: { kind: 'discovery_receipt', ref: 'E04:receipt:r-1@1' } });
    const quote = 'fictional ferry licence';
    const start = Buffer.from(v1Bytes).toString('utf8').indexOf(quote);
    const citation = await engine.createCitation(ctx(), { version: v1.ref, selector: { kind: 'text', start, end: start + quote.length, quote }, note: 'licence grant' });
    assert.equal(citation.sha256, v1.sha256); assert.deepEqual(citation.validation, { checked: true, basis: 'text offsets verified against preserved bytes' });
    await assert.rejects(engine.createCitation(ctx(), { version: v1.ref, selector: { kind: 'text', start, end: start + 5, quote: 'wrong' } }), code('invalid_input'));
    await assert.rejects(engine.createCitation(ctx(), { version: v1.ref.replace(/@1$/, ''), selector: { kind: 'whole' } }), code('invalid_input'));
    // a refresh brings changed bytes: a new immutable version, never an overwrite
    const v2Bytes = utf8('Register entry 4: the fictional ferry licence was REVOKED on the second day.\n');
    const v2 = await engine.addVersion(ctx(), { evidence: v1.ref, bytes: v2Bytes, mediaType: 'text/plain', filename: 'register.txt', origin: { kind: 'refresh', ref: 'E04:receipt:r-2@1' }, cause: 'correction' });
    assert.equal(v2.revision, 2); assert.equal(v2.evidenceId, v1.evidenceId);
    const unchanged = await engine.addVersion(ctx(), { evidence: v1.ref, bytes: v2Bytes, mediaType: 'text/plain', filename: 'register.txt', origin: { kind: 'refresh', ref: 'E04:receipt:r-3@1' } });
    assert.equal(unchanged.ref, v2.ref);
    const added = (await engine.events(ctx())).find((e) => e.type === 'evidence.version_added')!;
    assert.equal(added.subject, v2.ref); assert.deepEqual({ previous: (added.payload as { previous: string }).previous, cause: (added.payload as { cause: string }).cause }, { previous: v1.ref, cause: 'source_corrected' });
    assert.deepEqual((await engine.versions(ctx(), v1.ref)).map((v) => [v.revision, v.sha256, v.isCurrent]), [[1, v1.sha256, false], [2, v2.sha256, true]]);
    // old citation → the exact preserved version
    const resolved = await engine.resolveCitation(ctx(), citation.ref);
    assert.equal(resolved.state, 'resolved'); assert.equal(resolved.version.ref, v1.ref); assert.equal(resolved.version.sha256, v1.sha256);
    assert.equal(resolved.isCurrentVersion, false); assert.equal(resolved.currentRef, v2.ref); assert.equal(resolved.authenticity, 'not_assessed');
    assert.deepEqual(Buffer.from(await engine.getBytes(ctx(), v1.ref)), Buffer.from(v1Bytes));
    const view = await engine.renderView(ctx(), v1.ref, { citation: citation.ref });
    assert.equal(view.kind, 'text'); assert.deepEqual(view.highlights, [{ kind: 'text', start, end: start + quote.length, quote }]);
    assert.equal((await engine.inspect(ctx(), citation.ref))?.stale, true);

    // mutate the ACTUAL stored object of v1
    const stored = await files(objectRoot); assert.equal(stored.length, 2);
    const before = await engine.verifyAll(ctx());
    assert.deepEqual([before.checked, before.matched, before.failed, before.ok], [2, 2, 0, true]);
    // find which file is v1 by mutating and checking
    const original = await readFile(stored[0]!);
    const mutated = Buffer.from(original); mutated[mutated.length - 3] = mutated[mutated.length - 3]! ^ 0x01;
    await writeFile(stored[0]!, mutated);
    const after = await engine.verifyAll(ctx());
    assert.deepEqual([after.matched, after.failed, after.ok], [1, 1, false]);
    const failedRef = after.results.find((r) => r.status === 'mismatch')!.ref;
    assert.equal((await engine.describeVersion(ctx(), failedRef))?.bytesState, 'corrupt');
    await assert.rejects(engine.getBytes(ctx(), failedRef), code('invalid_state'));
    const failedEvents = (await engine.events(ctx())).filter((e) => e.type === 'evidence.integrity_failed');
    assert.equal(failedEvents.length, 1); assert.equal(failedEvents[0]!.subject, failedRef);
    assert.ok((await engine.provenance(ctx(), failedRef)).gaps.some((g) => g.code === 'bytes_corrupt'));
    assert.equal((await engine.search(ctx(), { q: 'register' })).find((h) => h.ref === failedRef)?.state, 'bytes_corrupt');
    // restore the original object bytes (as an operator would from backup): the restored original matches its digest
    await writeFile(stored[0]!, original);
    assert.equal((await engine.verifyIntegrity(ctx(), failedRef)).status, 'matched');
    assert.equal((await engine.describeVersion(ctx(), failedRef))?.bytesState, 'present');
    // restoreBytes refuses bytes that do not match the retained digest and accepts the true original
    await rm(stored[0]!); await rm(stored[1]!);
    const gone = await engine.verifyAll(ctx());
    assert.deepEqual([gone.failed, gone.results.map((r) => r.status)], [2, ['missing', 'missing']]);
    const gap = await engine.resolveCitation(ctx(), citation.ref);
    assert.equal(gap.state, 'gap'); assert.equal(gap.gap?.code, 'bytes_missing'); assert.equal(gap.version.sha256, v1.sha256); assert.equal(gap.version.available, false);
    assert.equal((await engine.inspect(ctx(), v1.ref))?.state, 'bytes_missing');
    assert.equal((await engine.describe(ctx(), v1.ref))?.available, false);
    await assert.rejects(engine.restoreBytes(ctx(), v1.ref, utf8('not the original'), { reason: 'attempt' }), code('invalid_input'));
    const restored = await engine.restoreBytes(ctx(), v1.ref, v1Bytes, { reason: 'restored from offline copy' });
    assert.equal(restored.bytesState, 'present');
    assert.deepEqual(Buffer.from(await engine.getBytes(ctx(), v1.ref)), Buffer.from(v1Bytes));
    assert.equal((await engine.resolveCitation(ctx(), citation.ref)).state, 'resolved');
    assert.equal((await engine.describeVersion(ctx(), v2.ref))?.bytesState, 'missing'); // the other gap stays visible
    // integrity batch as a durable job with a report
    const { jobId } = await engine.startIntegrityBatch(ctx()); await engine.runJobsOnce();
    const report = (await engine.job(ctx(), jobId))!.result as { checked: number; failed: number; ok: boolean };
    assert.deepEqual([report.checked, report.failed, report.ok], [2, 1, false]);
  });
});

test('acquisition records keep handed-over ownership and handling history; missing origin information is an explicit gap', needsPg, async () => {
  await withEngine({}, async ({ engine }) => {
    const intake = await engine.accept(ctx(), { bytes: utf8('fictional intake attachment'), mediaType: 'text/plain', filename: 'attachment.txt', origin: { kind: 'intake_attachment', ref: 'E02:attachment:att-9@1', submission: 'E02:submission:sub-3', originalOwner: 'intake-case-team', handlingHistory: [{ at: '2026-01-02T09:00:00Z', actor: 'intake-officer-2', action: 'received' }, { at: '2026-01-02T09:05:00Z', actor: 'intake-scanner', action: 'scanned_clean' }] } });
    const p = await engine.provenance(ctx(), intake.ref);
    const a = p.acquisitions[0] as { originKind: string; originalOwner: string; handlingHistory: unknown[]; gaps: unknown[] };
    assert.deepEqual([a.originKind, a.originalOwner, a.handlingHistory.length, a.gaps.length], ['intake_attachment', 'intake-case-team', 2, 0]);
    assert.deepEqual([...((await engine.inspect(ctx(), intake.ref))?.sources ?? [])].sort(), ['E02:attachment:att-9@1', 'E02:submission:sub-3']);
    const copied = await engine.recordHandling(ctx(), intake.ref, { action: 'copied', reason: 'working copy for transcription', destination: 'E06:job:j-1' });
    assert.equal(copied.action, 'copied'); assert.ok((await engine.custody(ctx(), intake.ref)).chainValid);
    const bare = await engine.accept(ctx(), { bytes: utf8('found on a shared drive'), mediaType: 'text/plain', filename: 'unknown.txt', origin: {} });
    assert.deepEqual((await engine.provenance(ctx(), bare.ref)).gaps.map((g) => g.code), ['origin_unknown']);
    const partial = await engine.accept(ctx(), { bytes: utf8('intake without history'), mediaType: 'text/plain', filename: 'partial.txt', origin: { kind: 'intake_attachment' } });
    assert.deepEqual((await engine.provenance(ctx(), partial.ref)).gaps.map((g) => g.code), ['intake_reference_missing', 'original_owner_unknown', 'prior_handling_history_missing']);
    assert.deepEqual(((await engine.inspect(ctx(), partial.ref))?.data as { gaps: { code: string }[] }).gaps.length, 3);
  });
});

test('tenant, project and compartment isolation through every surface, including object keys', needsPg, async () => {
  await withEngine({}, async ({ engine, objects }) => {
    const a = ctx({ compartments: ['sealed'] });
    const open = await engine.accept(a, { bytes: utf8('open fictional record'), mediaType: 'text/plain', filename: 'open.txt', origin: manual });
    const sealed = await engine.accept(a, { bytes: utf8('sealed fictional record'), mediaType: 'text/plain', filename: 'sealed.txt', origin: manual, compartment: 'sealed' });
    const citation = await engine.createCitation(a, { version: sealed.ref, selector: { kind: 'whole' } });
    const pkgA = await engine.exportPackage(a, [open.ref]);
    await engine.verifyAll(a);
    for (const other of [ctx({ tenantId: 'tenant-b' }), ctx({ projectId: 'project-2' })]) {
      for (const ref of [open.ref, sealed.ref]) {
        assert.equal(await engine.describe(other, ref), null); assert.equal(await engine.inspect(other, ref), null);
        await assert.rejects(engine.getBytes(other, ref), code('not_found')); await assert.rejects(engine.provenance(other, ref), code('not_found'));
        await assert.rejects(engine.verifyIntegrity(other, ref), code('not_found')); await assert.rejects(engine.exportPackage(other, [ref]), code('not_found'));
        await assert.rejects(engine.addDerivative(other, { parent: ref, bytes: utf8('x'), mediaType: 'text/plain', filename: 'x.txt', relation: 'note', tool: {} }), code('not_found'));
        await assert.rejects(engine.addVersion(other, { evidence: ref, bytes: utf8('x'), mediaType: 'text/plain', filename: 'x.txt', origin: {} }), code('not_found'));
        await assert.rejects(engine.dispose(other, ref, { reason: 'x', authorization: { authorizedBy: 'x', basis: 'x' } }), code('not_found'));
        await assert.rejects(engine.redact(other, ref, { textRanges: [{ start: 0, end: 1 }], reason: 'x' }), code('not_found'));
        await assert.rejects(engine.renderView(other, ref), code('not_found'));
      }
      await assert.rejects(engine.resolveCitation(other, citation.ref), code('not_found'));
      assert.deepEqual(await engine.list(other), []); assert.deepEqual(await engine.search(other, { q: 'record' }), []); assert.deepEqual(await engine.search(other, { q: 'txt' }), []);
      assert.deepEqual(await engine.audit(other), []); assert.deepEqual(await engine.jobs(other), []);
      const report = await engine.verifyAll(other);
      assert.deepEqual([report.checked, report.results.length, report.orphanObjects.length, report.hiddenChecked], [0, 0, 0, 0]);
      assert.deepEqual((await engine.applyUpstreamChange(other, { eventId: 'evt-x', kind: 'permission_withdrawn', refs: [open.ref], reason: 'x' })).affected, []);
    }
    assert.deepEqual(await engine.events(ctx({ tenantId: 'tenant-b' })), []);
    assert.equal((await engine.describeVersion(a, open.ref))?.restricted, false);
    // the same bytes accepted by another tenant are a separate object under that tenant's prefix
    const b = ctx({ tenantId: 'tenant-b' });
    const theirs = await engine.accept(b, { bytes: utf8('open fictional record'), mediaType: 'text/plain', filename: 'open.txt', origin: manual });
    assert.notEqual(theirs.evidenceId, open.evidenceId);
    const keysA = await objects.list('tenant-a/project-1/'), keysB = await objects.list('tenant-b/project-1/');
    assert.equal(keysA.length, 2); assert.equal(keysB.length, 1); assert.equal((await objects.list('')).length, 3);
    assert.ok((await engine.verifyPackage(pkgA.bytes)).ok);
    await assert.rejects(engine.accept(ctx({ tenantId: '../escape' }), { bytes: utf8('x'), mediaType: 'text/plain', filename: 'x.txt', origin: {} }), code('invalid_input'));
    // compartments: same project, caller without the compartment
    const outsider = ctx();
    assert.equal(await engine.describe(outsider, sealed.ref), null); assert.equal(await engine.inspect(outsider, sealed.ref), null);
    await assert.rejects(engine.getBytes(outsider, sealed.ref), code('not_found'));
    await assert.rejects(engine.resolveCitation(outsider, citation.ref), code('not_found'));
    assert.equal(await engine.inspect(outsider, citation.ref), null);
    assert.deepEqual((await engine.list(outsider)).map((v) => v.ref), [open.ref]);
    assert.deepEqual(await engine.search(outsider, { q: 'sealed' }), []);
    assert.ok((await engine.audit(outsider)).every((r) => !r.subject.includes(sealed.evidenceId)));
    assert.ok((await engine.audit(a)).some((r) => r.subject.includes(sealed.evidenceId)));
    await assert.rejects(engine.accept(outsider, { bytes: utf8('y'), mediaType: 'text/plain', filename: 'y.txt', origin: {}, compartment: 'sealed' }), code('forbidden'));
    const same = await engine.accept(outsider, { bytes: utf8('sealed fictional record'), mediaType: 'text/plain', filename: 'dup.txt', origin: manual });
    assert.notEqual(same.evidenceId, sealed.evidenceId); // dedupe never reveals a hidden compartment's holdings
    const report = await engine.verifyAll(outsider);
    assert.equal(report.hiddenChecked, 1); assert.ok(report.results.every((r) => r.ref !== sealed.ref));
  });
});

test('fail-closed authorization: every method needs its own capability; export, admin and events are never implied', needsPg, async () => {
  await withEngine({}, async ({ engine, make }) => {
    const info = await engine.accept(ctx(), { bytes: utf8('fictional authorisation fixture'), mediaType: 'text/plain', filename: 'authz.txt', origin: manual });
    const none = ctx({ capabilities: [] }); const reader = ctx({ capabilities: ['evidence:read'] }); const wild = ctx({ capabilities: ['evidence:*'] });
    const auth = { authorizedBy: 'records-officer-1', basis: 'fictional retention schedule 4' };
    const calls: [string, (c: ReturnType<typeof ctx>) => Promise<unknown>][] = [
      ['describe', (c) => engine.describe(c, info.ref)], ['getBytes', (c) => engine.getBytes(c, info.ref)], ['list', (c) => engine.list(c)], ['inspect', (c) => engine.inspect(c, info.ref)],
      ['search', (c) => engine.search(c, { q: 'authz' })], ['provenance', (c) => engine.provenance(c, info.ref)], ['custody', (c) => engine.custody(c, info.ref)], ['audit', (c) => engine.audit(c)],
      ['events', (c) => engine.events(c)], ['verifyAll', (c) => engine.verifyAll(c)], ['jobs', (c) => engine.jobs(c)], ['renderView', (c) => engine.renderView(c, info.ref)],
      ['resolveCitation', (c) => engine.resolveCitation(c, 'E05:citation:00000000-0000-4000-8000-000000000000')],
    ];
    for (const [name, call] of calls) await assert.rejects(call(none), code('forbidden'), name);
    await assert.rejects(engine.describe(undefined as never, info.ref), code('unauthenticated'));
    const writes: [string, (c: ReturnType<typeof ctx>) => Promise<unknown>][] = [
      ['accept', (c) => engine.accept(c, { bytes: utf8('z'), mediaType: 'text/plain', filename: 'z.txt', origin: {} })],
      ['addDerivative', (c) => engine.addDerivative(c, { parent: info.ref, bytes: utf8('z'), mediaType: 'text/plain', filename: 'z.txt', relation: 'note', tool: {} })],
      ['addVersion', (c) => engine.addVersion(c, { evidence: info.ref, bytes: utf8('z'), mediaType: 'text/plain', filename: 'z.txt', origin: {} })],
      ['createCitation', (c) => engine.createCitation(c, { version: info.ref, selector: { kind: 'whole' } })],
      ['redact', (c) => engine.redact(c, info.ref, { textRanges: [{ start: 0, end: 1 }], reason: 'r' })],
      ['setRetention', (c) => engine.setRetention(c, info.ref, { action: 'hold', reason: 'r', authorization: auth })],
      ['verifyIntegrity', (c) => engine.verifyIntegrity(c, info.ref)], ['recordHandling', (c) => engine.recordHandling(c, info.ref, { action: 'note', reason: 'r' })],
      ['applyUpstreamChange', (c) => engine.applyUpstreamChange(c, { eventId: 'e', kind: 'permission_withdrawn', refs: [info.ref], reason: 'r' })],
      ['exportPackage', (c) => engine.exportPackage(c, [info.ref])], ['dispose', (c) => engine.dispose(c, info.ref, { reason: 'r', authorization: auth })],
      ['rotateKeys', (c) => engine.rotateKeys(c)], ['restoreBytes', (c) => engine.restoreBytes(c, info.ref, utf8('z'), { reason: 'r' })],
    ];
    for (const [name, call] of writes) await assert.rejects(call(reader), code('forbidden'), name);
    for (const name of ['exportPackage', 'dispose', 'rotateKeys', 'restoreBytes']) await assert.rejects(writes.find((w) => w[0] === name)![1](wild), code('forbidden'), name);
    await assert.rejects(engine.events(wild), code('forbidden'));
    assert.equal((await engine.describeVersion(ctx(), info.ref))?.restricted, false);
    // AuthorizationPort is re-checked before sensitive side effects and denies when it says no
    const denying = make({ ports: { authorization: { authorize: async () => ({ allowed: false, reason: 'revoked', policyVersion: 'p2' }) } } });
    await assert.rejects(denying.exportPackage(ctx(), [info.ref]), code('forbidden'));
    await assert.rejects(denying.dispose(ctx(), info.ref, { reason: 'r', authorization: auth }), code('forbidden'));
    assert.equal((await engine.describeVersion(ctx(), info.ref))?.bytesState, 'present');
  });
});

test('reproduction asks the use-decision port; research reads and citation do not; permission withdrawal restricts but preserves', needsPg, async () => {
  const asked: { action: string; subjects: readonly string[] }[] = []; let answer: 'allow' | 'deny' | 'review' = 'allow';
  const useDecisions: UseDecisionPort = { decide: async (_c, request) => { asked.push({ action: request.action, subjects: request.subjects }); return { decision: answer, reasons: [], permissionRefs: ['E11:permission:p-1'], restrictions: [], decidedAt: new Date().toISOString() }; } };
  await withEngine({}, async ({ engine, make }) => {
    const bytes = utf8('Fictional witness letter about the ferry licence.');
    const info = await engine.accept(ctx(), { bytes, mediaType: 'text/plain', filename: 'letter.txt', origin: { kind: 'correspondence_message', ref: 'E03:message:m-5@1', permission: 'E11:permission:p-1' } });
    const derived = await engine.addDerivative(ctx(), { parent: info.ref, bytes: utf8('translated fictional letter'), mediaType: 'text/plain', filename: 'letter.es.txt', relation: 'translation', tool: { name: 'translator' } });
    // no port: research read and citation work; reproduction is denied, not skipped
    await engine.getBytes(ctx(), info.ref); await engine.createCitation(ctx(), { version: info.ref, selector: { kind: 'whole' } });
    await assert.rejects(engine.getBytes(ctx({ purpose: 'publish' }), info.ref), code('consent_denied'));
    await assert.rejects(engine.getBytes(ctx(), info.ref, { use: 'reproduce' }), code('consent_denied'));
    await assert.rejects(engine.exportPackage(ctx(), [info.ref], { includeOriginals: true }), code('consent_denied'));
    assert.ok((await make({ config: { reproductionWithoutPort: 'allow' } }).getBytes(ctx(), info.ref, { use: 'reproduce' })).byteLength > 0);
    const withPort = make({ ports: { useDecisions } });
    await withPort.getBytes(ctx(), info.ref); await withPort.getBytes(ctx({ purpose: 'cite' }), info.ref);
    assert.equal(asked.length, 0);
    assert.deepEqual(Buffer.from(await withPort.getBytes(ctx({ purpose: 'reproduce' }), info.ref)), Buffer.from(bytes));
    assert.deepEqual(asked, [{ action: 'reproduce', subjects: [info.ref] }]);
    const accessed = (await engine.custody(ctx(), info.ref)).entries.at(-1)!;
    assert.equal((accessed.detail as { use: string }).use, 'reproduce'); assert.deepEqual((accessed.detail as { useDecision: { permissionRefs: string[] } }).useDecision.permissionRefs, ['E11:permission:p-1']);
    for (answer of ['deny', 'review'] as const) await assert.rejects(withPort.getBytes(ctx(), info.ref, { use: 'publish' }), code('consent_denied'));
    answer = 'allow';
    // permission withdrawn upstream
    const change = { eventId: 'E11-evt-41', kind: 'permission_withdrawn' as const, refs: ['E11:permission:p-1'], reason: 'the fictional correspondent withdrew permission' };
    const out = await withPort.applyUpstreamChange(ctx(), change);
    assert.deepEqual(out.affected.sort(), [`E05:evidence_version:${info.evidenceId}`, `E05:evidence_version:${derived.evidenceId}`].sort());
    assert.deepEqual(await withPort.applyUpstreamChange(ctx(), change), out); // idempotent by eventId
    const restrictedEvents = (await engine.events(ctx())).filter((e) => e.type === 'evidence.restricted');
    assert.equal(restrictedEvents.length, 2); assert.equal((restrictedEvents[0]!.payload as { cause: string }).cause, 'E11-evt-41');
    const before = asked.length;
    for (const ref of [info.ref, derived.ref]) {
      await assert.rejects(withPort.getBytes(ctx(), ref, { use: 'reproduce' }), code('consent_denied'));
      await assert.rejects(withPort.exportPackage(ctx(), [ref]), code('consent_denied'));
      const ins = await withPort.inspect(ctx(), ref);
      assert.equal(ins?.blocked, true); assert.equal(ins?.state, 'restricted'); assert.ok(ins?.staleReasons.some((r) => r.includes('withdrew permission')));
    }
    assert.equal(asked.length, before); // restricted evidence is refused before the port is consulted
    // preservation continues: research read, integrity and custody all still work
    assert.deepEqual(Buffer.from(await withPort.getBytes(ctx(), info.ref)), Buffer.from(bytes));
    assert.equal((await withPort.verifyIntegrity(ctx(), info.ref)).status, 'matched');
    const later = await withPort.addDerivative(ctx(), { parent: info.ref, bytes: utf8('summary'), mediaType: 'text/plain', filename: 's.txt', relation: 'summary', tool: {} });
    assert.equal((await withPort.describeVersion(ctx(), later.ref))?.restricted, true);
    // source corrected upstream → stale, visible, cleared by a refresh
    const stale = await withPort.applyUpstreamChange(ctx(), { eventId: 'E03-evt-9', kind: 'source_corrected', refs: ['E03:message:m-5'], reason: 'message body corrected' });
    assert.equal(stale.affected.length, 3);
    assert.equal((await withPort.inspect(ctx(), info.ref))?.stale, true);
    assert.equal((await engine.events(ctx())).filter((e) => e.type === 'evidence.stale').length, 3);
    await withPort.addVersion(ctx(), { evidence: info.ref, bytes: utf8('corrected fictional letter'), mediaType: 'text/plain', filename: 'letter.txt', origin: { kind: 'refresh', ref: 'E03:message:m-5@2' }, cause: 'correction' });
    assert.equal((await withPort.inspect(ctx(), info.ref.replace(/@1$/, '')))?.stale, false);
    const lifted = await withPort.liftRestriction(ctx(), info.ref, { reason: 'permission re-granted', authorization: { authorizedBy: 'consent-officer-1', basis: 'E11:permission:p-2' } });
    assert.equal(lifted.restricted, false);
    assert.ok((await withPort.getBytes(ctx(), info.ref, { use: 'reproduce' })).byteLength > 0);
  });
});
