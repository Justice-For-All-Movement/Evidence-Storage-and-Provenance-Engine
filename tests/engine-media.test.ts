// Redaction, source viewer, provenance packages, retention, key rotation, backup/restore and the HTTP surface.
// Real tools: pdftoppm, pdftotext, pdfinfo, ImageMagick, exiftool, ffmpeg/ffprobe, pg_dump/psql.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { FsObjectStore, engineClient, generateSigningKey, pgSql, signAccessToken } from '../src/service-kit.ts';
import { createEngine, readZip, verifyPackage, writeZip } from '../src/engine/index.ts';
import type { EvidenceVersionInfo, UseDecisionPort } from '../src/service-kit.ts';
import { start } from '../src/engine/serve.ts';
import { ADMIN, ALL_CAPS, code, ctx, manual, needsPg, signatureDb, textPdf, utf8, withEngine } from './engine-helpers.ts';

const allow: UseDecisionPort = { decide: async () => ({ decision: 'allow', reasons: [], permissionRefs: [], restrictions: [], decidedAt: new Date().toISOString() }) };
const tool = (cmd: string, args: string[], input?: Uint8Array): Buffer => execFileSync(cmd, args, { ...(input === undefined ? {} : { input }), maxBuffer: 256 * 1024 * 1024, stdio: ['pipe', 'pipe', 'ignore'] });
async function inTemp<T>(fn: (dir: string) => Promise<T>): Promise<T> { const dir = await mkdtemp(join(tmpdir(), 'e05-media-')); try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); } }
const pdfText = (pdf: Uint8Array): Promise<string> => inTemp(async (dir) => { await writeFile(join(dir, 'x.pdf'), pdf); return tool('pdftotext', [join(dir, 'x.pdf'), '-']).toString('utf8'); });
/** Returns [r,g,b] of one pixel of an image (or of a PDF page rendered at the given dpi). */
const pixel = (bytes: Uint8Array, ext: string, x: number, y: number, dpi?: number): Promise<number[]> => inTemp(async (dir) => {
  const file = join(dir, `x.${ext}`); await writeFile(file, bytes);
  let image = file;
  if (ext === 'pdf') { tool('pdftoppm', ['-png', '-r', String(dpi ?? 72), '-f', '1', '-l', '1', '-singlefile', file, join(dir, 'page')]); image = join(dir, 'page.png'); }
  return [...tool('convert', [image, '-crop', `1x1+${x}+${y}`, '-depth', '8', 'rgb:-'])].slice(0, 3);
});

test('PDF: viewer renders a page image with word boxes and a highlighted citation; redaction removes text and pixels', needsPg, async () => {
  await withEngine({}, async ({ engine }) => {
    const pdf = textPdf([['Fictional council minutes', 'Informant: Marta Example-Witness'], ['Second page: budget table']]);
    assert.match(await pdfText(pdf), /Marta Example-Witness/);
    const info = await engine.accept(ctx({ compartments: ['source-protected'] }), { bytes: pdf, mediaType: 'application/pdf', filename: 'minutes.pdf', origin: manual, compartment: 'source-protected' });
    assert.equal(info.available, true);
    const insider = ctx({ compartments: ['source-protected', 'review'] });
    const view1 = await engine.renderView(insider, info.ref, { page: 1, dpi: 72 });
    assert.equal(view1.kind, 'pdf_page'); if (view1.kind !== 'pdf_page') return;
    assert.deepEqual([view1.pageCount, view1.widthPx, view1.heightPx, view1.pageWidthPt, view1.pageHeightPt], [2, 612, 792, 612, 792]);
    assert.deepEqual([...view1.image.subarray(0, 4)], [0x89, 0x50, 0x4e, 0x47]);
    assert.deepEqual(view1.words.map((w) => w.text), ['Fictional', 'council', 'minutes', 'Informant:', 'Marta', 'Example-Witness']);
    // cite the informant line by the box the viewer reported, then re-open through the citation
    const words = view1.words.slice(3); const x = Math.min(...words.map((w) => w.x)), y = Math.min(...words.map((w) => w.y));
    const box = { x, y, w: Math.max(...words.map((w) => w.x + w.w)) - x, h: Math.max(...words.map((w) => w.y + w.h)) - y };
    const citation = await engine.createCitation(insider, { version: info.ref, selector: { kind: 'page', page: 1, box } });
    assert.equal((citation.validation as { checked: boolean }).checked, true);
    await assert.rejects(engine.createCitation(insider, { version: info.ref, selector: { kind: 'page', page: 3 } }), code('invalid_input'));
    const cited = await engine.renderView(insider, info.ref, { citation: citation.ref, dpi: 72 });
    assert.equal(cited.kind, 'pdf_page'); const h = cited.highlights[0]!;
    assert.equal(h.kind, 'box'); if (h.kind !== 'box') return;
    assert.equal(h.page, 1); assert.ok(Math.abs(h.pixels.x - 72) <= 2 && h.pixels.y > 70 && h.pixels.y < 140 && h.pixels.w > 150, JSON.stringify(h.pixels));
    assert.equal((await engine.renderView(insider, info.ref, { page: 2 })).kind === 'pdf_page', true);
    await assert.rejects(engine.renderView(insider, info.ref, { page: 9 }), code('invalid_input'));

    // redaction into the "review" compartment
    const padded = { x: Math.max(0, box.x - 0.01), y: Math.max(0, box.y - 0.01), w: box.w + 0.02, h: box.h + 0.02 };
    const { derivative, manifest } = await engine.redact(insider, info.ref, { regions: [{ page: 1, ...padded }], reason: 'protect the fictional informant', compartment: 'review', dpi: 100 });
    assert.equal(derivative.mediaType, 'application/pdf'); assert.equal(derivative.compartment, 'review'); assert.equal(derivative.available, true);
    const redacted = await engine.getBytes(insider, derivative.ref);
    // text is really gone (re-extracted with pdftotext) and no bytes of the name or the original metadata remain
    assert.equal((await pdfText(redacted)).trim(), '');
    for (const needle of ['Marta', 'Example-Witness', 'Fictional Clerk', 'Helvetica']) assert.ok(!Buffer.from(redacted).includes(Buffer.from(needle)), needle);
    assert.doesNotMatch(tool('exiftool', ['-a', '-G1', '-'], redacted).toString('utf8'), /Author|Creator|Producer|Title/);
    // pixels are really gone: inside the region every sampled pixel is black; the same spot in the original has ink on white
    const at = (fx: number, fy: number, dpi: number): [number, number] => [Math.round(fx * 612 * dpi / 72), Math.round(fy * 792 * dpi / 72)];
    for (const [fx, fy] of [[padded.x + 0.02, padded.y + padded.h / 2], [padded.x + padded.w / 2, padded.y + padded.h / 2], [padded.x + padded.w - 0.02, padded.y + padded.h / 2]] as const) assert.deepEqual(await pixel(redacted, 'pdf', ...at(fx, fy, 100), 100), [0, 0, 0]);
    assert.deepEqual(await pixel(redacted, 'pdf', ...at(0.9, 0.9, 100), 100), [255, 255, 255]);
    assert.deepEqual(await pixel(pdf, 'pdf', ...at(padded.x + 0.005, padded.y + 0.003, 100), 100), [255, 255, 255]);
    // the unredacted first line is still legible as pixels (ink present) in the derivative
    const titleRow = await inTemp(async (dir) => { await writeFile(join(dir, 'r.pdf'), redacted); tool('pdftoppm', ['-png', '-r', '100', '-f', '1', '-l', '1', '-singlefile', join(dir, 'r.pdf'), join(dir, 'p')]); return tool('convert', [join(dir, 'p.png'), '-crop', `400x30+100+${Math.round(view1.words[0]!.y * 1100)}`, '-colorspace', 'Gray', '-format', '%[fx:minima]', 'info:']).toString(); });
    assert.ok(Number(titleRow) < 0.3, titleRow);
    assert.equal((manifest as { method: string }).method, 'rasterize_and_remove_pixels'); assert.equal((manifest as { source: string }).source, info.ref);
    // original untouched
    assert.deepEqual(Buffer.from(await engine.getBytes(insider, info.ref)), Buffer.from(pdf));
    assert.equal((await engine.verifyIntegrity(insider, info.ref)).status, 'matched');
    assert.ok((await engine.events(ctx())).some((e) => e.type === 'evidence.redaction_created' && e.subject === derivative.ref));
    // a holder of only the derivative's compartment can read the derivative and cannot reach the original
    const reviewer = ctx({ compartments: ['review'], actor: { id: 'reviewer-7', kind: 'human', roles: [] } });
    assert.ok((await engine.getBytes(reviewer, derivative.ref)).byteLength > 0);
    assert.equal(await engine.describe(reviewer, info.ref), null); await assert.rejects(engine.getBytes(reviewer, info.ref), code('not_found'));
    const prov = await engine.provenance(reviewer, derivative.ref);
    assert.deepEqual(prov.derivedFrom, [{ hidden: true, relation: 'redacted', note: 'The related version is outside the caller\'s compartments' }]);
    assert.ok(prov.gaps.some((g) => g.code === 'source_not_visible'));
    const ins = await engine.inspect(reviewer, derivative.ref);
    assert.ok(!JSON.stringify({ sources: ins?.sources, acquisitions: prov.acquisitions, derivedFrom: prov.derivedFrom }).includes(info.evidenceId));
    assert.deepEqual((await engine.list(reviewer)).map((v) => v.ref), [derivative.ref]);
    await assert.rejects(engine.redact(ctx({ compartments: ['source-protected'] }), info.ref, { regions: [{ page: 1, ...padded }], reason: 'x', compartment: 'review' }), code('forbidden'));
  });
});

test('image and text redaction; image viewer; metadata stripped', needsPg, async () => {
  await withEngine({}, async ({ engine }) => {
    const jpeg = await inTemp(async (dir) => {
      const f = join(dir, 'photo.jpg');
      tool('convert', ['-size', '400x300', 'xc:white', '-fill', 'red', '-draw', 'rectangle 100,100 199,199', '-fill', 'blue', '-draw', 'rectangle 300,200 349,249', f]);
      tool('exiftool', ['-overwrite_original', '-q', '-Artist=Fictional Photographer', '-GPSLatitude=12.345', '-GPSLatitudeRef=N', '-Comment=taken near the fictional pier', f]);
      return new Uint8Array(await readFile(f));
    });
    assert.match(tool('exiftool', ['-'], jpeg).toString(), /Fictional Photographer/);
    const info = await engine.accept(ctx(), { bytes: jpeg, mediaType: 'image/jpeg', filename: 'photo.jpg', origin: manual });
    const cite = await engine.createCitation(ctx(), { version: info.ref, selector: { kind: 'page', page: 1, box: { x: 0.25, y: 1 / 3, w: 0.25, h: 1 / 3 } } });
    const view = await engine.renderView(ctx(), info.ref, { citation: cite.ref });
    assert.equal(view.kind, 'image'); if (view.kind !== 'image') return;
    assert.deepEqual([view.widthPx, view.heightPx], [400, 300]); assert.deepEqual(Buffer.from(view.image), Buffer.from(jpeg));
    assert.deepEqual(view.highlights, [{ kind: 'box', page: 1, box: { x: 0.25, y: 1 / 3, w: 0.25, h: 1 / 3 }, pixels: { x: 100, y: 100, w: 101, h: 101 } }]);
    const { derivative, manifest } = await engine.redact(ctx(), info.ref, { regions: [{ x: 0.25, y: 1 / 3, w: 0.25, h: 1 / 3 }], reason: 'hide the red marker' });
    const png = await engine.getBytes(ctx(), derivative.ref);
    assert.equal(derivative.mediaType, 'image/png');
    const [r0, g0, b0] = await pixel(jpeg, 'jpg', 150, 150); assert.ok(r0! > 200 && g0! < 60 && b0! < 60);
    for (const [x, y] of [[101, 101], [150, 150], [198, 198]] as const) assert.deepEqual(await pixel(png, 'png', x, y), [0, 0, 0]);
    const [r1, g1, b1] = await pixel(png, 'png', 325, 225); assert.ok(b1! > 200 && r1! < 60 && g1! < 60); // untouched area preserved
    assert.deepEqual(await pixel(png, 'png', 20, 20), [255, 255, 255]);
    const meta = tool('exiftool', ['-a', '-G1', '-'], png).toString();
    assert.doesNotMatch(meta, /Fictional Photographer|GPS|fictional pier|Artist|Comment/);
    assert.ok(!Buffer.from(png).includes(Buffer.from('Fictional Photographer')));
    assert.match(String((manifest as { metadata: string }).metadata), /stripped/);
    // text
    const body = 'Call from Marta Example-Witness, tel. 555-0100, about the ferry licence.';
    const txt = await engine.accept(ctx(), { bytes: utf8(body), mediaType: 'text/plain', filename: 'call-note.txt', origin: manual });
    const s1 = body.indexOf('Marta'), e1 = s1 + 'Marta Example-Witness'.length, s2 = body.indexOf('555-0100');
    const red = await engine.redact(ctx(), txt.ref, { textRanges: [{ start: s1, end: e1 }, { start: s2, end: s2 + 8 }], reason: 'protect the fictional caller' });
    const out = Buffer.from(await engine.getBytes(ctx(), red.derivative.ref)).toString('utf8');
    assert.equal(out.length, body.length); assert.ok(!out.includes('Marta') && !out.includes('555-0100') && !out.includes('Witness'));
    assert.equal(out.slice(0, s1), body.slice(0, s1)); assert.equal(out.slice(e1, s2), body.slice(e1, s2)); assert.ok(out.endsWith('about the ferry licence.'));
    assert.equal(Buffer.from(await engine.getBytes(ctx(), txt.ref)).toString('utf8'), body);
    await assert.rejects(engine.redact(ctx(), txt.ref, { textRanges: [{ start: 0, end: 9999 }], reason: 'x' }), code('invalid_input'));
    await assert.rejects(engine.redact(ctx(), txt.ref, { regions: [{ x: 0, y: 0, w: 1, h: 1 }], reason: 'x' }), code('invalid_input'));
    const idem = { textRanges: [{ start: 0, end: 4 }], reason: 'replay', idempotencyKey: 'redact-1' };
    assert.equal((await engine.redact(ctx(), txt.ref, idem)).derivative.ref, (await engine.redact(ctx(), txt.ref, idem)).derivative.ref);
  });
});

test('audio: streamable byte ranges, duration from ffprobe and time-range citations', needsPg, async () => {
  await withEngine({}, async ({ engine }) => {
    const wav = await inTemp(async (dir) => { tool('ffmpeg', ['-v', 'error', '-f', 'lavfi', '-i', 'sine=frequency=440:duration=2', '-ar', '8000', '-ac', '1', join(dir, 'tone.wav')]); return new Uint8Array(await readFile(join(dir, 'tone.wav'))); });
    const info = await engine.accept(ctx(), { bytes: wav, mediaType: 'audio/wav', filename: 'call.wav', origin: manual });
    const cite = await engine.createCitation(ctx(), { version: info.ref, selector: { kind: 'time', startMs: 500, endMs: 1500 } });
    assert.equal((cite.validation as { checked: boolean }).checked, true);
    await assert.rejects(engine.createCitation(ctx(), { version: info.ref, selector: { kind: 'time', startMs: 500, endMs: 60_000 } }), code('invalid_input'));
    const view = await engine.renderView(ctx(), info.ref, { citation: cite.ref, range: { start: 100, end: 1099 } });
    assert.equal(view.kind, 'media'); if (view.kind !== 'media') return;
    assert.equal(view.durationMs, 2000); assert.equal(view.totalBytes, wav.byteLength); assert.equal(view.seekMs, 500);
    assert.deepEqual(view.range, { start: 100, end: 1099 }); assert.deepEqual(Buffer.from(view.bytes), Buffer.from(wav.subarray(100, 1100)));
    assert.deepEqual(view.highlights, [{ kind: 'time', startMs: 500, endMs: 1500 }]);
  });
});

test('provenance package: export, independent verification, tamper detection, redactedOnly withholds the source', needsPg, async () => {
  await withEngine({ ports: { useDecisions: allow } }, async ({ engine }) => {
    const owner = ctx({ compartments: ['source-protected', 'review'] });
    const body = 'Statement by Marta Example-Witness about the fictional harbour contract.';
    const original = await engine.accept(owner, { bytes: utf8(body), mediaType: 'text/plain', filename: 'statement.txt', origin: { kind: 'intake_attachment', ref: 'E02:attachment:att-1@1' }, compartment: 'source-protected' });
    const red = await engine.redact(owner, original.ref, { textRanges: [{ start: 13, end: 34 }], reason: 'protect the fictional witness', compartment: 'review' });
    const plain = await engine.accept(owner, { bytes: utf8('public fictional tender notice'), mediaType: 'text/plain', filename: 'tender notice.txt', origin: manual });
    const pkg = await engine.exportPackage(owner, [original.ref, plain.ref], { includeOriginals: true, reason: 'handover to fictional counsel' });
    const entries = await readZip(pkg.bytes);
    assert.deepEqual([...entries.keys()].sort(), ['README.txt', 'manifest.json', `objects/${original.sha256}/statement.txt`, `objects/${plain.sha256}/tender_notice.txt`].sort());
    assert.match(Buffer.from(entries.get('README.txt')!).toString(), /does not show that the\s+content is authentic/);
    // the archive is a real ZIP readable by an independent tool
    await inTemp(async (dir) => { await writeFile(join(dir, 'p.zip'), pkg.bytes); tool('unzip', ['-q', join(dir, 'p.zip'), '-d', join(dir, 'out')]); assert.equal((await readFile(join(dir, 'out', 'objects', original.sha256, 'statement.txt'))).toString(), body); });
    const m = JSON.parse(Buffer.from(entries.get('manifest.json')!).toString()) as { items: { ref: string; sha256: string; authenticity: string; custody: { action: string }[]; acquisition: { gaps: { code: string }[] }[]; gaps: { code: string }[] }[]; gaps: { code: string }[]; statement: string };
    assert.equal(m.items[0]!.ref, original.ref); assert.equal(m.items[0]!.authenticity, 'not_assessed'); assert.match(m.statement, /does not establish authenticity or truth/);
    assert.deepEqual(m.items[0]!.custody.map((c) => c.action).slice(0, 2), ['accepted', 'released']);
    assert.deepEqual(m.gaps.map((g) => g.code), ['original_owner_unknown', 'prior_handling_history_missing']);
    const ok = await verifyPackage(pkg.bytes);
    assert.ok(ok.ok); assert.equal(ok.files.length, 2); assert.ok(ok.custody.every((c) => c.ok)); assert.equal(ok.gaps.length, 2);
    assert.equal((await engine.custody(owner, original.ref)).entries.at(-1)!.action, 'exported');
    assert.equal(((await engine.custody(owner, original.ref)).entries.at(-1)!.detail as { packageSha256: string }).packageSha256, pkg.sha256);
    // tampering: changed content, changed custody, removed file, extra file
    const rebuild = (mutate: (files: Map<string, Uint8Array>) => void): Uint8Array => { const copy = new Map(entries); mutate(copy); return writeZip([...copy].map(([name, data]) => ({ name, data }))); };
    const t1 = await verifyPackage(rebuild((f) => f.set(`objects/${original.sha256}/statement.txt`, utf8(body.replace('harbour', 'airport')))));
    assert.equal(t1.ok, false); assert.equal(t1.files.find((f) => !f.ok)?.detail, 'bytes do not match the manifest digest');
    const t2 = await verifyPackage(rebuild((f) => { const mm = JSON.parse(Buffer.from(f.get('manifest.json')!).toString()); mm.items[0].custody[0].actorId = 'someone-else'; f.set('manifest.json', utf8(JSON.stringify(mm))); }));
    assert.equal(t2.ok, false); assert.equal(t2.custody[0]!.ok, false);
    assert.equal((await verifyPackage(rebuild((f) => { f.delete(`objects/${plain.sha256}/tender_notice.txt`); }))).ok, false);
    assert.equal((await verifyPackage(rebuild((f) => { f.set('objects/extra.bin', utf8('x')); }))).ok, false);
    assert.equal((await verifyPackage(utf8('not a zip'))).ok, false);
    // metadata-only export shows that bytes are not included
    const meta = await engine.exportPackage(owner, [plain.ref]);
    assert.deepEqual([...(await readZip(meta.bytes)).keys()].sort(), ['README.txt', 'manifest.json']);
    assert.ok((await verifyPackage(meta.bytes)).gaps.some((g) => (g as { code: string }).code === 'bytes_not_included'));
    // redactedOnly: only redacted derivatives; neither the source bytes, its digest nor the redacted words appear anywhere
    await assert.rejects(engine.exportPackage(owner, [original.ref], { redactedOnly: true }), code('invalid_input'));
    const safe = await engine.exportPackage(owner, [red.derivative.ref], { redactedOnly: true });
    const safeEntries = await readZip(safe.bytes);
    assert.deepEqual([...safeEntries.keys()].sort(), ['README.txt', 'manifest.json', `objects/${red.derivative.sha256}/statement.redacted.txt`].sort());
    const everything = Buffer.concat([...safeEntries.values()].map((v) => Buffer.from(v))).toString('utf8');
    assert.ok(!everything.includes('Marta') && !everything.includes(original.sha256));
    const sv = await verifyPackage(safe.bytes);
    assert.ok(sv.ok); assert.ok(sv.gaps.some((g) => (g as { code: string }).code === 'source_withheld'));
    // a missing original stays visible in a package as a gap instead of failing or being silently skipped
    await engine.dispose(owner, plain.ref, { reason: 'fictional retention period ended', authorization: { authorizedBy: 'records-officer-1', basis: 'fictional schedule 4' } });
    const after = await engine.exportPackage(owner, [plain.ref], { includeOriginals: true });
    const av = await verifyPackage(after.bytes);
    assert.ok(av.ok); assert.equal(av.files.length, 0); assert.ok(av.gaps.some((g) => (g as { code: string }).code === 'bytes_disposed'));
  });
});

test('retention: hold blocks disposal; authorised disposal removes bytes, keeps a tombstone digest and a visible gap', needsPg, async () => {
  await withEngine({}, async ({ engine, objects }) => {
    const auth = { authorizedBy: 'records-officer-1', basis: 'fictional retention schedule 4', reference: 'decision-2026-11' };
    const bytes = utf8('fictional record due for disposal');
    const info = await engine.accept(ctx(), { bytes, mediaType: 'text/plain', filename: 'old.txt', origin: manual });
    const citation = await engine.createCitation(ctx(), { version: info.ref, selector: { kind: 'whole' } });
    await assert.rejects(engine.setRetention(ctx(), info.ref, { action: 'hold', reason: 'x', authorization: {} as never }), code('invalid_input'));
    assert.equal((await engine.setRetention(ctx(), info.ref, { action: 'hold', reason: 'fictional litigation hold', authorization: auth })).hold, true);
    await assert.rejects(engine.dispose(ctx(), info.ref, { reason: 'period ended', authorization: auth }), code('invalid_state'));
    assert.equal((await objects.list('tenant-a/')).length, 1);
    await engine.setRetention(ctx(), info.ref, { action: 'schedule', reason: 'schedule 4', disposeAfter: '2026-06-01T00:00:00Z', authorization: auth });
    assert.deepEqual(await engine.dueForDisposal(ctx()), []); // held
    await engine.setRetention(ctx(), info.ref, { action: 'release_hold', reason: 'litigation ended', authorization: auth });
    assert.deepEqual((await engine.dueForDisposal(ctx())).map((v) => v.ref), [info.ref]);
    await assert.rejects(engine.dispose(ctx(), info.ref, { reason: 'period ended', authorization: { authorizedBy: '', basis: '' } }), code('invalid_input'));
    const disposed = await engine.dispose(ctx(), info.ref, { reason: 'period ended', authorization: auth, idempotencyKey: 'dispose-1' });
    assert.deepEqual([disposed[0]!.bytesState, disposed[0]!.sha256, disposed[0]!.available], ['disposed', info.sha256, false]);
    assert.deepEqual(await objects.list('tenant-a/'), []); // bytes really removed
    await engine.dispose(ctx(), info.ref, { reason: 'period ended', authorization: auth, idempotencyKey: 'dispose-1' });
    await assert.rejects(engine.getBytes(ctx(), info.ref), code('invalid_state'));
    const res = await engine.resolveCitation(ctx(), citation.ref);
    assert.equal(res.state, 'gap'); assert.equal(res.gap?.code, 'bytes_disposed'); assert.equal(res.version.sha256, info.sha256);
    const prov = await engine.provenance(ctx(), info.ref);
    assert.deepEqual(prov.retention.map((r) => (r as { action: string }).action), ['hold', 'schedule', 'release_hold', 'disposal']);
    assert.deepEqual((prov.retention.at(-1) as { authorization: unknown }).authorization, auth);
    assert.ok(prov.gaps.some((g) => g.code === 'bytes_disposed')); assert.ok(prov.custodyChainValid);
    assert.equal((await engine.verifyIntegrity(ctx(), info.ref)).status, 'disposed');
    const all = await engine.verifyAll(ctx()); assert.deepEqual([all.disposed, all.failed, all.ok], [1, 0, true]);
    assert.equal((await engine.inspect(ctx(), info.ref))?.state, 'bytes_disposed');
    assert.deepEqual((await engine.events(ctx())).filter((e) => e.type === 'evidence.retention_changed').map((e) => (e.payload as { action: string }).action), ['hold', 'schedule', 'release_hold', 'disposal']);
    await assert.rejects(engine.restoreBytes(ctx(), info.ref, bytes, { reason: 'x' }), code('invalid_state'));
    // accepting the same bytes again is a new acquisition; the tombstone remains
    const again = await engine.accept(ctx(), { bytes, mediaType: 'text/plain', filename: 'old.txt', origin: manual });
    assert.notEqual(again.evidenceId, info.evidenceId); assert.equal((await engine.describeVersion(ctx(), info.ref))?.bytesState, 'disposed');
  });
});

test('encryption at rest: wrapping-key rotation re-wraps data keys without rewriting objects; old key can then be retired', needsPg, async () => {
  await withEngine({}, async ({ engine, make, keys, objectRoot }) => {
    const bytes = utf8('fictional sealed ledger');
    const info = await engine.accept(ctx(), { bytes, mediaType: 'text/plain', filename: 'ledger.txt', origin: manual });
    const file = join(objectRoot, (await readdir(objectRoot, { recursive: true })).find((f) => /objects\/..\/[0-9a-f-]{36}$/.test(f))!);
    const before = await readFile(file);
    const k2 = new Uint8Array(randomBytes(32));
    const rotated = make({ config: { encryption: { currentKeyVersion: 'k2', keys: { ...keys, k2 } } } });
    assert.deepEqual(await rotated.rotateKeys(ctx()), { rewrapped: 1, remaining: 0, unavailable: 0, currentKeyVersion: 'k2' });
    assert.deepEqual(await readFile(file), before);
    assert.equal((await rotated.describeVersion(ctx(), info.ref))?.keyVersion, 'k2');
    const onlyNew = make({ config: { encryption: { currentKeyVersion: 'k2', keys: { k2 } } } });
    assert.deepEqual(Buffer.from(await onlyNew.getBytes(ctx(), info.ref)), Buffer.from(bytes));
    assert.equal((await onlyNew.verifyIntegrity(ctx(), info.ref)).status, 'matched');
    // the old key alone can no longer open it, and that is reported as a key problem, not as corruption
    assert.equal((await engine.verifyIntegrity(ctx(), info.ref)).status, 'key_unavailable');
    await assert.rejects(engine.getBytes(ctx(), info.ref), code('unavailable'));
    assert.equal((await onlyNew.describeVersion(ctx(), info.ref))?.bytesState, 'present');
    const wrong = make({ config: { encryption: { currentKeyVersion: 'k2', keys: { k2: new Uint8Array(randomBytes(32)) } } } });
    assert.equal((await wrong.verifyIntegrity(ctx({ capabilities: ['evidence:verify'] }), info.ref)).status, 'mismatch');
    assert.equal((await onlyNew.verifyIntegrity(ctx(), info.ref)).status, 'matched');
  });
});

test('backup and restore: pg_dump + object copy into a new database and directory verifies; corruption and deletion are detected', needsPg, async () => {
  await withEngine({}, async ({ engine, url, objectRoot, dir, keys }) => {
    const contents = ['fictional ledger page one', 'fictional ledger page two', 'fictional ledger page three'].map(utf8);
    const infos: EvidenceVersionInfo[] = [];
    for (const [i, bytes] of contents.entries()) infos.push(await engine.accept(ctx(), { bytes, mediaType: 'text/plain', filename: `ledger-${i}.txt`, origin: manual }));
    const citation = await engine.createCitation(ctx(), { version: infos[0]!.ref, selector: { kind: 'whole' } });
    // documented procedure: logical dump of the engine schema + copy of the object tree
    const dump = join(dir, 'backup.sql'); tool('pg_dump', ['--no-owner', '--schema=e05_evidence', '-f', dump, url]);
    const restoredRoot = join(dir, 'restored-objects'); await cp(objectRoot, restoredRoot, { recursive: true });
    const name = `e05_restore_${randomBytes(6).toString('hex')}`;
    const admin = new pg.Pool({ connectionString: ADMIN as string, max: 1 });
    await admin.query(`create database ${name}`);
    const target = new URL(ADMIN as string); target.pathname = `/${name}`;
    const pool = new pg.Pool({ connectionString: target.toString(), max: 4 });
    try {
      tool('psql', ['-q', '-v', 'ON_ERROR_STOP=1', '-f', dump, target.toString()]);
      const restored = createEngine({ sql: pgSql(pool), objects: new FsObjectStore(restoredRoot), config: { encryption: { currentKeyVersion: 'k1', keys } } });
      const report = await restored.verifyAll(ctx());
      assert.deepEqual([report.checked, report.matched, report.failed, report.ok, report.orphanObjects.length], [3, 3, 0, true, 0]);
      for (const [i, info] of infos.entries()) assert.deepEqual(Buffer.from(await restored.getBytes(ctx(), info.ref)), Buffer.from(contents[i]!));
      assert.equal((await restored.resolveCitation(ctx(), citation.ref)).state, 'resolved');
      assert.ok((await restored.custody(ctx(), infos[0]!.ref)).chainValid);
      // now damage the restored copy: flip one byte in one object, delete another, drop in a stray file
      const objectFiles = (await readdir(restoredRoot, { recursive: true, withFileTypes: true })).filter((e) => e.isFile()).map((e) => join(e.parentPath, e.name)).sort();
      assert.equal(objectFiles.length, 3);
      const damaged = await readFile(objectFiles[0]!); damaged[40] = damaged[40]! ^ 0xff; await writeFile(objectFiles[0]!, damaged);
      await rm(objectFiles[1]!);
      await writeFile(join(restoredRoot, 'tenant-a', 'project-1', 'objects', 'stray-file'), 'unreferenced');
      const bad = await restored.verifyAll(ctx());
      assert.deepEqual([bad.checked, bad.matched, bad.failed, bad.ok], [3, 1, 2, false]);
      assert.deepEqual(bad.results.map((r) => r.status).sort(), ['matched', 'mismatch', 'missing']);
      assert.deepEqual(bad.orphanObjects, ['tenant-a/project-1/objects/stray-file']);
      assert.equal((await restored.events(ctx())).filter((e) => e.type === 'evidence.integrity_failed').length, 2);
      // the source system is unaffected
      assert.ok((await engine.verifyAll(ctx())).ok);
    } finally { await pool.end(); await admin.query(`drop database if exists ${name} with (force)`); await admin.end(); }
  });
});

test('HTTP: standalone server with signed tokens, uploads, ranges, citations, packages and 404 for foreign tenants', needsPg, async () => {
  await withEngine({ scanner: 'none' }, async ({ url, dir }) => {
    const key = generateSigningKey('k-test');
    const token = (over: { tid?: string; caps?: string[] } = {}): string => { const now = Math.floor(Date.now() / 1000); return signAccessToken({ iss: 'identity', sub: 'researcher-1', kind: 'human', tid: over.tid ?? 'tenant-a', pid: 'project-1', roles: [], caps: over.caps ?? ALL_CAPS, cmp: [], purpose: 'investigate', pv: '1', iat: now, exp: now + 300, jti: randomBytes(8).toString('hex') }, key); };
    const running = await start({ DATABASE_URL: url, PORT: '0', IDENTITY_PUBLIC_KEYS: JSON.stringify({ [key.kid]: key.publicKeyPem }), OBJECT_STORE: 'fs', OBJECT_STORE_PATH: join(dir, 'http-objects'), EVIDENCE_MASTER_KEY: randomBytes(32).toString('base64'), CLAMAV_DATABASE_DIR: await signatureDb(dir), EVIDENCE_REPRODUCTION_WITHOUT_PORT: 'allow', EVIDENCE_WORKER_IDLE_MS: '25' });
    try {
      const base = `http://127.0.0.1:${running.port}`; const api = engineClient(base, () => token());
      assert.equal(((await (await fetch(`${base}/healthz`)).json()) as { ok: boolean }).ok, true);
      assert.equal((await api.call<{ id: string }>('GET', '/v1/manifest')).id, 'E05');
      const body = 'Fictional HTTP upload about the harbour contract.';
      const accepted = await api.call<EvidenceVersionInfo>('POST', '/v1/evidence/accept', { contentBase64: Buffer.from(body).toString('base64'), mediaType: 'text/plain', filename: 'upload.txt', origin: manual, idempotencyKey: 'http-1' });
      assert.equal(accepted.available, false); // quarantined until the worker loop scans it
      let state = '';
      for (let i = 0; i < 100 && state !== 'released'; i++) { await new Promise((r) => setTimeout(r, 50)); state = (await api.call<{ state: string }>('GET', `/v1/evidence/describe?ref=${encodeURIComponent(accepted.ref)}`)).state; }
      assert.equal(state, 'released');
      const res = await fetch(`${base}/v1/evidence/content?ref=${encodeURIComponent(accepted.ref)}`, { headers: { authorization: `Bearer ${token()}`, range: 'bytes=10-13' } });
      assert.equal(res.status, 206); assert.equal(res.headers.get('content-range'), `bytes 10-13/${body.length}`); assert.equal(await res.text(), 'HTTP');
      assert.equal(res.headers.get('x-evidence-sha256'), accepted.sha256); assert.equal(res.headers.get('x-evidence-authenticity'), 'not_assessed');
      assert.equal(Buffer.from(await api.bytes(`/v1/evidence/content?ref=${encodeURIComponent(accepted.ref)}`)).toString(), body);
      const versions = await api.call<{ revision: number }[]>('GET', `/v1/evidence/${accepted.evidenceId}/versions`); assert.equal(versions.length, 1);
      assert.equal((await api.call<{ status: string }>('POST', `/v1/evidence/${accepted.evidenceId}/verify`, {})).status, 'matched');
      assert.equal((await api.call<{ custodyChainValid: boolean }>('GET', `/v1/provenance/${accepted.evidenceId}`)).custodyChainValid, true);
      const cite = await api.call<{ id: string; ref: string }>('POST', '/v1/citations', { version: accepted.ref, selector: { kind: 'text', start: 10, end: 14, quote: 'HTTP' } });
      assert.equal((await api.call<{ state: string }>('GET', `/v1/citations/${cite.id}`)).state, 'resolved');
      const view = await api.call<{ kind: string; text: string; highlights: unknown[] }>('POST', '/v1/evidence/view', { ref: accepted.ref, citation: cite.ref });
      assert.deepEqual([view.kind, view.text, view.highlights.length], ['text', body, 1]);
      const pkgRes = await fetch(`${base}/v1/packages`, { method: 'POST', headers: { authorization: `Bearer ${token()}`, 'content-type': 'application/json' }, body: JSON.stringify({ refs: [accepted.ref], includeOriginals: true }) });
      assert.equal(pkgRes.status, 200); const zip = new Uint8Array(await pkgRes.arrayBuffer());
      assert.equal((await api.call<{ ok: boolean }>('POST', '/v1/packages/verify', zip)).ok, true);
      assert.equal((await api.call<{ ref: string }[]>('GET', '/v1/search?q=upload')).length, 1);
      // foreign tenant, missing capability, missing token
      const foreign = engineClient(base, () => token({ tid: 'tenant-b' }));
      await assert.rejects(foreign.call('GET', `/v1/provenance/${accepted.evidenceId}`), code('not_found'));
      await assert.rejects(foreign.bytes(`/v1/evidence/content?ref=${encodeURIComponent(accepted.ref)}`), code('not_found'));
      assert.deepEqual(await foreign.call('GET', '/v1/evidence'), []);
      await assert.rejects(engineClient(base, () => token({ caps: ['evidence:read'] })).call('POST', '/v1/packages', { refs: [accepted.ref] }), code('forbidden'));
      assert.equal((await fetch(`${base}/v1/evidence`)).status, 401);
      const marked = await api.call<EvidenceVersionInfo>('POST', '/v1/evidence/accept', { contentBase64: Buffer.from('HARMLESS-PAM-TEST-SIGNATURE').toString('base64'), mediaType: 'text/plain', filename: 'marked.txt', origin: {} });
      for (let i = 0; i < 100 && state !== 'blocked'; i++) { await new Promise((r) => setTimeout(r, 50)); state = (await api.call<{ state: string }>('GET', `/v1/evidence/describe?ref=${encodeURIComponent(marked.ref)}`)).state; }
      assert.equal(state, 'blocked');
      assert.equal((await fetch(`${base}/v1/evidence/content?ref=${encodeURIComponent(marked.ref)}`, { headers: { authorization: `Bearer ${token()}` } })).status, 409);
    } finally { await running.close(); }
  });
});
