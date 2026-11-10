// Evidence engine tooling: subprocess runner, structural checks, ClamAV adapter, ZIP and PDF writers, viewer and
// redaction helpers. Every subprocess is spawned with an argument array, a timeout and an output limit; never a shell.
import { spawn } from 'node:child_process';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crc32, deflateRawSync, deflateSync, gunzip, inflateRaw } from 'node:zlib';
import { promisify } from 'node:util';
import { DomainError, canonical, invariant } from '../contracts.ts';

export const sha256Hex = (bytes: Uint8Array | string): string => createHash('sha256').update(bytes).digest('hex');

// ───────────────────────────── Subprocesses ─────────────────────────────
export type RunResult = Readonly<{ code: number; stdout: Buffer; stderr: string }>;
export function run(command: string, args: readonly string[], options: { timeoutMs?: number; maxOutputBytes?: number; cwd?: string } = {}): Promise<RunResult> {
  const max = options.maxOutputBytes ?? 64 * 1024 * 1024;
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, [...args], { shell: false, stdio: ['ignore', 'pipe', 'pipe'], ...(options.cwd === undefined ? {} : { cwd: options.cwd }), env: { PATH: process.env.PATH ?? '/usr/bin:/bin', LANG: 'C.UTF-8', HOME: options.cwd ?? tmpdir() } });
    const out: Buffer[] = []; let size = 0; let err = ''; let failed: DomainError | undefined;
    const timer = setTimeout(() => { failed = new DomainError('unavailable', `${command} timed out`); child.kill('SIGKILL'); }, options.timeoutMs ?? 120_000);
    child.stdout.on('data', (chunk: Buffer) => { size += chunk.byteLength; if (size > max) { failed = new DomainError('payload_too_large', `${command} produced too much output`); child.kill('SIGKILL'); } else out.push(chunk); });
    child.stderr.on('data', (chunk: Buffer) => { if (err.length < 8192) err += chunk.toString('utf8'); });
    child.on('error', (error: NodeJS.ErrnoException) => { clearTimeout(timer); reject(error.code === 'ENOENT' ? new DomainError('unavailable', `Required tool ${command} is not installed`) : error); });
    child.on('close', (code) => { clearTimeout(timer); if (failed !== undefined) reject(failed); else resolvePromise({ code: code ?? -1, stdout: Buffer.concat(out), stderr: err.slice(0, 8192) }); });
  });
}
/** Runs fn with a private temporary directory that is removed afterwards. */
export async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'e05-'));
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}
async function must(command: string, args: readonly string[], options: { timeoutMs?: number; maxOutputBytes?: number; cwd?: string } = {}): Promise<Buffer> {
  const r = await run(command, args, options);
  if (r.code !== 0) throw new DomainError('invalid_input', `${command} could not process the content`);
  return r.stdout;
}
export async function toolVersion(command: string, args: readonly string[] = ['-v']): Promise<string> {
  try { const r = await run(command, args, { timeoutMs: 10_000, maxOutputBytes: 65536 }); return ((r.stdout.toString('utf8') + '\n' + r.stderr).trim().split('\n')[0] ?? '').slice(0, 120); }
  catch { return 'unavailable'; }
}

// ───────────────────────────── Envelope encryption ─────────────────────────────
// Same construction as the foundation PrivateObjectStore (AES-256-GCM, additional data binding scope + plaintext digest),
// with a per-object data key that is wrapped by a versioned master key so the wrapping key can be rotated without
// rewriting objects.
export type EncryptionConfig = Readonly<{ currentKeyVersion: string; keys: Readonly<Record<string, Uint8Array>> }>;
export type SealBinding = Readonly<{ tenantId: string; projectId: string; sha256: string }>;
const MAGIC = Buffer.from('EVE1');
function gcmSeal(key: Uint8Array, plain: Uint8Array, aad: string): Buffer {
  const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(Buffer.from(aad));
  const data = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]);
}
function gcmOpen(key: Uint8Array, sealed: Uint8Array, aad: string): Buffer {
  const b = Buffer.from(sealed.buffer, sealed.byteOffset, sealed.byteLength);
  invariant(b.byteLength >= 28, 'integrity_failure', 'Sealed value is truncated');
  const decipher = createDecipheriv('aes-256-gcm', key, b.subarray(0, 12)); decipher.setAAD(Buffer.from(aad)); decipher.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([decipher.update(b.subarray(28)), decipher.final()]);
}
const wrapAad = (keyVersion: string, b: SealBinding): string => canonical({ v: 1, use: 'wrap', keyVersion, tenantId: b.tenantId, projectId: b.projectId, sha256: b.sha256 });
const dataAad = (b: SealBinding): string => canonical({ v: 1, use: 'data', tenantId: b.tenantId, projectId: b.projectId, sha256: b.sha256 });
export function validateEncryption(config: EncryptionConfig): void {
  invariant(typeof config.currentKeyVersion === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(config.currentKeyVersion) && config.currentKeyVersion !== 'none', 'invalid_config', 'Invalid key version');
  invariant(config.keys[config.currentKeyVersion] !== undefined, 'invalid_config', 'Current master key is missing');
  for (const key of Object.values(config.keys)) invariant(key instanceof Uint8Array && key.byteLength === 32, 'invalid_config', 'Master keys must be 32 bytes');
}
/** Encrypts plaintext under a fresh data key; returns the stored object bytes and the wrapped data key. */
export function sealObject(config: EncryptionConfig, binding: SealBinding, plain: Uint8Array): { stored: Buffer; wrappedKey: string; keyVersion: string } {
  const dek = randomBytes(32);
  const stored = Buffer.concat([MAGIC, gcmSeal(dek, plain, dataAad(binding))]);
  const wrappedKey = gcmSeal(config.keys[config.currentKeyVersion] as Uint8Array, dek, wrapAad(config.currentKeyVersion, binding)).toString('base64');
  return { stored, wrappedKey, keyVersion: config.currentKeyVersion };
}
export function openObject(config: EncryptionConfig, binding: SealBinding, stored: Uint8Array, wrappedKey: string, keyVersion: string): Buffer {
  const master = config.keys[keyVersion];
  if (master === undefined) throw new DomainError('unavailable', `Master key version ${keyVersion} is not configured`);
  const b = Buffer.from(stored.buffer, stored.byteOffset, stored.byteLength);
  invariant(b.byteLength >= 4 && b.subarray(0, 4).equals(MAGIC), 'integrity_failure', 'Stored object is not a sealed evidence object');
  const dek = gcmOpen(master, Buffer.from(wrappedKey, 'base64'), wrapAad(keyVersion, binding));
  return gcmOpen(dek, b.subarray(4), dataAad(binding));
}
/** Re-wraps a data key under the current master key (key rotation). Object bytes are untouched. */
export function rewrapKey(config: EncryptionConfig, binding: SealBinding, wrappedKey: string, keyVersion: string): { wrappedKey: string; keyVersion: string } {
  const master = config.keys[keyVersion];
  if (master === undefined) throw new DomainError('unavailable', `Master key version ${keyVersion} is not configured`);
  const dek = gcmOpen(master, Buffer.from(wrappedKey, 'base64'), wrapAad(keyVersion, binding));
  return { wrappedKey: gcmSeal(config.keys[config.currentKeyVersion] as Uint8Array, dek, wrapAad(config.currentKeyVersion, binding)).toString('base64'), keyVersion: config.currentKeyVersion };
}

// ───────────────────────────── Content sniffing and structural checks ─────────────────────────────
const starts = (b: Uint8Array, sig: readonly number[], offset = 0): boolean => b.byteLength >= offset + sig.length && sig.every((v, i) => b[offset + i] === v);
const ascii = (b: Uint8Array, offset: number, length: number): string => Buffer.from(b.buffer, b.byteOffset + offset, Math.max(0, Math.min(length, b.byteLength - offset))).toString('latin1');
/** Returns a coarse content family from magic bytes, or null when unrecognised. */
export function sniff(b: Uint8Array): string | null {
  if (starts(b, [0x25, 0x50, 0x44, 0x46, 0x2d])) return 'pdf';
  if (starts(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'png';
  if (starts(b, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (ascii(b, 0, 6) === 'GIF87a' || ascii(b, 0, 6) === 'GIF89a') return 'gif';
  if (ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 4) === 'WEBP') return 'webp';
  if (ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 4) === 'WAVE') return 'wav';
  if (ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 4) === 'AVI ') return 'avi';
  if (starts(b, [0x50, 0x4b, 0x03, 0x04]) || starts(b, [0x50, 0x4b, 0x05, 0x06])) return 'zip';
  if (starts(b, [0x1f, 0x8b])) return 'gzip';
  if (ascii(b, 4, 4) === 'ftyp') return 'mp4';
  if (ascii(b, 0, 4) === 'OggS') return 'ogg';
  if (ascii(b, 0, 4) === 'fLaC') return 'flac';
  if (starts(b, [0x1a, 0x45, 0xdf, 0xa3])) return 'ebml';
  if (ascii(b, 0, 3) === 'ID3' || (b.byteLength > 1 && b[0] === 0xff && ((b[1] as number) & 0xe0) === 0xe0 && ((b[1] as number) & 0x06) !== 0)) return 'mp3';
  if (starts(b, [0x7f, 0x45, 0x4c, 0x46]) || starts(b, [0x4d, 0x5a]) || starts(b, [0xcf, 0xfa, 0xed, 0xfe]) || starts(b, [0xfe, 0xed, 0xfa, 0xcf]) || starts(b, [0xca, 0xfe, 0xba, 0xbe])) return 'executable';
  return null;
}
const DECLARED: Readonly<Record<string, readonly string[]>> = {
  'application/pdf': ['pdf'], 'image/png': ['png'], 'image/jpeg': ['jpeg'], 'image/gif': ['gif'], 'image/webp': ['webp'],
  'application/zip': ['zip'], 'application/gzip': ['gzip'], 'audio/wav': ['wav'], 'audio/x-wav': ['wav'], 'audio/wave': ['wav'],
  'audio/mpeg': ['mp3'], 'video/mp4': ['mp4'], 'audio/mp4': ['mp4'], 'video/quicktime': ['mp4'], 'audio/ogg': ['ogg'], 'video/ogg': ['ogg'],
  'audio/flac': ['flac'], 'video/webm': ['ebml'], 'audio/webm': ['ebml'], 'video/x-matroska': ['ebml'], 'video/x-msvideo': ['avi'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['zip'],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['zip'],
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['zip'],
  'application/vnd.oasis.opendocument.text': ['zip'], 'application/epub+zip': ['zip'],
};
export const baseMediaType = (mediaType: string): string => (mediaType.split(';')[0] ?? '').trim().toLowerCase();
export const isTextMedia = (mediaType: string): boolean => { const t = baseMediaType(mediaType); return t.startsWith('text/') || t === 'application/json' || t === 'application/xml'; };

export type StructuralLimits = Readonly<{ maxBytes: number; maxArchiveEntries: number; maxArchiveUncompressedBytes: number; maxArchiveRatio: number }>;
export const DEFAULT_LIMITS: StructuralLimits = { maxBytes: 256 * 1024 * 1024, maxArchiveEntries: 10_000, maxArchiveUncompressedBytes: 512 * 1024 * 1024, maxArchiveRatio: 200 };
export type StructuralFinding = Readonly<{ code: string; blocking: boolean; detail: string }>;
export type StructuralReport = Readonly<{ ok: boolean; sniffed: string | null; findings: readonly StructuralFinding[] }>;
const inflateRawAsync = promisify(inflateRaw), gunzipAsync = promisify(gunzip);
const tooLarge = (error: unknown): boolean => (error as NodeJS.ErrnoException).code === 'ERR_BUFFER_TOO_LARGE';

/** Content checks that do not need a malware engine: size, magic/media-type agreement, executables, archive bombs. */
export async function structuralCheck(bytes: Uint8Array, declared: { mediaType: string }, limits: StructuralLimits = DEFAULT_LIMITS): Promise<StructuralReport> {
  const findings: StructuralFinding[] = [];
  const kind = sniff(bytes); const type = baseMediaType(declared.mediaType);
  if (bytes.byteLength > limits.maxBytes) findings.push({ code: 'size_limit_exceeded', blocking: true, detail: `Content is ${bytes.byteLength} bytes; limit ${limits.maxBytes}` });
  if (bytes.byteLength === 0) findings.push({ code: 'empty_content', blocking: false, detail: 'Content has zero bytes' });
  const expected = DECLARED[type];
  if (expected !== undefined && (kind === null || !expected.includes(kind))) findings.push({ code: 'media_type_mismatch', blocking: true, detail: `Declared ${type} but content looks like ${kind ?? 'unrecognised data'}` });
  else if (kind === 'executable' && !['application/x-executable', 'application/x-msdownload', 'application/octet-stream', 'application/vnd.microsoft.portable-executable'].includes(type)) findings.push({ code: 'executable_content', blocking: true, detail: `Declared ${type} but content is an executable` });
  else if (isTextMedia(type) && (bytes.subarray(0, 1024 * 1024).includes(0) || (kind !== null && kind !== 'mp3'))) findings.push({ code: 'media_type_mismatch', blocking: true, detail: `Declared ${type} but content looks like ${kind ?? 'binary data'}` });
  else if (expected === undefined && kind !== null && !isTextMedia(type) && type !== 'application/octet-stream') findings.push({ code: 'media_type_unverified', blocking: false, detail: `Declared ${type}; content looks like ${kind}` });
  if (kind === 'zip') {
    try {
      const entries = listZip(bytes);
      if (entries.length > limits.maxArchiveEntries) findings.push({ code: 'archive_bomb', blocking: true, detail: `Archive has ${entries.length} entries; limit ${limits.maxArchiveEntries}` });
      else {
        let total = 0;
        for (const e of entries) {
          if (e.encrypted) { findings.push({ code: 'archive_entry_encrypted', blocking: false, detail: 'Archive contains an encrypted entry that cannot be inspected' }); continue; }
          const remaining = limits.maxArchiveUncompressedBytes - total;
          try { total += e.method === 0 ? e.data.byteLength : e.method === 8 ? (await inflateRawAsync(e.data, { maxOutputLength: Math.max(1, remaining + 1) })).byteLength : 0; }
          catch (error) { if (tooLarge(error)) { total = limits.maxArchiveUncompressedBytes + 1; } else { findings.push({ code: 'archive_malformed', blocking: false, detail: 'An archive entry could not be inflated' }); continue; } }
          if (total > limits.maxArchiveUncompressedBytes) break;
        }
        if (total > limits.maxArchiveUncompressedBytes) findings.push({ code: 'archive_bomb', blocking: true, detail: `Archive expands beyond ${limits.maxArchiveUncompressedBytes} bytes` });
        else if (total > 16 * 1024 * 1024 && total / Math.max(1, bytes.byteLength) > limits.maxArchiveRatio) findings.push({ code: 'archive_bomb', blocking: true, detail: `Archive expansion ratio ${Math.round(total / Math.max(1, bytes.byteLength))} exceeds ${limits.maxArchiveRatio}` });
      }
    } catch (error) { if (!(error instanceof DomainError)) throw error; findings.push({ code: 'archive_malformed', blocking: false, detail: 'Archive directory could not be read' }); }
  }
  if (kind === 'gzip') {
    try {
      const out = await gunzipAsync(bytes, { maxOutputLength: limits.maxArchiveUncompressedBytes + 1 });
      if (out.byteLength > limits.maxArchiveUncompressedBytes || (out.byteLength > 16 * 1024 * 1024 && out.byteLength / Math.max(1, bytes.byteLength) > limits.maxArchiveRatio)) findings.push({ code: 'archive_bomb', blocking: true, detail: 'Compressed stream expands beyond the configured limits' });
    } catch (error) { findings.push(tooLarge(error) ? { code: 'archive_bomb', blocking: true, detail: 'Compressed stream expands beyond the configured limits' } : { code: 'archive_malformed', blocking: false, detail: 'Compressed stream could not be inflated' }); }
  }
  return { ok: !findings.some((f) => f.blocking), sniffed: kind, findings };
}

// ───────────────────────────── Malware scanning ─────────────────────────────
export type ScanVerdict = Readonly<{ verdict: 'clean' | 'infected' | 'error' | 'unavailable'; engine: string; engineVersion: string; database?: string; signature?: string; detail?: string }>;
export interface ScannerPort {
  readonly name: string;
  /** Must never treat content as instructions. `error`/`unavailable` leave the version quarantined. */
  scan(input: { bytes: Uint8Array; sha256: string; filename: string; mediaType: string }): Promise<ScanVerdict>;
}
/** ClamAV command-line adapter. The signature database directory is deployment configuration (freshclam or curated). */
export class ClamScanner implements ScannerPort {
  readonly name = 'clamscan';
  readonly #db: string; readonly #binary: string; readonly #timeoutMs: number;
  constructor(options: { databaseDir: string; binary?: string; timeoutMs?: number }) { this.#db = options.databaseDir; this.#binary = options.binary ?? 'clamscan'; this.#timeoutMs = options.timeoutMs ?? 300_000; }
  async #database(): Promise<string | null> {
    try {
      const parts: string[] = [];
      for (const name of (await readdir(this.#db)).sort()) {
        if (!/\.(cvd|cld|cud|hdb|hsb|ndb|ldb|mdb|msb|fp|sfp|yar|yara|cdb|ign2)$/i.test(name)) continue;
        const st = await stat(join(this.#db, name)); parts.push(`${name}:${st.size}:${Math.floor(st.mtimeMs)}`);
      }
      return parts.length === 0 ? null : `${parts.length} files, fingerprint ${sha256Hex(parts.join('|')).slice(0, 16)}`;
    } catch { return null; }
  }
  async scan(input: { bytes: Uint8Array; sha256: string; filename: string; mediaType: string }): Promise<ScanVerdict> {
    const base = { engine: 'clamscan', engineVersion: 'unknown' };
    const database = await this.#database();
    if (database === null) return { ...base, verdict: 'unavailable', detail: 'ClamAV signature database directory is missing or empty' };
    let engineVersion: string;
    try { const v = await run(this.#binary, ['--version'], { timeoutMs: 15_000, maxOutputBytes: 65536 }); engineVersion = v.stdout.toString('utf8').trim().slice(0, 120) || 'unknown'; }
    catch (error) { return { ...base, verdict: 'unavailable', detail: error instanceof DomainError ? error.message : 'clamscan could not be started' }; }
    return withTempDir(async (dir) => {
      const file = join(dir, 'content.bin'); // fixed name: the untrusted filename never reaches the command line
      await writeFile(file, input.bytes, { mode: 0o600 });
      let r: RunResult;
      try { r = await run(this.#binary, ['--no-summary', '--stdout', `--database=${this.#db}`, file], { timeoutMs: this.#timeoutMs, maxOutputBytes: 1024 * 1024 }); }
      catch (error) { return { engine: 'clamscan', engineVersion, database, verdict: 'error' as const, detail: error instanceof DomainError ? error.message : 'clamscan failed' }; }
      if (r.code === 0) return { engine: 'clamscan', engineVersion, database, verdict: 'clean' as const };
      if (r.code === 1) { const m = /: (.+) FOUND\s*$/m.exec(r.stdout.toString('utf8')); return { engine: 'clamscan', engineVersion, database, verdict: 'infected' as const, signature: (m?.[1] ?? 'unknown').slice(0, 200) }; }
      return { engine: 'clamscan', engineVersion, database, verdict: 'error' as const, detail: `clamscan exited with status ${r.code}` };
    });
  }
}

// ───────────────────────────── ZIP (store/deflate, no zip64) ─────────────────────────────
export type ZipEntry = Readonly<{ name: string; method: number; encrypted: boolean; size: number; crc: number; data: Uint8Array }>;
const DOS_DATE = 0x0021, DOS_TIME = 0; // 1980-01-01: packages are byte-reproducible for identical content
export function writeZip(files: readonly { name: string; data: Uint8Array }[]): Uint8Array {
  const local: Buffer[] = []; const central: Buffer[] = []; let offset = 0;
  const seen = new Set<string>();
  for (const f of files) {
    invariant(/^[A-Za-z0-9._\/-]{1,240}$/.test(f.name) && !f.name.startsWith('/') && !f.name.split('/').includes('..') && !seen.has(f.name), 'invalid_input', 'Invalid archive entry name');
    seen.add(f.name);
    invariant(f.data.byteLength < 0xffffffff, 'payload_too_large', 'Archive entry too large');
    const name = Buffer.from(f.name, 'utf8'); const deflated = deflateRawSync(f.data);
    const method = deflated.byteLength < f.data.byteLength ? 8 : 0; const body = method === 8 ? deflated : Buffer.from(f.data);
    const crc = crc32(f.data) >>> 0;
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(method, 8); lh.writeUInt16LE(DOS_TIME, 10); lh.writeUInt16LE(DOS_DATE, 12);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(body.byteLength, 18); lh.writeUInt32LE(f.data.byteLength, 22); lh.writeUInt16LE(name.byteLength, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(method, 10); ch.writeUInt16LE(DOS_TIME, 12); ch.writeUInt16LE(DOS_DATE, 14);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(body.byteLength, 20); ch.writeUInt32LE(f.data.byteLength, 24); ch.writeUInt16LE(name.byteLength, 28); ch.writeUInt32LE(offset, 42);
    local.push(lh, name, body); central.push(ch, name); offset += 30 + name.byteLength + body.byteLength;
    invariant(offset < 0xffffffff, 'payload_too_large', 'Archive too large');
  }
  const cd = Buffer.concat(central); const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.byteLength, 12); end.writeUInt32LE(offset, 16);
  invariant(files.length < 0xffff, 'payload_too_large', 'Too many archive entries');
  return new Uint8Array(Buffer.concat([...local, cd, end]));
}
/** Parses the central directory. Entry data is the raw (possibly compressed) bytes; nothing is inflated here. */
export function listZip(bytes: Uint8Array): ZipEntry[] {
  const b = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const bad = (): never => { throw new DomainError('invalid_input', 'Malformed ZIP archive'); };
  let eocd = -1;
  for (let i = b.byteLength - 22; i >= Math.max(0, b.byteLength - 22 - 65535); i--) if (b.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) bad();
  const count = b.readUInt16LE(eocd + 10); let p = b.readUInt32LE(eocd + 16);
  if (count === 0xffff || p === 0xffffffff) bad(); // zip64 is not supported
  const out: ZipEntry[] = [];
  for (let i = 0; i < count; i++) {
    if (p + 46 > b.byteLength || b.readUInt32LE(p) !== 0x02014b50) bad();
    const flags = b.readUInt16LE(p + 8), method = b.readUInt16LE(p + 10), crc = b.readUInt32LE(p + 16), csize = b.readUInt32LE(p + 20), size = b.readUInt32LE(p + 24);
    const n = b.readUInt16LE(p + 28), x = b.readUInt16LE(p + 30), c = b.readUInt16LE(p + 32), lo = b.readUInt32LE(p + 42);
    if (p + 46 + n > b.byteLength || lo + 30 > b.byteLength || b.readUInt32LE(lo) !== 0x04034b50) bad();
    const name = b.subarray(p + 46, p + 46 + n).toString('utf8');
    const start = lo + 30 + b.readUInt16LE(lo + 26) + b.readUInt16LE(lo + 28);
    if (start + csize > b.byteLength) bad();
    out.push({ name, method, encrypted: (flags & 1) === 1, size, crc, data: b.subarray(start, start + csize) });
    p += 46 + n + x + c;
  }
  return out;
}
/** Reads a ZIP fully into memory with hard limits; verifies CRC-32 of every entry. */
export async function readZip(bytes: Uint8Array, limits: { maxEntries?: number; maxTotalBytes?: number } = {}): Promise<Map<string, Uint8Array>> {
  const entries = listZip(bytes); const max = limits.maxTotalBytes ?? 1024 * 1024 * 1024;
  invariant(entries.length <= (limits.maxEntries ?? 10_000), 'payload_too_large', 'Archive has too many entries');
  const out = new Map<string, Uint8Array>(); let total = 0;
  for (const e of entries) {
    invariant(!e.encrypted && (e.method === 0 || e.method === 8), 'invalid_input', 'Unsupported ZIP entry');
    invariant(!e.name.startsWith('/') && !e.name.split('/').includes('..') && !out.has(e.name), 'invalid_input', 'Unsafe ZIP entry name');
    let data: Uint8Array;
    try { data = e.method === 0 ? e.data : await inflateRawAsync(e.data, { maxOutputLength: Math.max(1, max - total + 1) }); }
    catch (error) { throw new DomainError(tooLarge(error) ? 'payload_too_large' : 'invalid_input', 'ZIP entry could not be inflated within limits'); }
    total += data.byteLength;
    invariant(total <= max, 'payload_too_large', 'Archive expands beyond the limit');
    invariant((crc32(data) >>> 0) === e.crc && data.byteLength === e.size, 'invalid_input', 'ZIP entry checksum mismatch');
    out.set(e.name, data);
  }
  return out;
}

// ───────────────────────────── Minimal image-only PDF writer ─────────────────────────────
/** `flate` is the zlib-compressed 8-bit RGB raster (width*height*3 bytes before compression). */
export type RasterPage = Readonly<{ widthPx: number; heightPx: number; flate: Uint8Array; dpi: number }>;
export const flateRgb = (rgb: Uint8Array): Uint8Array => deflateSync(rgb);
/** Writes a PDF whose pages are opaque RGB images. It contains no text layer, annotations or document metadata. */
export function writeImagePdf(pages: readonly RasterPage[]): Uint8Array {
  invariant(pages.length > 0, 'invalid_input', 'At least one page required');
  const objects: Buffer[] = []; // object n is objects[n-1]
  const kids = pages.map((_, i) => `${3 + i * 3} 0 R`).join(' ');
  objects.push(Buffer.from('<< /Type /Catalog /Pages 2 0 R >>'));
  objects.push(Buffer.from(`<< /Type /Pages /Count ${pages.length} /Kids [${kids}] >>`));
  pages.forEach((page, i) => {
    const w = (page.widthPx * 72 / page.dpi).toFixed(2), h = (page.heightPx * 72 / page.dpi).toFixed(2);
    const base = 3 + i * 3;
    const content = Buffer.from(`q ${w} 0 0 ${h} 0 0 cm /Im0 Do Q`);
    const image = Buffer.from(page.flate.buffer, page.flate.byteOffset, page.flate.byteLength);
    objects.push(Buffer.from(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${w} ${h}] /Resources << /XObject << /Im0 ${base + 2} 0 R >> >> /Contents ${base + 1} 0 R >>`));
    objects.push(Buffer.concat([Buffer.from(`<< /Length ${content.byteLength} >>\nstream\n`), content, Buffer.from('\nendstream')]));
    objects.push(Buffer.concat([Buffer.from(`<< /Type /XObject /Subtype /Image /Width ${page.widthPx} /Height ${page.heightPx} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length ${image.byteLength} >>\nstream\n`), image, Buffer.from('\nendstream')]));
  });
  const parts: Buffer[] = [Buffer.from('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n', 'latin1')]; const offsets: number[] = []; let position = (parts[0] as Buffer).byteLength;
  objects.forEach((body, i) => { const chunk = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`), body, Buffer.from('\nendobj\n')]); offsets.push(position); position += chunk.byteLength; parts.push(chunk); });
  const xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${position}\n%%EOF\n`;
  parts.push(Buffer.from(xref));
  return new Uint8Array(Buffer.concat(parts));
}

// ───────────────────────────── Viewer and redaction helpers ─────────────────────────────
/** Fractions of the page or image (0..1), origin top-left. */
export type Box = Readonly<{ x: number; y: number; w: number; h: number }>;
export function validBox(box: unknown): Box {
  const b = box as Box;
  invariant(b !== null && typeof b === 'object' && [b.x, b.y, b.w, b.h].every((v) => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1) && b.w > 0 && b.h > 0 && b.x + b.w <= 1.000001 && b.y + b.h <= 1.000001, 'invalid_input', 'Box must use fractions between 0 and 1 within the page');
  return { x: b.x, y: b.y, w: b.w, h: b.h };
}
const pixelRect = (box: Box, width: number, height: number): { x0: number; y0: number; x1: number; y1: number } => ({
  x0: Math.max(0, Math.floor(box.x * width)), y0: Math.max(0, Math.floor(box.y * height)),
  x1: Math.min(width - 1, Math.ceil((box.x + box.w) * width)), y1: Math.min(height - 1, Math.ceil((box.y + box.h) * height)),
});
export async function pdfPageCount(file: string): Promise<number> {
  const out = (await must('pdfinfo', [file], { timeoutMs: 30_000, maxOutputBytes: 1024 * 1024 })).toString('utf8');
  const n = Number(/^Pages:\s+(\d+)/m.exec(out)?.[1]);
  invariant(Number.isSafeInteger(n) && n > 0, 'invalid_input', 'PDF page count could not be determined');
  return n;
}
export async function imageSize(file: string): Promise<{ width: number; height: number }> {
  const out = (await must('identify', ['-format', '%w %h\n', `${file}[0]`], { timeoutMs: 30_000, maxOutputBytes: 65536 })).toString('utf8').trim().split(/\s+/);
  const width = Number(out[0]), height = Number(out[1]);
  invariant(Number.isSafeInteger(width) && Number.isSafeInteger(height) && width > 0 && height > 0 && width * height <= 100_000_000, 'invalid_input', 'Image dimensions are not supported');
  return { width, height };
}
export type PdfWord = Readonly<{ text: string } & Box>;
const unescapeXml = (s: string): string => s.replace(/&(lt|gt|quot|apos|amp|#(\d+)|#x([0-9a-fA-F]+));/g, (_m, name: string, dec?: string, hex?: string) => dec !== undefined ? String.fromCodePoint(Number(dec)) : hex !== undefined ? String.fromCodePoint(parseInt(hex, 16)) : ({ lt: '<', gt: '>', quot: '"', apos: "'", amp: '&' } as Record<string, string>)[name] ?? '');
export async function pdfPageWords(file: string, page: number): Promise<{ widthPt: number; heightPt: number; words: PdfWord[] }> {
  const xml = (await must('pdftotext', ['-bbox', '-f', String(page), '-l', String(page), file, '-'], { timeoutMs: 60_000 })).toString('utf8');
  const pg = /<page width="([\d.]+)" height="([\d.]+)"/.exec(xml);
  const widthPt = Number(pg?.[1] ?? 0), heightPt = Number(pg?.[2] ?? 0);
  const words: PdfWord[] = [];
  if (widthPt > 0 && heightPt > 0) for (const m of xml.matchAll(/<word xMin="([\d.-]+)" yMin="([\d.-]+)" xMax="([\d.-]+)" yMax="([\d.-]+)">([^<]*)<\/word>/g)) {
    const [x0, y0, x1, y1] = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
    words.push({ text: unescapeXml(m[5] as string), x: x0 / widthPt, y: y0 / heightPt, w: (x1 - x0) / widthPt, h: (y1 - y0) / heightPt });
  }
  return { widthPt, heightPt, words };
}
export async function renderPdfPage(dir: string, file: string, page: number, dpi: number): Promise<string> {
  const prefix = join(dir, `page-${page}-${randomBytes(4).toString('hex')}`);
  await must('pdftoppm', ['-png', '-r', String(dpi), '-f', String(page), '-l', String(page), '-singlefile', file, prefix], { timeoutMs: 120_000 });
  return `${prefix}.png`;
}
export async function mediaDurationMs(file: string): Promise<number | null> {
  const r = await run('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'json', file], { timeoutMs: 60_000, maxOutputBytes: 1024 * 1024 });
  if (r.code !== 0) return null;
  try { const d = Number((JSON.parse(r.stdout.toString('utf8')) as { format?: { duration?: string } }).format?.duration); return Number.isFinite(d) && d >= 0 ? Math.round(d * 1000) : null; } catch { return null; }
}
/** Paints opaque black rectangles into the pixel data and returns raw RGB. The covered pixels no longer exist in the output. */
async function rasterWithBoxes(dir: string, image: string, boxes: readonly Box[]): Promise<{ width: number; height: number; rgb: Buffer }> {
  const { width, height } = await imageSize(image);
  const draw: string[] = [];
  for (const box of boxes) { const r = pixelRect(box, width, height); draw.push('-draw', `rectangle ${r.x0},${r.y0} ${r.x1},${r.y1}`); }
  const raw = join(dir, `raw-${randomBytes(4).toString('hex')}.rgb`);
  await must('convert', [`${image}[0]`, '-auto-orient', '-background', 'white', '-alpha', 'remove', '-alpha', 'off', '-fill', 'black', '-stroke', 'none', ...draw, '-depth', '8', `rgb:${raw}`], { timeoutMs: 120_000 });
  const rgb = await readFile(raw); await rm(raw, { force: true });
  // -auto-orient may swap dimensions; trust the pixel count
  const swapped = rgb.byteLength === width * height * 3 ? { width, height } : { width: height, height: width };
  invariant(rgb.byteLength === swapped.width * swapped.height * 3, 'invalid_input', 'Raster output has an unexpected size');
  return { ...swapped, rgb };
}
export type PageRegion = Readonly<{ page: number } & Box>;
/** Rasterises every page, removes the listed regions' pixels and rebuilds an image-only PDF (no text layer or metadata). */
export async function redactPdf(bytes: Uint8Array, regions: readonly PageRegion[], options: { dpi: number; maxPages: number }): Promise<{ bytes: Uint8Array; pageCount: number }> {
  return withTempDir(async (dir) => {
    const file = join(dir, 'source.pdf'); await writeFile(file, bytes, { mode: 0o600 });
    const pageCount = await pdfPageCount(file);
    invariant(pageCount <= options.maxPages, 'payload_too_large', `PDF has ${pageCount} pages; redaction limit is ${options.maxPages}`);
    for (const r of regions) invariant(Number.isSafeInteger(r.page) && r.page >= 1 && r.page <= pageCount, 'invalid_input', 'Redaction region names a page that does not exist');
    const pages: RasterPage[] = [];
    for (let page = 1; page <= pageCount; page++) {
      const png = await renderPdfPage(dir, file, page, options.dpi);
      const raster = await rasterWithBoxes(dir, png, regions.filter((r) => r.page === page));
      await rm(png, { force: true });
      pages.push({ widthPx: raster.width, heightPx: raster.height, flate: flateRgb(raster.rgb), dpi: options.dpi });
    }
    return { bytes: writeImagePdf(pages), pageCount };
  });
}
/** Re-encodes an image as PNG with the regions' pixels replaced, then strips all metadata with exiftool. */
export async function redactImage(bytes: Uint8Array, boxes: readonly Box[]): Promise<{ bytes: Uint8Array; width: number; height: number }> {
  return withTempDir(async (dir) => {
    const file = join(dir, 'source.img'); await writeFile(file, bytes, { mode: 0o600 });
    const raster = await rasterWithBoxes(dir, file, boxes);
    const raw = join(dir, 'clean.rgb'), out = join(dir, 'redacted.png');
    await writeFile(raw, raster.rgb, { mode: 0o600 });
    await must('convert', ['-size', `${raster.width}x${raster.height}`, '-depth', '8', `rgb:${raw}`, '-strip', `png:${out}`], { timeoutMs: 120_000 });
    await must('exiftool', ['-all=', '-overwrite_original', '-q', out], { timeoutMs: 60_000 });
    return { bytes: new Uint8Array(await readFile(out)), width: raster.width, height: raster.height };
  });
}
export type TextRange = Readonly<{ start: number; end: number }>;
/** Replaces the ranges (UTF-16 code unit offsets) with block characters of the same length so later offsets stay valid. */
export function redactText(text: string, ranges: readonly TextRange[]): string {
  let out = text;
  for (const r of ranges) {
    invariant(Number.isSafeInteger(r.start) && Number.isSafeInteger(r.end) && r.start >= 0 && r.end > r.start && r.end <= text.length, 'invalid_input', 'Text redaction range is outside the content');
    out = out.slice(0, r.start) + '█'.repeat(r.end - r.start) + out.slice(r.end);
  }
  return out;
}
export function decodeText(bytes: Uint8Array): string {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw new DomainError('invalid_input', 'Content is not valid UTF-8 text'); }
}
export function boxToPixels(box: Box, width: number, height: number): { x: number; y: number; w: number; h: number } {
  const r = pixelRect(box, width, height); return { x: r.x0, y: r.y0, w: r.x1 - r.x0 + 1, h: r.y1 - r.y0 + 1 };
}
