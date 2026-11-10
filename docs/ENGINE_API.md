# E05 Evidence storage and provenance — engine API

Service layer under the engine service convention v1. Schema `e05_evidence`, capability prefix `evidence`,
kit `src/service-kit.ts` version 1.0.1, sha256 `95475a907267ba1fdd54b557aabe5645c37add9788a5b2d0854d9accfd5d8ea5`
(byte-identical copy of the Identity engine's file; `src/contracts.ts` is byte-identical to the Identity version too).

**What a digest means here.** A SHA-256 digest establishes that bytes are identical to the preserved version. It does not
establish authenticity or truth. Every statement surface carries `digestMeaning` and `authenticity: 'not_assessed'`
unless another engine's assessment was recorded with `recordAssessment` (then
`{status:'assessed_elsewhere', assessmentRef, claimedOutcome, …}` — this engine never assesses authenticity itself).

## Entry points

```ts
import { manifest, SCHEMA, migrations, migrate, createEngine, routes, verifyPackage, ClamScanner } from '@accountability/evidence/engine';
import { start } from '@accountability/evidence/serve';

createEngine({
  sql,                       // kit Sql (pgSql(pool))
  objects,                   // kit ObjectStore (FsObjectStore, S3ObjectStore, …) — required
  ports?: { scanner?: ScannerPort; useDecisions?: UseDecisionPort; authorization?: AuthorizationPort },
  config?: {
    encryption?: { currentKeyVersion: string; keys: Record<string, Uint8Array /* 32 bytes */> },
    scanPolicy?: 'structural_only',        // only meaningful without a scanner; see Quarantine
    scanInline?: boolean,                  // run the scan job in-process right after accept/addDerivative/addVersion
    limits?: { maxBytes?, maxArchiveEntries?, maxArchiveUncompressedBytes?, maxArchiveRatio? },
    reproductionWithoutPort?: 'allow',     // standalone mode; default DENIES reproduce/export of bytes without a UseDecisionPort
    redaction?: { dpi?: number; maxPages?: number },
    workerId?: string,
  },
}): EvidenceEngine   // implements StandardEngine and the kit EvidencePort
```

`npm run serve` (`node src/engine/serve.ts`) environment:

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | PostgreSQL (required). Migrations run at start. |
| `PORT`, `HOST` | Listen address (default `8080`, `127.0.0.1`). |
| `IDENTITY_PUBLIC_KEYS` or `IDENTITY_JWKS_FILE` | JSON map `kid → PEM` of Identity token keys (required). `IDENTITY_ISSUER` optional. |
| `OBJECT_STORE` (`fs`\|`s3`), `OBJECT_STORE_PATH`, `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_PREFIX` | Kit object store. |
| `EVIDENCE_MASTER_KEY` | 32-byte wrapping key, base64 or hex (required unless `EVIDENCE_ALLOW_PLAINTEXT=1`). |
| `EVIDENCE_MASTER_KEY_VERSION` | Label of that key (default `v1`); recorded on every version. |
| `EVIDENCE_PREVIOUS_KEYS` | JSON `{version: key}` of older wrapping keys still needed to unwrap. |
| `CLAMAV_DATABASE_DIR`, `CLAMSCAN_BINARY` | Enables the `clamscan` scanner with that signature directory. |
| `EVIDENCE_SCAN_POLICY=structural_only` | Release on structural checks when no scanner is configured. |
| `EVIDENCE_REPRODUCTION_WITHOUT_PORT=allow` | Standalone: allow reproduce/export without a use-decision port. |
| `EVIDENCE_MAX_BYTES`, `EVIDENCE_WORKER=off`, `EVIDENCE_WORKER_IDLE_MS`, `DATABASE_POOL_MAX` | Limits and worker loop. |

The standalone server wires no `UseDecisionPort`/`AuthorizationPort`; a host (PAM) passes them to `createEngine`.

## References

`E05:evidence:<uuid>` (item; resolves to its current version), `E05:evidence_version:<uuid>@<rev>` (immutable version;
without `@rev` = current), `E05:citation:<uuid>`. Unknown, foreign-tenant, foreign-project and compartment-hidden objects
are all `not_found` / `null`.

## Service methods (`ctx: ServiceContext` first; capability in brackets)

```ts
// kit EvidencePort
describe(ctx, ref): Promise<EvidenceVersionInfo | null>                                             // [evidence:read]
getBytes(ctx, ref, options?: { use?: UseAction; reason?: string }): Promise<Uint8Array>             // [evidence:read]
accept(ctx, { bytes, mediaType, filename, origin, compartment?, idempotencyKey? }): Promise<EvidenceVersionInfo>          // [evidence:write]
addDerivative(ctx, { parent, bytes, mediaType, filename, relation, tool, idempotencyKey? }): Promise<EvidenceVersionInfo> // [evidence:write]
// wider service
describeVersion(ctx, ref): Promise<VersionDetail | null>                                            // [evidence:read]
list(ctx, { limit?, before? }?): Promise<VersionDetail[]>                                           // [evidence:read] current versions
versions(ctx, ref): Promise<VersionDetail[]>                                                        // [evidence:read]
addVersion(ctx, { evidence, bytes, mediaType, filename, origin, cause?: 'refresh'|'correction', idempotencyKey? }): Promise<EvidenceVersionInfo> // [evidence:write]
rescan(ctx, ref): Promise<{ jobId }>                                                                // [evidence:write]
recordHandling(ctx, ref, { action: 'referenced'|'copied'|'transferred'|'viewed'|'note', reason, destination?, idempotencyKey? }): Promise<CustodyEntry> // [evidence:write]
custody(ctx, ref): Promise<{ entries: CustodyEntry[]; chainValid: boolean }>                        // [evidence:read]
provenance(ctx, ref): Promise<Provenance>                                                           // [evidence:read]
createCitation(ctx, { version, selector, note?, idempotencyKey? }): Promise<Citation>               // [evidence:cite]
resolveCitation(ctx, citationRefOrId): Promise<CitationResolution>                                  // [evidence:read]
renderView(ctx, ref, { page?, timeMs?, range?: {start, end?}, dpi?, citation?, selector? }?): Promise<ViewData> // [evidence:read]
redact(ctx, ref, { regions?, textRanges?, reason, compartment?, dpi?, idempotencyKey? }): Promise<{ derivative: EvidenceVersionInfo; manifest: Json }> // [evidence:redact]
setRetention(ctx, ref, { action: 'hold'|'release_hold'|'schedule'|'clear_schedule', reason, disposeAfter?, authorization, idempotencyKey? }): Promise<VersionDetail> // [evidence:retain]
dueForDisposal(ctx, { at? }?): Promise<VersionDetail[]>                                             // [evidence:retain]
dispose(ctx, ref, { reason, authorization, idempotencyKey? }): Promise<VersionDetail[]>             // [evidence:admin] + AuthorizationPort
verifyIntegrity(ctx, ref): Promise<IntegrityResult>                                                 // [evidence:verify]
verifyAll(ctx): Promise<IntegrityReport>                                                            // [evidence:verify]
startIntegrityBatch(ctx, { idempotencyKey? }?): Promise<{ jobId }>                                  // [evidence:verify]; report = job result
restoreBytes(ctx, ref, bytes, { reason }): Promise<VersionDetail>                                   // [evidence:admin]
recordAssessment(ctx, ref, { assessmentRef, claimedOutcome }): Promise<VersionDetail>               // [evidence:assess]
liftRestriction(ctx, ref, { reason, authorization }): Promise<VersionDetail>                        // [evidence:admin] + AuthorizationPort
exportPackage(ctx, refs, { includeOriginals?, redactedOnly?, reason? }?): Promise<{ bytes; sha256; filename; manifest }> // [evidence:export] + AuthorizationPort
verifyPackage(bytes): Promise<PackageVerification>                                                  // pure; also exported as a function
rotateKeys(ctx, { limit? }?): Promise<{ rewrapped; remaining; unavailable; currentKeyVersion }>     // [evidence:admin]
job(ctx, id) / jobs(ctx, { kind?, limit? }?)                                                        // [evidence:read]
controlJob(ctx, id, 'cancel'|'pause'|'resume'|'retry')                                              // [evidence:admin]
runJobsOnce({ worker?, limit?, leaseMs? }?): Promise<number>                                        // worker pass (no ctx; jobs carry theirs)
// StandardEngine
inspect [evidence:read] · search [evidence:read] · audit [evidence:audit] · events [evidence:events, tenant-wide feed]
applyUpstreamChange [evidence:upstream] · health()
```

`authorization` = `{ authorizedBy, basis, reference? }` and is stored verbatim with the decision.
`evidence:export`, `evidence:admin` and `evidence:events` are sensitive actions: `evidence:*` never grants them.

### Behaviour

- **Versions are immutable.** `accept` creates an item at revision 1. `addVersion` with different bytes creates revision
  N+1 (`evidence.version_added`, payload `cause: 'source_corrected'` for `correction`, else `'source_superseded'`) and
  clears a stale flag; identical bytes create no version (`refresh_unchanged` custody entry). Nothing is overwritten:
  each version has its own object.
- **Duplicates.** A second `accept` of identical bytes in the same tenant, project and compartment returns the existing
  version, adds a second acquisition record and a `duplicate_acquisition` custody entry (serialised with an advisory
  lock, so concurrent accepts converge on one version). It also restores bytes if that version was missing or corrupt.
  Dedupe never crosses compartments, projects or tenants.
- **Acquisition records.** `origin` is free JSON; recognised `kind`s: `intake_attachment`, `intake_submission`,
  `discovery_receipt`, `correspondence_message`, `manual_import`, `refresh`. `ref` (uref), `originalOwner` and
  `handlingHistory[]` handed over by intake are stored on the record. Missing information is recorded as explicit gaps
  (`origin_unknown`, `intake_reference_missing`, `original_owner_unknown`, `prior_handling_history_missing`,
  `discovery_receipt_missing`, `correspondence_reference_missing`, `collector_unknown`, `acquisition_time_unknown`,
  `source_unknown`). Every uref found in `origin` becomes a `source` used by `applyUpstreamChange`.
- **Quarantine.** Every new version starts `quarantined` and a kit job `evidence.scan` runs: (1) re-read and verify the
  stored bytes, (2) structural checks — size limit, magic bytes vs declared media type, executables, ZIP and gzip bombs
  (entries are actually inflated under a budget; nested archives are not recursed), (3) `ScannerPort`. Outcomes:
  `released` (`evidence.released`) or `blocked` (`evidence.blocked`). Scanner `error`/`unavailable` keeps the version
  quarantined and the job retries with backoff. **No scanner:** the version stays quarantined
  (`scan.status: 'awaiting_scanner'`) unless `scanPolicy: 'structural_only'`, in which case the record says
  `policy: 'structural_only', malwareScan: 'not_performed'`. `getBytes`, viewing, citing and redacting require
  `released`. `rescan` re-queues a quarantined version.
- **`ClamScanner`** (`{ databaseDir, binary?, timeoutMs? }`): spawns `clamscan --no-summary --stdout --database=<dir>`
  on a private temporary copy; exit 0 clean, 1 infected (signature recorded), otherwise error; a missing or empty
  database directory is `unavailable`.
- **Custody.** Accesses, views, citations, derivations, exports, retention and integrity transitions append to a
  per-evidence hash chain (`custody`, verified by `verifyCustodyChain`) and to the kit tenant audit chain, in the same
  transaction as the state change. Entries carry actor, purpose, request id, time and detail.
- **Retrieval.** `getBytes` re-reads the object, decrypts and compares SHA-256 before returning. Uses `reproduce`,
  `adapt`, `publish`, `license` (from `options.use`, or `ctx.purpose` when it is one of those words) ask the
  `UseDecisionPort`; anything but `allow` is `consent_denied`; an absent port denies unless
  `reproductionWithoutPort: 'allow'`. Research reads and citation never ask it.
- **Citations** pin an exact version and its sha256. Selectors: `{kind:'whole'}`, `{kind:'page', page, box?}` (box =
  fractions 0..1 of the page, origin top-left), `{kind:'text', start, end, quote?}` (UTF-16 code-unit offsets of the
  UTF-8 text), `{kind:'time', startMs, endMs}`. Text offsets/quote, PDF page numbers and media time ranges are checked
  against the preserved bytes at creation (`validation`). `resolveCitation` re-verifies the bytes and returns
  `state: 'resolved'` with the exact version (plus `isCurrentVersion`, `currentRef`), or `state: 'gap'` with a `gap`
  (`bytes_missing`, `bytes_corrupt`, `bytes_disposed`, `version_blocked`) and the retained digest.
- **Viewer.** PDF → `pdf_page` (PNG from `pdftoppm`, word boxes from `pdftotext -bbox`, page count from `pdfinfo`);
  PNG/JPEG/GIF/WebP → `image` with pixel size; `audio/*`, `video/*` → `media` with `durationMs` (ffprobe), the
  requested byte range (default first 4 MiB) and `seekMs`; text → `text`. `highlights` gives the citation's region as
  fractions and pixels, text offsets or a time range.
- **Redaction.** PDF: every page is rasterised, region pixels are painted into the raster and a new image-only PDF is
  written (no text layer, annotations or metadata). Images: decoded to raw pixels, regions painted, re-encoded as PNG,
  `exiftool -all=`. Text: ranges replaced by `█` per code unit. The result is a new derivative (relation `redacted`)
  whose `tool` is the redaction manifest; `evidence.redaction_created` is emitted; the original is unchanged.
  `compartment` places the derivative in another compartment; a caller holding only that compartment sees the
  derivative, and its source is reported as hidden (`source_not_visible`) without id or digest.
- **Retention.** `hold` blocks disposal. `schedule` records a date; disposal is never automatic — `dueForDisposal`
  lists candidates and `dispose` executes with a recorded authorization. Disposal deletes the object and the wrapped
  data key, keeps the row as a tombstone with its digest, and the gap `bytes_disposed` stays visible everywhere.
- **Integrity.** `verifyIntegrity` and `verifyAll` read the actual object bytes from the `ObjectStore`. Results:
  `matched`, `mismatch`, `missing`, `disposed`, `disposed_bytes_present`, `key_unavailable`. A transition to
  missing/corrupt sets `bytesState`, appends custody and emits `evidence.integrity_failed`; a later match (object put
  back, or `restoreBytes` with bytes matching the retained digest) restores it. `verifyAll` also lists unreferenced
  objects under the tenant/project prefix and reports hidden-compartment results only as counts.
- **Encryption at rest.** Each object is AES-256-GCM encrypted under its own data key; the data key is wrapped by the
  master key and stored with `key_version` in PostgreSQL. Additional data binds tenant, project and plaintext digest.
  This is the construction of the foundation `PrivateObjectStore`, re-implemented over the kit `ObjectStore` interface
  with a wrapped per-object key so rotation does not rewrite objects (`PrivateObjectStore` itself writes to a
  directory and is kept unchanged for the legacy service). `rotateKeys` re-wraps keys for the caller's tenant/project.
- **Packages.** ZIP (own store/deflate writer, no zip64) with `manifest.json`, `README.txt` and optional
  `objects/<sha256>/<filename>`. `includeOriginals` adds the requested versions' bytes; `redactedOnly` accepts only
  redacted derivatives, includes their bytes and withholds the source's reference and digest. Including bytes asks the
  `UseDecisionPort` (`reproduce`). Restricted evidence cannot be exported. Missing bytes are listed as gaps.
  `verifyPackage` re-checks file digests, custody chains and unlisted files. Packages are not signed; the package
  digest is recorded in the custody log.
- **`applyUpstreamChange`** (idempotent by `eventId`): matches refs against evidence items, versions and acquisition
  sources, then follows derivation edges. `permission_withdrawn` → `restricted` (blocks reproduce and export; reads,
  integrity checks and preservation continue; new derivatives inherit it) and `evidence.restricted`; every other kind →
  `stale` with reason and `evidence.stale`. Returns `E05:evidence_version:<id>` (no revision: all versions).
  Nothing is deleted or rewritten.

## Events (subject)

`evidence.accepted`, `evidence.version_added`, `evidence.derivative_added`, `evidence.released`, `evidence.blocked`,
`evidence.integrity_failed`, `evidence.integrity_restored`, `evidence.redaction_created` (all: `E05:evidence_version:<id>@<rev>`);
`evidence.retention_changed` (version uref; unrevisioned for hold/schedule), `evidence.restricted`,
`evidence.restriction_lifted`, `evidence.stale` (`E05:evidence_version:<id>`). The design catalog's names
`evidence.versioned`, `evidence.integrity.failed`, `evidence.retention.changed` correspond to `evidence.version_added`,
`evidence.integrity_failed`, `evidence.retention_changed`.

## HTTP routes

Standard: `GET /healthz`, `/v1/manifest`, `/v1/inspect?ref=`, `/v1/search?q=`, `/v1/audit`, `/v1/events`, `POST /v1/upstream-changes`.

| Route | Method |
|---|---|
| `POST /v1/evidence/accept` | `accept`; JSON `{contentBase64, mediaType, filename, origin, compartment?, idempotencyKey?}` |
| `POST /v1/evidence/derivatives` | `addDerivative` (`parent`, `contentBase64`, `relation`, `tool`, …) |
| `GET /v1/evidence` · `GET /v1/evidence/describe?ref=` | `list` · `describeVersion` |
| `GET /v1/evidence/content?ref=&use=` | `getBytes`; honours `Range: bytes=a-b` (206); sandboxed content headers |
| `GET|POST /v1/evidence/:id/versions` | `versions` · `addVersion` |
| `POST /v1/evidence/:id/verify` | `verifyIntegrity` (body `{revision?}`) |
| `GET /v1/provenance/:id` | `provenance` |
| `GET /v1/evidence/custody?ref=` · `POST /v1/evidence/handling` · `POST /v1/evidence/rescan` | `custody` · `recordHandling` · `rescan` |
| `POST /v1/citations` · `GET /v1/citations/:id` | `createCitation` · `resolveCitation` |
| `POST /v1/evidence/view` | `renderView` (binary fields as `imageBase64` / `bytesBase64`) |
| `POST /v1/evidence/redactions` | `redact` |
| `POST /v1/evidence/retention` · `GET /v1/evidence/retention/due` · `POST /v1/evidence/disposals` | retention |
| `POST /v1/evidence/restore` · `/v1/evidence/assessments` · `/v1/evidence/restrictions/lift` | `restoreBytes` · `recordAssessment` · `liftRestriction` |
| `POST /v1/integrity/verify-all` · `POST /v1/integrity/batches` | `verifyAll` · `startIntegrityBatch` |
| `POST /v1/packages` (ZIP response, `x-package-sha256`) · `POST /v1/packages/verify` (raw ZIP body) | packages |
| `POST /v1/keys/rotate` · `GET /v1/jobs` · `GET /v1/jobs/:id` · `POST /v1/jobs/:id/:action` | keys, jobs |

`:id` is the evidence uuid (or a full uref). Uploads are base64 in JSON and held in memory.

## Backup and restore

1. `pg_dump --no-owner --schema=e05_evidence "$DATABASE_URL" > evidence.sql` (wrapped data keys are in this dump).
2. Copy the object tree/bucket (`OBJECT_STORE_PATH` or the S3 prefix) as-is. Keep the master key(s) separately.
3. Restore: `psql -v ON_ERROR_STOP=1 -f evidence.sql "$NEW_DATABASE_URL"`, place the objects, start the engine with the
   same `EVIDENCE_MASTER_KEY`/`EVIDENCE_PREVIOUS_KEYS`.
4. Run `verifyAll` (`POST /v1/integrity/verify-all`) per tenant/project: `ok: true` means every restored object
   decrypts and matches its retained digest; `mismatch`, `missing` and `orphanObjects` name what does not.

An object written after the dump shows as an orphan; a version recorded after the object copy shows as `missing`.

## Tool dependencies

`clamscan` (scanner, optional), `pdftoppm`, `pdftotext`, `pdfinfo` (PDF view, citation checks, redaction),
ImageMagick `convert`/`identify` (image size, rasters), `exiftool` (metadata stripping), `ffprobe` (media duration).
A missing tool yields `unavailable` for the operation that needs it; `health()` lists tool versions.
Content is written to a private temporary directory (mode 0700) for these tools and removed afterwards; untrusted
filenames never reach a command line.

## Status

Implemented and tested locally on real PostgreSQL 16, the kit `FsObjectStore`, real `clamscan` (ClamAV 1.5.4 with a
locally authored `.ndb` signature for a harmless marker string), poppler, ImageMagick, exiftool, ffmpeg/ffprobe,
`pg_dump`/`psql` and `unzip`: everything listed above (`tests/engine.test.ts`, `tests/engine-media.test.ts`).

Not implemented / not verified:

- `S3ObjectStore`: not verified (no S3-compatible server was run). The engine only uses the `ObjectStore` interface.
  Provider-side retention/object-lock semantics are not used or tested; versions get distinct keys instead.
- ClamAV with the official signature databases: not verified (database host unreachable in development).
- Whole objects are buffered in memory (default limit 256 MiB); no streaming upload, no HTTP multipart, no zip64.
- Redaction: PDF, PNG/JPEG/GIF/WebP (first frame only) and text. Audio/video redaction, office formats and
  redaction of selected PDF pages while keeping others as vector text are not implemented (all pages are rasterised).
- Viewer: no thumbnails/waveforms/transcoding; video is served as byte ranges of the original container.
- Scheduled disposal is not executed automatically. Authorization records for disposal are stored, not verified
  against another engine (the `AuthorizationPort` is consulted when supplied).
- Packages are unsigned. `events()` is a tenant-wide feed for the orchestrator (all projects of the tenant).
- Audit records for compartment-hidden evidence are filtered from `audit()`; custody entries of a derivative name its
  source by opaque reference inside hash-covered detail (the source's digest and content are never included).
- Key rotation re-wraps per tenant/project per call; there is no deployment-wide rotation command.
- Structural checks do not recurse into nested archives and do not parse tar/7z/rar.
- The legacy foundation API (`./service`, `./database`, `./objects`, selector review) is unchanged and not connected to
  the service layer; its selector types are not reused because they are bound to the foundation state model.
- No independent security review. Not deployed; CI on GitHub for this branch was not observed.
