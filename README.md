# Evidence Storage and Provenance Engine

Standalone Node 24 TypeScript dependency library for exact-byte acquisition, immutable revisions, quarantine/scans, revision-bound selectors, source-family analysis, handling chains, redaction derivatives and encrypted local objects. Synthetic fixtures only.

```sh
npm ci
npm run check
```

Import evidence functions from `@accountability/evidence`, local encrypted storage from `@accountability/evidence/objects`, and shared types from `@accountability/evidence/contracts`. `npm run build` produces ESM and declarations in `dist/`.

## Foundation checkpoint (PR #1)

- Implementation: recovered foundation with two storage fixes (snapshot caller bytes before async work; reject symlinked tenant directories on read).
- Local validation: Node 24.22.1; strict typecheck, 21 automated tests, ESM/declaration build, registry validation and byte-identical contract comparison (including the pinned remote Identity commit) passed.
- CI validation: push and PR checks passed for implementation commit `200012f6aaadb0973504388bb79ab30a89fbb2b8`, including clean `npm ci` and `npm run check` ([run](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/actions/runs/40382672960)). Later documentation-only heads have separate runs on GitHub.
- Live acceptance: not performed. No deployed service, real scanner or identity integration is claimed.

Ready for review, one bounded foundation PR: [#1](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/pull/1). The initial recovered code was pushed before packaging/tests in [28276f0](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/commit/28276f04feddcf3579759a63c3df8ff526c759d4). The canonical machine-readable plan is [registry/prs.json](registry/prs.json); it describes only this authorized foundation unit.

## Provenance

`src/contracts.ts` is vendored byte-identically from `engines/identity/src/contracts.ts`, `neophilism/Identity-Authorization-and-Policy-Engine` commit `2ecac5a7ec01e4470774ef545060b99dba38014d`. Recovery sources were `accountability-machine/packages/evidence/src/index.ts` and `accountability-machine/packages/runtime/src/objects.ts`; their relative contract imports were rewritten. Original recovery files were not modified. The registry parser and pinned toolchain follow the local Identity foundation example; the parser was copied unchanged.

See [architecture and limits](docs/ARCHITECTURE.md) for consumer responsibilities and remaining integration work.

## Durable scoped persistence checkpoint

Import `postgresDatabase`, `scoped` and `verifyAudit` from `@accountability/evidence/database`. The package includes `migrations/001_foundation.sql`; apply it once as a separate migration owner to a dedicated Evidence database. Connect the application through a restricted LOGIN granted the NOLOGIN `evidence_runtime` role. Privileged/owner connections are rejected before SET ROLE. See [SQL review and deployment contract](docs/SQL_REVIEW.md).

The adapter stores generic scoped metadata snapshots and immutable revisions, chained audits, actor/input-bound idempotency results and generation-fenced outbox jobs in one PostgreSQL transaction. It uses project-row locks and expected revisions, keeps raw SQL private, captures caller context/JSON before awaits, and rejects caught failures or unawaited operations at commit. Outbox completion/failure checks scope, owner, generation and lease deadline; expired final-attempt jobs become dead.

- Implementation: durable persistence foundation in ready-for-review [PR #2](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/pull/2), initially pinned to foundation head `24d8440589648783263934216d9fac202ab3480a`.
- Local validation: strict typecheck, **39 tests** (18 persistence integration tests plus 21 foundation tests), ESM/declaration build and canonical registry validation passed on Node 24.22.1. PGlite applies the actual migration, exercises roles/RLS and persists across a filesystem restart.
- CI validation: push and PR checks passed for implementation commit `6464615b423ec95ed0293f6b8b0e2db291ea120b` ([PR run](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/actions/runs/40384840936)). Later documentation-only heads have separate GitHub runs.
- Live acceptance: not performed; no external infrastructure was created. PGlite is not proof of production authentication, network pooling or true multi-session locking.

Recovery provenance: `accountability-machine/packages/runtime/src/database.ts` and `accountability-machine/migrations/001_foundation.sql`; originals are unchanged. The first WIP code checkpoint was pushed in [ce22563](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/commit/ce22563b6cd3066587bbee066942672dda7f1a4c) before hardening and tests. Evidence-prefixed tables/role and local contracts imports isolate the recovered generic persistence layer from application storage.

Next coordinated work: Identity-gated service operations, production PostgreSQL acceptance (including independent-session locking and runtime login provisioning), object/metadata reconciliation, durable audit anchoring, retention/key lifecycle and scanner/worker integration.

## Authenticated command facade (ESP-003)

Import `EvidenceService` and its typed request/command/scanner contracts from `@accountability/evidence/service`. Supply a restricted Database, dedicated PrivateObjectStore, trusted Identity directory/server clock and a required deployment ScannerPort. Identity SDK is vendored byte-identically from commit `49822985616d00521ec6f425dcea5993953fb7a1`.

The facade derives actor/scope from authentication, authorizes commands and uses optimistic project aggregate revisions. Acquire stages a durable upload intent, verifies exact encrypted bytes, then atomically publishes immutable metadata/receipt and a quarantine scan job. Trusted service workers alone can run the scanner port; exact attempt/hash/version replies and generation-fenced leases govern publication. Stalled/failed scans remain unusable. Text is exposed only after a clean authorized scan. Storage maintenance retires expired orphan intents under the same project lock, preserving every retained historical object reference.

- Implementation: ready-for-review [PR #3](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/pull/3); initial WIP [9adb217](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/commit/9adb2178b355803ba5dc0e41e17f050856de2449), worker/reconciliation checkpoint [2b5e5da](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/commit/2b5e5da58ac8f0318869f5f5a55c6aaf1683ed47).
- Local validation: Node 24.22.1; strict typecheck, **58 tests** (19 facade, 18 persistence, 21 domain/object), compiled ESM/declaration build and canonical registry validation pass.
- CI validation: push and PR checks passed for implementation commit `070f2dd1f2287d04b0e2e29cb35b96b423db21fc` ([PR run](https://github.com/neophilism/Evidence-Storage-and-Provenance-Engine/actions/runs/40389725032)). Later documentation-only heads have separate GitHub runs.
- Live acceptance: not performed. No real malware scanner, external infrastructure or HTTP application was created; a production scanner is a mandatory deployment port with no clean shortcut.

See [service contract, roles and failure protocols](docs/SERVICE_CONTRACT.md) and [SQL review](docs/SQL_REVIEW.md). The Database and object adapter remain trusted infrastructure; application callers receive only this typed facade. Next coordinated work: real scanner and managed Identity adapters, production PostgreSQL concurrency/worker acceptance, externally anchored audit, storage retention/key lifecycle and live end-to-end acceptance.

## Service layer

The engine service (convention v1) lives in `src/engine/` and is documented in [docs/ENGINE_API.md](docs/ENGINE_API.md):
evidence items with immutable versions, acquisition records with explicit provenance gaps, quarantine and scanning,
hash-chained custody, citations bound to exact versions, integrity verification against the stored bytes, retention and
disposal with tombstones, encrypted storage with key rotation, a source viewer, redacted derivatives and exportable
provenance packages. A SHA-256 digest shows byte consistency only, never authenticity or truth.

- Run: `DATABASE_URL=… IDENTITY_PUBLIC_KEYS='{"kid":"<PEM>"}' EVIDENCE_MASTER_KEY=<base64 32 bytes> OBJECT_STORE_PATH=./data npm run serve`
  (add `CLAMAV_DATABASE_DIR=…` to release scanned content; without a scanner, versions stay quarantined).
- Test: `TEST_DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/postgres npm run check` (needs clamscan, poppler,
  ImageMagick, exiftool, ffmpeg, pg_dump/psql, unzip; engine tests are skipped visibly without `TEST_DATABASE_URL`).
- Use: `import { createEngine, migrate, routes } from '@accountability/evidence/engine'`; the engine object satisfies the
  kit `EvidencePort`.

The sections above describe the earlier foundation work and are kept as a historical record.
