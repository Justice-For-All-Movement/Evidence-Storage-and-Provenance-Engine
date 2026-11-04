# Authenticated Evidence application facade — ESP-003

Export: `@accountability/evidence/service` (compiled ESM and declarations). This is a typed application/worker SDK, not an HTTP application or deployed service.

## Authentication and authorization

`EvidenceService` receives trusted deployment dependencies: `database`, `objects`, `identities`, `now`, and a mandatory `scanner` port. `identities()` returns current Identity SDK mappings; it must load from a trusted credential/identity authority, never request JSON. `now()` must be a trusted server clock. Each method authenticates its bearer credential and derives tenant, project, actor and roles from that mapping. Request fields are exactly `token`, `purpose`, `requestId`; scope/actor/role fields are rejected. Raw credentials never enter database commands, idempotency fingerprints, audit payloads or outbox jobs.

Identity authentication/authorization is vendored byte-identically from `neophilism/Identity-Authorization-and-Policy-Engine`, commit `49822985616d00521ec6f425dcea5993953fb7a1`, `src/index.ts`, into `src/identity-sdk.ts`. Its relative `./contracts.ts` import already matches this package. Shared contracts were also verified byte-identical to that pinned commit. The SDK's role checks apply; this facade does not invent an additional identity provider or claim signed-capability enforcement. Deployment owns credential custody, rotation, revocation and the trusted Identity mapping adapter.

| Method | Required authority | Result |
| --- | --- | --- |
| `acquire(request, command)` | SDK `investigate` | `{ref, revision}` for a quarantined acquisition |
| `inspect(request, ref)` | SDK `read`, matching scope | Immutable metadata, scan state and current aggregate revision; quarantined metadata remains inspectable |
| `read(request, ref)` | SDK `read`, matching scope/purpose, current clean revision | Verified exact plaintext bytes; storage failure durably quarantines before throwing |
| `representation(request, ref, representationId)` | SDK `read`, matching scope/purpose, current clean revision | Exact stored extraction; no user representation-write endpoint |
| `quarantine(request, ref, expectedRevision, key)` | SDK `process`, matching scope | New aggregate revision; can only reduce usability |
| `runNextScan(request)` | SDK `process`, actor kind `service`, role `evidence_scanner` | A bounded worker outcome or null; no caller verdict argument |
| `recoverStalledScans(request)` | Same scanner authority | Count of expired attempts quarantined |
| `reconcileUploads(request, after?, limit?)` | SDK `process`, actor kind `service`, role `evidence_storage_maintenance` | `{removed, retained, next}` for a maintenance page |

Worker mappings need both a supported SDK role granting `process` (for example `operator`) and the dedicated worker role. A human carrying the dedicated role is still rejected. Authority is reloaded after scanner execution, so a revoked/disabled worker cannot publish its previously obtained result.

## Acquisition, optimistic state and object lifecycle

`AcquireCommand` contains exactly `id`, `acquisitionId`, `bytes`, `mediaType`, `capturedAt`, `originalLanguage`, `supersedes`, `expectedRevision`, `idempotencyKey`. Allowed purpose is derived from the authenticated request; callers cannot supply storage paths/receipts, scope, scan status or extra authority. Bytes are copied before the first await. This narrow facade creates original acquisitions/replacements; source-family management and redaction workflows remain in the low-level domain library.

One project-wide `evidence.aggregate/project` snapshot holds immutable domain state, all historical object bindings and active scanner handles. Its persistence revision is distinct from an EvidenceRef's source revision. Acquisition and explicit quarantine require the observed aggregate revision. Scanner transitions also advance it, so consumers must refresh using inspect after a conflict. Aggregate growth and per-project write serialization are intentional bounded-foundation tradeoffs, not a high-volume partitioning design.

Before a blob write, a separate transaction commits an `evidence.upload` intent keyed by actor/idempotency key and a canonical command fingerprint. Publication then takes the project lock, checks expected revision and intent lifetime, writes/verifies the exact encrypted object, and atomically commits domain state, receipt binding, scan outbox job and referenced intent state. Replays require the same actor/scoped key and input/purpose; credentials are reauthenticated even on replay. Blob writes and SQL are not atomically committed together.

On SQL failure the intent remains pending and the blob is retained; a retry within its lifetime can publish it. Maintenance only considers expired pending intents. It holds the same project lock, checks every retained historical object binding, and only unlinks an unreferenced scoped path. Referenced/deduplicated blobs are retained even when the failed upload is retired. An expired/retired upload cannot later publish. Missing files are safe to retire. If SQL rollback occurs after orphan unlink, only an unreferenced expired candidate was removed; reconciliation can replay without deleting retained data.

**Storage ownership requirement:** use a dedicated Evidence root, and have all publication/deletion paths honor this facade's project lock and aggregate reference set. Independent writers or hidden references outside that set make automatic cleanup unsupported. `PrivateObjectStore.removeUnreferenced` is a trusted maintenance primitive; never expose it to application callers. Administrator filesystem races, key rotation and retention policy remain deployment work.

## Scanner port and lease lifecycle

`ScannerPort` supplies a fixed `version` and `scan(input): Promise<ScanReply>`. No scanner is bundled or silently substituted. Production must connect a real deployment malware/extraction adapter; synthetic ports occur only in tests. Every file, including text, goes through the configured port. A file extension or successful decoding never marks bytes clean.

The port receives a unique durable attempt ID, exact evidence reference/hash/bytes/media type, deadline and AbortSignal. It returns that exact attempt ID/hash/version, a clean/infected/failed verdict and optional extracted representation. The engine rejects mismatched bindings, bounds execution with a timeout, and aborts the signal on timeout. Late results from the raced promise have no publication path. Deployment adapters should honor cancellation and limit their own resource use.

The worker only claims `evidence.scan` jobs. `UnitOfWork.claim(worker, leaseMs?, topic?)` adds an optional backwards-compatible topic filter; existing two-argument callers retain their behavior. Claim and start atomically append a domain scan record, persist an `evidence.scan-attempt` record keyed by job/generation, and advance the aggregate. The scanner runs outside a SQL transaction. Completion takes the project lock, checks the current attempt, and acknowledges/fails only the exact scoped owner/generation/unexpired lease while committing attempt and domain changes together.

Clean replies can publish an extraction only after domain clean-scan, purpose and exact-source-hash checks. Malformed/unauthorized extraction causes a failed unusable result, not partially published clean state. Infected replies are terminal and never publish text. Failed/malformed/timeout replies remain unusable and use bounded outbox retries; each retry has a new attempt/generation. Superseded source work is terminally failed. An authorized quarantine invalidates an in-flight reply.

`recoverStalledScans` quarantines expired active attempts and records a durable lease-expired failure. Claim then reclaims an eligible job or sweeps an exhausted final attempt to dead. A process that died without calling back cannot leave readable bytes. Deployment must schedule recovery/worker calls; this SDK starts no background timers except the bounded per-call timeout. A scanner token revoked during work leaves its attempt unreadable until a different authorized worker recovers it.

Default bounds: 30-second lease, 20-second scanner timeout, 15-minute upload intent lifetime, five scan attempts. Timeouts must fit inside the lease; intent lifetime is 1 second-1 day, leases 1-300 seconds, maximum attempts 1-100. Worker request purpose must permit any representation it publishes. Returned scan outcomes are clean/infected/failed/stale; they are observations, not inputs accepted from users.

## Source-bound acceptance and limits

`tests/service.test.ts` uses the actual checked-in SQL migration, PGlite under a restricted non-owner login and real encrypted temporary objects. Its synthetic scanner is declared only in that test file. Nineteen facade tests cover exact acquisition bytes, quarantine/read/text gates, Identity scope/role denial, atomic idempotency, optimistic source revisions, wrong hash/attempt/version replies, infection, timeout/retry, stale generations, expired final attempts, explicit quarantine, malformed/wrong-purpose extraction, orphan deletion/retention across historical revisions, encrypted tampering, topic filtering, mandatory port configuration, worker revocation and atomic completion rollback.

These join the 39 existing domain/storage/database tests. Local strict typecheck, all 58 tests and ESM/declaration build pass. PGlite serializes transactions; independent PostgreSQL sessions, real malware/extraction infrastructure, managed-identity deployment, power-loss recovery and end-to-end live acceptance remain unverified. The orphan protocol coordinates SQL and filesystem effects; it does not make them one distributed transaction.

SELECTOR_REVIEW.md documents the additive owning authenticated selector metadata read. Existing inspect/read/representation semantics remain unchanged.
