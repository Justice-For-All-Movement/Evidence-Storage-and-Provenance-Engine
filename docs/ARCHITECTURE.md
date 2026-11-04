# Foundation contract

All metadata APIs receive a trusted tenant/project Context and validate the full immutable snapshot before operating. This library does not authenticate callers or authorize scanner roles; consumers must obtain contexts through Identity and enforce operation permissions at a trusted boundary. Human review checks establish attribution, not verified identity.

Acquisition hashes the exact Uint8Array without decoding, normalization or extraction. Each replacement names the current predecessor and appends a new revision. Every acquired revision and redacted derivative starts quarantined. Only a matching active scan attempt over the exact hash may make it usable; failures, infections, stale completions and integrity mismatches fail closed. Scanner results are supplied by the consumer; no malware scanning implementation is included.

Selectors bind evidence revision, byte hash, representation ID and digest. Text offsets are JavaScript UTF-16 indices and cannot split surrogate pairs; pages are one-based and time ranges use milliseconds. Historical selectors require explicit `requireCurrent:false` and retain purpose/scan checks. Dependency fingerprints are for downstream invalidation, not signatures or authorization tokens.

Source analysis merges duplicate-byte, shared-root and derivative ancestry groups transitively. Different files or families alone do not establish independence. Cross-group root pairs require explicit current human assessments; any source-graph change invalidates those assessments. Unknown families do not yield a confirmed independent count. Source analysis describes lineage and does not itself release quarantined evidence.

Redaction creates new UTF-8 text bytes from an approved exact representation, retains source lineage and the target purpose, and requires a separate clean scan. Expiry, replacement or quarantine of the source blocks normal derivative use. It does not redact arbitrary binary formats or establish that extracted text faithfully represents source bytes.

The local object adapter uses AES-256-GCM with a fresh nonce, binding tenant/project, key version and plaintext hash as authenticated data. Objects are scoped, content-addressed and published by an exclusive hard link; duplicate writes verify existing bytes. Caller bytes and scope are snapshotted before awaits. Stored bytes are rehashed after authenticated decryption. Symlinked tenant directories and object files are rejected. Consumers must control the root and parent directories; this is not a defense against an administrator racing filesystem path replacement. Keys are supplied by the caller; key custody, rotation and retention are not implemented.

Metadata snapshots and object receipts are separate. A trusted consumer must persist bytes and metadata atomically or reconcile incomplete acquisitions, use compare-and-swap for concurrent snapshot writers, enforce retention, and preserve immutable storage/version receipts. Handling hashes and metadata digests detect accidental corruption; an administrator who can rewrite the entire snapshot can recompute them. No external signed audit anchor or live metadata service is included. The database adapter in PR #2 adds durable scoped metadata/revision/audit/outbox primitives; see SQL_REVIEW.md for tested guarantees and remaining service boundaries.

## Validation and next work

Synthetic automated tests cover exact bytes/hash, immutable revisions, quarantine and stale scans, selectors and revisions, source independence and graph invalidation, tenant/project isolation, metadata/handling corruption, redacted lineage and encrypted envelope tampering. Object tests use ephemeral random keys and temporary directories.

Next coordinated work: Identity-gated service boundary; durable metadata and object transaction adapter with concurrent-writer tests; real scanner integration; external audit anchoring; key lifecycle and retention; live service acceptance. These are follow-up integration tasks, not additional approved PRs in this foundation scope.

SELECTOR_LINK_CAPTURE.md documents the additive owning selector/link metadata capture with compact selected family basis. Existing reviewSelectors stays unchanged; current Knowledge link writes and source/consent/deployment acceptance remain separate.
