import {canonical, invariant, validateRef, type Context, type Scope} from './contracts.ts';
import {analyzeSources, assertEvidenceState, evidenceDependencyFingerprint, validateEvidenceSelector,
  type EvidenceSelector, type EvidenceState, type SourceAnalysis} from './index.ts';

/** Owning metadata observation only; never a content verification or transferable permission. */
export type SelectorReview = Scope & Readonly<{
  schemaVersion: 1; purpose: string; revision: number;
  selectors: readonly Readonly<{selector: EvidenceSelector; fingerprint: string}>[];
  sources: SourceAnalysis;
}>;
export function captureSelectors(input: readonly EvidenceSelector[]): readonly EvidenceSelector[] {
  invariant(Array.isArray(input) && input.length > 0 && input.length <= 64,
    'invalid_selector_review', 'One to64 selectors required');
  const selected = structuredClone(input);
  invariant(Buffer.byteLength(canonical(selected)) <= 64 * 1024,
    'invalid_selector_review', 'Selector request byte budget exceeded');
  for (const s of selected) {
    const fields = s.kind === 'whole' ? ['kind','evidence','sha256']
      : s.kind === 'text' ? ['kind','evidence','sha256','representationId','representationDigest','page','start','end','quote']
      : s.kind === 'page' ? ['kind','evidence','sha256','representationId','representationDigest','fromPage','toPage']
      : s.kind === 'time' ? ['kind','evidence','sha256','representationId','representationDigest','startMs','endMs'] : [];
    invariant(fields.length > 0 && Object.keys(s).length === fields.length && fields.every(k => Object.hasOwn(s,k)),
      'invalid_selector_review', 'Exact supported selector fields required');
    validateRef(s.evidence);
    invariant(s.evidence.kind === 'evidence', 'invalid_selector_review', 'Evidence reference required');
  }
  return selected;
}
/** Bound the actual stored graph BEFORE entering recursive owning domain validation. */
export function assertReviewBudget(s: EvidenceState): void {
  invariant(Buffer.byteLength(canonical(s)) <= 8 * 1024 * 1024,
    'review_full', 'Evidence metadata byte budget exceeded');
  for (const a of [s.versions,s.families,s.independence,s.scans,s.representations,s.integrity,s.handling,s.redactionPlans])
    invariant(Array.isArray(a) && a.length <= 4096, 'review_full', 'Evidence collection budget exceeded');
  invariant(s.versions.length <= 512 && s.families.length <= 64, 'review_full', 'Evidence graph budget exceeded');
  const graph = new Map(s.families.map(f => [f.id,f.parentIds]));
  let visits = 0;
  function walk(id: string, path: Set<string>): void {
    invariant(++visits <= 8192 && !path.has(id), 'review_full', 'Evidence ancestry expansion budget exceeded');
    const parents = graph.get(id);
    invariant(Array.isArray(parents) && parents.length <= 64, 'review_full', 'Bounded known family parents required');
    const next = new Set(path).add(id);
    for (const parent of parents) walk(parent,next);
  }
  for (const id of graph.keys()) walk(id,new Set());
  assertEvidenceState(s);
}
export function reviewSelectors(s: EvidenceState, c: Context, selected: readonly EvidenceSelector[], revision: number): SelectorReview {
  const selectors = selected.map(selector => {
    validateEvidenceSelector(s,c,selector); // Current, clean, purpose-authorized and exact representation/quote.
    return {selector, fingerprint: evidenceDependencyFingerprint(s,c,selector)};
  });
  const result: SelectorReview = {schemaVersion:1,tenantId:c.tenantId,projectId:c.projectId,purpose:c.purpose,revision,
    selectors, sources:analyzeSources(s,c,selected.map(s => s.evidence))};
  invariant(Buffer.byteLength(canonical(result)) <= 256 * 1024, 'review_full', 'Selector response budget exceeded');
  return structuredClone(result);
}
