import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {DomainError, type Context} from '../src/contracts.ts';
import * as e from '../src/index.ts';

const ctx: Context = {tenantId:'tenant-fixture', projectId:'project-fixture', actor:{id:'reviewer-fixture', kind:'human', roles:[]}, purpose:'verify', requestId:'request-fixture', now:'2026-01-01T00:00:00Z'};
const input = (id='source', bytes: Uint8Array=Buffer.from('fixture\r\n\0😀')): e.AcquisitionInput => ({id, bytes, acquisitionId:`acq-${id}`, storageVersionRef:`object-${id}`, mediaType:'application/octet-stream', sourceFamilyId:null, capturedAt:ctx.now, originalLanguage:'und', allowedPurposes:['verify'], supersedes:null});
const last = (s:e.EvidenceState) => s.versions.at(-1)!;
const acquired = () => e.acquireEvidence(e.createEvidenceState(ctx),ctx,input());
function clean(s:e.EvidenceState, ref=last(s).ref, attempt='attempt-1'):e.EvidenceState {
  s=e.beginScan(s,ctx,{id:`start-${attempt}`, evidence:ref, attemptId:attempt, engineVersion:'fixture-scanner-1'});
  return e.completeScan(s,ctx,{id:`end-${attempt}`, evidence:ref, attemptId:attempt, sha256:e.getEvidenceVersion(s,ctx,ref).sha256, status:'clean', reason:'Synthetic scanner result'});
}
function rejects(code:string, fn:()=>unknown):void {assert.throws(fn,(err:unknown)=>err instanceof DomainError && err.code===code);}
function represented() {
  let s=clean(acquired()); const v=last(s);
  s=e.addRepresentation(s,ctx,{id:'representation-1', evidence:v.ref, sourceSha256:v.sha256, text:'A😀B fixture', pages:['A😀B fixture','page two'], durationMs:1000, toolVersion:'fixture-parser-1'});
  const r=s.representations[0]!;
  return {s,v,anchor:{evidence:v.ref,sha256:v.sha256,representationId:r.id,representationDigest:r.digest}};
}

test('acquisition hashes exact bytes including CRLF, NUL and Unicode; copies and freezes metadata',()=>{
  const bytes=Buffer.from([0,255,13,10,240,159,152,128]); const original=Buffer.from(bytes);
  const i=input('binary',bytes); const before=e.createEvidenceState(ctx); const s=e.acquireEvidence(before,ctx,i); bytes.fill(42);
  assert.equal(last(s).sha256,createHash('sha256').update(original).digest('hex'));
  assert.equal(last(s).byteLength,8); assert.equal(before.versions.length,0);
  assert.ok(Object.isFrozen(s)); assert.ok(Object.isFrozen(last(s).allowedPurposes));
  assert.throws(()=>{(last(s).allowedPurposes as string[]).push('other');},TypeError);
  e.assertEvidenceState(JSON.parse(JSON.stringify(s)) as e.EvidenceState);
});

test('replacements preserve original revisions and reject stale predecessors',()=>{
  const first=clean(acquired()); const v1=last(first); const snapshot=JSON.stringify(v1);
  const s=e.acquireEvidence(first,ctx,{...input('source',Buffer.from('replacement')), acquisitionId:'acq-v2', storageVersionRef:'object-v2', supersedes:v1.ref});
  assert.equal(last(s).ref.revision,2); assert.equal(JSON.stringify(e.getEvidenceVersion(s,ctx,v1.ref)),snapshot);
  assert.equal(first.versions.length,1); rejects('stale_revision',()=>e.requireEvidenceUsable(s,ctx,v1.ref));
  assert.equal(e.requireEvidenceUsable(s,ctx,v1.ref,{requireCurrent:false}).sha256,v1.sha256);
  rejects('stale_revision',()=>e.acquireEvidence(s,ctx,{...input(),acquisitionId:'acq-v3',storageVersionRef:'object-v3',supersedes:v1.ref}));
  rejects('stale_revision',()=>e.acquireEvidence(s,ctx,input()));
  assert.equal(e.getScanStatus(s,ctx,last(s).ref),'quarantined');
});

test('new evidence, active scans, failed and infected outcomes cannot be consumed',()=>{
  let s=acquired(); const v=last(s); assert.equal(e.getScanStatus(s,ctx,v.ref),'quarantined');
  rejects('evidence_quarantined',()=>e.requireEvidenceUsable(s,ctx,v.ref));
  s=e.beginScan(s,ctx,{id:'start',evidence:v.ref,attemptId:'scan',engineVersion:'fixture-1'});
  rejects('evidence_quarantined',()=>e.requireEvidenceUsable(s,ctx,v.ref));
  rejects('invalid_transition',()=>e.beginScan(s,ctx,{id:'overlap',evidence:v.ref,attemptId:'scan-2',engineVersion:'fixture-1'}));
  for(const status of ['failed','infected'] as const){
    const done=e.completeScan(s,ctx,{id:status,evidence:v.ref,attemptId:'scan',sha256:v.sha256,status,reason:'Fixture result'});
    rejects('evidence_quarantined',()=>e.requireEvidenceUsable(done,ctx,v.ref));
    if(status==='infected') rejects('invalid_transition',()=>e.beginScan(done,ctx,{id:'unsafe-retry',evidence:v.ref,attemptId:'retry',engineVersion:'fixture-1'}));
  }
  s=clean(acquired()); assert.equal(e.requireEvidenceUsable(s,ctx,v.ref).sha256,v.sha256);
  rejects('purpose_denied',()=>e.requireEvidenceUsable(s,{...ctx,purpose:'publish'},v.ref));
});

test('quarantine invalidates outstanding attempts and rejects replay or wrong-byte completion',()=>{
  let s=acquired(); const v=last(s);
  s=e.beginScan(s,ctx,{id:'start-1',evidence:v.ref,attemptId:'a1',engineVersion:'fixture-1'});
  s=e.quarantineEvidence(s,ctx,{id:'quarantine',evidence:v.ref,reason:'Fixture invalidation'});
  const complete=(state:e.EvidenceState,attemptId='a1',sha256=v.sha256)=>e.completeScan(state,ctx,{id:'result',evidence:v.ref,attemptId,sha256,status:'clean',reason:'Fixture result'});
  rejects('stale_scan',()=>complete(s));
  s=e.beginScan(s,ctx,{id:'start-2',evidence:v.ref,attemptId:'a2',engineVersion:'fixture-1'});
  rejects('stale_scan',()=>complete(s)); rejects('integrity_failure',()=>complete(s,'a2','0'.repeat(64)));
  s=complete(s,'a2'); rejects('stale_scan',()=>complete(s,'a2'));
  rejects('duplicate',()=>e.beginScan(s,ctx,{id:'start-3',evidence:v.ref,attemptId:'a1',engineVersion:'fixture-1'}));
});

test('integrity mismatch quarantines clean evidence and requires repair plus a fresh scan',()=>{
  let s=clean(acquired()); const v=last(s);
  s=e.recordIntegrityCheck(s,ctx,{id:'bad',evidence:v.ref,bytes:Buffer.from('corruption')});
  assert.equal(e.getScanStatus(s,ctx,v.ref),'quarantined');
  s=e.beginScan(s,ctx,{id:'start-repair',evidence:v.ref,attemptId:'repair',engineVersion:'fixture-1'});
  const complete=(state:e.EvidenceState)=>e.completeScan(state,ctx,{id:'end-repair',evidence:v.ref,attemptId:'repair',sha256:v.sha256,status:'clean',reason:'Fixture rescan'});
  rejects('integrity_failure',()=>complete(s));
  s=e.recordIntegrityCheck(s,ctx,{id:'fixed',evidence:v.ref,bytes:input().bytes});
  rejects('evidence_quarantined',()=>e.requireEvidenceUsable(s,ctx,v.ref));
  s=complete(s); assert.equal(e.requireEvidenceUsable(s,ctx,v.ref).sha256,v.sha256);
});

test('text, page, time and whole selectors bind exact bytes and representation digests',()=>{
  const {s,v,anchor}=represented();
  const selector:e.EvidenceSelector={...anchor,kind:'text',page:null,start:1,end:3,quote:'😀'};
  assert.equal(e.validateEvidenceSelector(s,ctx,selector).sha256,v.sha256);
  rejects('invalid_selector',()=>e.validateEvidenceSelector(s,ctx,{...selector,quote:'x'}));
  rejects('invalid_selector',()=>e.validateEvidenceSelector(s,ctx,{...selector,start:2,quote:'\uDE00'}));
  rejects('invalid_selector',()=>e.validateEvidenceSelector(s,ctx,{...selector,representationDigest:'0'.repeat(64)}));
  rejects('invalid_selector',()=>e.validateEvidenceSelector(s,ctx,{...selector,sha256:'0'.repeat(64)}));
  e.validateEvidenceSelector(s,ctx,{...anchor,kind:'page',fromPage:1,toPage:2});
  rejects('invalid_selector',()=>e.validateEvidenceSelector(s,ctx,{...anchor,kind:'page',fromPage:1,toPage:3}));
  e.validateEvidenceSelector(s,ctx,{...anchor,kind:'time',startMs:0,endMs:1000});
  rejects('invalid_selector',()=>e.validateEvidenceSelector(s,ctx,{...anchor,kind:'time',startMs:0,endMs:1001}));
  const updated=e.acquireEvidence(s,ctx,{...input('source',Buffer.from('new revision')),acquisitionId:'a-v2',storageVersionRef:'o-v2',supersedes:v.ref});
  rejects('stale_revision',()=>e.validateEvidenceSelector(updated,ctx,selector));
  e.validateEvidenceSelector(updated,ctx,selector,{requireCurrent:false});
  const v2=last(updated); const ready=clean(updated,v2.ref,'v2');
  rejects('invalid_selector',()=>e.validateEvidenceSelector(ready,ctx,{...selector,evidence:v2.ref,sha256:v2.sha256}));
});

test('dependency fingerprints change with scans, integrity and source graph; quarantine blocks them',()=>{
  let s=clean(acquired()); const v=last(s); const selector:e.EvidenceSelector={kind:'whole',evidence:v.ref,sha256:v.sha256};
  const initial=e.evidenceDependencyFingerprint(s,ctx,selector);
  s=e.recordIntegrityCheck(s,ctx,{id:'check',evidence:v.ref,bytes:input().bytes});
  const checked=e.evidenceDependencyFingerprint(s,ctx,selector); assert.notEqual(checked,initial);
  s=clean(s,v.ref,'rescan'); const rescanned=e.evidenceDependencyFingerprint(s,ctx,selector); assert.notEqual(rescanned,checked);
  s=e.addSourceFamily(s,ctx,{id:'root-fixture',label:'Fixture root',parentIds:[],reason:'Synthetic family'});
  assert.notEqual(e.evidenceDependencyFingerprint(s,ctx,selector),rescanned);
  s=e.quarantineEvidence(s,ctx,{id:'q',evidence:v.ref,reason:'Fixture quarantine'});
  rejects('evidence_quarantined',()=>e.evidenceDependencyFingerprint(s,ctx,selector));
});

test('source counts group duplicate bytes and derived families; independence requires current human assessment',()=>{
  let s=e.createEvidenceState(ctx);
  for(const id of ['root-a','root-b'])s=e.addSourceFamily(s,ctx,{id,label:id,parentIds:[],reason:'Synthetic root'});
  s=e.addSourceFamily(s,ctx,{id:'child-a',label:'Fixture copy',parentIds:['root-a'],reason:'Derived fixture'});
  for(const [id,family,bytes] of [['a','root-a','one'],['b','root-b','two'],['copy','root-b','one'],['derived','child-a','three']] as const){
    s=e.acquireEvidence(s,ctx,{...input(id,Buffer.from(bytes)),sourceFamilyId:family});
  }
  const refs=s.versions.map(v=>v.ref); const a=refs[0]!,b=refs[1]!;
  assert.equal(e.analyzeSources(s,ctx,[a,b]).independentFamilyCount,null);
  rejects('human_review_required',()=>e.recordFamilyIndependence(s,{...ctx,actor:{...ctx.actor,kind:'agent'}},{id:'assessment',familyIds:['root-a','root-b'],rationale:'Fixture assessment'}));
  s=e.recordFamilyIndependence(s,ctx,{id:'assessment',familyIds:['root-a','root-b'],rationale:'Synthetic human assessment'});
  assert.equal(e.analyzeSources(s,ctx,[a,b]).independentFamilyCount,2);
  const all=e.analyzeSources(s,ctx,refs); assert.equal(all.sourceGroupCount,1); assert.equal(all.uniqueByteCount,3);
  rejects('family_cycle',()=>e.linkSourceFamilies(s,ctx,{childId:'root-a',parentId:'child-a',reason:'Circular fixture'}));
  s=e.addSourceFamily(s,ctx,{id:'new-root',label:'New root',parentIds:[],reason:'Graph change fixture'});
  assert.equal(e.analyzeSources(s,ctx,[a,b]).independentFamilyCount,null);
  s=e.acquireEvidence(s,ctx,input('unknown')); assert.equal(e.analyzeSources(s,ctx,[last(s).ref]).independentFamilyCount,null);
});

for(const change of [{tenantId:'other-tenant'},{projectId:'other-project'}])test(`scope isolation ${Object.keys(change)[0]} rejects reads, writes, references and analysis`,()=>{
  const s=clean(acquired()); const v=last(s); const foreign={...ctx,...change}; const ref={...v.ref,...change};
  rejects('scope_denied',()=>e.getEvidenceVersion(s,foreign,v.ref));
  rejects('scope_denied',()=>e.acquireEvidence(s,foreign,input('foreign')));
  rejects('scope_denied',()=>e.getEvidenceVersion(s,ctx,ref));
  rejects('scope_denied',()=>e.analyzeSources(s,ctx,[ref]));
  rejects('scope_denied',()=>e.beginScan(s,ctx,{id:'foreign',evidence:ref,attemptId:'foreign',engineVersion:'fixture'}));
});

test('deserialized metadata and handling corruption is rejected',()=>{
  const s=clean(acquired());
  const badMetadata=structuredClone(s); Object.assign(badMetadata.versions[0]!,{mediaType:'text/plain'});
  rejects('integrity_failure',()=>e.assertEvidenceState(badMetadata));
  const badChain=structuredClone(s); Object.assign(badChain.handling[1]!,{detail:'changed'});
  rejects('integrity_failure',()=>e.assertEvidenceState(badChain));
  const missing=structuredClone(s); Object.assign(missing,{handling:s.handling.slice(1)});
  rejects('integrity_failure',()=>e.assertEvidenceState(missing));
});

test('redacted derivatives retain exact lineage, quarantine, purpose and source invalidation',()=>{
  let {s,v}=represented();
  s=e.approveTextRedaction(s,ctx,{id:'plan',source:v.ref,representationId:'representation-1',ranges:[{start:1,end:3,reason:'Fixture removal'}],targetPurpose:'share-fixture',policyVersion:'fixture-policy-1',expiresAt:'2026-01-02T00:00:00Z'});
  const result=e.createRedactedDerivative(s,ctx,{planId:'plan',id:'derivative',acquisitionId:'acq-derivative',storageVersionRef:'object-derivative'});
  assert.equal(Buffer.from(result.bytes).toString(),'A[REDACTED]B fixture');
  assert.deepEqual(last(result.state).lineage,{parent:v.ref,redactionPlanId:'plan'});
  assert.equal(e.getScanStatus(result.state,ctx,result.ref),'quarantined');
  s=clean(result.state,result.ref,'derivative'); const share={...ctx,purpose:'share-fixture'};
  e.requireEvidenceUsable(s,share,result.ref);
  rejects('purpose_denied',()=>e.requireEvidenceUsable(s,ctx,result.ref));
  rejects('expired',()=>e.requireEvidenceUsable(s,{...share,now:'2026-01-02T00:00:00Z'},result.ref));
  assert.equal(e.analyzeSources(s,ctx,[v.ref,result.ref]).sourceGroupCount,1);
  s=e.quarantineEvidence(s,ctx,{id:'parent-q',evidence:v.ref,reason:'Fixture recall'});
  rejects('evidence_quarantined',()=>e.requireEvidenceUsable(s,share,result.ref));
});

test('selector capture retains known shared roots and rejects expanded family output over its response budget',async()=>{
 const {captureSelectorLinks,reviewSelectors}=await import('../src/selector-review.ts');
 let s=e.createEvidenceState(ctx);
 for(let i=0;i<63;i++)s=e.addSourceFamily(s,ctx,{id:`root-${i}-`+'x'.repeat(120),label:'Fictional root',parentIds:[],reason:'Synthetic lineage only'});
 const roots=s.families.map(f=>f.id);
 s=e.addSourceFamily(s,ctx,{id:'derived-family',label:'Shared ancestry',parentIds:roots,reason:'Synthetic shared roots, not independence proof'});
 s=clean(e.acquireEvidence(s,ctx,{...input(),sourceFamilyId:'derived-family'}));
 const v=last(s),q={kind:'whole' as const,evidence:v.ref,sha256:v.sha256};
 const captured=captureSelectorLinks(s,ctx,[q],1);
 assert.equal(captured.selectors[0]!.family.familyId,'derived-family');
 assert.deepEqual(captured.selectors[0]!.family.roots,e.getFamilySnapshot(s,ctx,v.ref).roots);
 assert.equal(captured.selectors[0]!.family.roots.length,63);
 assert.equal(captured.selectors[0]!.fingerprint,e.evidenceDependencyFingerprint(s,ctx,q));
 const many=Array.from({length:64},()=>q);
 assert.equal(reviewSelectors(s,ctx,many,1).selectors.length,64);
 rejects('review_full',()=>captureSelectorLinks(s,ctx,many,1));
});
