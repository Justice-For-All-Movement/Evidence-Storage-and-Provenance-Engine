import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {PGlite} from '@electric-sql/pglite';
import {EvidenceService,type AcquireCommand,type EvidenceRequest,type ScanInput,type ScanReply,type ScannerPort,type Identity} from '../src/service.ts';
import {tokenHash} from '../src/identity-sdk.ts';
import {DomainError,digest,type Context,type Json} from '../src/contracts.ts';
import {scoped,verifyAudit,type Database} from '../src/database.ts';
import {PrivateObjectStore} from '../src/objects.ts';
const migration=await readFile(new URL('../migrations/001_foundation.sql',import.meta.url),'utf8');
const code=(wanted:string)=>(error:unknown)=>error instanceof DomainError&&error.code===wanted;
const scope={tenantId:'tenant-fixture',projectId:'project-fixture'};
const BASE='2026-01-01T00:00:00.000Z';
const command=(overrides:Partial<AcquireCommand>={}):AcquireCommand=>({id:'original',acquisitionId:'acquisition-fixture',bytes:Buffer.from('Synthetic fixture\r\n\0😀'),mediaType:'text/plain',capturedAt:BASE,originalLanguage:'und',supersedes:null,expectedRevision:0,idempotencyKey:'acquire-fixture',...overrides});
// A deliberately synthetic deployment port used only in this test file. Production has no scanner default.
const syntheticClean=(input:ScanInput):ScanReply=>({attemptId:input.attemptId,sha256:input.sha256,engineVersion:'synthetic-test-scanner-1',verdict:'clean',representation:{sourceSha256:input.sha256,text:'Extracted synthetic fixture',pages:null,durationMs:null,toolVersion:'synthetic-test-extractor-1'}});
async function setup(t:{after:(fn:()=>Promise<void>)=>void},options:{scan?:(input:ScanInput)=>Promise<ScanReply>;timeout?:number;maxAttempts?:number}={}){
 const pg=new PGlite();t.after(()=>pg.close());await pg.exec(migration);
 await pg.exec('CREATE ROLE evidence_facade_test_login LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; GRANT evidence_runtime TO evidence_facade_test_login; SET SESSION AUTHORIZATION evidence_facade_test_login;');
 const root=await mkdtemp(join(tmpdir(),'evidence-facade-fixture-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const objects=new PrivateObjectStore(root,randomBytes(32),'test-key-1');let time=Date.parse(BASE),request=0;let inject:((sql:string,values?:unknown[])=>boolean)|null=null;
 const db:Database={transaction:fn=>pg.transaction(tx=>fn({query:async<T>(sql:string,values?:unknown[])=>{if(inject?.(sql,values)){inject=null;throw new Error('injected_database_failure');}return {rows:(await tx.query(sql,values)).rows as T[]};}})),close:()=>pg.close()};
 const tokens=Object.fromEntries(['author','viewer','worker','worker2','maintenance','humanWorker','foreign','foreignWorker'].map(name=>[name,randomBytes(32).toString('hex')])) as Record<'author'|'viewer'|'worker'|'worker2'|'maintenance'|'humanWorker'|'foreign'|'foreignWorker',string>;
 const identities:Identity[]=Object.entries(tokens).map(([name,token])=>({...scope,tenantId:name.startsWith('foreign')?'other-tenant':scope.tenantId,actor:{id:name,kind:['worker','worker2','maintenance','foreignWorker'].includes(name)?'service':'human',roles:name==='viewer'?['viewer']:name==='maintenance'?['operator','evidence_storage_maintenance']:['worker','worker2','humanWorker','foreignWorker'].includes(name)?['operator','evidence_scanner']:['researcher']},tokenHash:tokenHash(token),disabled:false,epoch:1}));
 const seen:ScanInput[]=[];const scanner:ScannerPort={version:'synthetic-test-scanner-1',scan:async input=>{seen.push(input);return options.scan?options.scan(input):syntheticClean(input);}};
 const service=new EvidenceService({database:db,objects,identities:async()=>identities,now:()=>new Date(time).toISOString(),scanner,leaseMs:1000,scanTimeoutMs:options.timeout??500,uploadTtlMs:1000,maxScanAttempts:options.maxAttempts??3});
 const req=(actor:keyof typeof tokens='author',purpose='verify-fixture'):EvidenceRequest=>({token:tokens[actor],purpose,requestId:`request-${++request}`});
 const ctx=(actor='author'):Context=>({...scope,actor:{id:actor,kind:'human',roles:['researcher']},purpose:'verify-fixture',requestId:`inspect-${++request}`,now:new Date(time).toISOString()});
 const rows=<T=Record<string,unknown>>(sql:string)=>db.transaction(async q=>{await q.query('SET LOCAL ROLE evidence_runtime');await q.query("SELECT set_config('evidence.tenant_id',$1,true),set_config('evidence.project_id',$2,true)",[scope.tenantId,scope.projectId]);return (await q.query<T>(sql)).rows;});
 return {service,db,pg,objects,root,tokens,identities,seen,req,ctx,rows,advance:(ms:number)=>{time+=ms;},failOnce:(test:(sql:string,values?:unknown[])=>boolean)=>{inject=test;}};
}

test('acquire hashes exact bytes, atomically publishes a quarantined aggregate/receipt/job, and worker scan gates reads/text',async t=>{
 const f=await setup(t);const input=command();const original=Buffer.from(input.bytes);const pending=f.service.acquire(f.req(),input);input.bytes.fill(0);const acquired=await pending;
 assert.equal(acquired.revision,1);assert.equal((await f.service.inspect(f.req(),acquired.ref)).scan,'quarantined');
 await assert.rejects(f.service.read(f.req('viewer'),acquired.ref),code('evidence_quarantined'));
 await assert.rejects(f.service.representation(f.req('viewer'),acquired.ref,'missing'),code('evidence_quarantined'));
 const jobs=await f.rows<{topic:string;state:string;payload:{sha256:string}}>('SELECT * FROM public.evidence_outbox');assert.equal(jobs.length,1);assert.equal(jobs[0]!.topic,'evidence.scan');assert.equal(jobs[0]!.state,'pending');
 assert.equal(jobs[0]!.payload.sha256,createHash('sha256').update(original).digest('hex'));
 const outcome=await f.service.runNextScan(f.req('worker'));assert.equal(outcome?.verdict,'clean');assert.equal(f.seen.length,1);assert.deepEqual(Buffer.from(f.seen[0]!.bytes),original);
 assert.deepEqual(Buffer.from(await f.service.read(f.req('viewer'),acquired.ref)),original);
 const representation=await f.service.representation(f.req('viewer'),acquired.ref,`representation:${digest({attemptId:outcome!.attemptId})}`);assert.equal(representation.text,'Extracted synthetic fixture');
 await assert.rejects(f.service.representation(f.req('viewer','other-purpose'),acquired.ref,representation.id),code('purpose_denied'));
 const stored=await scoped(f.db,f.ctx(),tx=>tx.get<{domain:unknown;objects:unknown[]}>('evidence.aggregate','project'));assert.equal(stored?.value.objects.length,1);
 assert.ok(verifyAudit(await scoped(f.db,f.ctx(),tx=>tx.audits())));
 assert.equal((await f.pg.query<{name:string}>('SELECT current_user AS name')).rows[0]!.name,'evidence_facade_test_login');
});

test('identity owns scope/roles; viewers, humans, foreign tenants and supplied status/context cannot bypass the facade',async t=>{
 const f=await setup(t);const acquired=await f.service.acquire(f.req(),command());
 await assert.rejects(f.service.acquire(f.req('viewer'),command({id:'denied',idempotencyKey:'denied'})),code('forbidden'));
 await assert.rejects(f.service.runNextScan(f.req('author')),code('worker_required'));
 await assert.rejects(f.service.runNextScan(f.req('humanWorker')),code('worker_required'));
 await assert.rejects(f.service.reconcileUploads(f.req('worker')),code('worker_required'));
 await assert.rejects(f.service.read(f.req('foreign'),acquired.ref),code('scope_denied'));
 await assert.rejects(f.service.inspect(f.req('foreign'),acquired.ref),code('scope_denied'));
 assert.equal(await f.service.runNextScan(f.req('foreignWorker')),null);assert.equal(f.seen.length,0);
 await assert.rejects(f.service.acquire(f.req(),{...command(),scanStatus:'clean'} as AcquireCommand),code('invalid_input'));
 await assert.rejects(f.service.acquire({...f.req(),actor:{roles:['owner']}} as EvidenceRequest,command()),code('invalid_input'));
 assert.equal('completeScan' in f.service,false);assert.equal('q' in f.service,false);assert.equal('database' in f.service,false);
 const identity=f.identities.find(i=>i.actor.id==='author')!;identity.disabled=true;
 await assert.rejects(f.service.acquire(f.req(),command()),code('unauthenticated'));
});

test('atomic idempotency rolls back aggregate/audit publication/job together; durable intent/blob survive for retry',async t=>{
 const f=await setup(t);f.failOnce(sql=>sql.startsWith('INSERT INTO public.evidence_outbox'));
 const input=command();await assert.rejects(f.service.acquire(f.req(),input),/injected_database_failure/);
 assert.equal(await scoped(f.db,f.ctx(),tx=>tx.get('evidence.aggregate','project')),null);
 assert.equal((await f.rows('SELECT * FROM public.evidence_outbox')).length,0);
 const intents=await scoped(f.db,f.ctx(),tx=>tx.list<{status:string}>('evidence.upload'));assert.equal(intents[0]!.value.status,'pending');
 const result=await f.service.acquire(f.req(),input);assert.deepEqual(await f.service.acquire(f.req(),input),result);
 assert.equal((await f.rows('SELECT * FROM public.evidence_outbox')).length,1);
 await assert.rejects(f.service.acquire(f.req(),command({bytes:Buffer.from('different')})),code('idempotency_conflict'));
 const audits=await scoped(f.db,f.ctx(),tx=>tx.audits());assert.ok(verifyAudit(audits));assert.equal(audits.filter(a=>(a.payload as {kind?:string}).kind==='evidence.aggregate').length,1);
 assert.ok(!JSON.stringify(audits).includes(f.tokens.author));
});

test('aggregate CAS and immutable source revisions survive through the service',async t=>{
 const f=await setup(t);const first=await f.service.acquire(f.req(),command());await f.service.runNextScan(f.req('worker'));
 const before=await f.service.inspect(f.req(),first.ref);
 await assert.rejects(f.service.acquire(f.req(),command({id:'other',acquisitionId:'other',idempotencyKey:'stale',expectedRevision:0})),code('revision_conflict'));
 const second=await f.service.acquire(f.req(),command({acquisitionId:'replacement',idempotencyKey:'replacement',bytes:Buffer.from('replacement fixture'),supersedes:first.ref,expectedRevision:before.revision}));
 assert.equal(second.ref.revision,2);assert.deepEqual((await f.service.inspect(f.req(),first.ref)).version,before.version);
 await assert.rejects(f.service.read(f.req(),first.ref),code('stale_revision'));
 assert.equal((await f.service.inspect(f.req(),second.ref)).scan,'quarantined');
});

for(const field of ['sha256','attemptId','engineVersion'] as const)test(`scanner reply with wrong ${field} fails closed with a durable failed attempt`,async t=>{
 const f=await setup(t,{scan:async input=>({...syntheticClean(input),[field]:'wrong-fixture-value'}),maxAttempts:1});const acquired=await f.service.acquire(f.req(),command());
 assert.equal((await f.service.runNextScan(f.req('worker')))?.verdict,'failed');assert.equal((await f.service.inspect(f.req(),acquired.ref)).scan,'failed');
 await assert.rejects(f.service.read(f.req(),acquired.ref),code('evidence_quarantined'));
 const attempt=(await scoped(f.db,f.ctx(),tx=>tx.list<{status:string;reason:string}>('evidence.scan-attempt')))[0]!;assert.equal(attempt.value.status,'failed');assert.equal(attempt.value.reason,'invalid_scanner_reply');
 assert.equal((await f.rows<{state:string}>('SELECT state FROM public.evidence_outbox'))[0]!.state,'dead');
});

test('infected results never publish representation or usable bytes',async t=>{
 const f=await setup(t,{scan:async input=>({...syntheticClean(input),verdict:'infected'})});const acquired=await f.service.acquire(f.req(),command());
 assert.equal((await f.service.runNextScan(f.req('worker')))?.verdict,'infected');
 await assert.rejects(f.service.read(f.req(),acquired.ref),code('evidence_quarantined'));
 assert.equal(await f.service.runNextScan(f.req('worker')),null);
 const aggregate=await scoped(f.db,f.ctx(),tx=>tx.get<{domain:{representations:unknown[]}}>('evidence.aggregate','project'));assert.equal(aggregate?.value.domain.representations.length,0);
});

test('stalled scanner timeout aborts its signal and retries with a new durable generation',async t=>{
 let calls=0;let signal:AbortSignal|undefined;
 const f=await setup(t,{timeout:20,scan:async input=>{calls++;signal=input.signal;if(calls===1)return new Promise<ScanReply>(()=>{});return syntheticClean(input);}});
 const acquired=await f.service.acquire(f.req(),command());assert.equal((await f.service.runNextScan(f.req('worker')))?.verdict,'failed');assert.equal(signal!.aborted,true);
 await assert.rejects(f.service.read(f.req(),acquired.ref),code('evidence_quarantined'));f.advance(1000);
 assert.equal((await f.service.runNextScan(f.req('worker2')))?.verdict,'clean');assert.notEqual(f.seen[0]!.attemptId,f.seen[1]!.attemptId);
 const attempts=await scoped(f.db,f.ctx(),tx=>tx.list<{reason:string}>('evidence.scan-attempt'));assert.ok(attempts.some(a=>a.value.reason==='scanner_timeout'));
});

test('expired first worker cannot overwrite the newer generation after recovery',async t=>{
 let resolveFirst!:(reply:ScanReply)=>void;let called!:(input:ScanInput)=>void;const firstStarted=new Promise<ScanInput>(resolve=>{called=resolve;});let calls=0;
 const f=await setup(t,{scan:async input=>{calls++;if(calls===1){called(input);return new Promise<ScanReply>(resolve=>{resolveFirst=resolve;});}return syntheticClean(input);}});
 const acquired=await f.service.acquire(f.req(),command());const first=f.service.runNextScan(f.req('worker'));const original=await firstStarted;f.advance(1000);
 assert.equal(await f.service.recoverStalledScans(f.req('worker2')),1);assert.equal((await f.service.inspect(f.req(),acquired.ref)).scan,'quarantined');
 const second=await f.service.runNextScan(f.req('worker2'));assert.equal(second?.verdict,'clean');const revision=(await f.service.inspect(f.req(),acquired.ref)).revision;
 resolveFirst(syntheticClean(original));assert.equal((await first)?.verdict,'stale');assert.equal((await f.service.inspect(f.req(),acquired.ref)).scan,'clean');assert.equal((await f.service.inspect(f.req(),acquired.ref)).revision,revision);
});

test('expired final-attempt jobs are quarantined and dead without any scanner callback',async t=>{
 let finish!:(reply:ScanReply)=>void;let started!:(input:ScanInput)=>void;const observed=new Promise<ScanInput>(resolve=>{started=resolve;});
 const f=await setup(t,{maxAttempts:1,scan:async input=>{started(input);return new Promise<ScanReply>(resolve=>{finish=resolve;});}});
 const acquired=await f.service.acquire(f.req(),command());const running=f.service.runNextScan(f.req('worker'));const input=await observed;f.advance(1000);
 assert.equal(await f.service.runNextScan(f.req('worker2')),null);assert.equal((await f.service.inspect(f.req(),acquired.ref)).scan,'quarantined');
 assert.equal((await f.rows<{state:string}>('SELECT state FROM public.evidence_outbox'))[0]!.state,'dead');finish(syntheticClean(input));assert.equal((await running)?.verdict,'stale');
});

test('authorized quarantine invalidates an in-flight reply',async t=>{
 let finish!:(reply:ScanReply)=>void;let started!:(input:ScanInput)=>void;const observed=new Promise<ScanInput>(resolve=>{started=resolve;});
 const f=await setup(t,{scan:async input=>{started(input);return new Promise<ScanReply>(resolve=>{finish=resolve;});}});
 const acquired=await f.service.acquire(f.req(),command());const running=f.service.runNextScan(f.req('worker'));const input=await observed;
 const state=await f.service.inspect(f.req(),acquired.ref);await f.service.quarantine(f.req(),acquired.ref,state.revision,'safety-fixture');
 finish(syntheticClean(input));assert.equal((await running)?.verdict,'stale');assert.equal((await f.service.inspect(f.req(),acquired.ref)).scan,'quarantined');
});

test('malformed or wrong-purpose representation cannot turn a clean verdict into published text',async t=>{
 const f=await setup(t,{scan:async input=>({...syntheticClean(input),representation:{...syntheticClean(input).representation!,sourceSha256:'0'.repeat(64)}})});
 const acquired=await f.service.acquire(f.req(),command());assert.equal((await f.service.runNextScan(f.req('worker')))?.verdict,'failed');
 await assert.rejects(f.service.representation(f.req(),acquired.ref,'anything'),code('evidence_quarantined'));
 const f2=await setup(t);const acquired2=await f2.service.acquire(f2.req(),command());assert.equal((await f2.service.runNextScan(f2.req('worker','other-purpose')))?.verdict,'failed');await assert.rejects(f2.service.read(f2.req(),acquired2.ref),code('evidence_quarantined'));
});

test('metadata/outbox rollback leaves a reclaimable orphan; maintenance alone retires it after expiry',async t=>{
 const f=await setup(t);f.failOnce(sql=>sql.startsWith('INSERT INTO public.evidence_outbox'));const input=command();await assert.rejects(f.service.acquire(f.req(),input),/injected_database_failure/);
 const receipt={key:`${digest(scope)}/${createHash('sha256').update(input.bytes).digest('hex')}`,plaintextHash:createHash('sha256').update(input.bytes).digest('hex'),size:input.bytes.byteLength,keyVersion:'test-key-1'};
 assert.deepEqual(Buffer.from(await f.objects.get(scope,receipt)),Buffer.from(input.bytes));assert.equal((await f.service.reconcileUploads(f.req('maintenance'))).removed,0);
 f.advance(1000);const result=await f.service.reconcileUploads(f.req('maintenance'));assert.equal(result.removed,1);await assert.rejects(f.objects.get(scope,receipt));
 await assert.rejects(f.service.acquire(f.req(),input),code('upload_expired'));
});

test('orphan reconciliation preserves deduplicated blobs referenced by any retained source revision',async t=>{
 const f=await setup(t);const first=await f.service.acquire(f.req(),command());f.failOnce(sql=>sql.startsWith('INSERT INTO public.evidence_outbox'));
 await assert.rejects(f.service.acquire(f.req(),command({id:'unpublished',acquisitionId:'unpublished',idempotencyKey:'unpublished',expectedRevision:1})),/injected_database_failure/);
 const replacement=await f.service.acquire(f.req(),command({acquisitionId:'replacement-fixture',idempotencyKey:'replacement-fixture',bytes:Buffer.from('replacement fixture'),expectedRevision:1,supersedes:first.ref}));
 f.advance(1000);const result=await f.service.reconcileUploads(f.req('maintenance'));assert.equal(result.retained,1);assert.equal(result.removed,0);
 const originalHash=createHash('sha256').update(command().bytes).digest('hex');
 assert.deepEqual(Buffer.from(await f.objects.get(scope,{key:`${digest(scope)}/${originalHash}`,plaintextHash:originalHash,size:command().bytes.byteLength,keyVersion:'test-key-1'})),Buffer.from(command().bytes));
 assert.equal((await f.service.inspect(f.req(),first.ref)).version.ref.revision,1);
 await f.service.runNextScan(f.req('worker'));await f.service.runNextScan(f.req('worker'));
 assert.deepEqual(Buffer.from(await f.service.read(f.req(),replacement.ref)),Buffer.from('replacement fixture'));
});

test('encrypted object tampering on read durably quarantines evidence without returning plaintext',async t=>{
 const f=await setup(t);const acquired=await f.service.acquire(f.req(),command());await f.service.runNextScan(f.req('worker'));
 const hash=(await f.service.inspect(f.req(),acquired.ref)).version.sha256;const path=join(f.root,digest(scope),hash);const envelope=JSON.parse(await readFile(path,'utf8')) as {tag:string};const tag=Buffer.from(envelope.tag,'base64');tag[0]=tag[0]!^1;envelope.tag=tag.toString('base64');await writeFile(path,JSON.stringify(envelope));
 await assert.rejects(f.service.read(f.req(),acquired.ref),code('object_integrity_failure'));assert.equal((await f.service.inspect(f.req(),acquired.ref)).scan,'quarantined');
});

test('worker claims only the scan topic and a scanner port is mandatory',async t=>{
 const f=await setup(t);await scoped(f.db,f.ctx(),tx=>tx.enqueue('unrelated.topic',{fixture:true},'a-first-unrelated'));
 await f.service.acquire(f.req(),command());assert.equal((await f.service.runNextScan(f.req('worker')))?.verdict,'clean');
 const job=(await f.rows<{topic:string;state:string}>('SELECT topic,state FROM public.evidence_outbox')).find(j=>j.topic==='unrelated.topic');assert.equal(job?.state,'pending');
 assert.throws(()=>new EvidenceService({database:f.db,objects:f.objects,identities:async()=>f.identities,now:()=>BASE} as unknown as ConstructorParameters<typeof EvidenceService>[0]),code('scanner_required'));
});

test('worker credential revocation during scanning prevents publication and recovery quarantines the stalled attempt',async t=>{
 let finish!:(reply:ScanReply)=>void;let started!:(input:ScanInput)=>void;const observed=new Promise<ScanInput>(resolve=>{started=resolve;});
 const f=await setup(t,{scan:async input=>{started(input);return new Promise<ScanReply>(resolve=>{finish=resolve;});}});
 const acquired=await f.service.acquire(f.req(),command());const running=f.service.runNextScan(f.req('worker'));const input=await observed;
 f.identities.find(identity=>identity.actor.id==='worker')!.disabled=true;finish(syntheticClean(input));
 await assert.rejects(running,code('unauthenticated'));assert.equal((await f.service.inspect(f.req(),acquired.ref)).scan,'scanning');
 f.advance(1000);assert.equal(await f.service.recoverStalledScans(f.req('worker2')),1);assert.equal((await f.service.inspect(f.req(),acquired.ref)).scan,'quarantined');
});

test('scan completion acknowledgement, attempt record and aggregate roll back together on publication failure',async t=>{
 const f=await setup(t);const acquired=await f.service.acquire(f.req(),command());
 f.failOnce((sql,values)=>sql.startsWith('INSERT INTO public.evidence_record')&&values?.[2]==='evidence.aggregate'&&JSON.parse(values[5] as string).domain.scans.some((scan:{status:string})=>scan.status==='clean'));
 await assert.rejects(f.service.runNextScan(f.req('worker')),/injected_database_failure/);
 assert.equal((await f.service.inspect(f.req(),acquired.ref)).scan,'scanning');
 const attempts=await scoped(f.db,f.ctx(),tx=>tx.list<{status:string}>('evidence.scan-attempt'));assert.equal(attempts[0]!.value.status,'scanning');
 assert.equal((await f.rows<{state:string}>('SELECT state FROM public.evidence_outbox'))[0]!.state,'leased');
 f.advance(1000);assert.equal((await f.service.runNextScan(f.req('worker2')))?.verdict,'clean');assert.equal(f.seen.length,2);
 assert.deepEqual(Buffer.from(await f.service.read(f.req(),acquired.ref)),Buffer.from(command().bytes));
});

test('owning selector review binds exact current metadata/representation and reports unknown family without exposing histories',async t=>{
 const f=await setup(t);const a=await f.service.acquire(f.req(),command());
 const scan=await f.service.runNextScan(f.req('worker'));const observed=await f.service.inspect(f.req(),a.ref);
 const r=await f.service.representation(f.req(),a.ref,`representation:${digest({attemptId:scan!.attemptId})}`);
 const whole={kind:'whole' as const,evidence:a.ref,sha256:observed.version.sha256};
 const text={kind:'text' as const,evidence:a.ref,sha256:whole.sha256,representationId:r.id,representationDigest:r.digest,page:null,start:0,end:9,quote:'Extracted'};
 const before=await f.rows('SELECT * FROM public.evidence_outbox');
 const result=await f.service.reviewSelectors(f.req('viewer'),[whole,text]);
 assert.equal(result.revision,observed.revision);assert.equal(result.purpose,'verify-fixture');assert.equal(result.selectors.length,2);
 assert.equal(result.sources.uniqueByteCount,1);assert.equal(result.sources.sourceGroupCount,1);assert.equal(result.sources.independentFamilyCount,null);
 assert.deepEqual(result.sources.unknownFamilyRefs,[a.ref]);assert.match(result.selectors[0]!.fingerprint,/^[a-f0-9]{64}$/);
 assert.notEqual(result.selectors[0]!.fingerprint,result.selectors[1]!.fingerprint);
 assert.equal('versions' in result,false);assert.equal('representations' in result,false);assert.equal('families' in result,false);
 assert.equal(JSON.stringify(result).includes(f.tokens.viewer),false);
 assert.deepEqual(await f.rows('SELECT * FROM public.evidence_outbox'),before);
 assert.equal((await f.service.inspect(f.req(),a.ref)).revision,observed.revision);
 Object.assign(result.selectors[0]!.selector.evidence,{id:'caller mutation'});
 assert.equal((await f.service.reviewSelectors(f.req(),[whole])).selectors[0]!.selector.evidence.id,a.ref.id);
});
test('selector review fails closed on quarantine, scope, purpose, hash, quote and extra authority fields with checked-audit rollback',async t=>{
 const f=await setup(t),a=await f.service.acquire(f.req(),command());
 const version=(await f.service.inspect(f.req(),a.ref)).version;
 const q={kind:'whole' as const,evidence:a.ref,sha256:version.sha256};
 await assert.rejects(f.service.reviewSelectors(f.req(),[q]),code('evidence_quarantined'));
 const scan=await f.service.runNextScan(f.req('worker'));const rep=await f.service.representation(f.req(),a.ref,`representation:${digest({attemptId:scan!.attemptId})}`);
 const audits=async()=> (await scoped(f.db,f.ctx(),tx=>tx.audits())).filter(a=>a.type==='evidence.selectors.review_checked');
 for(const run of [
  ()=>f.service.reviewSelectors(f.req('foreign'),[q]),
  ()=>f.service.reviewSelectors(f.req('viewer','other'),[q]),
  ()=>f.service.reviewSelectors(f.req(),[{...q,sha256:'0'.repeat(64)}]),
  ()=>f.service.reviewSelectors(f.req(),[{...q,kind:'text',representationId:rep.id,representationDigest:rep.digest,page:null,start:0,end:1,quote:'wrong'}]),
  ()=>f.service.reviewSelectors(f.req(),[{...q,requireCurrent:false} as typeof q]),
  ()=>f.service.reviewSelectors({...f.req(),roles:['owner']} as EvidenceRequest,[q]),
 ]) await assert.rejects(run());
 assert.equal((await audits()).length,0);
 await f.service.reviewSelectors(f.req(),[q]);
 assert.equal((await audits()).length,1);
 await f.service.quarantine(f.req(),a.ref,(await f.service.inspect(f.req(),a.ref)).revision,'revoke');
 await assert.rejects(f.service.reviewSelectors(f.req(),[q]),code('evidence_quarantined'));
 assert.equal((await audits()).length,1);
});
test('selector review captures request/selectors and reauthenticates after taking owning lock',async t=>{
 const f=await setup(t),a=await f.service.acquire(f.req(),command());await f.service.runNextScan(f.req('worker'));
 const q={kind:'whole' as const,evidence:{...a.ref},sha256:(await f.service.inspect(f.req(),a.ref)).version.sha256},req=f.req('viewer');
 const pending=f.service.reviewSelectors(req,[q]);q.evidence.id='mutation';Object.assign(req,{purpose:'changed'});
 assert.equal((await pending).selectors[0]!.selector.evidence.id,a.ref.id);
 let revoked=false;
 f.failOnce(sql=>{
  if(sql.includes('FROM public.evidence_project') && sql.includes('FOR UPDATE')){f.identities.find(i=>i.actor.id==='viewer')!.disabled=true;revoked=true;}
  return false;
 });
 await assert.rejects(f.service.reviewSelectors(f.req('viewer'),[{...q,evidence:a.ref}]),code('unauthenticated'));
 assert.equal(revoked,true);
});
test('replaced selectors cannot be reviewed as current and copied bytes do not multiply source groups',async t=>{
 const f=await setup(t),a=await f.service.acquire(f.req(),command());await f.service.runNextScan(f.req('worker'));
 const v=await f.service.inspect(f.req(),a.ref),q={kind:'whole' as const,evidence:a.ref,sha256:v.version.sha256};
 const b=await f.service.acquire(f.req(),command({id:'copy',idempotencyKey:'copy',acquisitionId:'copy',expectedRevision:v.revision}));await f.service.runNextScan(f.req('worker'));
 const result=await f.service.reviewSelectors(f.req(),[q,{...q,evidence:b.ref}]);
 assert.equal(result.sources.sourceGroupCount,1);assert.equal(result.sources.uniqueByteCount,1);assert.equal(result.sources.independentFamilyCount,null);
 const current=await f.service.inspect(f.req(),a.ref);
 await f.service.acquire(f.req(),command({idempotencyKey:'replacement-review',acquisitionId:'new',expectedRevision:current.revision,supersedes:a.ref,bytes:Buffer.from('new neutral fixture')}));
 await assert.rejects(f.service.reviewSelectors(f.req(),[q]),code('stale_revision'));
});
