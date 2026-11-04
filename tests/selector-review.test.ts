import test from 'node:test';
import assert from 'node:assert/strict';
import {captureSelectors,assertReviewBudget} from '../src/selector-review.ts';
import {createEvidenceState} from '../src/index.ts';
import type {Context} from '../src/contracts.ts';
const c:Context={tenantId:'fiction',projectId:'review',actor:{kind:'human',id:'owner',roles:['owner']},purpose:'review',now:'2026-01-01T00:00:00Z',requestId:'fixture'};
const q={kind:'whole' as const,evidence:{tenantId:c.tenantId,projectId:c.projectId,kind:'evidence' as const,id:'source',revision:1},sha256:'0'.repeat(64)};
test('selector count/UTF8 byte/exact-field limits reject before directory or SQL admission',()=>{
 for(const bad of [[],Array(65).fill(q),[{...q,kind:'text',representationId:'r',representationDigest:q.sha256,page:null,start:0,end:30000,quote:'😀'.repeat(30000)}],[{...q,requireCurrent:false}],[{...q,evidence:{...q.evidence,kind:'claim'}}]])
  assert.throws(()=>captureSelectors(bad as typeof q[]));
 assert.equal(captureSelectors(Array(64).fill(q)).length,64);
});
test('stored graph preflight rejects cycles, excessive ancestry expansion and aggregate budgets before recursive validation',()=>{
 const state=createEvidenceState(c);assert.doesNotThrow(()=>assertReviewBudget(state));
 const family=(id:string,parentIds:string[])=>({id,label:'Neutral family',parentIds,reason:'Fixture ancestry'});
 assert.throws(()=>assertReviewBudget({...state,families:[family('a',['b']),family('b',['a'])]}),{code:'review_full'});
 const graph=Array.from({length:20},(_,i)=>family(String(i),i<2?[]:[String(i-1),String(i-2)]));
 assert.throws(()=>assertReviewBudget({...state,families:graph}),{code:'review_full'});
 assert.throws(()=>assertReviewBudget({...state,families:Array.from({length:65},(_,i)=>family(String(i),[]))}),{code:'review_full'});
 assert.throws(()=>assertReviewBudget({...state,handling:Array(4097).fill({})}),{code:'review_full'});
 assert.throws(()=>assertReviewBudget({...state,families:[{...family('big',[]),label:'x'.repeat(8*1024*1024)}]}),{code:'review_full'});
});
