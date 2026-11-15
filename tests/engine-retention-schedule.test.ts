// Scheduled disposal execution: a schedule set with `execute: true` by a holder of evidence:admin is carried out by the
// worker when it falls due; holds, cleared/changed schedules and a refused re-authorization delete nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { AuthorizationPort } from '../src/service-kit.ts';
import { ctx, code, manual, needsPg, utf8, withEngine } from './engine-helpers.ts';

const auth = { authorizedBy: 'records-officer-1', basis: 'fictional retention schedule 7', reference: 'decision-2026-12' };
const past = '2026-01-01T00:00:00.000Z';
const future = '2999-01-01T00:00:00.000Z';

test('scheduled disposal executes when due; future, held, cleared and non-executable schedules delete nothing', needsPg, async () => {
  await withEngine({ scanner: 'none' }, async ({ engine, objects }) => {
    const accept = (s: string) => engine.accept(ctx(), { bytes: utf8(s), mediaType: 'text/plain', filename: `${s}.txt`, origin: manual });
    const due = await accept('fictional record due now');
    const later = await accept('fictional record due later');
    const listed = await accept('fictional record listed only');
    const held = await accept('fictional record under hold');
    const cleared = await accept('fictional record schedule cleared');
    assert.equal((await objects.list('tenant-a/')).length, 5);

    // execute needs the disposal capability and applies only to a schedule
    const retainOnly = ctx({ capabilities: ['evidence:read', 'evidence:retain'] });
    await assert.rejects(engine.setRetention(retainOnly, due.ref, { action: 'schedule', reason: 'r', disposeAfter: past, execute: true, authorization: auth }), code('forbidden'));
    await assert.rejects(engine.setRetention(ctx(), due.ref, { action: 'hold', reason: 'r', execute: true, authorization: auth }), code('invalid_input'));
    await assert.rejects(engine.setRetention(ctx(), due.ref, { action: 'schedule', reason: 'r', disposeAfter: past, execute: 'yes' as never, authorization: auth }), code('invalid_input'));

    for (const [v, at] of [[due, past], [later, future], [held, past], [cleared, past]] as const) await engine.setRetention(ctx(), v.ref, { action: 'schedule', reason: 'period ended', disposeAfter: at, execute: true, authorization: auth });
    await engine.setRetention(retainOnly, listed.ref, { action: 'schedule', reason: 'period ended', disposeAfter: past, authorization: auth });
    await engine.setRetention(ctx(), held.ref, { action: 'hold', reason: 'fictional litigation hold', authorization: auth });
    await engine.setRetention(ctx(), cleared.ref, { action: 'clear_schedule', reason: 'kept for review', authorization: auth });

    while (await engine.runJobsOnce({ limit: 20 }) > 0) { /* drain */ }
    const state = async (ref: string) => (await engine.describeVersion(ctx(), ref))!.bytesState;
    assert.equal(await state(due.ref), 'disposed');
    assert.deepEqual([await state(later.ref), await state(listed.ref), await state(held.ref), await state(cleared.ref)], ['present', 'present', 'present', 'present']);
    assert.equal((await objects.list('tenant-a/')).length, 4, 'exactly one object removed');
    assert.deepEqual((await engine.dueForDisposal(ctx())).map((v) => v.ref), [listed.ref], 'a non-executable schedule is still only listed');

    const prov = await engine.provenance(ctx(), due.ref);
    const disposal = prov.retention.at(-1) as { action: string; reason: string; authorization: unknown };
    assert.equal(disposal.action, 'disposal'); assert.match(disposal.reason, /^Scheduled disposal: period ended/); assert.deepEqual(disposal.authorization, auth);
    assert.ok(prov.custodyChainValid); assert.ok(prov.gaps.some((g) => g.code === 'bytes_disposed'));
    const skipped = (await engine.audit(ctx())).filter((a) => a.action === 'evidence.scheduled_disposal_skipped').map((a) => (a.detail as { reason: string }).reason).sort();
    assert.deepEqual(skipped, ['hold', 'schedule_changed']);

    // releasing the hold re-enqueues the still-executable schedule, which then runs
    await engine.setRetention(ctx(), held.ref, { action: 'release_hold', reason: 'litigation ended', authorization: auth });
    while (await engine.runJobsOnce({ limit: 20 }) > 0) { /* drain */ }
    assert.equal(await state(held.ref), 'disposed');
    assert.deepEqual((await engine.verifyAll(ctx())).ok, true);
  });
});

test('scheduled disposal re-asks the authorization port at execution time and deletes nothing when refused', needsPg, async () => {
  let allow = true;
  const authorization: AuthorizationPort = { authorize: async () => ({ allowed: allow, reason: allow ? 'fixture allows' : 'fixture withdrew authority', policyVersion: 'fixture-1' }) };
  await withEngine({ scanner: 'none', ports: { authorization } }, async ({ engine, objects }) => {
    const v = await engine.accept(ctx(), { bytes: utf8('fictional record, authority later withdrawn'), mediaType: 'text/plain', filename: 'w.txt', origin: manual });
    await engine.setRetention(ctx(), v.ref, { action: 'schedule', reason: 'period ended', disposeAfter: past, execute: true, authorization: auth });
    allow = false;
    while (await engine.runJobsOnce({ limit: 20 }) > 0) { /* drain */ }
    assert.equal((await engine.describeVersion(ctx(), v.ref))!.bytesState, 'present');
    assert.equal((await objects.list('tenant-a/')).length, 1);
    assert.deepEqual((await engine.audit(ctx())).filter((a) => a.action === 'evidence.scheduled_disposal_skipped').map((a) => (a.detail as { reason: string }).reason), ['authorization_refused']);
  });
});
