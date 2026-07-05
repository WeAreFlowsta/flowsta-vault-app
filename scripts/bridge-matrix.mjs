#!/usr/bin/env node
/**
 * Headless operation matrix for the Vault bridge.
 *
 * Drives sign / amend / revoke / thumbnail / profile through the localhost
 * bridge across the cold-start / locked / denied / double-submit conditions,
 * using the job model end to end. Requires a DEBUG vault started with
 * FLOWSTA_VAULT_AUTO_APPROVE=1 (approval dialogs resolve headlessly; the
 * /dev/lock + /dev/unlock endpoints and the x-flowsta-test-deny header are
 * active only then).
 *
 * Usage:
 *   node scripts/bridge-matrix.mjs --phase=refusal   # quota-refusal leg only
 *   node scripts/bridge-matrix.mjs --phase=full      # everything else
 *   node scripts/bridge-matrix.mjs                   # all legs
 *
 * Env:
 *   VAULT_MATRIX_ORIGIN   Flowsta page origin to impersonate
 *                         (default https://ourtest.flowsta.com)
 *   VAULT_MATRIX_NAME     display name used by the profile legs
 *                         (default: keep whatever /status reports)
 *   VAULT_MATRIX_API      API base for quota cross-checks
 *                         (default https://auth-api-staging.flowsta.com)
 */

import crypto from 'node:crypto';

const ORIGIN = process.env.VAULT_MATRIX_ORIGIN || 'https://ourtest.flowsta.com';
const EVIL_ORIGIN = 'https://example.com';
const API = process.env.VAULT_MATRIX_API || 'https://auth-api-staging.flowsta.com';
const PHASE = (process.argv.find((a) => a.startsWith('--phase=')) || '--phase=all').split('=')[1];

const TINY_PNG =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
const TINY_PNG_2 =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

let PORT = null;
const results = [];
let failures = 0;

function record(name, ok, detail = '') {
  results.push({ name, ok, detail });
  if (!ok) failures++;
  console.log(`${ok ? '  ✓' : '  ✗ FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
}

function randomHash() {
  return crypto.randomBytes(32).toString('hex');
}

async function api(path, { method = 'GET', body, origin = ORIGIN, deny = false } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (origin) headers.origin = origin;
  if (deny) headers['x-flowsta-test-deny'] = '1';
  const resp = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await resp.json().catch(() => null);
  return { status: resp.status, data };
}

async function findPort() {
  for (const p of [27777, 27778, 27779]) {
    try {
      const resp = await fetch(`http://127.0.0.1:${p}/status`, {
        signal: AbortSignal.timeout(2000),
      });
      if (resp.ok) {
        PORT = p;
        return resp.json();
      }
    } catch {}
  }
  throw new Error('Vault bridge not reachable on 27777-27779. Is the vault running?');
}

async function submitJob(path, body, opts = {}) {
  const { status, data } = await api(path, { method: 'POST', body: { ...body, job: true }, ...opts });
  if (status !== 200 || !data?.job_id) {
    throw new Error(`job submit ${path} failed: ${status} ${JSON.stringify(data)}`);
  }
  return data.job_id;
}

/** Poll a job to completion. Returns { stages, final } where final is the
 * last snapshot (stage done or failed). */
async function pollJob(jobId, { timeoutMs = 15 * 60 * 1000, intervalMs = 750 } = {}) {
  const stages = [];
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { status, data } = await api(`/op-status/${jobId}`);
    if (status === 404) throw new Error(`job ${jobId} expired/unknown`);
    if (data?.stage && data.stage !== stages[stages.length - 1]) stages.push(data.stage);
    if (data?.stage === 'done' || data?.stage === 'failed') return { stages, final: data };
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`job ${jobId} did not finish within ${timeoutMs / 1000}s (stages: ${stages})`);
}

async function runJob(path, body, opts = {}) {
  const jobId = await submitJob(path, body, opts);
  return { jobId, ...(await pollJob(jobId, opts)) };
}

/** Fetch /signatures with retries (right after a cold start the conductor
 * needs a few seconds). */
async function getSignatures({ attempts = 20, delayMs = 3000 } = {}) {
  let last;
  for (let i = 0; i < attempts; i++) {
    last = await api('/signatures');
    if (last.status === 200) return last.data.signatures;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw new Error(`/signatures unavailable: ${last.status} ${JSON.stringify(last.data)}`);
}

async function findRecord(fileHash, { attempts = 10, delayMs = 1000 } = {}) {
  for (let i = 0; i < attempts; i++) {
    const sigs = await getSignatures();
    const hits = sigs.filter((s) => s.file_hash === fileHash);
    if (hits.length > 0) return { hits, all: sigs };
    await new Promise((r) => setTimeout(r, delayMs));
  }
  return { hits: [], all: await getSignatures() };
}

async function serverQuota(agentKey) {
  try {
    const resp = await fetch(
      `${API}/api/v1/sign-it/quota/by-agent?agent_pub_key=${encodeURIComponent(agentKey)}`,
      { signal: AbortSignal.timeout(10000) },
    );
    if (!resp.ok) return null;
    return resp.json();
  } catch {
    return null;
  }
}

function signBody(fileHash, extra = {}) {
  return {
    file_hash: fileHash,
    label: 'bridge-matrix.txt',
    app_name: 'Bridge matrix',
    comment: 'automated bridge matrix run',
    thumbnail: TINY_PNG,
    commit: true,
    ...extra,
  };
}

// ───────────────────────── legs ─────────────────────────

async function preflight() {
  console.log('\n── Preflight');
  const status = await findPort();
  record('bridge reachable', true, `port ${PORT}`);
  record('vault unlocked', status.unlocked === true);
  if (!status.unlocked) throw new Error('Unlock the vault first, then re-run.');

  // Dev endpoints active = the auto-approve flag is actually on.
  const devProbe = await api('/dev/unlock', { method: 'POST', body: {} });
  const devActive = devProbe.status === 400 || devProbe.status === 200;
  record('dev harness endpoints active (auto-approve flag on)', devActive,
    devActive ? '' : `got ${devProbe.status} — start the vault with FLOWSTA_VAULT_AUTO_APPROVE=1`);
  if (!devActive) throw new Error('auto-approve flag missing');
  if (devProbe.status === 200) {
    // Shouldn't happen (nothing stashed yet) but leave the vault unlocked.
    console.log('  (note: /dev/unlock returned 200 on probe)');
  }

  const sigs = await getSignatures();
  record('GET /signatures (flowsta origin)', Array.isArray(sigs), `${sigs.length} records`);

  const evil = await api('/signatures', { origin: EVIL_ORIGIN });
  record('GET /signatures refused for non-Flowsta origin', evil.status === 403 && evil.data?.error === 'tier_forbidden');

  const noOrigin = await api('/signatures', { origin: null });
  record('GET /signatures refused without origin', noOrigin.status === 403);

  return { status, baseline: sigs };
}

async function guardLegs() {
  console.log('\n── Guards');
  const evilCommit = await api('/sign-document', {
    method: 'POST',
    body: signBody(randomHash()),
    origin: EVIL_ORIGIN,
  });
  record('commit refused for non-Flowsta origin', evilCommit.status === 403 && evilCommit.data?.error === 'tier_forbidden');

  const badHash = await api('/sign-document', { method: 'POST', body: signBody('nothex') });
  record('invalid file_hash refused', badHash.status === 400 && badHash.data?.error === 'invalid_file_hash');

  const reserved = Buffer.from('flowsta-auth-challenge:v1:xx1234', 'ascii').toString('hex');
  const reservedResp = await api('/sign-document', { method: 'POST', body: signBody(reserved) });
  record('reserved-prefix hash refused', reservedResp.status === 403 && reservedResp.data?.error === 'reserved_prefix');

  const unknownJob = await api('/op-status/sign-0-deadbeef');
  record('unknown job id → 404', unknownJob.status === 404);

  const badSupersedes = await api('/sign-document', {
    method: 'POST',
    body: signBody(randomHash(), { supersedes: 'zz' }),
  });
  record('invalid supersedes refused', badSupersedes.status === 400);
}

async function quotaRefusalLeg(agentKey) {
  console.log('\n── Quota refusal (expects the account at/over its limit)');
  const before = await serverQuota(agentKey);
  if (before) console.log(`  server quota: ${before.used}/${before.limit} (${before.tier})`);
  const { stages, final } = await runJob('/sign-document', signBody(randomHash()));
  record('sign at exhausted quota fails', final.stage === 'failed', JSON.stringify(final));
  record('…with quota_exceeded', final.error === 'quota_exceeded', final.error || '');
  record('…refused BEFORE the approval dialog', !stages.includes('awaiting_approval'), `stages: ${stages}`);
}

async function happyRow(profileName) {
  console.log('\n── Happy row (one of each op)');
  const hashA = randomHash();

  const sign = await runJob('/sign-document', signBody(hashA));
  record('sign publishes', sign.final.stage === 'done' && !!sign.final.result?.action_hash, JSON.stringify(sign.final).slice(0, 200));
  // Note: awaiting_approval is usually too brief to observe under
  // auto-approve — publishing is the stage that proves the pipeline ran.
  record('sign stages truthful', sign.stages.includes('publishing') && sign.stages[sign.stages.length - 1] === 'done', `stages: ${sign.stages}`);
  const recA = await findRecord(hashA);
  record('signature visible in Vault-first read within seconds', recA.hits.length === 1);
  // The thumbnail rides BEHIND the publish (background task) — poll for it.
  let thumbSeen = false;
  for (let i = 0; i < 30 && !thumbSeen; i++) {
    const check = await findRecord(hashA, { attempts: 1 });
    thumbSeen = !!check.hits[0]?.thumbnail;
    if (!thumbSeen) await new Promise((r) => setTimeout(r, 3000));
  }
  record('…thumbnail lands shortly after (background ride)', thumbSeen);
  const aHash = sign.final.result?.action_hash;

  const amend = await runJob('/sign-document', signBody(hashA, { supersedes: aHash, thumbnail: TINY_PNG_2, comment: 'amended by matrix' }));
  record('amend publishes', amend.final.stage === 'done' && !!amend.final.result?.action_hash);
  const bHash = amend.final.result?.action_hash;
  const recAfterAmend = await findRecord(hashA);
  const recB = recAfterAmend.hits.find((s) => s.action_hash === bHash);
  record('amend record carries supersedes marker', recB?.supersedes === aHash, `got ${recB?.supersedes}`);

  const thumb = await runJob('/set-thumbnail', { action_hash: bHash, thumbnail: TINY_PNG });
  record('thumbnail publishes', thumb.final.stage === 'done' && !!thumb.final.result?.thumbnail_hash, JSON.stringify(thumb.final).slice(0, 200));

  const revoke = await runJob('/revoke-signature', { action_hash: aHash, reason: 'matrix: superseded original' });
  record('revoke publishes', revoke.final.stage === 'done' && !!revoke.final.result?.revocation_hash, JSON.stringify(revoke.final).slice(0, 200));
  const recAfterRevoke = await findRecord(hashA);
  const revokedA = recAfterRevoke.hits.find((s) => s.action_hash === aHash);
  record('revocation visible in Vault-first read', revokedA?.revoked === true);

  const profile = await runJob('/profile-update', { display_name: profileName });
  record('profile update lands', profile.final.stage === 'done', JSON.stringify(profile.final).slice(0, 200));

  return { hashA, aHash, bHash };
}

async function deniedRow(ctx, profileName) {
  console.log('\n── Denied row');
  const freshHash = randomHash();
  const sign = await runJob('/sign-document', signBody(freshHash), { deny: true });
  record('denied sign fails with user_denied', sign.final.stage === 'failed' && sign.final.error === 'user_denied', JSON.stringify(sign.final).slice(0, 160));
  const rec = await findRecord(freshHash, { attempts: 2, delayMs: 1000 });
  record('denied sign published NOTHING', rec.hits.length === 0);

  const amend = await runJob('/sign-document', signBody(ctx.hashA, { supersedes: ctx.bHash }), { deny: true });
  record('denied amend fails with user_denied', amend.final.stage === 'failed' && amend.final.error === 'user_denied');

  const revoke = await runJob('/revoke-signature', { action_hash: ctx.bHash, reason: 'matrix denied' }, { deny: true });
  record('denied revoke fails with user_denied', revoke.final.stage === 'failed' && revoke.final.error === 'user_denied');
  const recB = await findRecord(ctx.hashA, { attempts: 1 });
  record('denied revoke changed nothing', recB.hits.find((s) => s.action_hash === ctx.bHash)?.revoked !== true);

  const thumb = await runJob('/set-thumbnail', { action_hash: ctx.bHash, thumbnail: TINY_PNG_2 }, { deny: true });
  record('denied thumbnail fails with user_denied', thumb.final.stage === 'failed' && thumb.final.error === 'user_denied');

  const profile = await runJob('/profile-update', { display_name: `${profileName} DENIED` }, { deny: true });
  record('denied profile fails with user_denied', profile.final.stage === 'failed' && profile.final.error === 'user_denied');
}

async function doubleSubmitRow(profileName) {
  console.log('\n── Double-submit row');
  const hashC = randomHash();
  const body = signBody(hashC);
  const [id1, id2] = await Promise.all([
    submitJob('/sign-document', body),
    submitJob('/sign-document', body),
  ]);
  record('double sign submit coalesces to one job', id1 === id2, `${id1} vs ${id2}`);
  const done = await pollJob(id1);
  record('coalesced sign completes', done.final.stage === 'done' && !!done.final.result?.action_hash);
  const rec = await findRecord(hashC);
  record('exactly ONE record published for double submit', rec.hits.length === 1, `${rec.hits.length} records`);
  const cHash = done.final.result?.action_hash;

  const [t1, t2] = await Promise.all([
    submitJob('/set-thumbnail', { action_hash: cHash, thumbnail: TINY_PNG_2 }),
    submitJob('/set-thumbnail', { action_hash: cHash, thumbnail: TINY_PNG_2 }),
  ]);
  record('double thumbnail coalesces', t1 === t2);
  const tDone = await pollJob(t1);
  record('coalesced thumbnail completes', tDone.final.stage === 'done');

  const [r1, r2] = await Promise.all([
    submitJob('/revoke-signature', { action_hash: cHash, reason: 'matrix double revoke' }),
    submitJob('/revoke-signature', { action_hash: cHash, reason: 'matrix double revoke' }),
  ]);
  record('double revoke coalesces', r1 === r2);
  const rDone = await pollJob(r1);
  record('coalesced revoke completes', rDone.final.stage === 'done');

  const [p1, p2] = await Promise.all([
    submitJob('/profile-update', { display_name: profileName }),
    submitJob('/profile-update', { display_name: profileName }),
  ]);
  record('double profile coalesces', p1 === p2);
  const pDone = await pollJob(p1);
  record('coalesced profile completes', pDone.final.stage === 'done');

  return { hashC, cHash };
}

async function lockedRow(ctx, profileName) {
  console.log('\n── Locked row (submit while locked, then unlock)');
  const lock = await api('/dev/lock', { method: 'POST', body: {} });
  record('/dev/lock', lock.status === 200, JSON.stringify(lock.data));

  const st = await api('/status');
  record('status reports locked', st.data?.unlocked === false);
  const readLocked = await api('/signatures');
  record('locked read refuses without popping unlock', readLocked.status === 403 && readLocked.data?.error === 'vault_locked');

  const hashE = randomHash();
  const jobs = {
    sign: await submitJob('/sign-document', signBody(hashE)),
    thumbnail: await submitJob('/set-thumbnail', { action_hash: ctx.bHash, thumbnail: TINY_PNG }),
    revoke: await submitJob('/revoke-signature', { action_hash: ctx.bHash, reason: 'matrix: locked-row revoke' }),
    profile: await submitJob('/profile-update', { display_name: profileName }),
  };

  // Every job should truthfully report waiting_unlock while locked.
  await new Promise((r) => setTimeout(r, 2500));
  for (const [op, id] of Object.entries(jobs)) {
    const snap = await api(`/op-status/${id}`);
    record(`${op} job reports waiting_unlock while locked`, snap.data?.stage === 'waiting_unlock', `stage: ${snap.data?.stage}`);
  }

  const unlock = await api('/dev/unlock', { method: 'POST', body: {} });
  record('/dev/unlock', unlock.status === 200, JSON.stringify(unlock.data).slice(0, 120));

  for (const [op, id] of Object.entries(jobs)) {
    const done = await pollJob(id);
    record(`${op} job rides through unlock to done`, done.final.stage === 'done', `${JSON.stringify(done.final).slice(0, 160)} stages: ${done.stages}`);
  }
  const recE = await findRecord(hashE);
  record('locked-row sign visible in Vault-first read', recE.hits.length === 1);
}

async function coldStartRow(ctx, profileName) {
  console.log('\n── Cold-start row (submit immediately after unlock)');
  const lock = await api('/dev/lock', { method: 'POST', body: {} });
  record('/dev/lock (cold prep)', lock.status === 200);
  const unlock = await api('/dev/unlock', { method: 'POST', body: {} });
  record('/dev/unlock (cold prep)', unlock.status === 200);

  const hashF = randomHash();
  const jobs = {
    sign: await submitJob('/sign-document', signBody(hashF)),
    thumbnail: await submitJob('/set-thumbnail', { action_hash: ctx.cHash, thumbnail: TINY_PNG }),
    profile: await submitJob('/profile-update', { display_name: profileName }),
  };

  const outcomes = {};
  for (const [op, id] of Object.entries(jobs)) {
    outcomes[op] = await pollJob(id);
    record(`${op} cold-start job completes`, outcomes[op].final.stage === 'done', `${JSON.stringify(outcomes[op].final).slice(0, 160)} stages: ${outcomes[op].stages}`);
  }
  record('cold-start jobs saw a preparing stage', Object.values(outcomes).some((o) => o.stages.includes('preparing')),
    Object.entries(outcomes).map(([k, o]) => `${k}: ${o.stages}`).join(' | '));
  const recF = await findRecord(hashF);
  record('cold-start sign visible in Vault-first read', recF.hits.length === 1);
}

async function signatureOnlyLeg(baselineCount) {
  console.log('\n── Signature-only (non-Flowsta app, no publish)');
  const h = randomHash();
  const resp = await api('/sign-document', {
    method: 'POST',
    body: { file_hash: h, app_name: 'Matrix third-party', commit: false },
    origin: EVIL_ORIGIN,
  });
  record('signature-only sign works for any origin', resp.status === 200 && !!resp.data?.signature);
  record('…and returns no action_hash', !resp.data?.action_hash);
  const sigs = await getSignatures();
  record('…and published nothing', !sigs.some((s) => s.file_hash === h));
}

// ───────────────────────── main ─────────────────────────

(async () => {
  console.log(`Bridge matrix — phase: ${PHASE}, origin: ${ORIGIN}`);
  const { status, baseline } = await preflight();
  const agentKey = status.agent_pub_key;
  const profileName = process.env.VAULT_MATRIX_NAME || status.display_name || 'Vlah test';

  await guardLegs();

  if (PHASE === 'refusal' || PHASE === 'all') {
    await quotaRefusalLeg(agentKey);
  }

  if (PHASE === 'full' || PHASE === 'all') {
    const quotaBefore = await serverQuota(agentKey);
    const ctx = await happyRow(profileName);
    await deniedRow(ctx, profileName);
    const dbl = await doubleSubmitRow(profileName);
    await lockedRow({ ...ctx, ...dbl }, profileName);
    await coldStartRow({ ...ctx, ...dbl }, profileName);
    await signatureOnlyLeg(baseline.length);

    // Quota accounting: 5 publishes (happy sign+amend, double sign, locked
    // sign, cold sign). Server sync is async — give it a moment.
    if (quotaBefore) {
      await new Promise((r) => setTimeout(r, 10000));
      const quotaAfter = await serverQuota(agentKey);
      record('server quota ticked for every publish', quotaAfter && quotaAfter.used === quotaBefore.used + 5,
        `before ${quotaBefore.used}, after ${quotaAfter?.used} (expected +5)`);
    }
  }

  const passed = results.filter((r) => r.ok).length;
  console.log(`\nRESULT: ${passed}/${results.length} checks passed${failures ? ` — ${failures} FAILED` : ' — ALL GREEN'}`);
  if (failures) {
    console.log('\nFailed checks:');
    for (const r of results.filter((x) => !x.ok)) console.log(`  ✗ ${r.name} ${r.detail}`);
  }
  process.exit(failures ? 1 : 0);
})().catch((e) => {
  console.error(`\nABORTED: ${e.message}`);
  process.exit(2);
});
