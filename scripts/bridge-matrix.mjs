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
 *   node scripts/bridge-matrix.mjs --phase=backup    # third-party /backup leg
 *   node scripts/bridge-matrix.mjs --phase=password  # change → relock → unlock with the new one → ready
 *   node scripts/bridge-matrix.mjs --phase=grants    # email never leaks without a grant; scopes ride /authenticate
 *   node scripts/bridge-matrix.mjs --phase=full      # everything else
 *   node scripts/bridge-matrix.mjs --phase=create    # create an identity on a FRESH instance (+ restore twin)
 *       needs VAULT_MATRIX_PORT = a fresh test instance (no identity yet), and
 *       optionally VAULT_MATRIX_RESTORE_PORT = a second fresh instance for the twin
 *   node scripts/bridge-matrix.mjs                   # all legs
 *
 * Env:
 *   VAULT_MATRIX_ORIGIN   Flowsta page origin to impersonate
 *                         (default https://ourtest.flowsta.com)
 *   VAULT_MATRIX_NAME     display name used by the profile legs
 *                         (default: keep whatever /status reports)
 *   VAULT_MATRIX_API      API base for quota cross-checks
 *                         (default https://auth-api-staging.flowsta.com)
 *   VAULT_MATRIX_APP_CLIENT_ID
 *                         registered third-party app client_id for the
 *                         backup leg (leg self-skips when unset)
 *   VAULT_MATRIX_PASSWORD the dev vault's CURRENT unlock password, for the
 *                         password leg (leg self-skips when unset; the leg
 *                         changes it and changes it back)
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
  // VAULT_MATRIX_PORT pins the target - the scan takes the FIRST responding
  // port, which is wrong when an installed vault (27777) and a dev vault
  // (27778) are both running.
  const pinned = Number(process.env.VAULT_MATRIX_PORT || 0);
  const ports = pinned ? [pinned] : [27777, 27778, 27779];
  for (const p of ports) {
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
  // GET /dev/status is nondestructive (a POST probe once re-unlocked a live
  // vault and respawned the conductor mid-run).
  const devProbe = await api('/dev/status');
  const devActive = devProbe.status === 200 && devProbe.data?.harness === true;
  record('dev harness endpoints active (auto-approve flag on)', devActive,
    devActive ? '' : `got ${devProbe.status} — start the vault with FLOWSTA_VAULT_AUTO_APPROVE=1`);
  if (!devActive) throw new Error('auto-approve flag missing');

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

  // /authenticate reserved-prefix carve-out. This endpoint IS the web
  // vault-grant login, so it must sign the `flowsta-auth-challenge:v1:`
  // string - but ONLY for a first-party origin, and no other reserved
  // prefix, ever. (A 2026-07-09 hardening blanket-refused all of them and
  // silently broke Chromium desktop login until 2026-08-02.)
  const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
  const loginFromFlowsta = await api('/authenticate', {
    method: 'POST', origin: ORIGIN,
    body: { app_name: 'Flowsta', challenge: b64('flowsta-auth-challenge:v1:matrixnonce:flowsta'), reason: 'matrix login' },
  });
  record('login challenge signs from a Flowsta origin',
    loginFromFlowsta.status === 200 && !!loginFromFlowsta.data?.signature,
    `${loginFromFlowsta.status} ${loginFromFlowsta.data?.error || ''}`);

  const loginFromEvil = await api('/authenticate', {
    method: 'POST', origin: EVIL_ORIGIN,
    body: { app_name: 'Evil', challenge: b64('flowsta-auth-challenge:v1:matrixnonce:flowsta'), reason: 'matrix login' },
  });
  record('login challenge refused from a non-Flowsta origin',
    loginFromEvil.status === 400 && loginFromEvil.data?.error === 'reserved_prefix',
    `${loginFromEvil.status} ${loginFromEvil.data?.error || ''}`);

  const relayFromFlowsta = await api('/authenticate', {
    method: 'POST', origin: ORIGIN,
    body: { app_name: 'Flowsta', challenge: b64('flowsta-relay-login:v1:matrixnonce'), reason: 'matrix relay' },
  });
  record('other reserved prefixes refused even from Flowsta',
    relayFromFlowsta.status === 400 && relayFromFlowsta.data?.error === 'reserved_prefix',
    `${relayFromFlowsta.status} ${relayFromFlowsta.data?.error || ''}`);
}

async function quotaRefusalLeg(agentKey) {
  console.log('\n── Quota refusal (expects the account at/over its limit)');
  const before = await serverQuota(agentKey);
  if (before) console.log(`  server quota: ${before.used}/${before.limit} (${before.tier})`);
  if (before && before.used < before.limit) {
    record(`quota refusal skipped - account not exhausted (${before.used}/${before.limit} ${before.tier}); run --phase=refusal on an at-limit account to exercise it`, true);
    return;
  }
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
  // Stages may be too brief to OBSERVE (fast pipeline vs 750ms polls) —
  // truthfulness means every stage we did see is a known stage in pipeline
  // order, ending at done.
  const PIPELINE = ['waiting_unlock', 'preparing', 'awaiting_approval', 'publishing', 'done'];
  const idxs = sign.stages.map((st) => PIPELINE.indexOf(st));
  const ordered = idxs.every((v, i) => v >= 0 && (i === 0 || v >= idxs[i - 1]));
  record('sign stages truthful', ordered && sign.stages[sign.stages.length - 1] === 'done', `stages: ${sign.stages}`);
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
  record('amend publishes', amend.final.stage === 'done' && !!amend.final.result?.action_hash, JSON.stringify(amend.final).slice(0, 200));
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

  // Login challenge arriving while LOCKED is HELD through the unlock (the
  // sign-in page's zero-click promise): /authenticate must not answer
  // vault_locked straight away - it raises the unlock screen, waits, and
  // carries the same request into approval once unlocked.
  const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
  let heldSettled = false;
  const heldLogin = api('/authenticate', {
    method: 'POST', origin: ORIGIN,
    body: { app_name: 'Flowsta', challenge: b64('flowsta-auth-challenge:v1:matrixheld:flowsta'), reason: 'matrix: held through unlock' },
  }).then((r) => { heldSettled = true; return r; });
  await new Promise((r) => setTimeout(r, 2500));
  record('login challenge is HELD while locked (no immediate vault_locked)', !heldSettled);

  const unlock = await api('/dev/unlock', { method: 'POST', body: {} });
  record('/dev/unlock', unlock.status === 200, JSON.stringify(unlock.data).slice(0, 120));

  const heldResult = await heldLogin;
  record('held login challenge signs after unlock',
    heldResult.status === 200 && !!heldResult.data?.signature,
    `${heldResult.status} ${heldResult.data?.error || ''}`);

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


// ── Profile sync leg: a bridge write must land in the vault's own state
// (the config mirror the app UI and header chip read), and at rest the
// server's public-profile cache must agree with the vault. The bridge
// itself never pushes the cache — the web dashboard and the in-app editor
// do — so the cache comparison happens only after the baseline restore.
// Picture writes are NOT exercised here: /dev/identity exposes only the
// picture length, so a test could not restore a real avatar it clobbered.
async function profileSyncLeg(trueBaseline) {
  console.log('\n── Profile sync leg');
  const before = await api('/dev/identity');
  record('identity read-back available', before.status === 200 && !!before.data, JSON.stringify(before.data)?.slice(0, 140));
  if (before.status !== 200) return;
  // Earlier legs rename the vault to profileName — restore to the name
  // the vault held BEFORE the matrix ran, not to their leftovers.
  const original = trueBaseline ?? before.data.display_name;
  const originalPicLen = before.data.profile_picture_len;

  const testName = `Matrix Sync ${Date.now() % 100000}`;
  const set = await runJob('/profile-update', { display_name: testName });
  record('sync: bridge write lands', set.final.stage === 'done');
  let ident = await api('/dev/identity');
  record('sync: vault state reflects the write immediately (no reload)',
    ident.data?.display_name === testName, `vault now "${ident.data?.display_name}"`);

  const restore = await runJob('/profile-update', { display_name: original });
  record('sync: baseline name restored', restore.final.stage === 'done');
  ident = await api('/dev/identity');
  record('sync: vault back to baseline', ident.data?.display_name === original);

  const uname = ident.data?.web_username;
  if (!uname) {
    record('server cache cross-check skipped (no username set)', true);
    return;
  }
  // The cache is an async best-effort projection (vault frontend pushes it
  // after the event lands) - allow it a few seconds to catch up.
  let prof = null;
  let cacheOk = false;
  for (let i = 0; i < 5; i++) {
    const resp = await fetch(`${API}/api/v1/profiles/by-username/${encodeURIComponent(uname)}`);
    prof = resp.ok ? (await resp.json().catch(() => null))?.profile : null;
    if (prof?.display_name === original) { cacheOk = true; break; }
    await new Promise((r) => setTimeout(r, 2000));
  }
  record('server profile cache agrees with vault at rest', cacheOk,
    `cache "${prof?.display_name}" vs vault "${original}"`);
  record('server cache has an avatar when the vault does',
    prof && (originalPicLen > 0 ? !!prof?.profile_picture : true),
    `vault pic len ${originalPicLen}, cache pic ${prof?.profile_picture ? 'present' : 'absent'}`);
}

// ───────────────────────── backup leg ─────────────────────────
//
// Exercises the third-party /backup surface (previously ZERO coverage):
// linked-app fixture, write/retrieve round-trip, the error taxonomy
// (404 absent vs non-404 failures - the split write guards depend on),
// per-origin isolation, delete semantics, and an app revoking its own
// link. Needs a client_id registered on the API the vault points at
// (auto-approve resolves the link dialog):
//   VAULT_MATRIX_APP_CLIENT_ID   registered third-party app client_id
const APP_CLIENT_ID = process.env.VAULT_MATRIX_APP_CLIENT_ID || '';
const APP_ORIGIN = 'https://backup-matrix.example';

function canonicalPayload(records) {
  return {
    version: 1,
    _summary: { countsByEntryType: { Test: records }, totalRecords: records },
    cells: [],
    app: { name: 'Matrix Backup Fixture', client_id: APP_CLIENT_ID },
  };
}

async function backupLegs() {
  console.log('\n── Backups (third-party surface)');
  if (!APP_CLIENT_ID) {
    record('backup leg skipped - set VAULT_MATRIX_APP_CLIENT_ID (a registered app client_id)', true);
    return;
  }

  // Fixture: link a synthetic app install under our own origin. The link
  // key must be agent-key-SHAPED (39 bytes with the 0x84 0x20 0x24 prefix,
  // "uhCAk…" once encoded) - the Vault validates the format.
  const linkKeyRaw = crypto.randomBytes(39);
  linkKeyRaw[0] = 0x84;
  linkKeyRaw[1] = 0x20;
  linkKeyRaw[2] = 0x24;
  const linkKey = `u${linkKeyRaw.toString('base64url')}`;
  const link = await api('/link-identity', {
    method: 'POST',
    origin: APP_ORIGIN,
    body: {
      app_name: 'Matrix Backup Fixture',
      client_id: APP_CLIENT_ID,
      app_agent_pub_key: linkKey,
    },
  });
  record('fixture app links (auto-approved)', link.status === 200 && link.data?.success === true,
    `${link.status} ${JSON.stringify(link.data)?.slice(0, 120)}`);
  if (link.status !== 200) return;

  // Unlinked origins stay out.
  const evilWrite = await api('/backup', {
    method: 'POST', origin: EVIL_ORIGIN,
    body: { client_id: APP_CLIENT_ID, app_name: 'x', label: 'evil', data: {} },
  });
  record('write refused for unlinked origin', evilWrite.status === 403 && evilWrite.data?.error === 'not_linked');

  const crossId = await api('/backup', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: 'someone_else', app_name: 'x', label: 'evil', data: {} },
  });
  record('write refused for foreign client_id', crossId.status === 403 && crossId.data?.error === 'client_id_mismatch');

  // Absent slot reads as 404 backup_not_found - THE contract the slot
  // gates build on (absent must be distinguishable from unreadable).
  const absent = await api('/backup/retrieve', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, label: 'matrix-absent' },
  });
  record('absent slot -> 404 backup_not_found', absent.status === 404 && absent.data?.error === 'backup_not_found');

  // Write + read back.
  const wrote = await api('/backup', {
    method: 'POST', origin: APP_ORIGIN,
    body: {
      client_id: APP_CLIENT_ID, app_name: 'Matrix Backup Fixture',
      label: 'matrix-test', data: canonicalPayload(3),
    },
  });
  record('write accepted for linked origin', wrote.status === 200 && wrote.data?.success === true,
    `${wrote.status}`);

  const readBack = await api('/backup/retrieve', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, label: 'matrix-test' },
  });
  record('round-trip preserves the payload',
    readBack.status === 200 && readBack.data?.data?._summary?.totalRecords === 3);

  // /backup/limits advertises the incremental contract.
  const limits = await api('/backup/limits', { origin: APP_ORIGIN });
  record('limits advertised (named labels never rotate)',
    limits.status === 200 && limits.data?.named_labels_rotate === false,
    `${limits.status} ${JSON.stringify(limits.data)?.slice(0, 80)}`);

  // Delete semantics: gone -> 404 on the second attempt (never a silent 200).
  const del = await api('/backup/delete', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, label: 'matrix-test' },
  });
  record('single-label delete succeeds', del.status === 200 && del.data?.success === true);
  const delAgain = await api('/backup/delete', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, label: 'matrix-test' },
  });
  record('deleting an absent label -> 404', delAgain.status === 404 && delAgain.data?.error === 'backup_not_found');

  // ── Identity contract: header on every response, expected_identity gate ──
  const vaultKey = link.data?.vault_agent_pub_key;
  const hdrResp = await fetch(`http://127.0.0.1:${PORT}/backup/limits`, {
    headers: { origin: APP_ORIGIN },
  });
  record('responses state the vault identity in a header',
    hdrResp.headers.get('x-flowsta-vault-identity') === vaultKey,
    `got ${hdrResp.headers.get('x-flowsta-vault-identity')}`);

  const expOk = await api('/backup/retrieve', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, label: 'matrix-exp-absent', expected_identity: vaultKey },
  });
  record('matching expected_identity passes the gate',
    expOk.status === 404 && expOk.data?.error === 'backup_not_found',
    `${expOk.status} ${expOk.data?.error}`);

  const expWrong = await api('/backup/retrieve', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, label: 'matrix-exp-absent', expected_identity: linkKey },
  });
  record('foreign expected_identity refused 409',
    expWrong.status === 409 && expWrong.data?.error === 'identity_mismatch',
    `${expWrong.status} ${expWrong.data?.error}`);

  const expWrite = await api('/backup', {
    method: 'POST', origin: APP_ORIGIN,
    body: {
      client_id: APP_CLIENT_ID, app_name: 'Matrix Backup Fixture',
      label: 'matrix-exp-write', data: canonicalPayload(1), expected_identity: linkKey,
    },
  });
  const expWriteProbe = await api('/backup/retrieve', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, label: 'matrix-exp-write' },
  });
  record('write with foreign expected_identity refused and nothing written',
    expWrite.status === 409 && expWriteProbe.status === 404,
    `write ${expWrite.status}, probe ${expWriteProbe.status}`);

  const expGarbage = await api('/backup/retrieve', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, label: 'matrix-exp-absent', expected_identity: 'not-a-key' },
  });
  record('undecodable expected_identity refused',
    expGarbage.status === 409, `${expGarbage.status} ${expGarbage.data?.error}`);

  // Locked vault: the gate answers from the active-identity marker (backups
  // deliberately keep working while locked).
  const lockForGate = await api('/dev/lock', { method: 'POST', body: {} });
  record('lock for identity-gate leg', lockForGate.status === 200);
  const lockedOk = await api('/backup/retrieve', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, label: 'matrix-exp-absent', expected_identity: vaultKey },
  });
  record('locked: matching expected_identity passes via the marker',
    lockedOk.status === 404 && lockedOk.data?.error === 'backup_not_found',
    `${lockedOk.status} ${lockedOk.data?.error}`);
  const lockedWrong = await api('/backup/retrieve', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, label: 'matrix-exp-absent', expected_identity: linkKey },
  });
  record('locked: foreign expected_identity still refused',
    lockedWrong.status === 409 && lockedWrong.data?.error === 'identity_mismatch',
    `${lockedWrong.status} ${lockedWrong.data?.error}`);
  const unlockAfterGate = await api('/dev/unlock', { method: 'POST', body: {} });
  record('unlock after identity-gate leg', unlockAfterGate.status === 200);

  // An app may revoke ITS OWN link (and only from its own origin).
  const evilRevoke = await api('/revoke-identity', {
    method: 'POST', origin: EVIL_ORIGIN,
    body: { app_name: 'Matrix Backup Fixture', app_agent_pub_key: linkKey },
  });
  record('own-link revoke refused for unlinked origin', evilRevoke.status === 403);
  const revoke = await api('/revoke-identity', {
    method: 'POST', origin: APP_ORIGIN,
    body: { app_name: 'Matrix Backup Fixture', app_agent_pub_key: linkKey },
  });
  record('app revokes its own link', revoke.status === 200 && revoke.data?.success === true,
    `${revoke.status}`);
  const afterRevoke = await api('/backup', {
    method: 'POST', origin: APP_ORIGIN,
    body: { client_id: APP_CLIENT_ID, app_name: 'x', label: 'after', data: {} },
  });
  record('writes refused after the app unlinked itself',
    afterRevoke.status === 403 && afterRevoke.data?.error === 'not_linked');
}

// ── Password leg ─────────────────────────────────────────────────────
//
// The password protects the vault file, the conductor's db.key and the
// lair keystore together. The field failure was the three disagreeing
// after a change (vault under one password, key store under another):
// lair died on its passphrase at the next launch and the UI said "try
// reinstalling". This leg proves the rotation end to end through the
// real command, then a full lock (conductor + lair stopped) and an unlock
// with the NEW password - the same path a relaunch takes - and that the
// OLD password is refused. Then it changes back so the dev vault stays
// usable.

async function waitForConductor(want, { timeoutMs = 5 * 60 * 1000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    const r = await api('/dev/status');
    last = r.data?.conductor;
    if (last?.status === want) return last;
    if (last?.status === 'error') return last;
    await new Promise((res) => setTimeout(res, 1000));
  }
  return last;
}

async function passwordLeg() {
  console.log('\n── Password leg (change → lock → unlock with new → ready → change back)');
  const CURRENT = process.env.VAULT_MATRIX_PASSWORD;
  if (!CURRENT) {
    record('password leg', true, 'skipped - set VAULT_MATRIX_PASSWORD to run it');
    return;
  }
  const TEMP = `Matrix-${crypto.randomBytes(6).toString('hex')}-Aa1!`;

  const wrong = await api('/dev/change-password', {
    method: 'POST', body: { current_password: 'definitely-not-it-9', new_password: TEMP },
  });
  record('change refused with the wrong current password', wrong.status === 400 && /incorrect/i.test(wrong.data?.description || ''),
    `${wrong.status} ${wrong.data?.description || ''}`);

  const t0 = Date.now();
  const change = await api('/dev/change-password', {
    method: 'POST', body: { current_password: CURRENT, new_password: TEMP },
  });
  record('change_vault_password succeeds', change.status === 200 && change.data?.success === true,
    `${change.status} ${change.data?.description || ''} in ${Math.round((Date.now() - t0) / 1000)}s`);
  if (change.status !== 200) return;

  let st = await waitForConductor('ready');
  record('conductor ready after the change (command returned only once it was)', st?.status === 'ready', JSON.stringify(st));
  const dev = await api('/dev/status');
  record('previous keystore removed after the new stack came up', dev.data?.old_keystores === 0,
    `old_keystores=${dev.data?.old_keystores}`);

  // Full lock stops conductor + lair; the unlock re-inits/starts lair under
  // the cached passphrase and decrypts the vault file - the relaunch path.
  const lock = await api('/dev/lock', { method: 'POST', body: {} });
  record('/dev/lock', lock.status === 200);
  const old = await api('/dev/unlock-with-password', { method: 'POST', body: { password: CURRENT } });
  record('OLD password refused after the change', old.status === 403, `${old.status}`);
  const fresh = await api('/dev/unlock-with-password', { method: 'POST', body: { password: TEMP } });
  record('NEW password unlocks the vault', fresh.status === 200 && fresh.data?.success === true,
    `${fresh.status} ${fresh.data?.description || ''}`);
  st = await waitForConductor('ready');
  record('conductor + key store come up under the NEW password', st?.status === 'ready', JSON.stringify(st));

  // A sign still works (lair holds the device key it re-imported).
  const probe = await api('/status');
  record('/status unlocked after the round trip', probe.status === 200 && probe.data?.unlocked === true);

  // Change back so the dev vault keeps its known password.
  const back = await api('/dev/change-password', {
    method: 'POST', body: { current_password: TEMP, new_password: CURRENT },
  });
  record('changed back to the original password', back.status === 200, `${back.status} ${back.data?.description || ''}`);
  st = await waitForConductor('ready');
  record('conductor ready after changing back', st?.status === 'ready', JSON.stringify(st));
  const lock2 = await api('/dev/lock', { method: 'POST', body: {} });
  const orig = await api('/dev/unlock-with-password', { method: 'POST', body: { password: CURRENT } });
  record('original password unlocks again', lock2.status === 200 && orig.status === 200, `${orig.status}`);
  st = await waitForConductor('ready');
  record('conductor ready on the original password', st?.status === 'ready', JSON.stringify(st));
}

// ── Email grants leg ─────────────────────────────────────────────────
//
// The rule under test: an email reaches an app only through a grant the
// user made in a Vault dialog. Without one, /status carries no `email`
// for any origin (first-party pages still get `web_email`, as before) and
// /authenticate with `scopes: ["email"]` answers without an address when
// nothing can be granted (unregistered client_id, or an unverified email -
// the harness vault is never verified). The positive path (dialog → grant
// → email in the response) is Eric's eyeball item: it needs a registered
// app and a verified staging identity.

async function grantsLeg() {
  console.log('\n── Email grants leg');
  const first = await api('/status');
  record('/status (Flowsta origin) has no `email` field without a grant', first.status === 200 && !('email' in (first.data || {})),
    JSON.stringify(Object.keys(first.data || {})));
  const evil = await api('/status', { origin: EVIL_ORIGIN });
  record('/status (other origin) has no `email` and no `web_email`',
    evil.status === 200 && !('email' in (evil.data || {})) && evil.data?.web_email == null);

  const challenge = Buffer.from(`matrix-grants-${randomHash().slice(0, 16)}`).toString('base64');
  const noApp = await api('/authenticate', {
    method: 'POST',
    body: { app_name: 'Matrix', challenge, reason: 'grants leg', scopes: ['email'] },
  });
  record('/authenticate with scopes but no client_id: signs, shares no email',
    noApp.status === 200 && !!noApp.data?.signature && noApp.data?.email === undefined, `${noApp.status}`);
  const unknownApp = await api('/authenticate', {
    method: 'POST',
    body: { app_name: 'Matrix', challenge, reason: 'grants leg', client_id: 'flowsta_app_does_not_exist', scopes: ['email'] },
  });
  record('/authenticate with an unregistered client_id + email scope: signs, shares no email',
    unknownApp.status === 200 && !!unknownApp.data?.signature && unknownApp.data?.email === undefined, `${unknownApp.status}`);
  const after = await api('/status');
  record('still no `email` on /status afterwards', after.status === 200 && !('email' in (after.data || {})));

  // A grant belongs to the page that asked. With a registered app that has
  // the email scope and a vault whose email is verified (Eric's staging
  // identity), an origin that is neither a Flowsta page nor the app's linked
  // page gets the dialog (auto-approved here) and may be handed the address
  // for that one answer, but files NO grant under the app's client_id; a
  // Flowsta page does. Observed through /dev/status.email_grants.
  if (APP_CLIENT_ID) {
    const dev0 = await api('/dev/status');
    const grants0 = dev0.data?.email_grants || [];
    if (dev0.status !== 200) {
      record('grant binding probe skipped - /dev/status unavailable (needs FLOWSTA_VAULT_AUTO_APPROVE=1)', true);
    } else if (grants0.includes(APP_CLIENT_ID)) {
      record(`grant binding probe skipped - ${APP_CLIENT_ID.slice(0, 20)}… already holds a grant in this vault`, true);
    } else {
      const ch2 = Buffer.from(`matrix-bind-${randomHash().slice(0, 16)}`).toString('base64');
      const evilAuth = await api('/authenticate', {
        method: 'POST', origin: EVIL_ORIGIN,
        body: { app_name: 'Matrix', challenge: ch2, reason: 'grants leg', client_id: APP_CLIENT_ID, scopes: ['email'] },
      });
      const dev1 = await api('/dev/status');
      record('unbound origin + registered app + email scope: signs, files NO grant',
        evilAuth.status === 200 && !!evilAuth.data?.signature && !(dev1.data?.email_grants || []).includes(APP_CLIENT_ID),
        `${evilAuth.status} email=${evilAuth.data?.email ? 'shared for this answer' : 'none'} grants=${JSON.stringify(dev1.data?.email_grants || [])}`);
      const boundAuth = await api('/authenticate', {
        method: 'POST',
        body: { app_name: 'Matrix', challenge: ch2, reason: 'grants leg', client_id: APP_CLIENT_ID, scopes: ['email'] },
      });
      const dev2 = await api('/dev/status');
      const boundRecorded = (dev2.data?.email_grants || []).includes(APP_CLIENT_ID);
      record('Flowsta origin + same app: signs and (verified email) files the grant',
        boundAuth.status === 200 && !!boundAuth.data?.signature && (boundRecorded || !boundAuth.data?.email),
        `${boundAuth.status} email=${boundAuth.data?.email ? 'shared' : 'none (unverified vault → nothing to grant)'} recorded=${boundRecorded}`);
      // The Vault's activity log saw both: the sign-in and, when a grant was
      // filed, the email share (newest first on /dev/status.activity).
      const acts = dev2.data?.activity || [];
      record('activity log recorded the sign-in (and the email share when granted)',
        acts.includes('sign_in') && (!boundRecorded || acts.includes('email_shared')),
        JSON.stringify(acts.slice(0, 5)));
    }
  } else {
    record('grant binding probe skipped - set VAULT_MATRIX_APP_CLIENT_ID (a registered app with the email scope)', true);
  }
}

// ── Remembered-site leg ──────────────────────────────────────────────
//
// "Remember this site" must mean it: a remembered origin signs in with no
// dialog (the activity line says so), the memory survives a lock + unlock,
// and forgetting it brings the dialog back. Runs inside the full phase.

async function rememberedSiteLeg() {
  console.log('\n── Remembered-site leg');
  const origin = 'https://remembered.example';
  const dev0 = await api('/dev/status');
  if (dev0.status !== 200) { record('remembered-site leg skipped - not a harness build', true); return; }
  const signIn = async () => {
    const challenge = Buffer.from(`matrix-remember-${randomHash().slice(0, 16)}`).toString('base64');
    const r = await api('/authenticate', { method: 'POST', origin, body: { app_name: 'Remembered', challenge, reason: 'Sign in to Remembered' } });
    const d = await api('/dev/status');
    return { status: r.status, last: d.data?.activity_last };
  };
  const before = await signIn();
  record('not remembered yet: sign-in logged without the "remembered" note',
    before.status === 200 && before.last?.kind === 'sign_in' && !(before.last?.detail || '').includes('Remembered'), JSON.stringify(before.last));
  const rem = await api('/dev/remember-origin', { method: 'POST', body: { origin } });
  record('remember the origin (what the tick does)', rem.status === 200 && rem.data?.remembered === true);
  const after = await signIn();
  record('remembered: the sign-in is logged as "Remembered site - no dialog"',
    after.status === 200 && after.last?.kind === 'sign_in' && (after.last?.detail || '').includes('Remembered'), JSON.stringify(after.last));
  // Survives a lock + unlock (the store is on disk, not in the session).
  await api('/dev/lock', { method: 'POST' });
  const unl = await api('/dev/unlock', { method: 'POST' });
  record('unlock after lock (harness)', unl.status === 200);
  const ready = await (async () => { const deadline = Date.now() + 120_000; while (Date.now() < deadline) { const d = await api('/dev/status'); if (d.data?.conductor?.status === 'ready') return true; await new Promise((r) => setTimeout(r, 2000)); } return false; })();
  record('conductor ready after relock', ready);
  const again = await signIn();
  record('still remembered after lock + unlock', again.status === 200 && (again.last?.detail || '').includes('Remembered'), JSON.stringify(again.last));
  const forget = await api('/dev/remember-origin', { method: 'POST', body: { origin, forget: true } });
  const gone = await signIn();
  record('forgotten: the next sign-in asks again (no "remembered" note)', forget.status === 200 && gone.status === 200 && !(gone.last?.detail || '').includes('Remembered'), JSON.stringify(gone.last));
}

// ── Create-identity leg ──────────────────────────────────────────────
//
// The wizard's create path, headlessly, on a FRESH instance: register the
// device key with Flowsta, build the vault, conductor up, the identity
// visible on /status, the server able to sign it in, the activity log
// saying "Created", lock, wrong password refused, right password unlocks.
// Then (second fresh instance) the offline restore from the same phrase
// lands on the same agent key and logs "Restored", and the account layer
// (email) reattaches from Flowsta by itself.

async function vaultFetch(port, path, { method = 'GET', body, origin = ORIGIN } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (origin) headers.origin = origin;
  const resp = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await resp.json().catch(() => null);
  return { status: resp.status, data };
}

async function waitConductorReady(port, secs) {
  const deadline = Date.now() + secs * 1000;
  while (Date.now() < deadline) {
    const d = await vaultFetch(port, '/dev/status').catch(() => null);
    if (d?.data?.conductor?.status === 'ready') return true;
    await new Promise((r) => setTimeout(r, 2000));
  }
  return false;
}

async function waitFor(port, predicate, secs) {
  const deadline = Date.now() + secs * 1000;
  while (Date.now() < deadline) {
    const d = await vaultFetch(port, '/dev/status').catch(() => null);
    const st = await vaultFetch(port, '/status').catch(() => null);
    if (predicate(st?.data, d?.data)) return true;
    await new Promise((r) => setTimeout(r, 2000));
  }
  return false;
}

async function createLeg() {
  console.log('\n── Create-identity leg');
  const port = Number(process.env.VAULT_MATRIX_PORT || 0);
  if (!port) { record('create leg skipped - set VAULT_MATRIX_PORT to a FRESH test instance', true); return; }
  const restorePort = Number(process.env.VAULT_MATRIX_RESTORE_PORT || 0);
  const password = process.env.VAULT_MATRIX_PASSWORD || `Matrix-create-${randomHash().slice(0, 12)}!`;
  const email = `matrix-create-${Date.now()}@example.com`;

  const fresh = await vaultFetch(port, '/status');
  record('fresh instance: no identity yet', fresh.status === 200 && fresh.data?.initialized === false, JSON.stringify(fresh.data));
  const dev0 = await vaultFetch(port, '/dev/status');
  if (dev0.status !== 200) { record('create leg skipped - instance is not a harness build (/dev/status 404)', true); return; }
  if (fresh.data?.initialized !== false) { record('create leg skipped - instance already holds an identity', true); return; }

  const t0 = Date.now();
  const created = await vaultFetch(port, '/dev/setup-identity', { method: 'POST', body: { api_url: API, password, email, display_name: 'Matrix Create' } });
  record('create: registered with Flowsta + vault built (wizard path, headless)', created.status === 200 && !!created.data?.agent_pub_key && !!created.data?.phrase,
    `${created.status} ${created.data?.error || ''} ${created.data?.description || ''} in ${Date.now() - t0} ms`);
  if (created.status !== 200) return;
  const { agent_pub_key: agent, did, phrase } = created.data;

  record('conductor ready after create', await waitConductorReady(port, 120));
  const st = await vaultFetch(port, '/status');
  record('/status: unlocked, initialized, the new agent key + DID, email held for Flowsta pages',
    st.data?.unlocked === true && st.data?.initialized === true && st.data?.agent_pub_key === agent && st.data?.did === did && st.data?.web_email === email,
    JSON.stringify({ agent: st.data?.agent_pub_key === agent, did: st.data?.did === did, email: st.data?.web_email }));

  // Flowsta knows the key: a login challenge signed by this vault is accepted.
  const ch = await fetch(`${API}/auth/vault/challenge`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_id: 'flowsta' }) }).then((r) => r.json()).catch(() => ({}));
  const signed = await vaultFetch(port, '/authenticate', { method: 'POST', body: { app_name: 'Flowsta', challenge: Buffer.from(ch.challenge || '').toString('base64'), reason: 'Sign in to Matrix' } });
  const tok = await fetch(`${API}/auth/vault/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ challenge: ch.challenge, agent_pub_key: agent, signature: signed.data?.signature }) }).then(async (r) => ({ status: r.status, data: await r.json().catch(() => ({})) }));
  record('Flowsta signs the new identity in (registration is real)', signed.status === 200 && tok.status === 200 && !!tok.data?.token,
    `authenticate ${signed.status}, token ${tok.status} ${tok.data?.error || ''}`);
  record('…and it is a device-hosted account', tok.data?.user?.hostingModel === 'device-hosted', `hostingModel=${tok.data?.user?.hostingModel}`);

  const dev1 = await vaultFetch(port, '/dev/status');
  record('activity log says the identity was created here', (dev1.data?.activity || []).includes('identity_created'), JSON.stringify(dev1.data?.activity || []));

  // Lock; the wrong password is refused; the right one unlocks and the conductor returns.
  const locked = await vaultFetch(port, '/dev/lock', { method: 'POST' });
  const stL = await vaultFetch(port, '/status');
  record('lock: /status reports locked, identity still initialized', locked.status === 200 && stL.data?.unlocked === false && stL.data?.initialized === true);
  const wrong = await vaultFetch(port, '/dev/unlock-with-password', { method: 'POST', body: { password: password + 'x' } });
  record('wrong password refused', wrong.status !== 200 || wrong.data?.success !== true, `${wrong.status}`);
  const right = await vaultFetch(port, '/dev/unlock-with-password', { method: 'POST', body: { password } });
  record('right password unlocks the new vault', right.status === 200 && right.data?.success === true && (right.data?.agent_pub_key === agent || right.data?.already_unlocked), `${right.status} ${right.data?.error || ''}`);
  record('conductor ready again after unlock', await waitConductorReady(port, 120));

  if (!restorePort) { record('restore twin skipped - set VAULT_MATRIX_RESTORE_PORT to a second FRESH instance', true); return; }
  const fresh2 = await vaultFetch(restorePort, '/status');
  if (fresh2.data?.initialized !== false) { record('restore twin skipped - second instance already holds an identity', true); return; }
  const t1 = Date.now();
  const restored = await vaultFetch(restorePort, '/dev/setup-identity', { method: 'POST', body: { api_url: API, password, phrase, restore: true } });
  record('restore (offline path) from the same phrase on a second fresh instance', restored.status === 200 && restored.data?.restored === true,
    `${restored.status} ${restored.data?.error || ''} in ${Date.now() - t1} ms`);
  if (restored.status !== 200) return;
  record('same agent key and DID as the created identity', restored.data?.agent_pub_key === agent && restored.data?.did === did,
    `${(restored.data?.agent_pub_key || '').slice(0, 16)}… vs ${agent.slice(0, 16)}…`);
  record('conductor ready after restore', await waitConductorReady(restorePort, 120));
  const dev2 = await vaultFetch(restorePort, '/dev/status');
  record('activity log says the identity was restored here', (dev2.data?.activity || []).includes('identity_restored'), JSON.stringify(dev2.data?.activity || []));
  // The account layer (display name, picture, username) reattaches from
  // Flowsta by itself once the vault is unlocked online. The EMAIL does not:
  // Flowsta holds only its hash, so a restored vault has none until the
  // person re-enters it on the Overview, where it is checked against the
  // hash. Both facts are asserted.
  await vaultFetch(restorePort, '/dev/lock', { method: 'POST', body: {} });
  await vaultFetch(restorePort, '/dev/unlock', { method: 'POST', body: {} });
  const reattached = await waitFor(restorePort, (status) => status?.display_name === 'Matrix Create', 120);
  const stR = await vaultFetch(restorePort, '/status');
  record('account layer reattached by itself after unlock: display name (and picture) are back', reattached, `display_name=${stR.data?.display_name} picture=${!!stR.data?.profile_picture}`);
  record('the email is NOT back by itself (Flowsta holds only its hash) - the Overview asks for it', stR.data?.web_email == null, `web_email=${stR.data?.web_email}`);
  // The Overview's step: re-enter the address; the server checks the hash.
  const wrongEmail = await vaultFetch(restorePort, '/dev/confirm-email', { method: 'POST', body: { api_url: API, email: `wrong-${email}` } });
  record('re-entering a WRONG email is refused (email_mismatch)', wrongEmail.status === 403 && wrongEmail.data?.error === 'email_mismatch', `${wrongEmail.status} ${wrongEmail.data?.error || ''}`);
  const rightEmail = await vaultFetch(restorePort, '/dev/confirm-email', { method: 'POST', body: { api_url: API, email: email.toUpperCase() } });
  const stE = await vaultFetch(restorePort, '/status');
  const devE = await vaultFetch(restorePort, '/dev/status');
  record('re-entering the registered email (any case) is confirmed and stored; activity says so',
    rightEmail.status === 200 && stE.data?.web_email === email && (devE.data?.activity || []).includes('email_added'),
    `${rightEmail.status} web_email=${stE.data?.web_email} activity=${JSON.stringify((devE.data?.activity || []).slice(0, 3))}`);
}

// ───────────────────────── main ─────────────────────────

(async () => {
  console.log(`Bridge matrix — phase: ${PHASE}, origin: ${ORIGIN}`);
  if (PHASE === 'create') {
    // A fresh instance has nothing for preflight to check yet.
    await createLeg();
    const passedC = results.filter((r) => r.ok).length;
    console.log(`\nRESULT: ${passedC}/${results.length} checks passed${failures ? ` — ${failures} FAILED` : ' — ALL GREEN'}`);
    process.exit(failures ? 1 : 0);
  }
  const { status, baseline } = await preflight();
  const agentKey = status.agent_pub_key;
  const profileName = process.env.VAULT_MATRIX_NAME || status.display_name || 'Vlah test';

  await guardLegs();

  if (PHASE === 'refusal' || PHASE === 'all') {
    await quotaRefusalLeg(agentKey);
  }

  if (PHASE === 'backup' || PHASE === 'all') {
    await backupLegs();
  }

  if (PHASE === 'password' || PHASE === 'all') {
    await passwordLeg();
  }

  if (PHASE === 'grants' || PHASE === 'all') {
    await grantsLeg();
  }

  if (PHASE === 'full' || PHASE === 'all') {
    await rememberedSiteLeg();
  }

  if (PHASE === 'full' || PHASE === 'all') {
    const identBefore = await api('/dev/identity');
    const quotaBefore = await serverQuota(agentKey);
    const ctx = await happyRow(profileName);
    await deniedRow(ctx, profileName);
    const dbl = await doubleSubmitRow(profileName);
    await lockedRow({ ...ctx, ...dbl }, profileName);
    await coldStartRow({ ...ctx, ...dbl }, profileName);
    await signatureOnlyLeg(baseline.length);
    await profileSyncLeg(identBefore.data?.display_name);

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
