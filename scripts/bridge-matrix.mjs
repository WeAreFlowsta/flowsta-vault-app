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
 *   node scripts/bridge-matrix.mjs --phase=switcher  # 1.5.0: two identities in one Vault, switch, one agent
 *       one identity, the epoch, claims, reset -> restore -> email. Same two fresh instances
 *       as --phase=create (VAULT_MATRIX_PORT required, VAULT_MATRIX_RESTORE_PORT optional).
 *   node scripts/bridge-matrix.mjs --phase=devices   # 1.6.0: one identity on two devices
 *       add with a code, sync, connections, backups, lock-and-sync, remove, stand down, the phrase
 *       door. Two FRESH instances: VAULT_MATRIX_PORT (A) and VAULT_MATRIX_RESTORE_PORT (B).
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
// → email in the response) is a by-eye item: it needs a registered
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
  // the email scope and a vault whose email is verified (a staging
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

/** Cells (not just the admin API) ready: a real zome-backed read succeeds.
 *  `GET /signatures` (a Flowsta-origin bridge call) runs the same readiness
 *  probe the Overview's poll runs, so it is the honest measure - nothing
 *  else polls in a headless instance, and /dev/status.cells_ready only
 *  flips once something has. Returns the seconds it took, or -1 on timeout. */
async function waitCellsReady(port, secs) {
  const t0 = Date.now();
  const deadline = t0 + secs * 1000;
  while (Date.now() < deadline) {
    const r = await vaultFetch(port, '/signatures').catch(() => null);
    if (r?.status === 200 && Array.isArray(r.data?.signatures)) return Math.round((Date.now() - t0) / 1000);
    await new Promise((r2) => setTimeout(r2, 2000));
  }
  return -1;
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
  const chResp = await fetch(`${API}/auth/vault/challenge`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_id: 'flowsta' }) }).catch(() => null);
  const ch = chResp ? await chResp.json().catch(() => ({})) : {};
  if (!ch.challenge) {
    record(`Flowsta challenge unavailable (${chResp?.status || 'no response'}${chResp?.status === 429 ? ' - staging limiter; wait 15 min' : ''}) - the sign-in, reattach and confirm checks below cannot pass`, false, JSON.stringify(ch).slice(0, 120));
  }
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
  // Phase 2: the first unlock of a legacy layout moves the identity into
  // identities/<partition key>/ (relocate.rs). The harness reports the layout.
  const devAfter = await vaultFetch(port, '/dev/status');
  record('unlock moved the identity into its partition (layout: partitioned)', devAfter.data?.layout === 'partitioned',
    `${devAfter.data?.layout} ${(devAfter.data?.identity_root || '').split('/').slice(-2).join('/')}`);

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
  // The reconcile is chained behind the post-unlock network checks, so it
  // can take a few minutes on staging - wait generously.
  // /status filters profile fields by the caller's granted scopes, so the
  // harness reads the config itself via /dev/identity.
  const devIdentity = async () => (await vaultFetch(restorePort, '/dev/identity')).data || {};
  const reattached = await (async () => { const deadline = Date.now() + 300_000; while (Date.now() < deadline) { const id = await devIdentity(); if (id.display_name === 'Matrix Create') return true; await new Promise((r) => setTimeout(r, 3000)); } return false; })();
  const idR = await devIdentity();
  record('account layer reattached by itself after unlock: display name (and picture) are back', reattached && idR.profile_picture_len > 0, `display_name=${idR.display_name} picture_len=${idR.profile_picture_len}`);
  record('the email is NOT back by itself (Flowsta holds only its hash) - the Overview asks for it', idR.web_email == null, `web_email=${idR.web_email}`);
  // The Overview's step: re-enter the address; the server checks the hash.
  const wrongEmail = await vaultFetch(restorePort, '/dev/confirm-email', { method: 'POST', body: { api_url: API, email: `wrong-${email}` } });
  record('re-entering a WRONG email is refused (email_mismatch)', wrongEmail.status === 403 && wrongEmail.data?.error === 'email_mismatch', `${wrongEmail.status} ${wrongEmail.data?.error || ''}`);
  const rightEmail = await vaultFetch(restorePort, '/dev/confirm-email', { method: 'POST', body: { api_url: API, email: email.toUpperCase() } });
  const idE = await devIdentity();
  const devE = await vaultFetch(restorePort, '/dev/status');
  record('re-entering the registered email (any case) is confirmed and stored; activity says so',
    rightEmail.status === 200 && idE.web_email === email && (devE.data?.activity || []).includes('email_added'),
    `${rightEmail.status} web_email=${idE.web_email} activity=${JSON.stringify((devE.data?.activity || []).slice(0, 3))}`);
}


// ───────────────────────── 1.5.0 switcher leg ─────────────────────────
//
// One fresh instance holds TWO identities (A created, B added while locked),
// the harness switches between them the way the unlock picker does, and
// asserts what apps see: /status.active_identity + identity_epoch, the
// per-identity link lists, the one-agent-one-identity refusal, GET
// expected_identity, the claim nonce. A second fresh instance (optional)
// proves claims never cross instances and runs reset -> restore -> email.
const SWITCHER_CLIENT_ID = process.env.VAULT_MATRIX_APP_CLIENT_ID
  || 'flowsta_app_2f0660aa9c7afdda85e8e8fc88e59cbcce79921cdecf9c81a2cbba8e34420a9b'; // staging fixture app
const SWITCHER_APP_ORIGIN = 'https://switcher-matrix.example';
function fakeAgentKey() {
  // 39 bytes: 0x84 0x20 0x24 prefix + 32 random + 4 - the Vault only needs it to decode.
  const raw = Buffer.concat([Buffer.from([0x84, 0x20, 0x24]), crypto.randomBytes(36)]);
  return 'u' + raw.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function switcherLeg() {
  console.log('\n── 1.5.0 switcher leg');
  const port = Number(process.env.VAULT_MATRIX_PORT || 0);
  if (!port) { record('switcher leg skipped - set VAULT_MATRIX_PORT to a FRESH test instance', true); return; }
  const port2 = Number(process.env.VAULT_MATRIX_RESTORE_PORT || 0);
  const dev0 = await vaultFetch(port, '/dev/status');
  if (dev0.status !== 200) { record('switcher leg skipped - not a harness build (/dev/status 404)', true); return; }
  const fresh = await vaultFetch(port, '/status');
  if (fresh.data?.initialized !== false) { record('switcher leg skipped - instance already holds an identity', true); return; }
  const stamp = Date.now();
  const pwA = `Matrix-A-${randomHash().slice(0, 10)}!`;
  const pwB = `Matrix-B-${randomHash().slice(0, 10)}!`;
  const emailA = `matrix-sw-a-${stamp}@example.com`;
  const emailB = `matrix-sw-b-${stamp}@example.com`;
  const ids = async (p = port) => (await vaultFetch(p, '/dev/identities')).data || {};
  const status = async (p = port) => (await vaultFetch(p, '/status')).data || {};
  const devStatus = async (p = port) => (await vaultFetch(p, '/dev/status')).data || {};
  const link = async (agent, opts = {}) => vaultFetch(port, '/link-identity', {
    method: 'POST', origin: SWITCHER_APP_ORIGIN,
    body: { app_name: 'Matrix switcher app', client_id: SWITCHER_CLIENT_ID, app_agent_pub_key: agent, ...opts },
  });
  const linkStatus = async (agent, expected) => vaultFetch(port,
    `/link-status?client_id=${encodeURIComponent(SWITCHER_CLIENT_ID)}&app_agent_pub_key=${encodeURIComponent(agent)}${expected ? `&expected_identity=${encodeURIComponent(expected)}` : ''}`,
    { origin: SWITCHER_APP_ORIGIN });

  // 1. A is created; born in its own partition; the status fields exist.
  const a = await vaultFetch(port, '/dev/setup-identity', { method: 'POST', body: { api_url: API, password: pwA, email: emailA, display_name: 'Matrix A' } });
  record('A created (registered with Flowsta, vault built)', a.status === 200 && !!a.data?.agent_pub_key, `${a.status} ${a.data?.error || ''} ${a.data?.description || ''}`);
  if (a.status !== 200) return;
  const agentA = a.data.agent_pub_key; const phraseA = a.data.phrase;
  record('conductor ready after A', await waitConductorReady(port, 120));
  { const secs = await waitCellsReady(port, 300); record('cells ready after A is created (budget 300 s)', secs >= 0, `${secs} s`); }
  let st = await status();
  const e0 = Number(st.identity_epoch);
  record('/status carries active_identity (= A), instance_id, identity_epoch, claims[]',
    st.active_identity === agentA && typeof st.instance_id === 'string' && st.instance_id.length > 0 && Number.isInteger(e0) && Array.isArray(st.claims),
    JSON.stringify({ active: st.active_identity === agentA, instance: !!st.instance_id, epoch: st.identity_epoch, claims: st.claims }));
  const instanceId = st.instance_id;
  let l = await ids();
  const keyA = (l.identities || []).find((x) => x.active)?.key;
  record('one identity on the device, A active, born partitioned (16-hex key, no legacy root)',
    (l.identities || []).length === 1 && /^[0-9a-f]{16}$/.test(keyA || ''), JSON.stringify((l.identities || []).map((x) => [x.key, x.active])));
  record('/dev/status layout: partitioned', (await devStatus()).layout === 'partitioned');

  // 2. One live vault: adding while UNLOCKED is refused.
  const addUnlocked = await vaultFetch(port, '/dev/setup-identity', { method: 'POST', body: { api_url: API, password: pwB, email: emailB, display_name: 'Matrix B' } });
  record('adding an identity while unlocked is refused (one live vault)', addUnlocked.status === 409 && addUnlocked.data?.error === 'already_set_up', `${addUnlocked.status} ${addUnlocked.data?.error}`);

  // 3. Lock, add B beside A.
  await vaultFetch(port, '/dev/lock', { method: 'POST' });
  st = await status();
  record('locked: /status still names the identity it holds (active_identity = A while locked)', st.unlocked === false && st.active_identity === agentA, JSON.stringify({ unlocked: st.unlocked, active: st.active_identity === agentA }));
  const b = await vaultFetch(port, '/dev/setup-identity', { method: 'POST', body: { api_url: API, password: pwB, email: emailB, display_name: 'Matrix B' } });
  record('B added while locked (second partition, its own keys)', b.status === 200 && !!b.data?.agent_pub_key && b.data.agent_pub_key !== agentA, `${b.status} ${b.data?.error || ''} ${b.data?.description || ''}`);
  if (b.status !== 200) return;
  const agentB = b.data.agent_pub_key; const phraseB = b.data.phrase;
  record('conductor ready after B', await waitConductorReady(port, 120));
  { const secs = await waitCellsReady(port, 300); record('cells ready after B is added (budget 300 s)', secs >= 0, `${secs} s`); }
  l = await ids();
  const keyB = (l.identities || []).find((x) => x.active)?.key;
  record('two identities on the device, B active, both partitioned, labels carry the names',
    (l.identities || []).length === 2 && keyB && keyB !== keyA && (l.identities || []).every((x) => /^[0-9a-f]{16}$/.test(x.key)) &&
      (l.identities || []).some((x) => x.label?.display_name === 'Matrix A') && (l.identities || []).some((x) => x.label?.display_name === 'Matrix B'),
    JSON.stringify((l.identities || []).map((x) => [x.key, x.active, x.label?.display_name])));
  st = await status();
  record('/status: active_identity = B, epoch +1, same instance_id', st.active_identity === agentB && Number(st.identity_epoch) === e0 + 1 && st.instance_id === instanceId,
    JSON.stringify({ active: st.active_identity === agentB, epoch: st.identity_epoch, want: e0 + 1, sameInstance: st.instance_id === instanceId }));

  // 4. An app links its agent X under B.
  const X = fakeAgentKey(); const Y = fakeAgentKey();
  const lx = await link(X);
  record('app agent X links under B', lx.status === 200 && lx.data?.vault_agent_pub_key === agentB, `${lx.status} ${lx.data?.error || ''} ${lx.data?.description || ''}`);
  const lsB = await linkStatus(X);
  record('link-status: X is linked under B', lsB.status === 200 && (lsB.data?.linked === true || lsB.data?.state === 'linked'), `${lsB.status} ${JSON.stringify(lsB.data)}`);
  const lsWrong = await linkStatus(X, agentA);
  record('GET link-status with expected_identity = A while B is active -> 409 identity_mismatch', lsWrong.status === 409 && lsWrong.data?.error === 'identity_mismatch', `${lsWrong.status} ${lsWrong.data?.error}`);
  const lsRight = await linkStatus(X, agentB);
  record('GET link-status with expected_identity = B -> 200', lsRight.status === 200, `${lsRight.status}`);

  // 5. Switch to A the picker's way: lock, select, unlock with A's password.
  const selUnlocked = await vaultFetch(port, '/dev/select-identity', { method: 'POST', body: { key: keyA } });
  record('select while unlocked is refused', selUnlocked.status === 409, `${selUnlocked.status} ${selUnlocked.data?.description || ''}`);
  await vaultFetch(port, '/dev/lock', { method: 'POST' });
  const selA = await vaultFetch(port, '/dev/select-identity', { method: 'POST', body: { key: keyA } });
  record('locked: select A', selA.status === 200 && selA.data?.selected?.key === keyA, `${selA.status} ${selA.data?.description || ''}`);
  const wrongPw = await vaultFetch(port, '/dev/unlock-with-password', { method: 'POST', body: { password: pwB } });
  record("B's password does not open A", wrongPw.status !== 200 || wrongPw.data?.success !== true, `${wrongPw.status}`);
  const unA = await vaultFetch(port, '/dev/unlock-with-password', { method: 'POST', body: { password: pwA } });
  record("A's password opens A", unA.status === 200 && unA.data?.agent_pub_key === agentA, `${unA.status} ${unA.data?.error || ''}`);
  record('conductor ready after switch to A', await waitConductorReady(port, 120));
  { const secs = await waitCellsReady(port, 300); record('cells ready after the switch back to A (a returning identity) (budget 300 s)', secs >= 0, `${secs} s`); }
  st = await status();
  record('/status: active_identity = A, epoch +2', st.active_identity === agentA && Number(st.identity_epoch) === e0 + 2, JSON.stringify({ active: st.active_identity === agentA, epoch: st.identity_epoch }));
  const dsA = await devStatus();
  record('activity narrates the switch (identity_switched)', (dsA.activity || []).includes('identity_switched'), JSON.stringify((dsA.activity || []).slice(0, 4)));

  // 6. One agent, one identity: X cannot link under A; Y can.
  const lxA = await link(X);
  record('X asks to link under A -> 409 agent_linked_elsewhere, naming B', lxA.status === 409 && lxA.data?.error === 'agent_linked_elsewhere' && /Matrix B/.test(lxA.data?.description || ''), `${lxA.status} ${lxA.data?.error} ${lxA.data?.description || ''}`);
  const lyA = await link(Y);
  record('a different agent Y links under A (many agents to one identity is fine)', lyA.status === 200 && lyA.data?.vault_agent_pub_key === agentA, `${lyA.status} ${lyA.data?.error || ''}`);
  const lsXA = await linkStatus(X);
  record('link lists are per identity: X is not linked under A', lsXA.status === 200 && !(lsXA.data?.linked === true || lsXA.data?.state === 'linked'), `${lsXA.status} ${JSON.stringify(lsXA.data)}`);

  // 7. Back to B: the epoch keeps counting; B still holds X.
  await vaultFetch(port, '/dev/lock', { method: 'POST' });
  await vaultFetch(port, '/dev/select-identity', { method: 'POST', body: { key: keyB } });
  const unB = await vaultFetch(port, '/dev/unlock-with-password', { method: 'POST', body: { password: pwB } });
  record("B's password opens B again", unB.status === 200 && unB.data?.agent_pub_key === agentB, `${unB.status}`);
  record('conductor ready after switch back to B', await waitConductorReady(port, 120));
  { const secs = await waitCellsReady(port, 300); record('cells ready after the switch back to B (budget 300 s)', secs >= 0, `${secs} s`); }
  st = await status();
  record('/status: active_identity = B, epoch +3 (A->B->A->B counted, never equal to a past value)', st.active_identity === agentB && Number(st.identity_epoch) === e0 + 3, JSON.stringify({ epoch: st.identity_epoch, want: e0 + 3 }));
  const lsXB = await linkStatus(X);
  record('X is still linked under B', lsXB.status === 200 && (lsXB.data?.linked === true || lsXB.data?.state === 'linked'));
  const lsYB = await linkStatus(Y);
  record('Y is not linked under B', lsYB.status === 200 && !(lsYB.data?.linked === true || lsYB.data?.state === 'linked'));

  // 8. Claims: this instance lists its nonce; junk is refused; another instance never lists it.
  const nonce = crypto.randomBytes(16).toString('hex');
  const cl = await vaultFetch(port, '/dev/claim', { method: 'POST', body: { url: `flowsta://claim/v1?nonce=${nonce}` } });
  st = await status();
  record('flowsta://claim/v1?nonce= is recorded and listed in /status.claims', cl.status === 200 && Array.isArray(st.claims) && st.claims.includes(nonce), `${cl.status} claims=${JSON.stringify(st.claims)}`);
  const badClaim = await vaultFetch(port, '/dev/claim', { method: 'POST', body: { url: 'flowsta://claim/v1?nonce=zzzz' } });
  const relayNotClaim = await vaultFetch(port, '/dev/claim', { method: 'POST', body: { url: 'flowsta://relay/v1?code=ABCD-EFGH' } });
  record('a bad nonce and a relay URL are not claims', badClaim.status === 400 && relayNotClaim.status === 400, `${badClaim.status} ${relayNotClaim.status}`);
  if (port2) {
    const st2 = await status(port2);
    record('the second instance never lists the first instance\'s nonce', Array.isArray(st2.claims) && !st2.claims.includes(nonce), JSON.stringify(st2.claims));
  } else {
    record('claims isolation across instances skipped - set VAULT_MATRIX_RESTORE_PORT', true);
  }

  // 8b. Two identities: removing the selected one selects the other (the
  // next launch lands on the picker, not an empty wizard); erasing the
  // device clears both.
  await vaultFetch(port, '/dev/lock', { method: 'POST' });
  const rm = await vaultFetch(port, '/dev/reset', { method: 'POST' });
  const afterRm = await ids();
  const stRm = await status();
  record('remove the selected identity (B): one remains and A is selected, marker and all',
    rm.status === 200 && rm.data?.remaining === 1 && (afterRm.identities || []).length === 1 && afterRm.identities?.[0]?.key === keyA && afterRm.identities?.[0]?.active === true && stRm.active_identity === agentA && stRm.initialized === true && stRm.unlocked === false,
    `${rm.status} remaining=${rm.data?.remaining} ids=${JSON.stringify((afterRm.identities || []).map((x) => [x.key, x.active]))} active=${stRm.active_identity === agentA}`);
  const unAgain = await vaultFetch(port, '/dev/unlock-with-password', { method: 'POST', body: { password: pwA } });
  record("A's password opens the remaining identity", unAgain.status === 200 && unAgain.data?.agent_pub_key === agentA, `${unAgain.status}`);
  await vaultFetch(port, '/dev/lock', { method: 'POST' });
  const er = await vaultFetch(port, '/dev/erase-device', { method: 'POST' });
  const afterEr = await ids();
  const stEr = await status();
  record('erase everything: no identities on the device, /status reports none',
    er.status === 200 && (afterEr.identities || []).length === 0 && stEr.initialized === false && !stEr.active_identity,
    `${er.status} ids=${(afterEr.identities || []).length} initialized=${stEr.initialized}`);

  // 9. Reset -> restore B -> the email is checked against B, not the identity that was there before.
  if (!port2) { record('reset -> restore -> email leg skipped - set VAULT_MATRIX_RESTORE_PORT to a second FRESH instance', true); return; }
  const fresh2 = await status(port2);
  if (fresh2.initialized !== false) { record('reset -> restore -> email leg skipped - second instance already holds an identity', true); return; }
  const emailC = `matrix-sw-c-${stamp}@example.com`;
  const c = await vaultFetch(port2, '/dev/setup-identity', { method: 'POST', body: { api_url: API, password: pwA, email: emailC, display_name: 'Matrix C' } });
  record('second instance: C created', c.status === 200 && !!c.data?.agent_pub_key, `${c.status} ${c.data?.error || ''}`);
  if (c.status !== 200) return;
  record('conductor ready after C', await waitConductorReady(port2, 120));
  // Warm the grant cache under C (the 2026-09-28 bug: a token issued for C confirmed B's email against C).
  await vaultFetch(port2, '/dev/confirm-email', { method: 'POST', body: { api_url: API, email: emailC } });
  const rs = await vaultFetch(port2, '/dev/reset', { method: 'POST' });
  const afterReset = await status(port2);
  record('Reset Vault wipes the device: /status reports no identity', rs.status === 200 && afterReset.initialized === false, `${rs.status} ${JSON.stringify({ initialized: afterReset.initialized })}`);
  const rb = await vaultFetch(port2, '/dev/setup-identity', { method: 'POST', body: { api_url: API, password: pwB, phrase: phraseB, restore: true } });
  record('restore B from its phrase on the reset device', rb.status === 200 && rb.data?.agent_pub_key === agentB, `${rb.status} ${rb.data?.error || ''} ${rb.data?.description || ''}`);
  if (rb.status !== 200) return;
  record('conductor ready after restoring B', await waitConductorReady(port2, 120));
  await vaultFetch(port2, '/dev/lock', { method: 'POST' });
  await vaultFetch(port2, '/dev/unlock', { method: 'POST', body: {} });
  const wrongC = await vaultFetch(port2, '/dev/confirm-email', { method: 'POST', body: { api_url: API, email: emailC } });
  if (wrongC.status !== 403 && /rate_limited/.test(wrongC.data?.description || '')) {
    record("email refusal check skipped - staging grant limiter (rate_limited); wait 15 min and rerun the leg to cover it", true, `${wrongC.status}`);
  } else {
    record("the previous identity's email is refused for B (grant follows the identity, not the device)", wrongC.status === 403 && wrongC.data?.error === 'email_mismatch', `${wrongC.status} ${wrongC.data?.error}`);
  }
  const rightB = await vaultFetch(port2, '/dev/confirm-email', { method: 'POST', body: { api_url: API, email: emailB.toUpperCase() } });
  const idB = (await vaultFetch(port2, '/dev/identity')).data || {};
  if (rightB.status !== 200 && /rate_limited/.test(rightB.data?.description || '')) {
    // The staging API's vault-grant limiter, not the Vault: several matrix
    // runs from one address in an hour trip it. The refusal above already
    // proved the grant is bound to the identity; the accept case passed on
    // the first run of the day.
    record("B's own email confirm skipped - staging grant limiter (rate_limited); wait 15 min and rerun the leg to cover it", true, `${rightB.status}`);
  } else {
    record("B's own email is confirmed and stored on the restored device", rightB.status === 200 && idB.web_email === emailB, `${rightB.status} web_email=${idB.web_email}`);
  }
  void phraseA;
}

// ───────────────────────── 1.6.0 devices leg ─────────────────────────
//
// One identity on two devices, end to end, through the dev harness's
// /dev/devices operations (the same functions the pages call). Two FRESH
// instances on the staging network. Regressions pinned here: the phrase
// door after a removal, a removal that holds when the removed device writes
// its record again, and a removed device that stays locked.

async function devicesLeg() {
  console.log('\n── Devices leg (one identity, two devices)');
  const a = Number(process.env.VAULT_MATRIX_PORT || 0);
  const b = Number(process.env.VAULT_MATRIX_RESTORE_PORT || 0);
  if (!a || !b) { record('devices leg skipped - set VAULT_MATRIX_PORT and VAULT_MATRIX_RESTORE_PORT to two FRESH test instances', true); return; }
  const op = async (port, body) => (await vaultFetch(port, '/dev/devices', { method: 'POST', body })).data || {};
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const until = async (fn, secs) => {
    const deadline = Date.now() + secs * 1000;
    while (Date.now() < deadline) { if (await fn().catch(() => false)) return true; await sleep(2000); }
    return false;
  };
  // Signing and reading signatures on a named instance.
  const signOn = async (port, fileHash) => {
    const sub = await vaultFetch(port, '/sign-document', { method: 'POST', body: { ...signBody(fileHash), job: true } });
    if (sub.status !== 200 || !sub.data?.job_id) return { stage: 'failed', error: `${sub.status} ${JSON.stringify(sub.data)}` };
    let last = {};
    await until(async () => { last = (await vaultFetch(port, `/op-status/${sub.data.job_id}`)).data || {}; return last.stage === 'done' || last.stage === 'failed'; }, 300);
    return last;
  };
  const sigsOn = async (port) => ((await vaultFetch(port, '/signatures')).data?.signatures) || [];
  const hashSignedOnA = randomHash();
  const hashSignedOnB = randomHash();
  const pwA = `Matrix-dev-a-${randomHash().slice(0, 10)}!`;
  const pwB = `Matrix-dev-b-${randomHash().slice(0, 10)}!`;

  for (const port of [a, b]) {
    const st = await vaultFetch(port, '/status');
    if (st.data?.initialized !== false) { record(`devices leg skipped - the instance on ${port} already holds an identity`, true); return; }
  }

  // 1. A creates the identity.
  const created = await vaultFetch(a, '/dev/setup-identity', { method: 'POST', body: { api_url: API, password: pwA, email: `matrix-devices-${Date.now()}@example.com`, display_name: 'Matrix Devices' } });
  record('A: identity created', created.status === 200 && !!created.data?.phrase, `${created.status} ${created.data?.description || ''}`);
  if (created.status !== 200) return;
  const phrase = created.data.phrase;
  record('A: its records answer', await until(async () => Array.isArray((await op(a, { op: 'list' })).devices), 240));
  const standingA = await op(a, { op: 'standing' });
  record('A: registered with the account, enrollment key in force from the start',
    standingA.standing?.device === 'registered' && standingA.standing?.enrollment === 'in_force', JSON.stringify(standingA.standing));
  const stA = await op(a, { op: 'status' });
  record('A: the first device runs the identity key', stA.own_conductor_key === false && stA.joined_existing === false);
  await op(a, { op: 'write', text: 'from A, before B' });
  await op(a, { op: 'connect', client_id: 'matrix_app', app_name: 'Matrix App' });
  await vaultFetch(a, '/dev/remember-origin', { method: 'POST', body: { origin: 'https://remembered.example' } });
  await op(a, { op: 'backup', client_id: 'matrix_app', label: 'recovery', text: 'A recovery v1' });
  const oldPicture = 'data:image/svg+xml;base64,PHN2Zy8+';
  record('A: holds a picture record written before devices were named', !!(await op(a, { op: 'old-picture', picture: oldPicture })).action_hash);
  const signedA = await signOn(a, hashSignedOnA);
  record('A: signs a file', signedA.stage === 'done' && !!signedA.result?.action_hash, JSON.stringify(signedA).slice(0, 200));
  record('A: lists its signature', await until(async () => (await sigsOn(a)).some((x) => x.file_hash === hashSignedOnA), 60));
  record('A: a round says what it holds', (await op(a, { op: 'round' })).round === 'done');

  // 2. B joins with a code. A cancelled code is refused at once.
  const cancelled = (await op(b, { op: 'pair-begin', password: pwB })).code;
  await op(b, { op: 'pair-cancel' });
  const refused = await vaultFetch(a, '/dev/devices', { method: 'POST', body: { op: 'pair-claim', code: cancelled } });
  record('a cancelled code is not found', refused.status === 400 && /code_not_found/.test(refused.data?.description || ''), JSON.stringify(refused.data));
  const code = (await op(b, { op: 'pair-begin', password: pwB })).code;
  record('B: shows a code in three groups', /^[A-Z]{4}-[A-Z]{4}-[A-Z]{4}$/.test(code || ''), code);
  const claim = await op(a, { op: 'pair-claim', code: (code || '').toLowerCase().replace(/-/g, ' ') });
  record('A: the typed code (lower case, spaces) names the new device', !!claim.intro?.install_id && !!claim.intro?.name, JSON.stringify(claim));
  // While B starts, commands that find its conductor down ask for it to be
  // started too. One start wins; what follows a start still happens.
  let hammering = true;
  const hammer = (async () => { while (hammering) { await op(b, { op: 'watchdog' }).catch(() => {}); await sleep(150); } })();
  record('A: approves', (await op(a, { op: 'pair-approve' })).approved === true);
  record('B: holds the identity', await until(async () => (await op(b, { op: 'status' })).unlocked === true, 60));
  record('B: its conductor comes up once, under competing starts', await until(async () => (await op(b, { op: 'status' })).conductor?.status === 'ready', 180));
  await sleep(5000);
  hammering = false;
  await hammer;
  record('B: the conductor is still the one that started', (await op(b, { op: 'status' })).conductor?.status === 'ready');
  const stB = await op(b, { op: 'status' });
  record('B: same identity, its own conductor key, joined', stB.agent_pub_key === stA.agent_pub_key && stB.own_conductor_key === true && stB.joined_existing === true, JSON.stringify(stB));
  record('B: registered with the account (approved by A)', await until(async () => (await op(b, { op: 'standing' })).standing?.device === 'registered', 90));
  const installB = stB.install_id;

  // 3. Records, devices, connections, backups reach B.
  record("B: A's record arrives", await until(async () => ((await op(b, { op: 'notes' })).notes || []).some((n) => n.text === 'from A, before B'), 240));
  // Real records only: a joined device lists itself as "being set up" before its own record exists.
  const written = async (x) => ((await op(x, { op: 'list' })).devices || []).filter((d) => d.state !== 'this_device_setting_up').length;
  record('both list two devices', await until(async () => (await written(a)) === 2 && (await written(b)) === 2, 180));
  record('B: lists itself without being asked to run a round', ((await op(b, { op: 'list' })).devices || []).some((d) => d.state === 'this_device'));
  // Signatures belong to the identity: made on either device, listed on both.
  record("B: lists the signature made on A before it joined", await until(async () => (await sigsOn(b)).some((x) => x.file_hash === hashSignedOnA), 300));
  const signedB = await signOn(b, hashSignedOnB);
  record('B: the added device signs a file', signedB.stage === 'done' && !!signedB.result?.action_hash, JSON.stringify(signedB).slice(0, 200));
  record('B: lists both signatures', await until(async () => { const l = await sigsOn(b); return l.some((x) => x.file_hash === hashSignedOnA) && l.some((x) => x.file_hash === hashSignedOnB); }, 120));
  record('A: lists the signature made on B', await until(async () => (await sigsOn(a)).some((x) => x.file_hash === hashSignedOnB), 300));
  const countA = (await sigsOn(a)).length, countB = (await sigsOn(b)).length;
  record("both list the identity's two signatures and nothing else", countA === 2 && countB === 2, `A ${countA}, B ${countB}`);
  await op(b, { op: 'round' });
  const connB = await op(b, { op: 'connections' });
  record('B: the picture written before devices were named arrives', await until(async () => { await op(b, { op: 'round' }); return (await op(b, { op: 'status' })).profile_picture === oldPicture; }, 120));
  record('B: the remembered site carried over; the app is NOT connected here', (connB.sites || []).includes('https://remembered.example') && !(connB.apps || []).includes('matrix_app'), JSON.stringify(connB));
  record('B: knows the app is used on A, so a link here says so', (connB.elsewhere || []).includes('matrix_app'), JSON.stringify(connB.elsewhere));
  const heldB = await until(async () => { await op(b, { op: 'round' }); return ((await op(b, { op: 'backups', client_id: 'matrix_app' })).held || []).some((h) => h.from && h.opens_as === 'A recovery v1'); }, 120);
  record("B: holds and opens a copy of A's app backup", heldB);
  const actB = (await vaultFetch(b, '/dev/status')).data?.activity || [];
  record('B: is not told that the devices already there were "added"', !actB.includes('device_added_elsewhere'), JSON.stringify(actB));
  const actA = (await vaultFetch(a, '/dev/status')).data?.activity || [];
  record('A: logs that it added B, not that B was added elsewhere', actA.includes('device_added') && !actA.includes('device_added_elsewhere'), JSON.stringify(actA));

  // 4. Disconnect applies on every device.
  await op(b, { op: 'connect', client_id: 'matrix_app', app_name: 'Matrix App' });
  await op(b, { op: 'round' });
  await op(a, { op: 'disconnect', client_id: 'matrix_app' });
  await op(a, { op: 'round' });
  record('a Disconnect on A disconnects the app on B', await until(async () => { await op(b, { op: 'round' }); return !((await op(b, { op: 'connections' })).apps || []).includes('matrix_app'); }, 120));

  // 5. Locked but still syncing.
  await op(a, { op: 'earlier-web-key', key: 'uhCAkHARNESS' });
  await op(a, { op: 'lock' });
  const lockedA = await op(a, { op: 'status' });
  record('A locked: the earlier web key is forgotten', lockedA.earlier_web_key == null, JSON.stringify(lockedA.earlier_web_key));
  record('A locked: still syncing, conductor up', lockedA.unlocked === false && lockedA.syncing_while_locked === true && lockedA.conductor?.status === 'ready', JSON.stringify(lockedA));
  const refusedRead = await vaultFetch(a, '/dev/devices', { method: 'POST', body: { op: 'notes' } });
  record('A locked: reads are refused', refusedRead.status === 400 && /vault_locked/.test(refusedRead.data?.description || ''));
  await op(b, { op: 'write', text: 'from B, while A was locked' });
  await sleep(15000);
  const t0 = Date.now();
  const unlocked = await vaultFetch(a, '/dev/unlock', { method: 'POST' });
  record('A unlocks onto the running conductor', unlocked.status === 200 && (await op(a, { op: 'status' })).conductor?.status === 'ready', `${Date.now() - t0} ms`);
  record('A unlocked: the earlier web key is its own (none), not a leftover', (await op(a, { op: 'status' })).earlier_web_key == null);
  record("A: B's record written while it was locked is there", await until(async () => ((await op(a, { op: 'notes' })).notes || []).some((n) => n.text === 'from B, while A was locked'), 60));

  // 6. Remove. The removal holds even after the removed device's own round.
  const removed = await op(a, { op: 'remove', install_id: installB });
  record('A: removes B', removed.removed === true, JSON.stringify(removed));
  const rowB = async () => ((await op(a, { op: 'list' })).devices || []).find((d) => d.install_id === installB);
  record('A: B reads as removed', (await rowB())?.state === 'removed');
  await op(b, { op: 'round' });   // B's routine round: it may refresh its record before it has heard
  await sleep(20000);
  await op(a, { op: 'round' });
  record('A: B still reads as removed after B wrote its record again', (await rowB())?.state === 'removed', JSON.stringify(await rowB()));
  const stood = await until(async () => { await op(b, { op: 'round' }).catch(() => {}); return (await op(b, { op: 'status' })).removed === true; }, 240);
  record('B: stands down (locked, conductor stopped)', stood && (await op(b, { op: 'status' })).unlocked === false);
  const tryUnlock = await vaultFetch(b, '/dev/unlock-with-password', { method: 'POST', body: { password: pwB } });
  record('B: the password does not unlock a removed device', tryUnlock.status !== 200 && /device_removed/.test(JSON.stringify(tryUnlock.data || {})), JSON.stringify(tryUnlock.data));

  // 7. The phrase door after a removal.
  const reset = await vaultFetch(b, '/dev/reset', { method: 'POST' });
  record('B: its copy is removed', reset.status === 200);
  const door = await vaultFetch(b, '/dev/devices', { method: 'POST', body: { op: 'phrase-door', phrase, password: pwB } });
  record('B: the recovery phrase adds it back although the account has removed a device', door.status === 200 && door.data?.agent_pub_key === stA.agent_pub_key, JSON.stringify(door.data));
  record('B: registered with the account again', await until(async () => (await op(b, { op: 'standing' })).standing?.device === 'registered', 120));
  record('B: its records arrive again', await until(async () => ((await op(b, { op: 'notes' })).notes || []).length >= 2, 300));
  record('A: lists B again as ONE device, not removed', await until(async () => { await op(a, { op: 'round' }); const rows = ((await op(a, { op: 'list' })).devices || []).filter((d) => d.install_id === installB); return rows.length === 1 && rows[0].state !== 'removed'; }, 300));
  record('A: is told a device was added elsewhere', await until(async () => { await op(a, { op: 'round' }); return ((await vaultFetch(a, '/dev/status')).data?.activity || []).includes('device_added_elsewhere'); }, 120));
}

// ───────────────────────── main ─────────────────────────

/** Staging leaves an address that presents the test key out of its rate
 * limits for two hours, so the legs can run back to back. The key comes
 * from VAULT_MATRIX_TEST_KEY or ~/.config/flowsta/staging-test-key; with
 * neither, the limits apply as they do to anyone. Never sent to production. */
async function askForRateLimitExemption() {
  if (!/staging/.test(API)) return;
  let key = process.env.VAULT_MATRIX_TEST_KEY || '';
  if (!key) {
    try { key = (await import('node:fs')).readFileSync(`${process.env.HOME}/.config/flowsta/staging-test-key`, 'utf8').trim(); } catch { /* none */ }
  }
  if (!key) { console.log('No staging test key: the rate limits apply.'); return; }
  // The Vaults may reach the API over IPv4 or IPv6: ask from both.
  const https = await import('node:https');
  const ask = (family) => new Promise((done) => {
    const req = https.request(`${API}/api/v1/test/rate-limit-exemption`, { method: 'POST', family, headers: { 'x-flowsta-test-key': key, 'content-length': 0 }, timeout: 15000 }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => { let until = null; try { until = JSON.parse(body).exempt_until; } catch { /* not JSON */ } done({ status: res.statusCode, until }); });
    });
    req.on('error', () => done({ status: null }));
    req.on('timeout', () => { req.destroy(); done({ status: null }); });
    req.end();
  });
  for (const family of [4, 6]) {
    const r = await ask(family);
    console.log(r.status === 200 ? `IPv${family}: left out of the staging rate limits until ${r.until}` : `IPv${family}: no exemption (${r.status ?? 'unreachable'}) - the limits apply on that route.`);
  }
}

(async () => {
  console.log(`Bridge matrix — phase: ${PHASE}, origin: ${ORIGIN}`);
  await askForRateLimitExemption();
  if (PHASE === 'switcher') {
    await switcherLeg();
    const passedS = results.filter((r) => r.ok).length;
    console.log(`\nRESULT: ${passedS}/${results.length} checks passed${failures ? ` — ${failures} FAILED` : ' — ALL GREEN'}`);
    if (failures) for (const r of results.filter((x) => !x.ok)) console.log(`  ✗ ${r.name} ${r.detail}`);
    process.exit(failures ? 1 : 0);
  }
  if (PHASE === 'devices') {
    await devicesLeg();
    const passedD = results.filter((r) => r.ok).length;
    console.log(`\nRESULT: ${passedD}/${results.length} checks passed${failures ? ` — ${failures} FAILED` : ' — ALL GREEN'}`);
    if (failures) for (const r of results.filter((x) => !x.ok)) console.log(`  ✗ ${r.name} ${r.detail}`);
    process.exit(failures ? 1 : 0);
  }
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
