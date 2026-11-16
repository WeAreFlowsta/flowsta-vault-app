#!/usr/bin/env node
/**
 * The published SDK, used from a Node program, against a test Vault.
 *
 * A desktop app's main process (Electron, a Node tool) calls the Vault with
 * Node's own fetch: no Origin, and Node's own request headers. This walks
 * the calls such an app makes with `@flowsta/holochain` exactly as npm
 * ships it: status, link, link status, backup, list, retrieve, the
 * identity check, a signature.
 *
 * The Vault tells apps apart by the origin a request carries, and Node
 * sends none. SDK_ORIGIN is the origin the app registered: the program adds
 * it to its requests to the Vault (`setVaultOrigin` from SDK 3.12.0; with
 * an earlier SDK this script adds the header itself).
 * Without SDK_ORIGIN the program sends no origin: it is told the identity
 * (a local program), and its request to connect is refused with words
 * that say what to do.
 *
 *   SDK_DIR=<a folder where `npm install @flowsta/holochain` was run> \
 *   SDK_ORIGIN=<the app's registered origin, for example tauri://localhost> \
 *   VAULT_MATRIX_PORT=<test Vault port> VAULT_MATRIX_APP_CLIENT_ID=<client id> \
 *   node scripts/sdk-from-node.mjs
 *
 * The test Vault is a debug build started by scripts/run-test-instance.sh,
 * unlocked, with an identity (it approves its dialogs itself).
 */
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import crypto from 'node:crypto';
import fs from 'node:fs';

const port = Number(process.env.VAULT_MATRIX_PORT || 0);
const clientId = process.env.VAULT_MATRIX_APP_CLIENT_ID || '';
const sdkDir = process.env.SDK_DIR || '';
if (!port || !clientId || !sdkDir) {
  console.error('needs SDK_DIR, VAULT_MATRIX_PORT and VAULT_MATRIX_APP_CLIENT_ID');
  process.exit(2);
}
const require = createRequire(path.join(path.resolve(sdkDir), 'package.json'));
const sdk = await import(pathToFileURL(require.resolve('@flowsta/holochain')).href);
const version = JSON.parse(fs.readFileSync(path.join(path.resolve(sdkDir), 'node_modules/@flowsta/holochain/package.json'), 'utf8')).version;
const ipcUrl = `http://127.0.0.1:${port}`;
const origin = process.env.SDK_ORIGIN || '';
// An SDK with setVaultOrigin (3.12.0) is told the origin; an earlier one has
// it added to its requests here.
if (origin && typeof sdk.setVaultOrigin === 'function') {
  sdk.setVaultOrigin(origin);
} else if (origin) {
  const plain = globalThis.fetch;
  globalThis.fetch = (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    if (!url.startsWith(ipcUrl)) return plain(input, init);
    const headers = new Headers(init.headers || {});
    headers.set('Origin', origin);
    return plain(input, { ...init, headers });
  };
}

let passed = 0;
let failed = 0;
const record = (name, ok, detail = '') => {
  if (ok) passed += 1; else failed += 1;
  console.log(`  ${ok ? '✓' : '✗'} ${name}${detail ? ` — ${String(detail).slice(0, 200)}` : ''}`);
};
const attempt = async (fn) => { try { return { value: await fn() }; } catch (error) { return { error }; } };
const fakeAgentKey = () => {
  const raw = Buffer.concat([Buffer.from([0x84, 0x20, 0x24]), crypto.randomBytes(36)]);
  return 'u' + raw.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

console.log(`── @flowsta/holochain ${version} from Node ${process.version}, Vault on ${port}, ${origin ? `as ${origin}` : 'with no origin'}`);
const appKey = fakeAgentKey();
const appName = 'SDK from Node';

const status = await attempt(() => sdk.getVaultStatus(ipcUrl));
record('status: running and unlocked', !!status.value?.running && !!status.value?.unlocked, JSON.stringify(status.value ?? String(status.error)));
if (!status.value?.unlocked) { console.log(`RESULT: ${passed}/${passed + failed} checks passed`); process.exit(1); }
// An origin that is not linked yet is not told the identity; a program
// with no origin is a local program and is.
if (!origin) record('status: a local program is told the identity', !!status.value?.agentPubKey);
else record('status: an origin that is not linked yet is not told the identity', !status.value?.agentPubKey);

const link = await attempt(() => sdk.linkFlowstaIdentity({ appName, clientId, localAgentPubKey: appKey, ipcUrl }));
if (!origin) {
  record('with no origin, the request to connect is refused and says what to do', link.error?.code === 'origin_required' && /Origin header/.test(link.error?.message || ''), link.error ? `${link.error.name}: ${link.error.message}` : 'it was linked');
  const none = await attempt(() => sdk.getFlowstaLinkStatus({ clientId, localAgentPubKey: appKey, ipcUrl }));
  record('and nothing was linked', !!none.value && none.value.state !== 'linked', JSON.stringify(none.value ?? String(none.error)));
  console.log(`RESULT: ${passed}/${passed + failed} checks passed${failed ? '' : ' — ALL GREEN'}`);
  process.exit(failed ? 1 : 0);
}
const me = link.value?.payload?.vaultAgentPubKey;
record('link: approved, signed by the Vault identity', link.value?.success === true && !!me && !!link.value?.payload?.vaultSignature, link.error ? `${link.error.name}: ${link.error.message}` : '');
record('link: a link token came back', typeof link.value?.linkToken === 'string' && link.value.linkToken.length > 0);
const identity = await attempt(() => sdk.getVaultIdentity(ipcUrl));
record('once linked, getVaultIdentity returns the identity it linked with', !!me && identity.value === me, identity.value ?? String(identity.error));
const linked = await attempt(() => sdk.getFlowstaLinkStatus({ clientId, localAgentPubKey: appKey, ipcUrl }));
record('link status: linked', linked.value?.state === 'linked', JSON.stringify(linked.value ?? String(linked.error)));

const data = { note: 'written by a Node program', at: Date.now(), bytes: crypto.randomBytes(24).toString('hex') };
const wrote = await attempt(() => sdk.backupToVault({ clientId, appName, localAgentPubKey: appKey, ipcUrl }, data));
record('backup: written', wrote.value?.success === true, wrote.error ? `${wrote.error.name}: ${wrote.error.message}` : JSON.stringify(wrote.value));
const listed = await attempt(() => sdk.listVaultBackups(ipcUrl, { clientId, localAgentPubKey: appKey }));
record('backups: this app\'s is listed', (listed.value?.totalBackups ?? 0) >= 1, JSON.stringify(listed.value ?? String(listed.error)));
const read = await attempt(() => sdk.retrieveFromVault({ clientId, localAgentPubKey: appKey, ipcUrl }));
record('retrieve: the same data comes back', JSON.stringify(read.value?.data) === JSON.stringify(data), read.error ? `${read.error.name}: ${read.error.message}` : '');

const signed = await attempt(() => sdk.signDocument({ clientId, appName, localAgentPubKey: appKey, ipcUrl, fileHash: crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex'), label: 'sdk-from-node', publish: false }));
record('sign: a signature by the Vault identity', !!signed.value?.signature, signed.error ? `${signed.error.name}: ${signed.error.message}` : '');

// Bound to another identity, a write is refused before it is made.
sdk.bindVaultIdentity(fakeAgentKey());
const mismatch = await attempt(() => sdk.backupToVault({ clientId, appName, localAgentPubKey: appKey, ipcUrl }, data));
record('a write for another identity is refused as a mismatch', mismatch.error?.name === 'IdentityMismatchError', mismatch.error ? `${mismatch.error.name}: ${mismatch.error.message}` : 'it was written');
sdk.clearBoundIdentity();

const unlinked = await attempt(() => sdk.revokeFlowstaIdentity({ appName, clientId, localAgentPubKey: appKey, ipcUrl }));
record('unlink: the app removes its own link', !unlinked.error, unlinked.error ? `${unlinked.error.name}: ${unlinked.error.message}` : '');
const after = await attempt(() => sdk.getFlowstaLinkStatus({ clientId, localAgentPubKey: appKey, ipcUrl }));
record('link status: no longer linked', !!after.value && after.value.state !== 'linked', JSON.stringify(after.value ?? String(after.error)));

console.log(`RESULT: ${passed}/${passed + failed} checks passed${failed ? '' : ' — ALL GREEN'}`);
process.exit(failed ? 1 : 0);
