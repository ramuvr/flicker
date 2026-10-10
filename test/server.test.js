'use strict';

// Limits are lowered so the abuse tests run quickly. Each test uses its own
// X-Forwarded-For address so rate-limit buckets do not interfere.
process.env.RATE_LIMIT_PER_MIN = '20';
process.env.MAX_TOTAL_MB = '1';
// Cheap proof-of-work so tests run fast; a known HMAC secret lets tests forge edge cases.
process.env.ALTCHA_HMAC_SECRET = 'test-hmac-secret';
process.env.ALTCHA_COST = '10';
process.env.ALTCHA_COUNTER_MIN = '1';
process.env.ALTCHA_COUNTER_MAX = '20';
// Hostile operator settings: must be rendered as text, never as markup.
process.env.OPERATOR_NAME = '<script>alert(1)</script> & "Co"';
process.env.CONTACT_EMAIL = 'privacy@example.com';
process.env.JURISDICTION = '<img src=x onerror=alert(1)>';
delete process.env.POLICY_EFFECTIVE_DATE;

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const crypto = require('node:crypto');
const altchaLib = require('altcha-lib');
const { deriveKey } = require('altcha-lib/algorithms/pbkdf2');
const { server, store, clientKey, usedChallenges } = require('../server.js');

let base;
let port;
test.before(async () => {
  await new Promise((r) => server.listen(0, r));
  port = server.address().port;
  base = `http://127.0.0.1:${port}`;
});
test.after(() => server.close());

const CT = 'A'.repeat(40); // minimal well-formed ciphertext
let ipCounter = 0;
const newIp = () => `203.0.113.${++ipCounter}`;

const encodePayload = (challenge, solution) => Buffer.from(JSON.stringify({ challenge, solution })).toString('base64');

// Fetches a challenge from the server and solves it, as the browser widget does.
async function solvedPayload() {
  const challenge = await (await fetch(base + '/api/challenge', { headers: { 'X-Forwarded-For': newIp() } })).json();
  const solution = await altchaLib.solveChallenge({ challenge, deriveKey });
  return encodePayload(challenge, solution);
}

// body.altcha: undefined = solve a fresh challenge automatically; null = send none.
async function create(body, { ip = newIp(), headers = {} } = {}) {
  if (typeof body === 'object' && body !== null && !Array.isArray(body) && body.altcha === undefined) {
    body = { ...body, altcha: await solvedPayload() };
  }
  return fetch(base + '/api/secrets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip, ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}
function read(id, { ip = newIp(), headers = {} } = {}) {
  return fetch(`${base}/api/secrets/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip, ...headers },
    body: '{}',
  });
}
async function newSecret(data = CT) {
  const res = await create({ data, ttl: 3600 });
  assert.strictEqual(res.status, 201);
  return (await res.json()).id;
}

// ---------- Core one-time behaviour ----------

test('secret can be read exactly once', async () => {
  const id = await newSecret();
  assert.match(id, /^[A-Za-z0-9_-]{22}$/);
  assert.strictEqual((await fetch(`${base}/api/secrets/${id}`, { method: 'HEAD' })).status, 204);

  const first = await read(id);
  assert.strictEqual(first.status, 200);
  assert.deepStrictEqual(await first.json(), { data: CT });

  assert.strictEqual((await read(id)).status, 404);
  assert.strictEqual((await fetch(`${base}/api/secrets/${id}`, { method: 'HEAD' })).status, 404);
  assert.strictEqual(store.has(id), false);
});

test('race: 20 simultaneous reads return the secret only once', async () => {
  const id = await newSecret();
  const results = await Promise.all(Array.from({ length: 20 }, () => read(id).then((r) => r.status)));
  assert.strictEqual(results.filter((s) => s === 200).length, 1);
  assert.strictEqual(results.filter((s) => s === 404).length, 19);
});

test('GET requests (link previews, scanners) do not consume the secret', async () => {
  const id = await newSecret();
  assert.strictEqual((await fetch(`${base}/api/secrets/${id}`)).status, 404);
  assert.strictEqual((await fetch(`${base}/s/${id}`)).status, 200);
  assert.strictEqual((await fetch(`${base}/api/secrets/${id}`, { method: 'HEAD' })).status, 204);
  assert.strictEqual(store.has(id), true);
});

test('expired secret is not returned and is removed', async () => {
  const id = await newSecret();
  store.get(id).expiresAt = Date.now() - 1;
  assert.strictEqual((await read(id)).status, 404);
  assert.strictEqual(store.has(id), false);
});

test('unknown, guessed and malformed IDs are rejected', async () => {
  for (const id of ['AAAAAAAAAAAAAAAAAAAAAA', 'short', '../../etc/passwd', '%00', 'a'.repeat(23)]) {
    assert.strictEqual((await read(encodeURIComponent(id))).status, 404, id);
  }
});

test('IDs are random and unique', async () => {
  const ids = new Set();
  for (let i = 0; i < 15; i++) ids.add(await newSecret());
  assert.strictEqual(ids.size, 15);
  for (const id of ids) store.delete(id);
});

// ---------- Input validation ----------

test('rejects malformed and hostile input', async () => {
  assert.strictEqual((await create({ data: 'not base64!' + 'A'.repeat(40), ttl: 3600 })).status, 400);
  assert.strictEqual((await create({ data: 'A'.repeat(10), ttl: 3600 })).status, 400, 'too short');
  assert.strictEqual((await create({ data: CT, ttl: 5 })).status, 400, 'ttl not allowed');
  assert.strictEqual((await create({ data: CT, ttl: '3600' })).status, 400, 'ttl wrong type');
  assert.strictEqual((await create({ data: ['A'], ttl: 3600 })).status, 400, 'data wrong type');
  assert.strictEqual((await create('null')).status, 400);
  assert.strictEqual((await create('[]')).status, 400);

  const bad = await create('{not json');
  assert.strictEqual(bad.status, 400);
  const text = await bad.text();
  assert.ok(!/at |stack|\.js:/i.test(text), 'no stack traces in errors');
});

test('error messages never echo user input (no reflected XSS)', async () => {
  const payload = '<script>alert(1)</script>';
  const res = await create({ data: payload, ttl: 3600 });
  assert.strictEqual(res.status, 400);
  assert.ok(!(await res.text()).includes(payload));
  assert.match(res.headers.get('content-type'), /^application\/json/);
});

test('prototype pollution payloads have no effect', async () => {
  const res = await create('{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}');
  assert.strictEqual(res.status, 400);
  assert.strictEqual({}.polluted, undefined);
});

// ---------- Cross-site request protection ----------

test('other websites cannot create or burn secrets (CSRF)', async () => {
  const id = await newSecret();
  // Simple cross-site form/fetch requests use text/plain to avoid CORS preflight.
  const plain = await fetch(`${base}/api/secrets/${id}`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
  assert.strictEqual(plain.status, 403);
  const noType = await fetch(`${base}/api/secrets/${id}`, { method: 'POST' });
  assert.strictEqual(noType.status, 403);
  assert.strictEqual((await read(id, { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.strictEqual((await create({ data: CT, ttl: 3600 }, { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.strictEqual(store.has(id), true, 'secret survives');

  // No CORS approval is ever granted.
  const pre = await fetch(`${base}/api/secrets`, {
    method: 'OPTIONS',
    headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' },
  });
  assert.strictEqual(pre.headers.get('access-control-allow-origin'), null);
});

// ---------- Static files / path traversal ----------

test('path traversal cannot read server files', async () => {
  for (const p of ['/../server.js', '/%2e%2e/server.js', '/public/../server.js', '/..%2fserver.js', '/server.js', '/package.json', '/.env', '/s/../../server.js']) {
    const res = await fetch(base + p);
    const body = await res.text();
    assert.ok(!body.includes('createServer'), `leaked source via ${p}`);
    assert.ok(res.status === 404 || res.status === 200, p);
  }
  // Raw request without URL normalisation by the client.
  const raw = await new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port, path: '/../../server.js' }, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => resolve(b));
    });
  });
  assert.ok(!raw.includes('createServer'));
});

test('unsupported methods are refused', async () => {
  const id = await newSecret();
  for (const method of ['PUT', 'DELETE', 'PATCH', 'GET']) {
    assert.strictEqual((await fetch(`${base}/api/secrets/${id}`, { method })).status, 404, method);
  }
  assert.strictEqual(store.has(id), true);
});

// ---------- Security headers ----------

test('security headers are present on pages, API and errors', async () => {
  const responses = [await fetch(base + '/'), await fetch(base + '/app.js'), await create({ data: 'x', ttl: 1 }), await fetch(base + '/nope')];
  for (const res of responses) {
    const h = res.headers;
    assert.ok(h.get('content-security-policy').includes("default-src 'none'"));
    assert.ok(h.get('content-security-policy').includes("frame-ancestors 'none'"));
    assert.ok(!h.get('content-security-policy').includes('unsafe-inline'));
    assert.strictEqual(h.get('referrer-policy'), 'no-referrer');
    assert.strictEqual(h.get('cache-control'), 'no-store');
    assert.strictEqual(h.get('x-content-type-options'), 'nosniff');
    assert.strictEqual(h.get('x-frame-options'), 'DENY');
    assert.strictEqual(h.get('cross-origin-opener-policy'), 'same-origin');
    assert.ok(h.get('strict-transport-security'));
    assert.strictEqual(h.get('set-cookie'), null, 'no cookies');
    assert.strictEqual(h.get('x-powered-by'), null);
  }
});

// ---------- Abuse / denial of service ----------

test('oversized body (declared length) is rejected with 413', async () => {
  const res = await create({ data: 'A'.repeat(300 * 1024), ttl: 3600 });
  assert.strictEqual(res.status, 413);
});

test('oversized body (chunked, no length) is cut off and server stays up', async () => {
  const status = await new Promise((resolve) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: '/api/secrets', method: 'POST', headers: { 'Content-Type': 'application/json', 'Transfer-Encoding': 'chunked' } },
      (res) => resolve(res.statusCode),
    );
    req.on('error', () => resolve('closed'));
    const chunk = 'A'.repeat(64 * 1024);
    let sent = 0;
    (function write() {
      while (sent < 2000 && req.write(chunk)) sent++; // up to ~128 MB if never cut off
      if (sent < 2000 && !req.destroyed) req.once('drain', write);
      else req.end();
    })();
  });
  assert.ok(status === 413 || status === 'closed', `got ${status}`);
  assert.strictEqual((await fetch(base + '/healthz')).status, 200);
});

test('rate limit applies per client', async () => {
  const ip = newIp();
  const statuses = [];
  for (let i = 0; i < 22; i++) statuses.push((await read('AAAAAAAAAAAAAAAAAAAAAA', { ip })).status);
  assert.deepStrictEqual(statuses.slice(0, 20), Array(20).fill(404));
  assert.deepStrictEqual(statuses.slice(20), [429, 429]);
  // A different client is unaffected.
  assert.strictEqual((await read('AAAAAAAAAAAAAAAAAAAAAA')).status, 404);
});

test('rate limit cannot be bypassed by forging X-Forwarded-For', async () => {
  const realIp = newIp();
  const statuses = [];
  for (let i = 0; i < 22; i++) {
    // The proxy appends the real address; a client can only add entries to the left.
    statuses.push((await read('AAAAAAAAAAAAAAAAAAAAAA', { ip: `10.0.0.${i}, ${realIp}` })).status);
  }
  assert.strictEqual(statuses.at(-1), 429);
});

test('IPv6 clients are grouped by /64 so rotating addresses does not help', () => {
  const k = (xff) => clientKey({ headers: { 'x-forwarded-for': xff }, socket: { remoteAddress: '127.0.0.1' } });
  assert.strictEqual(k('2001:db8:1:2::1'), k('2001:db8:1:2:ffff:ffff:ffff:ffff'));
  assert.notStrictEqual(k('2001:db8:1:2::1'), k('2001:db8:1:3::1'));
  assert.strictEqual(k('198.51.100.7:51234'), '198.51.100.7');
  assert.strictEqual(k('[2001:db8:1:2::9]:443'), k('2001:db8:1:2::1'));
});

test('memory cap: server refuses new secrets when total size limit is reached', async () => {
  const big = 'A'.repeat(250 * 1024);
  const ids = [];
  let refused = false;
  for (let i = 0; i < 6; i++) {
    const res = await create({ data: big, ttl: 3600 });
    if (res.status === 503) refused = true;
    else ids.push((await res.json()).id);
  }
  assert.ok(refused, 'expected 503 once 1 MB cap is hit');
  // Reading frees space again.
  for (const id of ids) await read(id);
  assert.strictEqual((await create({ data: big, ttl: 3600 })).status, 201);
});

// ---------- Policy pages ----------

const LEGAL_PAGES = { '/privacy': 'Privacy Policy', '/data-collection': 'Data Collection Policy', '/terms': 'Terms of Use' };

test('policy pages load with security headers and no scripts or third-party content', async () => {
  for (const [route, title] of Object.entries(LEGAL_PAGES)) {
    const res = await fetch(base + route);
    assert.strictEqual(res.status, 200, route);
    assert.match(res.headers.get('content-type'), /^text\/html/);
    assert.ok(res.headers.get('content-security-policy').includes("default-src 'none'"));
    assert.strictEqual(res.headers.get('x-frame-options'), 'DENY');
    assert.strictEqual(res.headers.get('set-cookie'), null);
    const html = await res.text();
    assert.ok(html.includes(`<h1>${title}</h1>`), route);
    assert.ok(!/<script/i.test(html.replace(/&lt;script/g, '')), `${route} has no script tags`);
    assert.ok(!/\son\w+\s*=/i.test(html.replace(/&lt;[^&]*&gt;/g, '')), `${route} has no inline event handlers`);
    assert.ok(!/(src|href)\s*=\s*["']?(https?:)?\/\//i.test(html), `${route} loads nothing from other sites`);
    assert.ok(!html.includes('{{'), `${route} has no unfilled template tokens`);
  }
});

test('operator settings are HTML-escaped on policy pages (no injection)', async () => {
  const html = await (await fetch(base + '/terms')).text();
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(!html.includes('<img src=x'));
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;Co&quot;'));
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(html.includes('<a href="mailto:privacy@example.com">privacy@example.com</a>'));
  // Missing settings are shown as visible placeholders rather than blank text.
  assert.ok(html.includes('[effective date not configured]'));
});

test('every link that opens a new window uses rel="noopener noreferrer"', async () => {
  for (const route of ['/', ...Object.keys(LEGAL_PAGES)]) {
    const html = await (await fetch(base + route)).text();
    const anchors = html.match(/<a\b[^>]*>/gi) || [];
    for (const a of anchors.filter((x) => /target="_blank"/i.test(x))) {
      assert.match(a, /rel="[^"]*\bnoopener\b[^"]*"/, `${route}: ${a}`);
      assert.match(a, /rel="[^"]*\bnoreferrer\b[^"]*"/, `${route}: ${a}`);
    }
    if (route === '/') {
      for (const r of Object.keys(LEGAL_PAGES)) assert.ok(html.includes(`href="${r}" target="_blank"`), `footer links to ${r}`);
    }
  }
});

// ---------- Bot protection (ALTCHA proof-of-work) ----------

const KEY_SECRET = crypto.createHmac('sha256', 'test-hmac-secret').update('altcha-key-signature').digest('hex');
function forgeChallenge({ hmac = 'test-hmac-secret', expiresAt = new Date(Date.now() + 60_000), algorithm = 'PBKDF2/SHA-256' } = {}) {
  return altchaLib.createChallenge({
    algorithm, cost: 10, counter: 5, expiresAt,
    deriveKey: algorithm === 'SHA-256' ? require('altcha-lib/algorithms/sha').deriveKey : deriveKey,
    hmacSignatureSecret: hmac,
    hmacKeySignatureSecret: crypto.createHmac('sha256', hmac).update('altcha-key-signature').digest('hex'),
  });
}

test('creating a secret requires a solved bot check', async () => {
  for (const altcha of [null, '', 'garbage', Buffer.from('{}').toString('base64'), 'A'.repeat(5000)]) {
    const res = await create({ data: CT, ttl: 3600, altcha });
    assert.strictEqual(res.status, 403, `altcha=${String(altcha).slice(0, 20)}`);
  }
  assert.strictEqual((await create({ data: CT, ttl: 3600 })).status, 201);
});

test('bot check: a solved challenge can be used only once (no replay)', async () => {
  const altcha = await solvedPayload();
  assert.strictEqual((await create({ data: CT, ttl: 3600, altcha })).status, 201);
  assert.strictEqual((await create({ data: CT, ttl: 3600, altcha })).status, 403);

  // Concurrent replay of one fresh payload: exactly one succeeds.
  const shared = await solvedPayload();
  const statuses = await Promise.all(Array.from({ length: 10 }, () => create({ data: CT, ttl: 3600, altcha: shared }).then((r) => r.status)));
  assert.strictEqual(statuses.filter((x) => x === 201).length, 1);
  assert.strictEqual(statuses.filter((x) => x === 403).length, 9);
});

test('bot check: wrong answer, tampered or foreign challenges are rejected', async () => {
  const challenge = await (await fetch(base + '/api/challenge', { headers: { 'X-Forwarded-For': newIp() } })).json();
  const solution = await altchaLib.solveChallenge({ challenge, deriveKey });

  // The proof is the derived key (only obtainable by doing the work); a wrong or missing key fails.
  const flipped = solution.derivedKey.slice(0, -2) + (solution.derivedKey.endsWith('00') ? '11' : '00');
  assert.strictEqual((await create({ data: CT, ttl: 3600, altcha: encodePayload(challenge, { ...solution, derivedKey: flipped }) })).status, 403, 'wrong answer');
  assert.strictEqual((await create({ data: CT, ttl: 3600, altcha: encodePayload(challenge, { counter: solution.counter }) })).status, 403, 'guessed counter without work');

  const easier = structuredClone(challenge);
  easier.parameters.cost = 1;
  assert.strictEqual((await create({ data: CT, ttl: 3600, altcha: encodePayload(easier, solution) })).status, 403, 'tampered difficulty');

  const foreign = await forgeChallenge({ hmac: 'attacker-secret' });
  const fsol = await altchaLib.solveChallenge({ challenge: foreign, deriveKey });
  assert.strictEqual((await create({ data: CT, ttl: 3600, altcha: encodePayload(foreign, fsol) })).status, 403, 'not signed by server');

  const expired = await forgeChallenge({ expiresAt: new Date(Date.now() - 1000) });
  const esol = await altchaLib.solveChallenge({ challenge: expired, deriveKey });
  assert.strictEqual((await create({ data: CT, ttl: 3600, altcha: encodePayload(expired, esol) })).status, 403, 'expired');

  const cheapAlg = await forgeChallenge({ algorithm: 'SHA-256' });
  const cheapSol = await altchaLib.solveChallenge({ challenge: cheapAlg, deriveKey: require('altcha-lib/algorithms/sha').deriveKey });
  assert.strictEqual((await create({ data: CT, ttl: 3600, altcha: encodePayload(cheapAlg, cheapSol) })).status, 403, 'cheaper algorithm');

  // "Server signature" payload type is not accepted, even with a valid-looking shape.
  const serverType = Buffer.from(JSON.stringify({ verificationData: 'verified=true', signature: 'x', algorithm: 'SHA-256' })).toString('base64');
  assert.strictEqual((await create({ data: CT, ttl: 3600, altcha: serverType })).status, 403, 'server payload');

  // The original, untampered solution still works once.
  assert.strictEqual((await create({ data: CT, ttl: 3600, altcha: encodePayload(challenge, solution) })).status, 201);
});

test('bot check: challenge endpoint is rate limited and reveals nothing secret', async () => {
  const ip = newIp();
  const res = await fetch(base + '/api/challenge', { headers: { 'X-Forwarded-For': ip } });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers.get('cache-control'), 'no-store');
  const text = await res.text();
  assert.ok(!text.includes('test-hmac-secret') && !text.includes(KEY_SECRET));
  const c = JSON.parse(text);
  assert.ok(c.signature && c.parameters.nonce && c.parameters.expiresAt);
  assert.strictEqual(c.parameters.counter, undefined, 'answer is not sent to the client');
  let last;
  for (let i = 0; i < 21; i++) last = (await fetch(base + '/api/challenge', { headers: { 'X-Forwarded-For': ip } })).status;
  assert.strictEqual(last, 429);
});

test('bot check widget files are served from this site with security headers', async () => {
  for (const [route, type] of [['/vendor/altcha.js', 'text/javascript'], ['/vendor/altcha.css', 'text/css'], ['/vendor/altcha-pbkdf2.js', 'text/javascript']]) {
    const res = await fetch(base + route);
    assert.strictEqual(res.status, 200, route);
    assert.ok(res.headers.get('content-type').startsWith(type), route);
    assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
  }
  assert.strictEqual((await fetch(base + '/vendor/../server.js')).status, 404);
  assert.strictEqual((await fetch(base + '/vendor/hash-wasm.js')).status, 404);
  assert.ok(usedChallenges.size > 0);
});

// ---------- HTTPS enforcement ----------

const viaProxy = (proto, extra = {}) => ({ 'X-Forwarded-For': newIp(), 'X-Forwarded-Proto': proto, ...extra });

test('plain HTTP page requests are redirected to HTTPS on the same host and path', async () => {
  const res = await fetch(`${base}/s/AAAAAAAAAAAAAAAAAAAAAA?x=1`, { redirect: 'manual', headers: viaProxy('http') });
  assert.strictEqual(res.status, 301);
  assert.strictEqual(res.headers.get('location'), `https://127.0.0.1:${port}/s/AAAAAAAAAAAAAAAAAAAAAA?x=1`);
  assert.ok(res.headers.get('strict-transport-security'));
  const home = await fetch(base + '/', { redirect: 'manual', headers: viaProxy('http') });
  assert.strictEqual(home.status, 301);
});

test('plain HTTP API writes are refused, not redirected, and store nothing', async () => {
  const before = store.size;
  const res = await fetch(base + '/api/secrets', {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/json', ...viaProxy('http') },
    body: JSON.stringify({ data: CT, ttl: 3600, altcha: await solvedPayload() }),
  });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(store.size, before);

  const id = await newSecret();
  const read = await fetch(`${base}/api/secrets/${id}`, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/json', ...viaProxy('http') }, body: '{}' });
  assert.strictEqual(read.status, 403);
  assert.strictEqual(store.has(id), true, 'secret not burned over HTTP');
});

test('HTTPS requests, health probes and direct local requests are served normally', async () => {
  assert.strictEqual((await fetch(base + '/', { redirect: 'manual', headers: viaProxy('https') })).status, 200);
  assert.strictEqual((await fetch(base + '/healthz', { redirect: 'manual', headers: viaProxy('http') })).status, 200);
  assert.strictEqual((await fetch(base + '/', { redirect: 'manual' })).status, 200, 'no proxy header: local development');
});

test('a client cannot forge "https" ahead of the proxy-appended scheme', async () => {
  const res = await fetch(base + '/', { redirect: 'manual', headers: viaProxy('https, http') });
  assert.strictEqual(res.status, 301);
});

test('a malformed Host header is rejected instead of being echoed into a redirect', async () => {
  const status = await new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port, path: '/', headers: { Host: 'evil.example/<x>', 'X-Forwarded-Proto': 'http' } }, (r) => {
      r.resume();
      resolve(r.statusCode);
    }).on('error', () => resolve('error'));
  });
  assert.strictEqual(status, 400);
});

// ---------- Size limit: browser cap vs server cap ----------

const fs = require('node:fs');
const path = require('node:path');
const appJs = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const MAX_PLAINTEXT_BYTES = Function(`return ${appJs.match(/const MAX_PLAINTEXT_BYTES = ([^;]+);/)[1]}`)();
const MAX_CIPHERTEXT_CHARS = 256 * 1024;

async function encryptedLength(bytes) {
  // Same scheme as the browser: 12-byte IV + AES-256-GCM (16-byte tag), base64url without padding.
  const { subtle } = crypto.webcrypto;
  const key = await subtle.importKey('raw', crypto.randomBytes(32), 'AES-GCM', false, ['encrypt']);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv: crypto.randomBytes(12) }, key, new Uint8Array(bytes));
  return Buffer.concat([crypto.randomBytes(12), Buffer.from(ct)]).toString('base64url').length;
}

test('browser size cap maps exactly onto the server cap after AES-GCM and base64url overhead', async () => {
  assert.strictEqual(MAX_PLAINTEXT_BYTES, 196580);
  assert.strictEqual(await encryptedLength(MAX_PLAINTEXT_BYTES), MAX_CIPHERTEXT_CHARS, 'largest allowed text fills the cap exactly');
  assert.ok(await encryptedLength(MAX_PLAINTEXT_BYTES + 1) > MAX_CIPHERTEXT_CHARS, 'one more byte would exceed it');
});

test('server accepts ciphertext at exactly the cap (with a real bot-check payload) and rejects one character more', async () => {
  const atCap = await create({ data: 'A'.repeat(MAX_CIPHERTEXT_CHARS), ttl: 604800 });
  assert.strictEqual(atCap.status, 201);
  const { id } = await atCap.json();
  assert.strictEqual((await create({ data: 'A'.repeat(MAX_CIPHERTEXT_CHARS + 1), ttl: 604800 })).status, 400);
  await read(id); // free memory for other tests
});

test('the text box has no character limit that would silently cut off pasted text', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  assert.ok(!/<textarea[^>]*maxlength/i.test(html));
});

test('challenge endpoint tells the browser how long a challenge lives', async () => {
  const res = await fetch(base + '/api/challenge', { headers: { 'X-Forwarded-For': newIp() } });
  assert.strictEqual(res.headers.get('x-challenge-ttl'), '600');
});

test('policy pages state the configured bot-check lifetime, not a hard-coded one', async () => {
  for (const route of ['/privacy', '/data-collection']) {
    const html = await (await fetch(base + route)).text();
    assert.ok(html.includes('up to 10 minutes') || html.includes('Up to 10 minutes'), route);
    assert.ok(!html.includes('{{'), route);
  }
});
