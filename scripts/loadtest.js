'use strict';

// Load test: creates many large secrets the way a browser would (fetch a bot-check
// challenge, solve it, upload ciphertext), optionally reads them all back, and reports
// status codes and latency. Watch the server's memory while it runs (on Azure: the
// App Service "Memory working set" metric). Secrets are random bytes, not real data.
//
//   node scripts/loadtest.js --url https://secrets.example.com [options]
//
//   --secrets N       secrets to create (default 400; 400 x 256 KB fills the 100 MB cap)
//   --size N          ciphertext characters per secret, max 262144 (default 262144)
//   --concurrency N   requests in flight at once (default 10)
//   --read            read every created secret back afterwards (frees the memory)
//   --spoof-ips       send a different X-Forwarded-For per request. Only useful against
//                     a local server started with TRUST_PROXY_HOPS=1; behind Azure the
//                     real address is appended, so all requests share one rate limit.
//
// Expect 429 responses once the per-client rate limit (RATE_LIMIT_PER_MIN, default 30)
// is reached, and 503 once the memory cap (MAX_TOTAL_MB) is full. Both mean the limits
// work. To measure memory at the cap on Azure, raise RATE_LIMIT_PER_MIN temporarily and
// set it back afterwards.

const crypto = require('node:crypto');
const altcha = require('altcha-lib');
const { deriveKey } = require('altcha-lib/algorithms/pbkdf2');

function args() {
  const a = process.argv.slice(2);
  const get = (name, def) => {
    const i = a.indexOf(`--${name}`);
    return i === -1 ? def : a[i + 1];
  };
  const opts = {
    url: get('url', ''),
    secrets: Number(get('secrets', 400)),
    size: Number(get('size', 262144)),
    concurrency: Number(get('concurrency', 10)),
    read: a.includes('--read'),
    spoof: a.includes('--spoof-ips'),
  };
  if (!/^https?:\/\//.test(opts.url) || !(opts.secrets > 0) || !(opts.size >= 38 && opts.size <= 262144) || !(opts.concurrency > 0)) {
    console.error('Usage: node scripts/loadtest.js --url https://host [--secrets 400] [--size 262144] [--concurrency 10] [--read] [--spoof-ips]');
    process.exit(2);
  }
  opts.url = opts.url.replace(/\/$/, '');
  return opts;
}

const ip = () => `198.18.${crypto.randomInt(256)}.${crypto.randomInt(1, 255)}`;
const pct = (sorted, p) => (sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] : 0);

async function createOne(o) {
  const headers = { 'Content-Type': 'application/json', ...(o.spoof ? { 'X-Forwarded-For': ip() } : {}) };
  const t0 = performance.now();
  const cr = await fetch(`${o.url}/api/challenge`, { headers });
  if (!cr.ok) return { status: `challenge ${cr.status}`, ms: performance.now() - t0 };
  const challenge = await cr.json();
  const solution = await altcha.solveChallenge({ challenge, deriveKey });
  const payload = Buffer.from(JSON.stringify({ challenge, solution })).toString('base64');
  const data = crypto.randomBytes(Math.ceil((o.size * 3) / 4)).toString('base64url').slice(0, o.size);
  const t1 = performance.now();
  const res = await fetch(`${o.url}/api/secrets`, { method: 'POST', headers, body: JSON.stringify({ data, ttl: 3600, altcha: payload }) });
  const body = await res.json().catch(() => ({}));
  return { status: String(res.status), ms: performance.now() - t1, id: body.id };
}

async function readOne(o, id) {
  const headers = { 'Content-Type': 'application/json', ...(o.spoof ? { 'X-Forwarded-For': ip() } : {}) };
  const res = await fetch(`${o.url}/api/secrets/${id}`, { method: 'POST', headers, body: '{}' });
  await res.arrayBuffer();
  return String(res.status);
}

async function pool(items, concurrency, fn) {
  const results = [];
  let next = 0;
  await Promise.all(
    Array.from({ length: concurrency }, async () => {
      while (next < items.length) {
        const i = next++;
        try {
          results[i] = await fn(items[i]);
        } catch (e) {
          results[i] = { status: `error ${e.cause?.code || e.message}`, ms: 0 };
        }
      }
    }),
  );
  return results;
}

(async () => {
  const o = args();
  console.log(`Target ${o.url}: ${o.secrets} secrets x ${o.size} chars, concurrency ${o.concurrency}`);
  const start = performance.now();
  const created = await pool([...Array(o.secrets).keys()], o.concurrency, () => createOne(o));
  const counts = {};
  for (const r of created) counts[r.status] = (counts[r.status] || 0) + 1;
  const lat = created.filter((r) => r.status === '201').map((r) => r.ms).sort((a, b) => a - b);
  console.log(`Create: ${JSON.stringify(counts)} in ${((performance.now() - start) / 1000).toFixed(1)} s`);
  console.log(`Upload latency (201 only): p50 ${pct(lat, 50).toFixed(0)} ms, p95 ${pct(lat, 95).toFixed(0)} ms, max ${(lat.at(-1) || 0).toFixed(0)} ms`);
  if (o.read) {
    const ids = created.filter((r) => r.id).map((r) => r.id);
    const reads = await pool(ids, o.concurrency, (id) => readOne(o, id));
    const rc = {};
    for (const s of reads) rc[s] = (rc[s] || 0) + 1;
    console.log(`Read back: ${JSON.stringify(rc)}`);
  }
})();
