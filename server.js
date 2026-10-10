'use strict';

// One-time self-destructing secret links.
// The server only ever sees ciphertext: encryption happens in the browser and
// the key lives in the URL fragment (#...), which browsers never send to servers.
// Ciphertext is held in memory only, deleted on first read or on expiry.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const altcha = require('altcha-lib');
const { deriveKey } = require('altcha-lib/algorithms/pbkdf2');

const PORT = Number(process.env.PORT) || 8080;
const MAX_CIPHERTEXT_BYTES = 256 * 1024; // ~190 KB of plaintext
const MIN_CIPHERTEXT_CHARS = 38; // 12-byte IV + 16-byte GCM tag, base64url
const MAX_BODY_BYTES = MAX_CIPHERTEXT_BYTES + 8 * 1024; // room for the ALTCHA payload
const MAX_ITEMS = Number(process.env.MAX_ITEMS) || 10000;
// Cap on total ciphertext held in memory, so a flood of large secrets cannot exhaust RAM.
const MAX_TOTAL_BYTES = (Number(process.env.MAX_TOTAL_MB) || 100) * 1024 * 1024;
const ALLOWED_TTLS = [3600, 86400, 604800]; // 1 hour, 1 day, 7 days
const RATE_LIMIT_PER_MIN = Number(process.env.RATE_LIMIT_PER_MIN) || 30;
const MAX_TRACKED_CLIENTS = 100000;
// Number of reverse proxies in front of the app that append to X-Forwarded-For.
// Azure App Service / most PaaS: 1. Exposed directly to the internet: 0.
const TRUST_PROXY_HOPS = process.env.TRUST_PROXY_HOPS === undefined ? 1 : Number(process.env.TRUST_PROXY_HOPS);

// ALTCHA proof-of-work bot check on secret creation. The browser must spend
// CPU time solving a signed challenge, which makes bulk creation by bots slow and costly.
// Without ALTCHA_HMAC_SECRET a random key is used, so outstanding challenges end on restart
// (secrets are lost on restart anyway).
const ALTCHA_HMAC_SECRET = process.env.ALTCHA_HMAC_SECRET || crypto.randomBytes(32).toString('hex');
const ALTCHA_KEY_SECRET = crypto.createHmac('sha256', ALTCHA_HMAC_SECRET).update('altcha-key-signature').digest('hex');
const ALTCHA_ALGORITHM = 'PBKDF2/SHA-256';
const ALTCHA_COST = Number(process.env.ALTCHA_COST) || 1000;
const ALTCHA_COUNTER_MIN = Number(process.env.ALTCHA_COUNTER_MIN) || 1000;
const ALTCHA_COUNTER_MAX = Number(process.env.ALTCHA_COUNTER_MAX) || 3000;
const ALTCHA_TTL_MS = 10 * 60_000;
const MAX_USED_CHALLENGES = 100000;
// nonce -> expiry (ms). A solved challenge can be used once only.
const usedChallenges = new Map();

function createChallenge() {
  return altcha.createChallenge({
    algorithm: ALTCHA_ALGORITHM,
    cost: ALTCHA_COST,
    counter: altcha.randomInt(ALTCHA_COUNTER_MIN, ALTCHA_COUNTER_MAX),
    deriveKey,
    expiresAt: new Date(Date.now() + ALTCHA_TTL_MS),
    hmacSignatureSecret: ALTCHA_HMAC_SECRET,
    hmacKeySignatureSecret: ALTCHA_KEY_SECRET,
  });
}

async function verifyAltcha(encoded) {
  if (typeof encoded !== 'string' || encoded.length > 4096) return false;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  } catch {
    return false;
  }
  // Accept only self-hosted proof-of-work payloads issued by this server.
  if (!payload || typeof payload !== 'object' || !payload.challenge || !payload.solution || 'verificationData' in payload) return false;
  const params = payload.challenge.parameters;
  if (!params || params.algorithm !== ALTCHA_ALGORITHM || !params.expiresAt || typeof params.nonce !== 'string') return false;
  let result;
  try {
    result = await altcha.verifySolution({
      challenge: payload.challenge,
      solution: payload.solution,
      deriveKey,
      hmacSignatureSecret: ALTCHA_HMAC_SECRET,
      hmacKeySignatureSecret: ALTCHA_KEY_SECRET,
    });
  } catch {
    return false;
  }
  if (!result.verified || result.expired) return false;
  // Check-and-mark runs synchronously after the await, so two concurrent uses cannot both pass.
  if (usedChallenges.has(params.nonce) || usedChallenges.size >= MAX_USED_CHALLENGES) return false;
  usedChallenges.set(params.nonce, Date.now() + ALTCHA_TTL_MS);
  return true;
}

// id -> { data, expiresAt }
const store = new Map();
let totalBytes = 0;

function removeSecret(id) {
  const item = store.get(id);
  if (!item) return undefined;
  store.delete(id);
  totalBytes -= item.data.length;
  return item;
}

// Fixed-window per-client rate limiter (create, check and read requests).
const hits = new Map();
function rateLimited(client) {
  const now = Date.now();
  const entry = hits.get(client);
  if (!entry || now - entry.start > 60_000) {
    // Bound memory if an attacker rotates through huge numbers of addresses.
    if (!entry && hits.size >= MAX_TRACKED_CLIENTS) return true;
    hits.set(client, { start: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT_PER_MIN;
}

// Sweep expired secrets and stale rate-limit entries every minute.
setInterval(() => {
  const now = Date.now();
  for (const [id, item] of store) if (item.expiresAt <= now) removeSecret(id);
  for (const [ip, entry] of hits) if (now - entry.start > 60_000) hits.delete(ip);
  for (const [nonce, exp] of usedChallenges) if (exp <= now) usedChallenges.delete(nonce);
}, 60_000).unref();

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex, nofollow',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
};

const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
};
const staticCache = {};
for (const [route, [file]] of Object.entries(STATIC)) {
  staticCache[route] = fs.readFileSync(path.join(__dirname, 'public', file));
}

// ALTCHA widget files, served from this origin (no third-party requests).
const ALTCHA_DIST = path.join(path.dirname(require.resolve('altcha')), '..');
const VENDOR = {
  '/vendor/altcha.js': [path.join(ALTCHA_DIST, 'external', 'altcha.min.js'), 'text/javascript; charset=utf-8'],
  '/vendor/altcha.css': [path.join(ALTCHA_DIST, 'external', 'altcha.css'), 'text/css; charset=utf-8'],
  '/vendor/altcha-pbkdf2.js': [path.join(ALTCHA_DIST, 'workers', 'pbkdf2.js'), 'text/javascript; charset=utf-8'],
};
for (const [route, [file, type]] of Object.entries(VENDOR)) {
  STATIC[route] = [file, type];
  staticCache[route] = fs.readFileSync(file);
}

// Policy pages. Operator details come from environment variables and are
// HTML-escaped, so a misconfigured value cannot inject markup or script.
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
function contactHtml(email) {
  if (!email) return '<span class="placeholder">[contact email not configured]</span>';
  if (!EMAIL_RE.test(email)) return escapeHtml(email);
  return `<a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a>`;
}
// Required settings show a highlighted placeholder until configured; optional ones fall back to a default.
function setting(name, placeholder) {
  const v = process.env[name];
  return v ? escapeHtml(v) : `<span class="placeholder">${escapeHtml(placeholder)}</span>`;
}
function optionalSetting(name, fallback) {
  return escapeHtml(process.env[name] || fallback);
}
const LEGAL_TOKENS = {
  OPERATOR_NAME: setting('OPERATOR_NAME', '[operator name not configured]'),
  CONTACT: contactHtml(process.env.CONTACT_EMAIL),
  JURISDICTION: setting('JURISDICTION', '[jurisdiction not configured]'),
  HOSTING: optionalSetting('HOSTING_PROVIDER', 'Microsoft Azure'),
  LOG_RETENTION: optionalSetting('LOG_RETENTION', '30 days'),
  EFFECTIVE_DATE: setting('POLICY_EFFECTIVE_DATE', '[effective date not configured]'),
};
const LEGAL = { '/privacy': 'privacy.html', '/data-collection': 'data-collection.html', '/terms': 'terms.html' };
for (const [route, file] of Object.entries(LEGAL)) {
  const html = fs
    .readFileSync(path.join(__dirname, 'public', 'legal', file), 'utf8')
    .replace(/\{\{([A-Z_]+)\}\}/g, (_, k) => LEGAL_TOKENS[k] ?? '');
  STATIC[route] = [file, 'text/html; charset=utf-8'];
  staticCache[route] = Buffer.from(html);
}

function send(res, status, body, type = 'application/json; charset=utf-8', extraHeaders = {}) {
  const payload = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type, ...extraHeaders });
  res.end(payload);
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function readJson(req, limit) {
  const declared = Number(req.headers['content-length']);
  if (declared > limit) return Promise.reject(new HttpError(413, 'Payload too large'));
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const onData = (c) => {
      size += c.length;
      if (size > limit) {
        // Stop buffering; the 413 handler closes the connection after replying.
        req.off('data', onData);
        req.pause();
        reject(new HttpError(413, 'Payload too large'));
        return;
      }
      chunks.push(c);
    };
    req.on('data', onData);
    req.on('end', () => {
      if (size > limit) return;
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new HttpError(400, 'Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

function clientKey(req) {
  let ip = req.socket.remoteAddress || '';
  if (TRUST_PROXY_HOPS > 0 && req.headers['x-forwarded-for']) {
    // Proxies append the address they saw, so only the rightmost entries are trustworthy;
    // anything further left can be forged by the client.
    const parts = String(req.headers['x-forwarded-for']).split(',').map((s) => s.trim()).filter(Boolean);
    ip = parts[Math.max(0, parts.length - TRUST_PROXY_HOPS)] || ip;
  }
  ip = ip.replace(/^::ffff:/, '');
  if (ip.startsWith('[')) ip = ip.slice(1, ip.indexOf(']')); // [v6]:port
  else if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(ip)) ip = ip.replace(/:\d+$/, ''); // v4:port
  // One IPv6 user usually controls a whole /64, so rate-limit per /64.
  if (ip.includes(':')) ip = ip.split(':').slice(0, 4).join(':') + '::/64';
  return ip;
}

// Blocks other websites from making a visitor's browser create or burn secrets.
// Requiring a JSON content type forces a CORS preflight, which this server never approves.
function isSameOriginJson(req) {
  const site = req.headers['sec-fetch-site'];
  if (site && site !== 'same-origin' && site !== 'none') return false;
  return /^application\/json\b/i.test(req.headers['content-type'] || '');
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const route = url.pathname;

  if (req.method === 'GET' && route === '/healthz') return send(res, 200, { ok: true });

  // Static files. /s/<id> serves the same page; the client decides what to show.
  if (req.method === 'GET' && (STATIC[route] || /^\/s\/[A-Za-z0-9_-]{22}$/.test(route))) {
    const key = STATIC[route] ? route : '/';
    return send(res, 200, staticCache[key], STATIC[key][1]);
  }

  if (route === '/api/challenge' && req.method === 'GET') {
    if (rateLimited(clientKey(req))) return send(res, 429, { error: 'Too many requests' });
    return send(res, 200, await createChallenge());
  }

  if (route === '/api/secrets' && req.method === 'POST') {
    if (!isSameOriginJson(req)) return send(res, 403, { error: 'Forbidden' });
    if (rateLimited(clientKey(req))) return send(res, 429, { error: 'Too many requests' });

    const body = await readJson(req, MAX_BODY_BYTES);
    const { data, ttl, altcha: altchaPayload } = body || {};
    if (
      typeof data !== 'string' ||
      data.length < MIN_CIPHERTEXT_CHARS ||
      data.length > MAX_CIPHERTEXT_BYTES ||
      !B64URL_RE.test(data)
    ) {
      return send(res, 400, { error: 'Invalid payload' });
    }
    if (!ALLOWED_TTLS.includes(ttl)) return send(res, 400, { error: 'Invalid expiry' });
    if (!(await verifyAltcha(altchaPayload))) {
      return send(res, 403, { error: 'Bot check failed. Please wait for the check to finish, or reload the page and try again.' });
    }
    if (store.size >= MAX_ITEMS || totalBytes + data.length > MAX_TOTAL_BYTES) {
      return send(res, 503, { error: 'Server is at capacity, try later' });
    }

    const id = crypto.randomBytes(16).toString('base64url'); // 128 bits, 22 chars
    const expiresAt = Date.now() + ttl * 1000;
    store.set(id, { data, expiresAt });
    totalBytes += data.length;
    return send(res, 201, { id, expiresAt });
  }

  const m = route.match(/^\/api\/secrets\/([^/]+)$/);
  if (m && ID_RE.test(m[1])) {
    const id = m[1];
    // Existence check without consuming (lets the UI say "already used" before the click).
    if (req.method === 'HEAD') {
      if (rateLimited(clientKey(req))) {
        res.writeHead(429, SECURITY_HEADERS);
        return res.end();
      }
      const item = store.get(id);
      const ok = item && item.expiresAt > Date.now();
      res.writeHead(ok ? 204 : 404, SECURITY_HEADERS);
      return res.end();
    }
    // Reading is a POST so link-preview bots (Teams, Slack, email scanners) that
    // issue GETs cannot burn the secret.
    if (req.method === 'POST') {
      if (!isSameOriginJson(req)) return send(res, 403, { error: 'Forbidden' });
      if (rateLimited(clientKey(req))) return send(res, 429, { error: 'Too many requests' });
      const item = removeSecret(id); // burn before responding
      if (!item || item.expiresAt <= Date.now()) {
        return send(res, 404, { error: 'This secret does not exist, has expired, or was already viewed.' });
      }
      return send(res, 200, { data: item.data });
    }
  }

  return send(res, 404, { error: 'Not found' });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    if (res.headersSent) return;
    if (err.status === 413) {
      // Close the connection so an oversized upload is not read any further.
      res.on('finish', () => req.socket.destroy());
      return send(res, 413, { error: err.message }, undefined, { Connection: 'close' });
    }
    send(res, err.status || 500, { error: err.status ? err.message : 'Server error' });
  });
});

// Limit slow-client attacks (slowloris): headers must arrive within 10s, whole request within 30s.
server.headersTimeout = 10_000;
server.requestTimeout = 30_000;

// No request logging: nothing about secrets or visitors is written to disk.
if (require.main === module) {
  server.listen(PORT, () => console.log(`Listening on port ${PORT}`));
}

module.exports = { server, store, clientKey, usedChallenges };
