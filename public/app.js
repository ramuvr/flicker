'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  // Server accepts 256 KiB of base64url ciphertext: 3/4 of that, minus IV and auth tag.
  const MAX_PLAINTEXT_BYTES = Math.floor((256 * 1024 * 3) / 4) - 28;
  const views = ['create', 'link', 'reveal', 'secret', 'gone'];
  function show(name) {
    for (const v of views) $('view-' + v).hidden = v !== name;
  }

  // base64url helpers
  function toB64u(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function fromB64u(str) {
    const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  async function encrypt(text) {
    const rawKey = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text)));
    const blob = new Uint8Array(iv.length + ct.length);
    blob.set(iv);
    blob.set(ct, iv.length);
    return { data: toB64u(blob), key: toB64u(rawKey) };
  }

  async function decrypt(data, keyStr) {
    const blob = fromB64u(data);
    const key = await crypto.subtle.importKey('raw', fromB64u(keyStr), 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.subarray(0, 12) }, key, blob.subarray(12));
    return new TextDecoder().decode(pt);
  }

  function showError(el, msg) {
    el.textContent = msg;
    el.hidden = false;
  }

  async function copyText(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
      const old = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => (btn.textContent = old), 1500);
    } catch {
      btn.textContent = 'Select and copy manually';
    }
  }

  // ---------- Bot check (ALTCHA proof-of-work, solved in the background) ----------
  let widget = null;
  let botToken = null;

  function initBotCheck() {
    if (!window.$altcha || !customElements.get('altcha-widget')) return;
    window.$altcha.algorithms.set('PBKDF2/SHA-256', () => new Worker('/vendor/altcha-pbkdf2.js'));
    widget = document.createElement('altcha-widget');
    widget.setAttribute('challenge', '/api/challenge');
    widget.setAttribute('auto', 'onload');
    // No interaction tracking; no external attribution link.
    widget.setAttribute('configuration', JSON.stringify({ humanInteractionSignature: false, hideFooter: true }));
    widget.addEventListener('statechange', (ev) => {
      botToken = ev.detail.state === 'verified' ? ev.detail.payload : null;
    });
    $('altcha-slot').append(widget);
  }

  function waitForBotCheck(timeoutMs = 60000) {
    if (botToken) return Promise.resolve(botToken);
    if (!widget) return Promise.reject(new Error('The bot check could not load. Please reload the page.'));
    return new Promise((resolve, reject) => {
      const done = (fn, value) => {
        clearTimeout(timer);
        widget.removeEventListener('statechange', onState);
        fn(value);
      };
      const timer = setTimeout(() => done(reject, new Error('The bot check timed out. Please try again.')), timeoutMs);
      function onState(ev) {
        if (ev.detail.state === 'verified') done(resolve, ev.detail.payload);
        else if (ev.detail.state === 'error') done(reject, new Error('The bot check failed. Please reload the page and try again.'));
      }
      widget.addEventListener('statechange', onState);
      if (widget.getState() !== 'verifying') widget.verify();
    });
  }

  // Each solved challenge is accepted once, so start a fresh one after every attempt.
  function renewBotCheck() {
    botToken = null;
    if (!widget) return;
    widget.reset();
    widget.verify();
  }

  // ---------- Create flow ----------
  function initCreate() {
    show('create');
    initBotCheck();
    const ta = $('secret');
    ta.addEventListener('input', () => {
      $('count').textContent = ta.value.length.toLocaleString() + ' characters';
    });

    $('create').addEventListener('click', async () => {
      const err = $('create-error');
      err.hidden = true;
      const text = ta.value;
      if (!text.trim()) return showError(err, 'Enter some text first.');
      if (new TextEncoder().encode(text).length > MAX_PLAINTEXT_BYTES) {
        return showError(err, 'This text is too long. The limit is about 190 KB.');
      }

      const btn = $('create');
      const label = btn.textContent;
      btn.disabled = true;
      let attempted = false;
      try {
        if (!botToken) btn.textContent = 'Checking you are not a bot...';
        const altcha = await waitForBotCheck();
        btn.textContent = label;
        const { data, key } = await encrypt(text);
        attempted = true;
        const res = await fetch('/api/secrets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ data, ttl: Number($('ttl').value), altcha }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || 'Could not create link.');

        ta.value = '';
        $('count').textContent = '0 characters';
        $('link').value = `${location.origin}/s/${body.id}#${key}`;
        $('expires').textContent = 'on ' + new Date(body.expiresAt).toLocaleString();
        show('link');
        $('link').select();
      } catch (e) {
        showError(err, e.message);
      } finally {
        btn.textContent = label;
        btn.disabled = false;
        if (attempted) renewBotCheck();
      }
    });

    $('copy').addEventListener('click', () => copyText($('link').value, $('copy')));
    $('another').addEventListener('click', () => show('create'));
  }

  // ---------- Read flow ----------
  async function initRead(id) {
    const keyStr = location.hash.slice(1);
    // Remove the key from the address bar and history right away.
    history.replaceState(null, '', '/s/' + id);

    if (!keyStr) {
      $('gone-msg').textContent = 'This link is incomplete: the decryption key (the part after #) is missing.';
      return show('gone');
    }

    // Non-consuming check so the recipient learns early if it is already gone.
    try {
      const head = await fetch('/api/secrets/' + id, { method: 'HEAD' });
      if (head.status === 404) return show('gone');
    } catch { /* fall through; the reveal call will report errors */ }

    show('reveal');
    $('reveal').addEventListener('click', async () => {
      const btn = $('reveal');
      btn.disabled = true;
      try {
        const res = await fetch('/api/secrets/' + id, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}',
        });
        const body = await res.json().catch(() => ({}));
        if (res.status === 404) return show('gone');
        if (!res.ok) throw new Error(body.error || 'Could not retrieve secret.');
        let text;
        try {
          text = await decrypt(body.data, keyStr);
        } catch {
          $('gone-msg').textContent = 'The secret could not be decrypted (the link may have been altered). It has now been deleted.';
          return show('gone');
        }
        $('plaintext').value = text;
        show('secret');
      } catch (e) {
        showError($('reveal-error'), e.message);
        btn.disabled = false;
      }
    });
    $('copy-secret').addEventListener('click', () => copyText($('plaintext').value, $('copy-secret')));
  }

  const m = location.pathname.match(/^\/s\/([A-Za-z0-9_-]{22})$/);
  if (m) initRead(m[1]);
  else initCreate();
})();
