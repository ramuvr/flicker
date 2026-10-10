# One-Time Secret

Share sensitive text through a link that can be opened **once**, then self-destructs. No logins, no database. One runtime dependency family (ALTCHA, MIT licence) for bot protection.

## How it works

1. You type text in the browser. The browser encrypts it with a random AES-256-GCM key (Web Crypto API).
2. Only the **ciphertext** is sent to the server, which holds it **in memory** with an expiry (1 hour, 1 day or 7 days).
3. The link looks like `https://host/s/<id>#<key>`. The key is after `#` (the URL fragment), which browsers never send to the server.
4. The recipient clicks **Reveal**; the server returns the ciphertext and deletes it in the same step. The browser decrypts it locally.

What the server holds, and for how long:

| Data | Where | Lifetime |
|---|---|---|
| Encrypted blob + expiry time | Process memory | Until first view or expiry, whichever comes first |
| Per-IP request counter (rate limit) | Process memory | 60 seconds |
| Plaintext, keys, request logs, cookies | Never stored | n/a |

Other protections:
- Reading requires a `POST` after the user clicks **Reveal**, so link-preview bots (Teams, Slack, Outlook Safe Links) that only `GET` the URL cannot burn the secret.
- The key is removed from the address bar/history as soon as the page loads.
- Other websites cannot make a visitor's browser create or burn secrets (JSON content type required, `Sec-Fetch-Site` checked, no CORS).
- Strict Content-Security-Policy (no inline scripts), `no-referrer`, `no-store`, `noindex`, HSTS, frame denial, COOP/CORP, Permissions-Policy.
- Abuse limits: ~190 KB per secret, 100 MB total in memory, 10,000 items, 30 requests/min per client (IPv6 grouped per /64), 10s header / 30s request timeouts.
- Rate limiting reads only the proxy-appended end of `X-Forwarded-For`, so clients cannot spoof their address.
- Bot protection on secret creation: ALTCHA proof-of-work (self-hosted, no third party, no cookies, interaction tracking off). Each solved challenge works once and expires after 10 minutes.
- Supply chain: only `altcha` and `altcha-lib` (exact versions, lockfile, `npm audit` in CI); GitHub Actions pinned to commit SHAs and the Docker base image pinned to a digest; Dependabot proposes updates.

## Security testing

`npm test` runs 27 tests covering: one-time read (including 20 simultaneous reads), expiry, ID guessing, input validation, reflected XSS, prototype pollution, CSRF, path traversal, HTTP methods, security headers, oversized bodies, rate limiting and spoofing, IPv6 rotation, memory caps, and the policy pages (security headers, no scripts or third-party content, HTML-escaping of operator settings, safe new-window links), and the bot check (missing, wrong, tampered, foreign-signed, expired, cheaper-algorithm and replayed solutions; rate-limited challenge endpoint).

## Run locally

Requires Node.js 20+.

```bash
npm ci             # install locked dependencies
npm start          # http://localhost:8080
npm test           # functional + security tests
```

## Deploy to Azure App Service (Linux)

```bash
az login
cd onetime-secret
az webapp up --name <unique-app-name> --sku B1 --runtime "NODE:22-lts"
# Keep the app running and on a single instance (see limitations below):
az webapp config set --name <unique-app-name> --resource-group <rg-from-output> --always-on true
az webapp update     --name <unique-app-name> --resource-group <rg-from-output> --https-only true
```

The app listens on the `PORT` environment variable, which App Service sets automatically. `--sku F1` (free) also works for trying it out, but free apps idle out and restart, which wipes unread secrets.

## Automatic deployment from GitHub

`.github/workflows/deploy-azure.yml` runs the tests on every push and pull request, and deploys to Azure App Service when `main` changes. Authentication uses OpenID Connect (short-lived tokens; no Azure password stored in GitHub).

One-time setup:

1. Push this folder to a GitHub repo (the folder contents at the repo root).
2. Create the App Service app once (portal, or `az webapp up` above).
3. Easiest route: in the Azure portal open the app > **Deployment Center** > Source **GitHub** > pick repo/branch > Authentication **User-assigned identity**. Azure creates the identity and the GitHub secrets for you, and commits its own workflow file. If you use this route, delete `deploy-azure.yml` so you do not have two pipelines.
4. Manual route (keeps this workflow file): create an Entra app registration or user-assigned managed identity with a federated credential for your repo (entity type **Environment**, name `production`, to match the workflow), grant it the Website Contributor role on the app, then in GitHub **Settings > Secrets and variables > Actions** add:
   - Secrets: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`
   - Variable: `AZURE_WEBAPP_NAME` (your app name)

Docs: https://learn.microsoft.com/azure/app-service/deploy-github-actions

Note: each deploy restarts the app, which deletes any unread secrets (they live in memory only).

## Deploy anywhere else (Docker)

```bash
docker build -t onetime-secret .
docker run -p 8080:8080 onetime-secret
```

Works on Azure Container Apps, Render, Railway, Fly.io, Google Cloud Run, etc. Always serve it over **HTTPS** (Web Crypto requires a secure context outside `localhost`).

## Limitations (by design)

- **Single instance only.** Secrets live in one process's memory. If you scale out to more than one instance, a link may hit an instance that does not have it. Restarts/redeploys delete all unread secrets.
- If you need multi-instance or restart survival, swap the in-memory `Map` in `server.js` for Redis (e.g. Azure Cache for Redis) with `SET ... EX <ttl>` and `GETDEL`; the encrypted-only design stays the same.
- Anyone who obtains the full link before the intended recipient can read the secret. Share the link over a different channel than the context it relates to where possible.

## Custom domain (Azure App Service)

Use a subdomain such as `secrets.example.com` (simplest, and the free certificate renews automatically).

1. Azure portal > your app > **Settings > Custom domains > Add custom domain**. Domain provider: **All other domain services**. TLS/SSL certificate: **App Service Managed Certificate**. Enter the domain. Do not select Validate yet.
2. At your DNS provider, add the two records the dialog shows:
   - `CNAME` `secrets` -> `<app-name>.azurewebsites.net` (must point **directly** at Azure, not through another CNAME or a proxy, or the free certificate cannot be issued or renewed).
   - `TXT` `asuid.secrets` -> the domain verification ID (prevents subdomain takeover).
   - If your domain has a `CAA` record, add `0 issue digicert.com` (DigiCert issues the free certificate).
3. Back in Azure select **Validate**, then **Add**. After a few minutes the domain shows **Secured**.
4. Keep **HTTPS Only** on (Settings > Configuration). Visit `https://secrets.example.com` and create a test secret.

For the root domain (`example.com`) use an `A` record to the app's IP instead of the CNAME. Docs: https://learn.microsoft.com/azure/app-service/app-service-web-tutorial-custom-domain and https://learn.microsoft.com/azure/app-service/configure-ssl-certificate

If you later put Cloudflare (or another proxy) in front, set `TRUST_PROXY_HOPS=2` and switch to a certificate that does not rely on the direct CNAME.

## Policy pages

`/privacy`, `/data-collection` and `/terms` are linked from the footer and open in a new window (`rel="noopener noreferrer"`). Their content matches what the code actually does. Set the operator settings below (on Azure: App Service > Settings > Environment variables). Unset required values appear as highlighted placeholders. The text is a template, not legal advice; have it reviewed for your jurisdiction before going live, and update it if you change what the service collects (for example, if you add a CAPTCHA provider).

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | 8080 | Listen port |
| `MAX_ITEMS` | 10000 | Max secrets held at once |
| `RATE_LIMIT_PER_MIN` | 30 | Create/check/read requests per client per minute |
| `MAX_TOTAL_MB` | 100 | Max total ciphertext held in memory |
| `OPERATOR_NAME` | (placeholder shown) | Your organisation name, shown on the policy pages |
| `CONTACT_EMAIL` | (placeholder shown) | Privacy / legal contact shown on the policy pages |
| `JURISDICTION` | (placeholder shown) | Governing law in the Terms of Use, e.g. `England and Wales` |
| `POLICY_EFFECTIVE_DATE` | (placeholder shown) | Date shown at the top of each policy, e.g. `10 October 2026` |
| `HOSTING_PROVIDER` | Microsoft Azure | Hosting provider named in the policies (add region if relevant, e.g. `Microsoft Azure (UK South)`) |
| `LOG_RETENTION` | 30 days | Retention you commit to if you enable platform access logs |
| `ALTCHA_HMAC_SECRET` | random per start | Secret that signs bot-check challenges. Optional on a single instance; set a long random value (App Service setting) if you want challenges to survive restarts. Never commit it. |
| `ALTCHA_COST` | 1000 | Bot-check difficulty (PBKDF2 iterations per attempt) |
| `ALTCHA_COUNTER_MIN` / `ALTCHA_COUNTER_MAX` | 1000 / 3000 | Range of attempts needed; together with cost this gives about 1-2 s of work in a typical browser |
| `TRUST_PROXY_HOPS` | 1 | Reverse proxies in front of the app (Azure App Service, Render, etc.: 1). Set to `0` if the app is exposed directly with no proxy, otherwise clients can spoof their IP. |

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please report privately, not in public issues.

## Licence

MIT, see [LICENSE](LICENSE).
