# Deployment checklist

Everything that needs a person, an Azure account or the live app. Work top to bottom on the first deployment; sections 5 to 8 are worth repeating after significant changes. Tick items as you go.

## 1. Create the Azure resources

- [ ] App Service plan: **Linux, Basic B1** or above (B1 is 1 core, 1.75 GB RAM per [Microsoft Q&A](https://learn.microsoft.com/answers/a/12329920)). Free F1 idles and restarts, which deletes unread secrets.
- [ ] Web app runtime: **Node 22 LTS**.
- [ ] **Exactly 1 instance.** Secrets live in one process's memory; a second instance would not see them.
- [ ] Settings > Configuration: **Always On: On**, **HTTPS Only: On**, minimum TLS **1.2**.

## 2. App settings (App Service > Settings > Environment variables)

Invalid values now stop the app at startup with a message in the log stream, so a typo shows up immediately rather than as odd behaviour.

- [ ] `OPERATOR_NAME`, `CONTACT_EMAIL`, `JURISDICTION`, `POLICY_EFFECTIVE_DATE`: your details for the policy pages.
- [ ] `ALTCHA_HMAC_SECRET`: a long random value, e.g. the output of `openssl rand -hex 32`. Optional on one instance; keeps bot checks valid across restarts. Never commit it.
- [ ] Leave the other settings at their defaults unless you have a reason (see the README configuration table).

## 3. Connect GitHub to Azure

- [ ] Create a user-assigned managed identity (or app registration) with a federated credential for `ramuvr/flicker`, entity type **Environment**, name `production`.
- [ ] Grant it the **Website Contributor** role on the web app.
- [ ] GitHub > Settings > Secrets and variables > Actions: secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`; variable `AZURE_WEBAPP_NAME`.

## 4. First deployment

- [ ] Merge a pull request to `main` (or re-run the latest "Test and deploy" workflow).
- [ ] The run must be green, including **Smoke test the deployed app**. It checks `/healthz`, the home page, the privacy page, the Content-Security-Policy header and a signed bot-check challenge on the deployed URL, retrying for up to 2 minutes while the app starts.
- [ ] If the smoke test fails: App Service > Log stream. An "Invalid configuration" line names the setting to fix.

## 5. Health check

- [ ] App Service > Monitoring > **Health check** > Enable, path `/healthz`. It returns 200 only when the app can issue a bot-check challenge.
- Note: enabling or changing it restarts the app (unread secrets are lost). On a single instance it monitors and alerts but cannot route around a failure; after an hour unhealthy the instance is replaced ([Microsoft Learn](https://learn.microsoft.com/azure/app-service/monitor-instances-health-check)).
- [ ] Optional: from the Health check page select **Metrics** and create an alert rule so you are emailed if it fails.

## 6. Custom domain and certificate

- [ ] Follow "Custom domain (Azure App Service)" in the README (CNAME + `asuid` TXT record, free managed certificate).
- [ ] The domain shows **Secured** in Custom domains.

## 7. Check the live site by hand

| Check | Expected |
| --- | --- |
| Create a secret, open the link in another browser, Reveal | Text shown; reopening the link says unavailable |
| Paste the link into Teams/Slack/Outlook, then open it | Still works once (previews do not burn it) |
| Visit `http://<your-domain>/` | Redirected to `https://` |
| Footer links | Each policy opens in a new tab with your details, no "not configured" placeholders |
| `curl -sI https://<your-domain>/` | `content-security-policy`, `strict-transport-security`, `x-frame-options: DENY`, no `set-cookie` |
| Wait 10+ minutes on the create page, then create | Works without a "bot check failed" error |
| Paste over 192 KB of text | Clear "too long" message; nothing is cut off silently |

## 8. Load and memory test on your plan

Locally (2026-10-10, not on Azure): idle 55 MB; 100 MB cap full about 200 MB; peak 235 MB during 100 simultaneous full-size uploads; memory released after secrets were read; exactly 400 full-size secrets accepted before the cap returned 503.

To repeat it on B1:

- [ ] Temporarily set `RATE_LIMIT_PER_MIN` to `100000` (from one machine, all requests share one rate limit).
- [ ] Run from your computer (Node 20+), in the repository folder after `npm ci`:
  `node scripts/loadtest.js --url https://<your-domain> --secrets 420 --concurrency 10 --read`
  Each secret needs a solved bot check (about 1 to 2 s of CPU per secret on your computer), so this takes several minutes.
- [ ] Expected: about 400 `201` then `503` (cap reached), all reads `200`, no `error` entries.
- [ ] Watch App Service > Monitoring > Metrics > **Memory working set** during the run. Expect a peak well under the plan's memory; investigate if it approaches it.
- [ ] **Set `RATE_LIMIT_PER_MIN` back** (delete the setting to return to 30). Changing settings restarts the app.

## 9. Restart and rollback

- [ ] Restart the app once: links created before the restart now say unavailable. This is expected (memory-only storage).
- [ ] Rollback plan on B1 (no deployment slots, which need Standard or above): revert the pull request on GitHub, or re-run the last good "Test and deploy" workflow run.
