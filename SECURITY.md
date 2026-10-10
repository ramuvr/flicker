# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report privately through GitHub: open the repository's **Security** tab and select **Report a vulnerability**. Include steps to reproduce and the impact you expect.

You should receive an acknowledgement within 7 days. Please allow time for a fix before any public disclosure.

## Scope

In scope: the application code in this repository (`server.js`, `public/`), the deployment workflow and the Dockerfile.

Out of scope: denial of service by volume, findings that need a compromised device or browser extension, and reports from automated scanners without a demonstrated impact.

## Design notes for reviewers

- Secrets are encrypted in the browser with AES-256-GCM; the key is only in the URL fragment and is never sent to the server.
- The server keeps ciphertext in memory only and deletes it on first read or expiry.
- See README.md for the full list of controls and the test suite that covers them.
