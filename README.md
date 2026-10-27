# @bydtech/port-audit

Point it at your running app on a local port and, in seconds, get the security problems anyone can see from outside: security headers and CSP, cookie flags, CORS, TLS, TRACE, third-party scripts without integrity hashes, front-end libraries with known vulnerabilities, and version headers. Each finding is mapped to the OWASP Top 10:2025, the API Security Top 10 2023 and ASVS 5.0, with a fix snippet for the framework it detects. Passive, no Docker, no account, no telemetry.

[![npm version](https://img.shields.io/npm/v/@bydtech/port-audit.svg)](https://www.npmjs.com/package/@bydtech/port-audit)
[![CI](https://github.com/BYDTechSolutions/port-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/BYDTechSolutions/port-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

With your app running on port 3000:

```sh
npx @bydtech/port-audit --port 3000
```

Any language, any framework. Node.js 20 or later. A URL works too: `npx @bydtech/port-audit http://localhost:8080/app`.

```text
Port audit: http://localhost:3000/
Detected: Express (X-Powered-By: Express; connect.sid cookie (express-session))
7 requests in 620 ms  2 fix now · 7 should fix · 6 nice to have · 1 passed

FIX NOW (2)

  1. CORS reflects any Origin and allows credentials
     http://localhost:3000/ [A02:2025 · API8:2023 · ASVS 3.4.2 · CWE-942]
     Saw: Request with "Origin: https://port-audit-origin.invalid" got "Access-Control-Allow-Origin:
          https://port-audit-origin.invalid" and "Access-Control-Allow-Credentials: true".
     Why: Any website a signed-in user visits can call this endpoint with the user's cookies and
          read the response: their data, CSRF tokens, anything the endpoint returns.
     Fix: Compare the Origin header with an allowlist of your own front-end origins and send
          Access-Control-Allow-Origin only for those. Never echo the request's Origin.
     Express:
       import cors from "cors";
       app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
       // never origin: true (reflects any Origin) together with credentials
       (https://github.com/expressjs/cors#configuration-options)
     Source: OWASP WSTG-CLNT-07: Cross Origin Resource Sharing <https://wstg.owasp.org/...>; ...

  2. CORS allows the "null" origin
     ...

SHOULD FIX (7)

  3. No Content-Security-Policy on HTML pages
     http://localhost:3000/ [A02:2025 · API8:2023 · ASVS 3.4.3]
     Saw: No Content-Security-Policy header or meta tag on the HTML page.
     Why: A CSP limits which scripts may run, which contains the damage of an injected script (XSS).
          Report-only mode reports but blocks nothing.
     Fix: Start with default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self',
          add the third parties you use, try it as Content-Security-Policy-Report-Only, then enforce
          it.
     Express:
       import helmet from "helmet"; // helmet 8 sets CSP, HSTS, nosniff, frame and COOP headers
       app.use(helmet({
         referrerPolicy: { policy: "strict-origin-when-cross-origin" },
         strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
       }));
       ...

  8. jQuery 1.12.4 has 4 known vulnerabilities
     https://code.jquery.com/jquery-1.12.4.min.js [A03:2025 · ASVS 15.2.1 · CWE-1104]
     Saw: jQuery 1.12.4 found in https://code.jquery.com/jquery-1.12.4.min.js; highest severity
          medium.
       - CVE-2020-11022 (medium): Passing untrusted HTML to DOM methods can run script
         (htmlPrefilter). Fixed in 3.5.0. https://github.com/advisories/GHSA-gxr4-xjj5-5px2
       ...

COVERAGE  (OWASP Top 10:2025; details: --format md or json)
  Checked in part: A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04
    Cryptographic Failures, A08 Software or Data Integrity Failures.
  Not checked: A01 Broken Access Control, A05 Injection, A06 Insecure Design, A07 Authentication
    Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions.
  This release does not check exposed files or endpoints, directory listing, error leakage, open
  redirects, injection, authentication or access control.

Findings cover only what a passive scan of the pages read can see. An empty list is not a security sign-off.
```

(Shortened. This is the real output for [`examples/demo-app.mjs`](examples/demo-app.mjs), a small app that imitates Express without helmet. To try it yourself, save that file, run `node demo-app.mjs`, then run the command above.)

## In CI: a GitHub Action

Start your app in the background, then add one step. The action waits for the app to answer, scans it once, prints the report in the log, adds it to the job summary, writes a SARIF file, and fails the job on anything in "Fix now":

```yaml
# .github/workflows/port-audit.yml
name: Port audit
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - run: npm ci && npm run build
      - name: Start the app
        run: npm start &
        env:
          PORT: '3000'
          NODE_ENV: production
      - uses: BYDTechSolutions/port-audit@v0
        with:
          target: 3000
```

Change the build and start commands to your stack's (`python manage.py runserver` is a development server; scan what you deploy, such as `gunicorn`). `@v0` moves to each 0.x release; pin `@v0.1.3` to stay on one version.

To see the findings as code-scanning alerts, upload the SARIF file. Add `security-events: write` to `permissions` and this step after the audit (code scanning on a private repository needs GitHub Advanced Security):

```yaml
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: port-audit.sarif
          category: port-audit
```

A port scan never sees your source, so each alert is filed under a made-up path such as `port-audit/localhost/index` and names the URL in its message. The full file is in [`examples/github-workflow.yml`](examples/github-workflow.yml).

| Input | Default | What it does |
|---|---|---|
| `target` | `3000` | a port on localhost, or a URL such as `http://localhost:8080/app` |
| `wait` | `60` | seconds to wait for the target to answer; `0` skips the wait |
| `fail-on` | `fix-now` | fail the step at `fix-now`, at `should-fix` or above, or `none` |
| `sarif-file` | `port-audit.sarif` | where to write SARIF; empty skips it |
| `paths` | | more pages on the same host, one per line (`--path`) |
| `headers` | | headers to send, one per line, e.g. `Cookie: ${{ secrets.SESSION }}`; redacted in reports |
| `baseline` | | an earlier JSON or SARIF report whose findings are hidden |
| `framework` | detected | use this framework's fix snippets |
| `i-own-this` | | allow one host outside localhost and private networks |
| `args` | | any other CLI options, e.g. `--rate 5` |
| `package` | this tag's version | the npm package to run |

Outputs: `fix-now`, `should-fix` and `nice-to-have` (counts), `sarif-file`, `report-json` and `report-md` (paths). The action needs Node.js 20 or newer on the runner, which GitHub-hosted runners have, and runs on Linux, macOS and Windows runners.

## Safety rules

These are built in and tested:

- **Only your own machine and private networks by default:** `localhost`, `*.localhost`, `*.test`, `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`. Anything else exits with code 2. A host you own outside those ranges needs `--i-own-this <host>`, which must equal the target's host exactly, and the tool prints a reminder that scanning systems you do not own may be illegal.
- **The check runs again after DNS:** an allowed name such as `shop.test` that resolves to a public address is refused, and requests go only to an address that passed.
- **One host only:** a redirect to another host is never followed, and `--path` cannot point elsewhere. Third-party scripts are judged from their URL and never fetched.
- **Passive only:** GET, OPTIONS and TRACE reads, two TLS handshakes for https targets, and nothing else. No form is submitted, no payload is injected, nothing is guessed or brute-forced, and nothing that writes state is sent.
- **Polite:** 10 requests per second by default (`--rate`), it backs off on 429 and 503 (honoring `Retry-After` up to 10 seconds), and a hard cap of 300 requests per run (`--max-requests`). A typical run sends 7 to 20 requests. The `User-Agent` names the tool and this repository.
- **Nothing leaves your machine except requests to the target.** No telemetry, no update check, and the advisory list ships inside the package.
- **Secrets are redacted:** the values of `--header`, cookie values the app sets, and common token and key shapes are replaced with `<redacted>` in every format before anything is printed or written.

## Why it exists

The established scanners are powerful but heavy for "check my app before I push": ZAP needs Docker or Java and its baseline scan takes minutes, Nuclei is a template engine rather than a developer report, and hosted header graders cannot reach `localhost`. This tool does the narrow, deterministic part well: one `npx`, a few seconds, findings that name the URL, the evidence and the fix for your framework, with low noise. A well-configured app gets an empty list; the test suite holds it to that.

## What it checks

| Check | Rules | OWASP Top 10:2025 | ASVS 5.0 |
|---|---|---|---|
| Security headers and CSP quality: HSTS (https), CSP present and restricting scripts (`unsafe-inline`, `unsafe-eval`, wildcards, `object-src`, `base-uri`), frame-ancestors / X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, X-XSS-Protection | `headers/*` | A02 (clickjacking also A06) | 3.4.1, 3.4.3, 3.4.4, 3.4.5, 3.4.6, 3.4.8 |
| Cookie flags: Secure (https), HttpOnly and SameSite on session-like cookies, SameSite=None without Secure, `__Host-` / `__Secure-` prefix rules | `cookies/*` | A02 | 3.3.1, 3.3.2, 3.3.3, 3.3.4 |
| CORS: reflected Origin with credentials, `null` origin, `*` with credentials (one read each with an `Origin` header) | `cors/*` | A02 | 3.4.2 |
| TLS (https targets): TLS 1.0/1.1 accepted, certificate expired or expiring within 14 days, host name mismatch, not publicly trusted | `tls/*` | A04 | 12.1.1, 12.2.1, 12.2.2 |
| HTTP methods: TRACE echoes the request; OPTIONS advertises WebDAV methods | `methods/*` | A02 | 13.4.4, 4.1.4 |
| Third-party scripts and stylesheets without Subresource Integrity, read from the HTML the app serves | `sri/*` | A08 | 3.6.1 |
| Known-vulnerable front-end libraries (jQuery, jQuery UI, AngularJS, Bootstrap, Lodash, Moment.js, DOMPurify), from script URLs and the banners of same-origin scripts the page loads, against a bundled advisory list with GitHub Advisory links | `libraries/*` | A03 | 15.2.1, 3.7.1 |
| Server and framework version disclosure (`Server` with a version, `X-Powered-By`, `X-AspNet-Version`) | `disclosure/*` | A02 | 13.4.6 |

`npx @bydtech/port-audit --list-checks` prints every rule with its full mapping (Top 10:2025, API Security Top 10 2023, ASVS 5.0.0, CWE) and its sources.

How the mapping was done: a rule maps to a Top 10:2025 category when that category's own list of mapped CWEs contains the rule's CWE; API Top 10 IDs follow the wording of the API8 page; ASVS IDs are given only where a 5.0.0 requirement's text covers the rule, and left empty otherwise (CORS credentials, the null origin, Permissions-Policy and X-XSS-Protection have none). All of it, and every MDN and OWASP cheat-sheet link, was read on 2026-10-25 (`FACTS_VERIFIED_ON` in the API).

### What 0.1.0 does not check

So that a short report is not misread: this release does **not** look for exposed files or endpoints (such as `.env`, `.git` or admin consoles), directory listings, error leakage or stack traces, or open redirects, and it does not test injection, authentication, sessions or access control. Supply chain is covered only for the front-end libraries the page loads; run `npm audit` or another SCA tool on your lockfile. Insecure design and logging cannot be checked from outside. Every report repeats this in its coverage section.

## Framework detection and fix snippets

From headers, cookie names and default page shapes, it recognizes Express, Next.js, NestJS, Django, Flask, FastAPI, Rails, Laravel, Spring Boot, ASP.NET, nginx and Apache, and shows what it saw (for example `X-Powered-By: Express`, `csrftoken cookie`). Each finding then carries a short snippet for the detected app framework, plus one for nginx or Apache when a server is detected too. Every snippet was checked against that framework's current documentation, which it links. If detection is wrong or empty, pick one with `--framework django` (or any id from `--help`).

When the responses look like a development server (Vite, `next dev`, webpack dev server, Django `runserver`, the Werkzeug server), the report says so: dev servers skip production settings, so scan a production build as well.

## Install

Run it without installing, as above, or add it to a project:

```sh
npm install --save-dev @bydtech/port-audit
npx port-audit --port 3000
```

## CLI

```text
port-audit [url | port] [options]
```

| Option | Default | What it does |
|---|---|---|
| `-p, --port <n>` | | audit `http://localhost:<n>/` |
| `-f, --format <fmt>` | `text` | `text`, `json`, `md`, `sarif` or `junit` |
| `-o, --out <file>` | stdout | write the report to a file; the format follows `.json`, `.md`, `.sarif` or `.xml` (anything else is text). Repeat it to write several formats from one scan |
| `--fail-on <level>` | | exit 1 if any finding is at `fix-now`, or at `should-fix` or above |
| `--baseline <file>` | | hide findings already in an earlier `--format json` or `sarif` report |
| `--path <path>` | | also read this page on the same host (repeatable); its headers, CORS answers and scripts are checked too |
| `--header "Name: value"` | | send this header on every request (repeatable), e.g. a session cookie for a signed-in page; redacted in all output |
| `--rate <n>` | `10` | requests per second (0.1 to 100) |
| `--max-requests <n>` | `300` | hard cap on requests for the run |
| `--timeout <ms>` | `10000` | timeout per request |
| `--framework <id>` | detected | use this framework's fix snippets |
| `--i-own-this <host>` | | allow one host outside the default ranges; must equal the target's host |
| `--list-checks` | | print every check with its OWASP mapping and sources |
| `--no-color`, `-q`, `-h`, `-v` | | plain output (also `NO_COLOR`), no progress, help, version |

Exit codes: `0` done, `1` the `--fail-on` threshold was met, `2` bad usage, a refused target, or nothing answered.

Priorities: **Fix now** means any website or anyone who can reach the app can act as a signed-in user or read their data (CORS with credentials, an expired certificate on a public host). **Should fix** is a real weakness with a known cost. **Nice to have** is hardening or a choice to confirm. In JUnit output, nice-to-have findings are reported as skipped tests, so they show without failing the build.

### Baseline

Accept today's findings and fail only on new ones:

```sh
npx @bydtech/port-audit --port 3000 --format json --out port-audit-baseline.json
npx @bydtech/port-audit --port 3000 --baseline port-audit-baseline.json --fail-on should-fix
```

A fingerprint is the rule, the URL path and a key (the host and port are left out), so a baseline made on one port works on another.

## API

```js
import { auditPort, formatReport } from '@bydtech/port-audit';

const report = await auditPort(3000, { paths: ['/login'], rate: 10 });
console.log(formatReport(report, 'text'));
if (report.findings.some((f) => f.priority === 'fix-now')) process.exitCode = 1;
```

`auditPort(target, options)` takes a port, `host:port` or URL, and resolves to a `Report`: `findings` (each with `id`, `priority`, `title`, `url`, `evidence`, `details`, `why`, `fix`, `snippets`, `mapping` `{ top10, api, asvs, cwe }`, `sources`, `fingerprint`), `passed`, `frameworks` (with evidence), `devServer`, `notes`, `coverage`, `requests` `{ sent, cap, skipped, backoffs }` and `suppressed`. Options: `paths`, `headers`, `rate`, `maxRequests`, `timeoutMs`, `iOwnThis`, `framework`, `baseline` (fingerprints), `onProgress`. It throws `PortAuditError` with `code` `INVALID_TARGET`, `REFUSED` or `UNREACHABLE`.

Also exported: `formatReport` / `formatText` / `formatMarkdown` / `formatSarif` / `formatJunit`, `RULE_LIST`, `SNIPPETS`, `LIBRARIES` and `advisoriesFor`, `COVERAGE`, `SOURCES` and `FACTS_VERIFIED_ON`, `isAllowedHost`, `readBaseline`. A runnable example is in [`examples/audit.mjs`](examples/audit.mjs).

## How it works, and its limits

1. It checks the target against the allowed ranges, resolves it, checks every address again, and connects only to one that passed.
2. It reads the page (following redirects on the same host), any `--path` pages, and up to 10 same-origin scripts the pages load. It sends one `Origin` read and one `Origin: null` read per page, one OPTIONS and one TRACE, and, for https, two TLS handshakes (one normal, one offering only TLS 1.0/1.1).
3. Every check is a deterministic rule on those responses. Nothing runs in a browser and nothing is crawled.

It uses `node:http` rather than `fetch` because `fetch` refuses TRACE and hides TLS details. It has **no runtime dependencies**.

Limits, said plainly:

- It sees only the pages it reads: the page you point it at and the `--path` pages. It does not crawl, and it does not run JavaScript, so headers set only on other routes and scripts injected at run time are missed.
- Locally, your app may not set headers that a proxy or CDN adds in production. Scan the deployed site too (with `--i-own-this` for a public host you own).
- Library detection needs a version in the script URL or a banner in a same-origin file. Bundles that strip license comments hide versions. The advisory list is short on purpose; it is not `npm audit`.
- Framework detection is a best guess from public signals, and the report shows the evidence. Use `--framework` when it is wrong.
- See "What 0.1.0 does not check" above. No findings means no findings for these checks, nothing more.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## License

MIT © 2026 BYD Tech

---

Maintained by [BYD Tech](https://bydtech.in), a software studio that builds MVPs, AI agents, and web & mobile apps.
