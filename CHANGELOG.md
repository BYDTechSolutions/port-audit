# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-10-28

### Fixed

- The npm description listed exposed files, debug pages and open redirects, which this release does not check. It now lists only what the checks cover.

## [0.1.2] - 2026-10-28

### Added

- A GitHub Action: `uses: BYDTechSolutions/port-audit@v0`. It waits for the app to answer, scans it once, prints the report in the log, adds it to the job summary, writes SARIF for code scanning, sets the finding counts as outputs, and fails on "Fix now" by default. It runs the npm version that matches its tag.
- `--out` can be repeated to write several formats from one scan, each picked by its file extension: `-o report.sarif -o report.md`.

## [0.1.1] - 2026-10-25

### Changed

- Published from GitHub Actions with npm trusted publishing, so the package carries a provenance attestation. No code changes.

## [0.1.0] - 2026-10-25

### Added

- `port-audit --port <n>` (or a URL): a passive audit of a running app, printed as Fix now / Should fix / Nice to have, where each finding names the URL, the evidence, why it matters, the fix with a snippet for the detected framework, and its OWASP Top 10:2025, API Security Top 10 2023, ASVS 5.0.0 and CWE IDs.
- Checks: security headers and CSP quality, cookie flags, CORS (reflected origin with credentials, `null`, `*` with credentials), TLS for https targets (legacy protocols, expiry, host name, trust), TRACE and WebDAV methods, Subresource Integrity on third-party scripts and stylesheets, known-vulnerable front-end libraries from a bundled advisory list, and version headers.
- Framework detection (Express, Next.js, NestJS, Django, Flask, FastAPI, Rails, Laravel, Spring Boot, ASP.NET, nginx, Apache) with the evidence shown, and fix snippets checked against each framework's documentation; `--framework` to override.
- Output as text, JSON, Markdown, SARIF 2.1.0 (GitHub code scanning) and JUnit; `--out`, `--fail-on fix-now|should-fix`, `--baseline`, `--path`, `--header` (redacted), `--rate`, `--max-requests`, `--timeout`, `--list-checks`.
- Safety: only localhost, `*.localhost`, `*.test`, 127.0.0.0/8, ::1 and RFC 1918 by default, re-checked after DNS; `--i-own-this <host>` for one exact host; no redirects or requests off the target's host; GET, OPTIONS and TRACE reads only; 10 requests per second with back-off on 429/503 and a 300-request cap; no telemetry; secrets redacted in every format.
- A coverage section in every report that states what this release does not check: exposed files or endpoints, directory listing, error leakage, open redirects, injection, authentication and access control.
- API: `auditPort`, `formatReport` and the individual renderers, the rule list, snippets, advisories, coverage and sources.

[Unreleased]: https://github.com/BYDTechSolutions/port-audit/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/BYDTechSolutions/port-audit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/BYDTechSolutions/port-audit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/BYDTechSolutions/port-audit/compare/d71c556...v0.1.1
[0.1.0]: https://github.com/BYDTechSolutions/port-audit/tree/d71c556
