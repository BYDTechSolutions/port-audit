# Contributing

Thanks for helping. Issues and pull requests are welcome at
[github.com/BYDTechSolutions/port-audit](https://github.com/BYDTechSolutions/port-audit).

## Setup

```sh
npm ci
npm run typecheck
npm test
npm run build
```

Node.js 20 or later. The TLS tests generate a throwaway certificate with the
`openssl` CLI and are skipped when it is not installed.

## Rules

- **Passive only.** Requests are GET, OPTIONS and TRACE reads, plus TLS
  handshakes. No request that writes state, submits a form, injects a payload
  or guesses anything. Active checks are out of scope for this release.
- **The safety boundary is not negotiable.** Every request goes through
  `Client` in `src/net/client.ts`, which only talks to the target's host at an
  address that passed `resolveTarget` in `src/target.ts`. Never call `fetch`,
  `http.request` or `tls.connect` anywhere else, and never fetch third-party
  URLs. `test/safety.test.ts` covers the allowed ranges, DNS re-checks,
  redirects, the rate, the cap and redaction; extend it with any change there.
- **Every fact needs its source.** A header rule cites MDN or an OWASP cheat
  sheet; an OWASP ID must be on OWASP's own page (a Top 10:2025 category maps
  only when its list of mapped CWEs contains the rule's CWE; an ASVS 5.0.0 ID
  only when the requirement's text covers the rule). A snippet links the
  framework's own documentation; an advisory links its GitHub Advisory page.
  Update `FACTS_VERIFIED_ON` in `src/facts/sources.ts` when you re-read them.
  If you cannot verify it, leave it out.
- **Low noise.** A finding names the URL, says what was seen, why it matters in
  one or two sentences, and gives a concrete fix. The well-configured fixture
  in `test/servers.ts` must keep producing no findings.
- **Never say "secure".** Clean output says "Nothing to report for the checks
  in this release", and the coverage section always says what is not checked.
- **Output is always safe to print.** Evidence goes through `Redactor`; never
  put a header value, cookie value or token in a finding unredacted.
- No runtime dependencies without a strong reason, stated in the README.
- Add a line to `CHANGELOG.md` under "Unreleased".
- American English in code, messages and docs.
