/*
 * What a passive 0.1.0 scan can and cannot see, per OWASP Top 10:2025
 * category (names as on top10.owasp.org/2025). Printed with every report so
 * a short or empty finding list is not read as "secure".
 */
import type { CoverageRow } from '../types.js';

export const COVERAGE: readonly CoverageRow[] = [
  { id: 'A01:2025', name: 'Broken Access Control', status: 'not-assessed', how: 'not checked: 0.1.0 does not look for exposed files or endpoints, directory listings or open redirects, and authorization needs test accounts' },
  { id: 'A02:2025', name: 'Security Misconfiguration', status: 'partly', how: 'security headers, CSP, cookie flags, CORS, TRACE and WebDAV methods, version headers; not exposed files, debug endpoints or directory listing' },
  { id: 'A03:2025', name: 'Software Supply Chain Failures', status: 'partly', how: 'only front-end libraries the pages load, against a small bundled advisory list; run npm audit or another SCA tool on your lockfile' },
  { id: 'A04:2025', name: 'Cryptographic Failures', status: 'partly', how: 'TLS protocol, certificate and HSTS when the target is https; not how data is stored or hashed' },
  { id: 'A05:2025', name: 'Injection', status: 'not-assessed', how: 'not checked: needs active payloads, which this release never sends' },
  { id: 'A06:2025', name: 'Insecure Design', status: 'not-assessed', how: 'not checkable from outside (the framing header is reported under clickjacking)' },
  { id: 'A07:2025', name: 'Authentication Failures', status: 'not-assessed', how: 'not checked: no login, session or rate-limit testing (cookie flags are reported under A02)' },
  { id: 'A08:2025', name: 'Software or Data Integrity Failures', status: 'partly', how: 'Subresource Integrity on third-party scripts and stylesheets only' },
  { id: 'A09:2025', name: 'Security Logging and Alerting Failures', status: 'not-assessed', how: 'not checkable from outside' },
  { id: 'A10:2025', name: 'Mishandling of Exceptional Conditions', status: 'not-assessed', how: 'not checked: 0.1.0 does not test error handling or look for stack traces' },
];

/** Areas this release does not check at all, said in every report. */
export const NOT_CHECKED = 'This release does not check exposed files or endpoints, directory listing, error leakage, open redirects, injection, authentication or access control.';

/** Printed under every report. Never "secure", never "compliant". */
export const NOT_A_VERDICT = 'Findings cover only what a passive scan of the pages read can see. An empty list is not a security sign-off.';
