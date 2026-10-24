/*
 * Every rule the tool can report, with its OWASP mapping and sources.
 *
 * Mapping method (checked on FACTS_VERIFIED_ON against OWASP's own pages):
 * - Top 10:2025: a rule maps to a category when that category's "List of
 *   Mapped CWEs" contains the rule's CWE (e.g. CWE-942 and CWE-614 are listed
 *   under A02, CWE-1021 under A06, CWE-829 under A08). Headers follow the
 *   design's A02.
 * - API Security Top 10 2023: API8 lists missing security headers, CORS,
 *   TLS and unnecessary HTTP verbs.
 * - ASVS 5.0.0: only requirements whose text covers the rule. Where no
 *   requirement does (CORS credentials, the null origin, Permissions-Policy,
 *   X-XSS-Protection), the ASVS list is empty rather than guessed.
 */
import { SOURCES as S } from './facts/sources.js';
import type { Mapping, Rule } from './types.js';

const m = (top10: string[], api: string[], asvs: string[], cwe: number[] = []): Mapping => ({ top10, api, asvs, cwe });

const A01 = 'A01:2025';
const A02 = 'A02:2025';
const A03 = 'A03:2025';
const A04 = 'A04:2025';
const A06 = 'A06:2025';
const A08 = 'A08:2025';
const API8 = 'API8:2023';

/** The rules, in report order. */
export const RULE_LIST: readonly Rule[] = [
  // Headers
  {
    id: 'headers/hsts-missing', group: 'headers', priority: 'should-fix', topic: 'headers',
    title: 'No Strict-Transport-Security (HSTS) header on HTTPS',
    why: 'HSTS tells browsers to use HTTPS for this host from then on, so a visitor cannot be downgraded to plain HTTP on a hostile network.',
    fix: 'Send "Strict-Transport-Security: max-age=31536000; includeSubDomains" on every HTTPS response (OWASP suggests max-age=63072000; includeSubDomains; preload once you are sure).',
    mapping: m([A02, A04], [API8], ['3.4.1'], [319]), sources: [S.owaspHeaders, S.mdnHsts],
  },
  {
    id: 'headers/hsts-short', group: 'headers', priority: 'nice-to-have', topic: 'headers',
    title: 'HSTS max-age is under one year',
    why: 'A short max-age lets the protection lapse between visits. ASVS asks for at least a year, and preloading requires it.',
    fix: 'Raise max-age to at least 31536000 (one year).',
    mapping: m([A02, A04], [API8], ['3.4.1'], [319]), sources: [S.mdnHsts],
  },
  {
    id: 'headers/csp-missing', group: 'headers', priority: 'should-fix', topic: 'headers',
    title: 'No Content-Security-Policy on HTML pages',
    why: 'A CSP limits which scripts may run, which contains the damage of an injected script (XSS). Report-only mode reports but blocks nothing.',
    fix: "Start with default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self', add the third parties you use, try it as Content-Security-Policy-Report-Only, then enforce it.",
    mapping: m([A02], [API8], ['3.4.3']), sources: [S.owaspCsp, S.mdnCsp],
  },
  {
    id: 'headers/csp-weak', group: 'headers', priority: 'nice-to-have', topic: 'headers',
    title: 'The Content-Security-Policy leaves scripts largely unrestricted',
    why: "'unsafe-inline' and 'unsafe-eval' let exactly the injected script a CSP exists to stop run anyway, and a policy without object-src 'none' and base-uri leaves two known bypasses open.",
    fix: "Move inline scripts to files or allow them with nonces or hashes, drop 'unsafe-eval', list script hosts explicitly, and add object-src 'none' and base-uri 'self' (or 'none').",
    mapping: m([A02], [API8], ['3.4.3']), sources: [S.owaspCsp, S.mdnCsp],
  },
  {
    id: 'headers/clickjacking', group: 'headers', priority: 'should-fix', topic: 'headers',
    title: 'Any site can embed this page in a frame',
    why: 'A hostile page can load yours in an invisible frame and trick signed-in visitors into clicking buttons on it (clickjacking).',
    fix: "Add frame-ancestors 'self' (or 'none') to the Content-Security-Policy header; X-Frame-Options: DENY or SAMEORIGIN covers older browsers.",
    mapping: m([A02, A06], [API8], ['3.4.6'], [1021]), sources: [S.mdnFrameAncestors, S.owaspHeaders],
  },
  {
    id: 'headers/nosniff', group: 'headers', priority: 'should-fix', topic: 'headers',
    title: 'X-Content-Type-Options is not "nosniff"',
    why: 'Without it, browsers may guess a response\'s type from its content and run an uploaded or user-supplied file as script or HTML.',
    fix: 'Send "X-Content-Type-Options: nosniff" on every response, with a correct Content-Type.',
    mapping: m([A02], [API8], ['3.4.4']), sources: [S.owaspHeaders],
  },
  {
    id: 'headers/referrer-policy', group: 'headers', priority: 'nice-to-have', topic: 'headers',
    title: 'No Referrer-Policy, or one that leaks full URLs',
    why: 'Full URLs, with paths and query strings, can carry tokens and IDs; a referrer policy keeps them from being sent to every third party you link to or load from.',
    fix: 'Send "Referrer-Policy: strict-origin-when-cross-origin" (or stricter).',
    mapping: m([A02], [API8], ['3.4.5']), sources: [S.owaspHeaders],
  },
  {
    id: 'headers/permissions-policy', group: 'headers', priority: 'nice-to-have', topic: 'headers',
    title: 'No Permissions-Policy',
    why: 'A Permissions-Policy switches off browser features the app does not use (camera, microphone, geolocation), so an injected or embedded script cannot use them either.',
    fix: 'Send e.g. "Permissions-Policy: camera=(), microphone=(), geolocation=()", listing the features you do not need.',
    mapping: m([A02], [API8], []), sources: [S.owaspHeaders],
  },
  {
    id: 'headers/coop', group: 'headers', priority: 'nice-to-have', topic: 'headers',
    title: 'No Cross-Origin-Opener-Policy on HTML pages',
    why: 'Without COOP, a page you open in a popup, or that opens yours, keeps a handle to your window, which enables cross-window attacks such as XS-Leaks.',
    fix: 'Send "Cross-Origin-Opener-Policy: same-origin" (or same-origin-allow-popups if you rely on OAuth or payment popups).',
    mapping: m([A02], [API8], ['3.4.8']), sources: [S.owaspHeaders, S.mdnCoop],
  },
  {
    id: 'headers/x-xss-protection', group: 'headers', priority: 'nice-to-have', topic: 'headers',
    title: 'X-XSS-Protection is turned on',
    why: 'OWASP says not to set it, or to turn it off: the old browser filter it controls could itself create XSS holes. CSP replaces it.',
    fix: 'Remove the header or set "X-XSS-Protection: 0".',
    mapping: m([A02], [API8], []), sources: [S.owaspHeaders],
  },

  // Cookies
  {
    id: 'cookies/no-secure', group: 'cookies', priority: 'should-fix', topic: 'cookies',
    title: 'Cookies set over HTTPS without the Secure attribute',
    why: 'Without Secure, the browser also sends the cookie over plain HTTP, where anyone on the network path can read it.',
    fix: 'Add Secure to every cookie set over HTTPS (and prefer the __Host- prefix for session cookies).',
    mapping: m([A02], [], ['3.3.1'], [614]), sources: [S.mdnSetCookie, S.owaspSession],
  },
  {
    id: 'cookies/no-httponly', group: 'cookies', priority: 'should-fix', topic: 'cookies',
    title: 'Session cookies readable by JavaScript (no HttpOnly)',
    why: 'Any script on the page, including an injected one, can read a cookie without HttpOnly and send the session to an attacker.',
    fix: 'Set HttpOnly on session and auth cookies. Only cookies that front-end code must read (such as some CSRF tokens) should go without it.',
    mapping: m([A02], [], ['3.3.4'], [1004]), sources: [S.mdnSetCookie, S.owaspSession],
  },
  {
    id: 'cookies/no-samesite', group: 'cookies', priority: 'nice-to-have', topic: 'cookies',
    title: 'Session cookies without an explicit SameSite attribute',
    why: 'Browsers differ in what they assume when SameSite is missing; an explicit Lax or Strict keeps the session cookie off cross-site requests (CSRF).',
    fix: 'Set SameSite=Lax (or Strict) on session cookies.',
    mapping: m([A02], [], ['3.3.2']), sources: [S.mdnSetCookie, S.owaspSession],
  },
  {
    id: 'cookies/samesite-none-insecure', group: 'cookies', priority: 'should-fix', topic: 'cookies',
    title: 'SameSite=None without Secure',
    why: 'Browsers require Secure with SameSite=None and reject the cookie otherwise, so it either breaks or was meant to cross sites without protection.',
    fix: 'Add Secure, or use SameSite=Lax if the cookie does not need to be sent on cross-site requests.',
    mapping: m([A02], [], ['3.3.2'], [614]), sources: [S.mdnSetCookie],
  },
  {
    id: 'cookies/bad-prefix', group: 'cookies', priority: 'should-fix', topic: 'cookies',
    title: 'A __Host- or __Secure- cookie breaks its prefix rules',
    why: 'Browsers reject a __Secure- cookie without Secure, and a __Host- cookie unless it has Secure, Path=/ and no Domain, so the cookie is silently dropped.',
    fix: '__Secure-: add Secure. __Host-: add Secure and Path=/, and remove Domain.',
    mapping: m([A02], [], ['3.3.1', '3.3.3']), sources: [S.mdnSetCookie],
  },

  // CORS
  {
    id: 'cors/reflected-credentials', group: 'cors', priority: 'fix-now', topic: 'cors',
    title: 'CORS reflects any Origin and allows credentials',
    why: "Any website a signed-in user visits can call this endpoint with the user's cookies and read the response: their data, CSRF tokens, anything the endpoint returns.",
    fix: 'Compare the Origin header with an allowlist of your own front-end origins and send Access-Control-Allow-Origin only for those. Never echo the request\'s Origin.',
    mapping: m([A02], [API8], ['3.4.2'], [942]), sources: [S.wstgCors, S.mdnAcao],
  },
  {
    id: 'cors/null-origin', group: 'cors', priority: 'should-fix', topic: 'cors',
    title: 'CORS allows the "null" origin',
    why: 'Sandboxed documents and data: or file: pages send Origin: null, and any site can create one, so allowing null is close to allowing everyone (with credentials, it is as bad as reflecting any origin).',
    fix: 'Remove "null" from the allowed origins; allow only your own front-end origins.',
    mapping: m([A02], [API8], ['3.4.2'], [942]), sources: [S.mdnAcao, S.wstgCors],
  },
  {
    id: 'cors/wildcard-credentials', group: 'cors', priority: 'should-fix', topic: 'cors',
    title: 'Access-Control-Allow-Origin: * together with Allow-Credentials: true',
    why: 'Browsers refuse this combination, so credentialed calls fail; the usual "fix" developers reach for is reflecting the Origin, which opens the endpoint to every site.',
    fix: 'Decide whether the endpoint needs cookies. If it does, allow a fixed list of origins; if not, drop Access-Control-Allow-Credentials.',
    mapping: m([A02], [API8], ['3.4.2'], [942]), sources: [S.mdnCorsCredentials],
  },

  // TLS
  {
    id: 'tls/legacy-protocol', group: 'tls', priority: 'should-fix',
    title: 'The server still accepts TLS 1.0 or 1.1',
    why: 'RFC 8996 deprecates TLS 1.0 and 1.1 ("MUST NOT be used"); they lack modern protections and keeping them invites downgrade attacks.',
    fix: 'Allow only TLS 1.2 and 1.3 in the server or proxy configuration (for example ssl_protocols TLSv1.2 TLSv1.3; in nginx).',
    mapping: m([A04], [API8], ['12.1.1'], [326, 327]), sources: [S.rfc8996, S.owaspTls],
  },
  {
    id: 'tls/cert-expired', group: 'tls', priority: 'fix-now',
    title: 'The TLS certificate has expired',
    why: 'Browsers and API clients reject an expired certificate, and users who click through warnings learn to ignore real attacks.',
    fix: 'Renew the certificate and automate renewal (for example with an ACME client).',
    mapping: m([A04], [API8], ['12.2.2']), sources: [S.owaspTls],
  },
  {
    id: 'tls/cert-expiring', group: 'tls', priority: 'should-fix',
    title: 'The TLS certificate expires within 14 days',
    why: 'Once it expires, browsers and clients refuse the connection.',
    fix: 'Renew the certificate now and check that automated renewal works.',
    mapping: m([A04], [API8], ['12.2.2']), sources: [S.owaspTls],
  },
  {
    id: 'tls/hostname-mismatch', group: 'tls', priority: 'should-fix',
    title: 'The TLS certificate does not match the host name',
    why: 'Clients reject a certificate issued for another name, so the connection is either refused or the user is trained to accept warnings.',
    fix: 'Serve a certificate whose subject alternative names include this host.',
    mapping: m([A04], [API8], ['12.2.2']), sources: [S.owaspTls],
  },
  {
    id: 'tls/untrusted', group: 'tls', priority: 'should-fix',
    title: 'The TLS certificate is not publicly trusted',
    why: 'A self-signed or privately issued certificate on an external-facing service makes clients refuse the connection or click through warnings.',
    fix: 'Use a certificate from a publicly trusted certificate authority on anything users or partners reach.',
    mapping: m([A04], [API8], ['12.2.2']), sources: [S.owaspTls],
  },
  {
    id: 'tls/no-https', group: 'tls', priority: 'should-fix',
    title: 'The app is served over plain HTTP',
    why: 'Without TLS, anyone on the network path can read and change requests and responses, including cookies and passwords.',
    fix: 'Serve the app over HTTPS and redirect user-facing http:// URLs to https://.',
    mapping: m([A04], [API8], ['12.2.1'], [319]), sources: [S.owaspTls],
  },

  // Methods
  {
    id: 'methods/trace', group: 'methods', priority: 'nice-to-have', topic: 'methods',
    title: 'The TRACE method is enabled',
    why: 'TRACE echoes the request back, headers included. Browsers block it, so cross-site tracing no longer works, but ASVS asks for it to be off and it signals weak hardening.',
    fix: 'Disable TRACE (TraceEnable Off in Apache; most frameworks only answer methods you route).',
    mapping: m([A02], [API8], ['13.4.4']), sources: [S.wstgMethods, S.apacheTrace],
  },
  {
    id: 'methods/webdav', group: 'methods', priority: 'nice-to-have', topic: 'methods',
    title: 'OPTIONS advertises WebDAV or other unexpected methods',
    why: 'WebDAV methods (PROPFIND, PUT on static files, MKCOL, MOVE, COPY) are rarely needed by an app and widen what can be done to the server.',
    fix: 'Allow only the methods your routes use; switch off WebDAV modules you do not use.',
    mapping: m([A02], [API8], ['4.1.4']), sources: [S.wstgMethods],
  },

  // SRI
  {
    id: 'sri/missing-script', group: 'sri', priority: 'should-fix',
    title: 'Third-party scripts load without Subresource Integrity',
    why: 'If the CDN or third-party host is compromised, the changed script runs on your page with full access to it. An integrity hash makes the browser refuse a changed file.',
    fix: 'Add integrity="sha384-..." and crossorigin="anonymous" to each <script> from another origin (for versioned files), or self-host them.',
    mapping: m([A08], [], ['3.6.1'], [829]), sources: [S.mdnSri],
  },
  {
    id: 'sri/missing-style', group: 'sri', priority: 'nice-to-have',
    title: 'Third-party stylesheets load without Subresource Integrity',
    why: 'A tampered stylesheet can change or hide what users see and leak data through CSS selectors. An integrity hash makes the browser refuse a changed file.',
    fix: 'Add integrity and crossorigin="anonymous" to each <link rel="stylesheet"> from another origin, or self-host them.',
    mapping: m([A08], [], ['3.6.1'], [829]), sources: [S.mdnSri],
  },

  // Libraries
  {
    id: 'libraries/vulnerable', group: 'libraries', priority: 'should-fix',
    title: 'A front-end library with known vulnerabilities is served',
    why: 'Published advisories describe how to exploit these versions, mostly as XSS or prototype pollution in the browser.',
    fix: 'Upgrade to the patched version named in each advisory (or replace the library), then re-run the audit.',
    mapping: m([A03], [], ['15.2.1'], [1104]), sources: [S.githubAdvisories],
  },
  {
    id: 'libraries/eol', group: 'libraries', priority: 'should-fix',
    title: 'An end-of-life front-end framework is served',
    why: 'An end-of-life library gets no security fixes; new advisories stay unpatched.',
    fix: 'Plan a migration off the library, or use a commercially supported fork until you can.',
    mapping: m([A03], [], ['3.7.1', '15.2.1'], [1104]), sources: [S.angularjsEol, S.cwe1104],
  },

  // Disclosure
  {
    id: 'disclosure/version-header', group: 'disclosure', priority: 'nice-to-have', topic: 'version',
    title: 'Response headers name the server or framework version',
    why: 'Version numbers let anyone match the app to known vulnerabilities in seconds. OWASP advises removing X-Powered-By and making Server non-informative. Hiding them is hardening, not a fix for an outdated server.',
    fix: 'Remove X-Powered-By and X-AspNet-Version, and strip the version from Server.',
    mapping: m([A01, A02], [API8], ['13.4.6'], [497]), sources: [S.owaspHeaders, S.wstgFingerprint],
  },
];

/** Rules by id. */
export const RULES: ReadonlyMap<string, Rule> = new Map(RULE_LIST.map((r) => [r.id, r]));

/** Looks up a rule; throws on an unknown id (a programming error). */
export function rule(id: string): Rule {
  const r = RULES.get(id);
  if (!r) throw new Error(`Unknown rule ${id}`);
  return r;
}
