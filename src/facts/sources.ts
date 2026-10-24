/*
 * Every page a rule relies on. Each URL was opened and read on
 * FACTS_VERIFIED_ON, and each rule's claim matches what the page says. When a
 * page moves or changes, the fix starts here.
 */
import type { Source } from '../types.js';

/** The day every source below, and every OWASP ID in `rules.ts`, was last checked. */
export const FACTS_VERIFIED_ON = '2026-10-25';

const s = (title: string, url: string): Source => ({ title, url });
const CS = 'https://cheatsheetseries.owasp.org/cheatsheets';
const MDN = 'https://developer.mozilla.org/en-US/docs/Web';
const WSTG = 'https://wstg.owasp.org/latest/4-Web_Application_Security_Testing';

export const SOURCES = {
  // OWASP lists (the mapping itself)
  top10: s('OWASP Top 10:2025', 'https://top10.owasp.org/2025/'),
  apiTop10: s('OWASP API Security Top 10 2023', 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/'),
  asvs: s('OWASP ASVS 5.0.0', 'https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en'),

  // Headers
  owaspHeaders: s('OWASP HTTP Headers Cheat Sheet', `${CS}/HTTP_Headers_Cheat_Sheet.html`),
  owaspCsp: s('OWASP Content Security Policy Cheat Sheet', `${CS}/Content_Security_Policy_Cheat_Sheet.html`),
  mdnHsts: s('MDN: Strict-Transport-Security', `${MDN}/HTTP/Reference/Headers/Strict-Transport-Security`),
  mdnCsp: s('MDN: Content Security Policy (CSP)', `${MDN}/HTTP/Guides/CSP`),
  mdnFrameAncestors: s('MDN: CSP frame-ancestors', `${MDN}/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors`),
  mdnXfo: s('MDN: X-Frame-Options', `${MDN}/HTTP/Reference/Headers/X-Frame-Options`),
  mdnCoop: s('MDN: Cross-Origin-Opener-Policy', `${MDN}/HTTP/Reference/Headers/Cross-Origin-Opener-Policy`),
  mdnCorp: s('MDN: Cross-Origin-Resource-Policy', `${MDN}/HTTP/Reference/Headers/Cross-Origin-Resource-Policy`),

  // Cookies
  mdnSetCookie: s('MDN: Set-Cookie', `${MDN}/HTTP/Reference/Headers/Set-Cookie`),
  owaspSession: s('OWASP Session Management Cheat Sheet: Cookies', `${CS}/Session_Management_Cheat_Sheet.html#cookies`),

  // CORS
  mdnCorsCredentials: s('MDN: CORS, credentialed requests and wildcards', `${MDN}/HTTP/Guides/CORS#credentialed_requests_and_wildcards`),
  mdnAcao: s('MDN: Access-Control-Allow-Origin', `${MDN}/HTTP/Reference/Headers/Access-Control-Allow-Origin`),
  wstgCors: s('OWASP WSTG-CLNT-07: Cross Origin Resource Sharing', `${WSTG}/11-Client-side/07-Cross_Origin_Resource_Sharing`),

  // TLS
  owaspTls: s('OWASP Transport Layer Security Cheat Sheet', `${CS}/Transport_Layer_Security_Cheat_Sheet.html`),
  rfc8996: s('RFC 8996: Deprecating TLS 1.0 and TLS 1.1', 'https://www.rfc-editor.org/rfc/rfc8996.html'),

  // Methods and fingerprinting
  wstgMethods: s('OWASP WSTG-CONF-06: HTTP Methods', `${WSTG}/02-Configuration_and_Deployment_Management/06-HTTP_Methods`),
  wstgFingerprint: s('OWASP WSTG-INFO-02: Fingerprint Web Server', `${WSTG}/01-Information_Gathering/02-Fingerprint_Web_Server`),
  apacheTrace: s('Apache httpd: TraceEnable', 'https://httpd.apache.org/docs/2.4/mod/core.html#traceenable'),
  cwe1104: s('CWE-1104: Use of Unmaintained Third Party Components', 'https://cwe.mitre.org/data/definitions/1104.html'),

  // SRI and libraries
  mdnSri: s('MDN: Subresource Integrity', `${MDN}/Security/Defenses/Subresource_Integrity`),
  githubAdvisories: s('GitHub Advisory Database', 'https://github.com/advisories'),
  angularjsEol: s('AngularJS: version support status', 'https://docs.angularjs.org/misc/version-support-status'),
} satisfies Record<string, Source>;
