import { capList, clip, type Ctx, type Page } from '../context.js';

const ONE_YEAR = 31_536_000;

/** CSP directives by name (lowercase); the first occurrence wins, as in browsers. */
export function parseCsp(value: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of value.split(';')) {
    const [name, ...tokens] = part.trim().split(/\s+/);
    if (!name) continue;
    const key = name.toLowerCase();
    if (!out.has(key)) out.set(key, tokens.map((t) => t.toLowerCase()));
  }
  return out;
}

/** What is weak about a CSP, as short phrases; empty when scripts are restricted. */
export function cspWeaknesses(csp: string): string[] {
  const d = parseCsp(csp);
  const script = d.get('script-src') ?? d.get('default-src');
  const weak: string[] = [];
  if (!script) weak.push('no script-src or default-src, so scripts are not restricted');
  else {
    const nonceOrHash = script.some((t) => /^'(nonce-|sha256-|sha384-|sha512-)/.test(t));
    if (script.includes("'unsafe-inline'") && !nonceOrHash && !script.includes("'strict-dynamic'")) weak.push("script-src allows 'unsafe-inline'");
    if (script.includes("'unsafe-eval'")) weak.push("script-src allows 'unsafe-eval'");
    const any = script.filter((t) => ['*', 'http:', 'https:', 'data:'].includes(t));
    if (any.length) weak.push(`script-src allows any source (${any.join(' ')})`);
  }
  const objectSrc = d.get('object-src') ?? d.get('default-src');
  if (!objectSrc || !(objectSrc.includes("'none'") || (objectSrc.length === 1 && objectSrc[0] === "'self'"))) weak.push("no object-src 'none'");
  if (!d.has('base-uri')) weak.push('no base-uri');
  return weak;
}

interface Issue {
  url: string;
  evidence: string;
  title?: string;
}

/** The header problems of one page, by rule id. Passes go to `passes`. */
function pageIssues(page: Page, passes: Map<string, string>): Map<string, Issue> {
  const out = new Map<string, Issue>();
  const res = page.res;
  const h = res.headers;
  const url = res.url;
  const add = (id: string, evidence: string, title?: string) => out.set(id, { url, evidence, title });

  if (new URL(url).protocol === 'https:') {
    const hsts = h['strict-transport-security'];
    if (!hsts) add('headers/hsts-missing', 'The HTTPS response has no Strict-Transport-Security header.');
    else {
      const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? NaN);
      if (!Number.isFinite(maxAge) || maxAge < ONE_YEAR) add('headers/hsts-short', `Strict-Transport-Security: ${hsts}`);
      else passes.set('headers/hsts', 'HSTS with max-age of a year or more');
    }
  }

  if (page.html) {
    const cspHeader = h['content-security-policy'];
    const cspMeta = page.tags.find((t) => t.name === 'meta' && (t.attrs['http-equiv'] ?? '').toLowerCase() === 'content-security-policy')?.attrs.content;
    const csp = cspHeader ?? cspMeta;
    const reportOnly = h['content-security-policy-report-only'];
    if (!csp) {
      if (reportOnly) add('headers/csp-missing', `Only Content-Security-Policy-Report-Only is set: ${clip(reportOnly, 120)}`, 'Content-Security-Policy is only in report-only mode');
      else add('headers/csp-missing', 'No Content-Security-Policy header or meta tag on the HTML page.');
    } else {
      const weak = cspWeaknesses(csp);
      if (weak.length) add('headers/csp-weak', `${weak.join('; ')}. Policy: ${clip(csp, 160)}`);
      else passes.set('headers/csp', 'Content-Security-Policy restricts scripts');
    }

    // frame-ancestors only works from the header, never from a meta tag.
    const frameAncestors = cspHeader ? parseCsp(cspHeader).get('frame-ancestors') : undefined;
    const xfo = h['x-frame-options'];
    if (!frameAncestors && !xfo) add('headers/clickjacking', 'No frame-ancestors in a Content-Security-Policy header and no X-Frame-Options header.');
    else if (frameAncestors?.some((t) => t === '*' || t === 'https:' || t === 'http:')) add('headers/clickjacking', `frame-ancestors allows any site: ${frameAncestors.join(' ')}`);
    else passes.set('headers/clickjacking', 'Framing is restricted');

    if (!h['cross-origin-opener-policy']) add('headers/coop', 'No Cross-Origin-Opener-Policy header on the HTML page.');
    else passes.set('headers/coop', `Cross-Origin-Opener-Policy: ${h['cross-origin-opener-policy']}`);

    const policy = (h['referrer-policy'] ?? page.tags.find((t) => t.name === 'meta' && (t.attrs.name ?? '').toLowerCase() === 'referrer')?.attrs.content ?? '').toLowerCase();
    const last = policy.split(',').map((p) => p.trim()).filter(Boolean).pop();
    if (!last) add('headers/referrer-policy', 'No Referrer-Policy header or meta tag.');
    else if (last === 'unsafe-url' || last === 'no-referrer-when-downgrade') add('headers/referrer-policy', `Referrer-Policy: ${policy} sends the full URL to other sites.`);
    else passes.set('headers/referrer-policy', `Referrer-Policy: ${policy}`);

    if (!h['permissions-policy']) add('headers/permissions-policy', 'No Permissions-Policy header.');
    else passes.set('headers/permissions-policy', 'Permissions-Policy set');
  }

  const nosniff = (h['x-content-type-options'] ?? '').trim().toLowerCase();
  if (nosniff !== 'nosniff') add('headers/nosniff', nosniff ? `X-Content-Type-Options: ${nosniff}` : 'No X-Content-Type-Options header.');
  else passes.set('headers/nosniff', 'X-Content-Type-Options: nosniff');

  const xxss = (h['x-xss-protection'] ?? '').trim();
  if (xxss && !xxss.startsWith('0')) add('headers/x-xss-protection', `X-XSS-Protection: ${xxss}`);
  return out;
}

/**
 * HSTS, CSP, framing, nosniff, Referrer-Policy, Permissions-Policy, COOP and
 * X-XSS-Protection on every page read. One finding per rule; other pages with
 * the same problem are listed under it.
 */
export async function checkHeaders(ctx: Ctx): Promise<void> {
  const passes = new Map<string, string>();
  const byRule = new Map<string, Issue[]>();
  for (const page of ctx.pages) {
    for (const [id, issue] of pageIssues(page, passes)) byRule.set(id, [...(byRule.get(id) ?? []), issue]);
  }
  for (const [id, issues] of byRule) {
    const [first, ...rest] = issues as [Issue, ...Issue[]];
    ctx.add({ id, url: first.url, evidence: first.evidence, title: first.title, details: rest.length ? capList(rest.map((i) => `Also on ${i.url}`)) : undefined });
  }
  for (const [id, title] of passes) if (!byRule.has(id)) ctx.pass(id, title);
  if (ctx.base.protocol === 'http:' && ctx.local) {
    ctx.note('Plain HTTP on your own machine: HSTS and TLS checks were skipped. If a proxy or CDN adds TLS and headers in production, audit that too (with --i-own-this for a public host).');
  }
}
