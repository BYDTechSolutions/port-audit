import type { Ctx } from '../context.js';

/** Cookie names that look like a session or auth token. CSRF tokens are left out: front-end code often must read them. */
const SESSIONISH = /sess|sid$|^sid|auth|token|jwt|login|remember|^_[a-z0-9_]+_session$/i;
const CSRF = /csrf|xsrf/i;

interface ParsedCookie {
  name: string;
  attrs: Map<string, string>;
  url: string;
}

/** Parses a Set-Cookie header into its name and attributes. The value is never kept. */
export function parseSetCookie(raw: string): { name: string; attrs: Map<string, string> } {
  const [pair = '', ...rest] = raw.split(';').map((s) => s.trim());
  const name = pair.split('=')[0]?.trim() ?? '';
  const attrs = new Map<string, string>();
  for (const a of rest) {
    const [k = '', ...v] = a.split('=');
    attrs.set(k.trim().toLowerCase(), v.join('=').trim());
  }
  return { name, attrs };
}

/** Secure, HttpOnly, SameSite and prefix rules on every cookie the app set during the run. */
export async function checkCookies(ctx: Ctx): Promise<void> {
  const seen = new Map<string, ParsedCookie>();
  for (const r of ctx.responses) {
    for (const raw of r.setCookies) {
      const c = parseSetCookie(raw);
      // A deletion (Max-Age=0 or an expiry in the past) is not a cookie being set.
      if (c.attrs.get('max-age') === '0' || /1970/.test(c.attrs.get('expires') ?? '')) continue;
      if (c.name && !seen.has(c.name)) seen.set(c.name, { ...c, url: r.url });
    }
  }
  if (!seen.size) return;
  const noSecure: ParsedCookie[] = [];
  const noHttpOnly: ParsedCookie[] = [];
  const noSameSite: ParsedCookie[] = [];
  const noneInsecure: ParsedCookie[] = [];
  const badPrefix: string[] = [];
  for (const c of seen.values()) {
    const https = new URL(c.url).protocol === 'https:';
    const secure = c.attrs.has('secure');
    const session = SESSIONISH.test(c.name) && !CSRF.test(c.name);
    if (https && !secure) noSecure.push(c);
    if (session && !c.attrs.has('httponly')) noHttpOnly.push(c);
    const sameSite = (c.attrs.get('samesite') ?? '').toLowerCase();
    if (session && !sameSite) noSameSite.push(c);
    if (sameSite === 'none' && !secure) noneInsecure.push(c);
    if (c.name.startsWith('__Secure-') && !secure) badPrefix.push(`${c.name}: __Secure- needs Secure`);
    if (c.name.startsWith('__Host-') && (!secure || c.attrs.has('domain') || c.attrs.get('path') !== '/')) badPrefix.push(`${c.name}: __Host- needs Secure, Path=/ and no Domain`);
  }
  const names = (list: ParsedCookie[]) => list.map((c) => c.name).join(', ');
  const first = (list: ParsedCookie[]) => (list[0] as ParsedCookie).url;
  if (noSecure.length) ctx.add({ id: 'cookies/no-secure', url: first(noSecure), evidence: `Set over HTTPS without Secure: ${names(noSecure)}` });
  if (noHttpOnly.length) ctx.add({ id: 'cookies/no-httponly', url: first(noHttpOnly), evidence: `Session-like cookies without HttpOnly: ${names(noHttpOnly)}` });
  if (noSameSite.length) ctx.add({ id: 'cookies/no-samesite', url: first(noSameSite), evidence: `Session-like cookies without SameSite: ${names(noSameSite)}` });
  if (noneInsecure.length) ctx.add({ id: 'cookies/samesite-none-insecure', url: first(noneInsecure), evidence: `SameSite=None without Secure: ${names(noneInsecure)}` });
  if (badPrefix.length) ctx.add({ id: 'cookies/bad-prefix', url: [...seen.values()][0]?.url ?? ctx.base.href, evidence: badPrefix.join('; ') });
  if (!noSecure.length && !noHttpOnly.length && !noSameSite.length && !noneInsecure.length && !badPrefix.length) {
    ctx.pass('cookies/flags', `${seen.size} cookie(s) carry the expected flags`);
  }
  if (!seen.size || ![...seen.values()].some((c) => new URL(c.url).protocol === 'https:')) {
    if ([...seen.values()].some((c) => !c.attrs.has('secure'))) ctx.note('Cookies were set over plain HTTP, so the Secure flag was not checked; make sure production sets it.');
  }
}
