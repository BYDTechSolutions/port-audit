/*
 * The audit: check the target against the safety rules, read the page (and
 * any extra pages), run the passive checks, detect the framework, and turn
 * raw findings into report findings with rule text, snippets, redaction and
 * fingerprints.
 */
import { createHash } from 'node:crypto';
import { checkCookies } from './checks/cookies.js';
import { checkCors } from './checks/cors.js';
import { checkDisclosure } from './checks/disclosure.js';
import { checkHeaders } from './checks/headers.js';
import { checkLibraries } from './checks/libraries.js';
import { checkMethods } from './checks/methods.js';
import { checkSri } from './checks/sri.js';
import { checkTls } from './checks/tls.js';
import type { Ctx, Page, RawFinding, Script } from './context.js';
import { detectDevServer, detectFrameworks } from './detect.js';
import { PortAuditError } from './errors.js';
import { COVERAGE } from './facts/coverage.js';
import { snippetFor } from './facts/snippets.js';
import { extractTags, isHtml } from './html.js';
import { Client, Limiter, type Response } from './net/client.js';
import { Redactor } from './redact.js';
import { rule } from './rules.js';
import { bareHost, isAllowedHost, parseTarget, resolveTarget } from './target.js';
import { GROUPS, PRIORITIES, type AuditOptions, type Finding, type FrameworkId, type Passed, type Report } from './types.js';
import { REPO_URL, VERSION } from './version.js';

/** Default requests per second. */
export const DEFAULT_RATE = 10;
/** Default hard cap on requests per run. */
export const DEFAULT_MAX_REQUESTS = 300;
/** Default timeout per request. */
export const DEFAULT_TIMEOUT_MS = 10_000;
/** Most same-origin scripts read for library fingerprints. */
const MAX_SCRIPTS = 10;

/** Stable id for a finding: rule, URL path and key. Ports and hosts are left out so a baseline survives them. */
export function fingerprint(id: string, url: string, key = ''): string {
  let path = '/';
  try {
    path = new URL(url).pathname;
  } catch {
    // keep "/"
  }
  return createHash('sha256').update(`${id}|${path}|${key}`).digest('hex').slice(0, 16);
}

/** Turns a --path value into a path on the target (a same-host URL is accepted too). */
export function normalizePath(value: string, base: URL): string {
  const v = value.trim();
  if (!v) throw new PortAuditError('INVALID_TARGET', 'An empty --path was given.');
  let url: URL;
  try {
    url = new URL(v, base);
  } catch {
    throw new PortAuditError('INVALID_TARGET', `Not a valid path: ${value}`);
  }
  if (!v.startsWith('/') && !/^https?:\/\//i.test(v)) throw new PortAuditError('INVALID_TARGET', `--path must start with / (got ${value}).`);
  if (url.host !== base.host) throw new PortAuditError('REFUSED', `--path ${value} is on another host; only ${base.host} is in scope.`);
  return url.pathname + url.search;
}

/**
 * Audits a running app: point it at a port (`3000`) or a URL
 * (`http://localhost:3000/`). Passive only: GET, HEAD, OPTIONS and TRACE
 * reads, plus two TLS handshakes for https targets.
 *
 * Throws {@link PortAuditError}: `INVALID_TARGET`, `REFUSED` (outside the
 * allowed hosts) or `UNREACHABLE`.
 */
export async function auditPort(target: string | number, options: AuditOptions = {}): Promise<Report> {
  const started = Date.now();
  const rate = options.rate ?? DEFAULT_RATE;
  const cap = options.maxRequests ?? DEFAULT_MAX_REQUESTS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!(rate > 0 && rate <= 100)) throw new PortAuditError('INVALID_TARGET', 'rate must be between 0 and 100 requests per second.');
  if (!(Number.isInteger(cap) && cap >= 1)) throw new PortAuditError('INVALID_TARGET', 'maxRequests must be a whole number, 1 or more.');
  const progress = options.onProgress ?? (() => undefined);

  const url = parseTarget(target);
  const resolved = await resolveTarget(url, options.iOwnThis, options.lookup);
  const paths = (options.paths ?? []).map((p) => normalizePath(p, url));
  const extraHeaders = options.headers ?? {};
  const redactor = new Redactor(Object.values(extraHeaders));
  const limiter = new Limiter(rate, cap);
  const client = new Client({ host: resolved.host, addresses: resolved.addresses, limiter, timeoutMs, extraHeaders });
  const notes: string[] = [];
  const responses: Response[] = [];
  const record = (r: Response | null) => {
    if (r) responses.push(r);
    return r;
  };

  progress(`Reading ${url.href}`);
  let main: Response = await client.connect(url);
  responses.push(main);
  const location = main.headers.location;
  if ([301, 302, 303, 307, 308].includes(main.status) && location) {
    let next: URL | null = null;
    try {
      next = new URL(location, url);
    } catch {
      notes.push(`${main.url} redirects to an invalid location; it was not followed.`);
    }
    if (next && (bareHost(next.hostname) !== resolved.host || (next.protocol !== 'http:' && next.protocol !== 'https:'))) {
      notes.push(`${main.url} redirects to ${next.origin}, another host; it was not followed (only ${resolved.host} is in scope).`);
    } else if (next) {
      notes.push(`Followed redirect: ${main.status} ${main.url} -> ${next.href}`);
      const followed = await client.get(next);
      for (const hop of followed.hops) notes.push(`Followed redirect: ${hop}`);
      if (followed.offHost) notes.push(`The redirect chain leads to ${followed.offHost}, another host; it was not followed (only ${resolved.host} is in scope).`);
      if (followed.res) main = record(followed.res) as Response;
      else if (!followed.offHost) notes.push('Could not follow the redirect from the main page.');
    }
  }
  const base = new URL(main.url);
  const toPage = (res: Response): Page => {
    const html = isHtml(res.headers['content-type'], res.text);
    return { res, html, tags: html ? extractTags(res.text) : [] };
  };
  const pages: Page[] = [toPage(main)];

  const fetchPath = async (path: string, opts?: Parameters<Client['request']>[1]) => record(await client.probe(new URL(path, base), opts));
  for (const path of paths) {
    const res = await fetchPath(path);
    if (!res) notes.push(`--path ${path}: no response.`);
    else if (res.status >= 400) notes.push(`--path ${path} answered HTTP ${res.status}; its headers were still checked.`);
    if (res) pages.push(toPage(res));
  }

  let scriptCache: Promise<Script[]> | undefined;
  const loadScripts = async (): Promise<Script[]> => {
    const seen = new Map<string, Script>();
    for (const page of pages) {
      for (const t of page.tags) {
        if (t.name !== 'script' || !t.attrs.src) continue;
        let u: URL;
        try {
          u = new URL(t.attrs.src, page.res.url);
        } catch {
          continue;
        }
        if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
        const sameOrigin = u.hostname.replace(/^\[|\]$/g, '').toLowerCase() === resolved.host;
        if (!seen.has(u.href)) seen.set(u.href, { url: u.href, sameOrigin, body: null });
      }
    }
    let read = 0;
    for (const s of seen.values()) {
      if (!s.sameOrigin || read >= MAX_SCRIPTS) continue;
      read++;
      const res = await fetchPath(new URL(s.url).pathname + new URL(s.url).search, { maxBytes: 1_000_000 });
      if (res && res.status === 200) s.body = res.text;
    }
    return [...seen.values()];
  };

  const raw: RawFinding[] = [];
  const passed: Passed[] = [];
  const ctx: Ctx = {
    client,
    base,
    local: isAllowedHost(resolved.host),
    pages,
    paths,
    timeoutMs,
    address: () => client.currentAddress,
    responses,
    fetch: fetchPath,
    scripts: () => (scriptCache ??= loadScripts()),
    add: (f) => raw.push(f),
    pass: (id, title) => passed.push({ id, group: id.split('/')[0] as Passed['group'], title }),
    note: (m) => notes.push(m),
  };

  const steps: [string, (c: Ctx) => Promise<void>][] = [
    ['security headers', checkHeaders],
    ['CORS', checkCors],
    ['TLS', checkTls],
    ['HTTP methods', checkMethods],
    ['Subresource Integrity', checkSri],
    ['front-end libraries', checkLibraries],
    ['cookies', checkCookies],
    ['version headers', checkDisclosure],
  ];
  for (const [name, step] of steps) {
    progress(`Checking ${name}`);
    await step(ctx);
  }

  const frameworks = detectFrameworks(responses);
  const devServer = detectDevServer(responses);
  if (devServer) notes.push(`This looks like a development server (${devServer}). Dev servers skip production settings, so audit a production build too.`);
  const snippetIds: FrameworkId[] = options.framework
    ? [options.framework]
    : ([frameworks.find((f) => f.kind === 'app')?.id, frameworks.find((f) => f.kind === 'server')?.id].filter(Boolean) as FrameworkId[]);

  // Cookie values the app set are secrets too.
  for (const r of responses) for (const c of r.setCookies) redactor.add((c.split(';')[0] ?? '').split('=').slice(1).join('='));

  const baseline = new Set(options.baseline ?? []);
  let suppressed = 0;
  const findings: Finding[] = [];
  for (const f of raw) {
    const r = rule(f.id);
    const fp = fingerprint(f.id, f.url, f.key);
    if (baseline.has(fp)) {
      suppressed++;
      continue;
    }
    findings.push({
      id: r.id,
      group: r.group,
      priority: f.priority ?? r.priority,
      title: redactor.redact(f.title ?? r.title),
      url: f.url,
      evidence: redactor.redact(f.evidence),
      details: f.details?.map((d) => redactor.redact(d)),
      why: r.why,
      fix: r.fix,
      snippets: r.topic ? (snippetIds.map((id) => snippetFor(id, r.topic as never)).filter(Boolean) as Finding['snippets']) : [],
      mapping: r.mapping,
      sources: r.sources,
      fingerprint: fp,
    });
  }
  findings.sort((x, y) => PRIORITIES.indexOf(x.priority) - PRIORITIES.indexOf(y.priority) || GROUPS.indexOf(x.group) - GROUPS.indexOf(y.group));

  if (limiter.skipped) notes.push(`The request cap (${cap}) was reached; ${limiter.skipped} planned request(s) were skipped. Raise it with --max-requests.`);
  if (limiter.backoffs) notes.push(`The app answered 429 or 503 ${limiter.backoffs} time(s); the scan slowed down.`);
  for (const [message, count] of client.errors) notes.push(`${count} request(s) failed: ${redactor.redact(message)}`);
  if (resolved.owned) notes.push(`${resolved.host} is outside the default ranges and was scanned because --i-own-this named it.`);

  return {
    tool: { name: 'port-audit', version: VERSION, url: REPO_URL },
    target: url.href,
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    requests: { sent: limiter.sent, cap, skipped: limiter.skipped, backoffs: limiter.backoffs },
    frameworks,
    devServer,
    findings,
    passed,
    notes: notes.map((n) => redactor.redact(n)),
    coverage: [...COVERAGE],
    suppressed,
  };
}
