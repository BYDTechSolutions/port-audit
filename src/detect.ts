/*
 * Framework detection from what any client can see: headers, cookie names,
 * and the shape of default error pages. Every detection carries the evidence
 * it rests on, because a guess shown without its reasons is worse than none.
 */
import type { Response } from './net/client.js';
import type { Detection, FrameworkId } from './types.js';

const NAMES: Record<FrameworkId, string> = {
  express: 'Express', nextjs: 'Next.js', nestjs: 'NestJS', django: 'Django', flask: 'Flask', fastapi: 'FastAPI',
  rails: 'Rails', laravel: 'Laravel', spring: 'Spring Boot', aspnet: 'ASP.NET', nginx: 'nginx', apache: 'Apache httpd',
};

/** Display name of a framework. */
export const frameworkName = (id: FrameworkId): string => NAMES[id];

type Signal = [FrameworkId, (r: Response, cookies: string[]) => string | null];

/** `x-powered-by` → `X-Powered-By`, for evidence lines. */
export const headerCase = (name: string): string => name.split('-').map((w) => (w ? w[0]!.toUpperCase() + w.slice(1) : w)).join('-');

const header = (name: string, re: RegExp, label?: string) => (r: Response) => {
  const v = r.headers[name];
  return v && re.test(v) ? label ?? `${headerCase(name)}: ${v}` : null;
};
const cookie = (re: RegExp, label: string) => (_r: Response, names: string[]) => (names.some((n) => re.test(n)) ? label : null);
const body = (re: RegExp, label: string) => (r: Response) => (re.test(r.text.slice(0, 200_000)) ? label : null);

const SIGNALS: Signal[] = [
  ['express', header('x-powered-by', /^express$/i)],
  ['express', cookie(/^connect\.sid$/, 'connect.sid cookie (express-session)')],
  ['express', (r) => (r.status === 404 && /<pre>Cannot (GET|HEAD) /.test(r.text) ? 'Express default 404 page ("Cannot GET ...")' : null)],
  ['nestjs', (r) => (r.status === 404 && /"statusCode"\s*:\s*404/.test(r.text) && /Cannot (GET|HEAD) /.test(r.text) ? 'NestJS default 404 JSON ({"message":"Cannot GET ...","statusCode":404})' : null)],
  ['nextjs', header('x-powered-by', /next\.js/i)],
  ['nextjs', (r) => {
    const k = Object.keys(r.headers).find((h) => h.startsWith('x-nextjs-'));
    return k ? `${headerCase(k)} header` : null;
  }],
  ['nextjs', body(/id="__NEXT_DATA__"|\/_next\/static\//, '/_next/static/ assets or __NEXT_DATA__ in the HTML')],
  ['django', cookie(/^(csrftoken|sessionid)$/, 'csrftoken or sessionid cookie')],
  ['django', body(/name="csrfmiddlewaretoken"/, 'csrfmiddlewaretoken form field')],
  ['flask', header('server', /werkzeug\//i)],
  ['flask', body(/The requested URL was not found on the server\. If you entered the URL manually please check your spelling and try again\./, 'Werkzeug default 404 page')],
  ['fastapi', (r) => (r.status === 404 && /^\s*\{"detail"\s*:\s*"Not Found"\}\s*$/.test(r.text) ? 'FastAPI/Starlette default 404 JSON ({"detail":"Not Found"})' : null)],
  ['fastapi', header('server', /^uvicorn/i)],
  ['rails', (r) => (r.headers['x-runtime'] && r.headers['x-request-id'] ? 'X-Runtime and X-Request-Id headers' : null)],
  ['rails', cookie(/^_[a-z0-9_]+_session$/i, '_<app>_session cookie')],
  ['rails', body(/name="csrf-param" content="authenticity_token"/, 'authenticity_token csrf-param meta tag')],
  ['laravel', cookie(/^laravel_session$/, 'laravel_session cookie')],
  ['spring', body(/Whitelabel Error Page/, 'Spring Boot "Whitelabel Error Page"')],
  ['spring', (r) => (/^\s*\{"timestamp"\s*:[^}]*"status"\s*:\s*\d+\s*,\s*"error"\s*:/.test(r.text) ? 'Spring Boot default error JSON (timestamp, status, error, path)' : null)],
  ['spring', body(/"_links"\s*:\s*\{\s*"self"\s*:\s*\{\s*"href"\s*:\s*"[^"]*\/actuator"/, 'Spring Boot Actuator index')],
  ['spring', cookie(/^JSESSIONID$/, 'JSESSIONID cookie (Java servlet container)')],
  ['aspnet', header('x-powered-by', /asp\.net/i)],
  ['aspnet', header('x-aspnet-version', /./)],
  ['aspnet', header('server', /^kestrel/i)],
  ['aspnet', cookie(/^(\.AspNetCore\.|ASP\.NET_SessionId$)/, '.AspNetCore.* or ASP.NET_SessionId cookie')],
  ['nginx', header('server', /^nginx/i)],
  ['nginx', body(/<center>nginx(\/[\d.]+)?<\/center>/, 'nginx default error page')],
  ['apache', header('server', /^apache/i)],
  ['apache', body(/<address>Apache(\/[\d.]+)?[^<]* Server at /, 'Apache default error page')],
];

/** Cookie names a response set. */
export function cookieNames(r: Response): string[] {
  return r.setCookies.map((c) => (c.split(';')[0] ?? '').split('=')[0]?.trim() ?? '').filter(Boolean);
}

/** Frameworks and servers the responses point to, app frameworks first. */
export function detectFrameworks(responses: Response[]): Detection[] {
  const found = new Map<FrameworkId, Set<string>>();
  for (const r of responses) {
    const names = cookieNames(r);
    for (const [id, test] of SIGNALS) {
      const ev = test(r, names);
      if (ev) found.set(id, (found.get(id) ?? new Set()).add(ev));
    }
  }
  // NestJS runs on Express by default: report NestJS, with Express's evidence folded in.
  if (found.has('nestjs') && found.has('express')) {
    for (const ev of found.get('express') as Set<string>) (found.get('nestjs') as Set<string>).add(ev);
    found.delete('express');
  }
  // JSESSIONID alone says "Java", not "Spring": keep Spring only with another signal.
  const spring = found.get('spring');
  if (spring && spring.size === 1 && [...spring][0]?.startsWith('JSESSIONID')) found.delete('spring');
  const out: Detection[] = [...found].map(([id, ev]) => ({ id, name: NAMES[id], kind: id === 'nginx' || id === 'apache' ? 'server' : 'app', evidence: [...ev] }));
  return out.sort((x, y) => (x.kind === y.kind ? y.evidence.length - x.evidence.length : x.kind === 'app' ? -1 : 1));
}

/** Evidence that the responses come from a development server, or `null`. */
export function detectDevServer(responses: Response[]): string | null {
  for (const r of responses) {
    const t = r.text.slice(0, 200_000);
    if (/\/@vite\/client/.test(t)) return 'Vite dev server (/@vite/client in the HTML)';
    if (/"buildId"\s*:\s*"development"|\/_next\/static\/development\/|\/_next\/webpack-hmr|\/_next\/static\/chunks\/[\w-]+\.js\?v=\d+/.test(t)) return 'next dev (development build assets in the HTML)';
    if (/webpack-dev-server|sockjs-node/.test(t)) return 'webpack dev server';
    const server = r.headers.server ?? '';
    if (/WSGIServer\/[\d.]+ CPython/.test(server)) return `Python development server (Server: ${server}, e.g. Django runserver)`;
    if (/^Werkzeug\//.test(server)) return `Werkzeug development server (Server: ${server})`;
  }
  return null;
}
