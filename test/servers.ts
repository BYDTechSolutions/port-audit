/*
 * Fixture apps on 127.0.0.1, built on node:http. Each imitates one kind of
 * app from the outside: its headers, cookies and pages. They record every
 * request so tests can prove what the scanner did and did not send.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface Hit {
  method: string;
  url: string;
  headers: IncomingMessage['headers'];
  at: number;
}

export interface Fixture {
  url: string;
  port: number;
  hits: Hit[];
  close: () => Promise<void>;
}

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

/** Starts a fixture server on a free port. */
export async function serve(handler: Handler): Promise<Fixture> {
  const hits: Hit[] = [];
  const server = createServer((req, res) => {
    hits.push({ method: req.method ?? '', url: req.url ?? '', headers: req.headers, at: Date.now() });
    handler(req, res);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/`,
    port,
    hits,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

const html = (head: string, body = '<h1>App</h1>') => `<!doctype html><html><head><title>App</title>${head}</head><body>${body}</body></html>`;

/** Answers OPTIONS with an Allow list and TRACE with 405, like most routed frameworks. */
function methods(req: IncomingMessage, res: ServerResponse, allow = 'GET, HEAD, OPTIONS'): boolean {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { Allow: allow });
    res.end();
    return true;
  }
  if (req.method === 'TRACE') {
    res.writeHead(405, { Allow: allow });
    res.end();
    return true;
  }
  return false;
}

/** Express without helmet: no security headers, X-Powered-By, express-session cookie without HttpOnly. */
export const expressNoHelmet: Handler = (req, res) => {
  res.setHeader('X-Powered-By', 'Express');
  if (req.method === 'TRACE' || req.method === 'OPTIONS') {
    res.writeHead(404, { 'Content-Type': 'text/html' });
    res.end(`<pre>Cannot ${req.method} ${req.url}</pre>`);
    return;
  }
  res.setHeader('Set-Cookie', 'connect.sid=s%3Aexpress-fixture-session.sig; Path=/');
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html(''));
};

/** Next.js-like: X-Powered-By: Next.js, /_next/static assets, a CSP that allows unsafe-inline scripts. */
export const nextLike: Handler = (req, res) => {
  if (methods(req, res)) return;
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'X-Powered-By': 'Next.js',
    'x-nextjs-cache': 'HIT',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
  });
  res.end(html('<script src="/_next/static/chunks/main-abc123.js" defer></script>'));
};

/** CORS that reflects any Origin with credentials, and allows null. */
export const permissiveCors: Handler = (req, res) => {
  if (methods(req, res)) return;
  const origin = req.headers.origin;
  const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff' };
  if (origin) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Credentials'] = 'true';
  }
  res.writeHead(200, headers);
  res.end('{"ok":true}');
};

/** Apache-like: TRACE echoes the request, OPTIONS lists WebDAV methods, Server shows a version. */
export const traceEnabled: Handler = (req, res) => {
  res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
  if (req.method === 'TRACE') {
    const lines = [`TRACE ${req.url} HTTP/1.1`, ...Object.entries(req.headers).map(([k, v]) => `${k}: ${String(v)}`)];
    res.writeHead(200, { 'Content-Type': 'message/http' });
    res.end(`${lines.join('\r\n')}\r\n\r\n`);
    return;
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(200, { Allow: 'GET,HEAD,POST,OPTIONS,TRACE,PROPFIND,MKCOL' });
    res.end();
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain', 'X-Content-Type-Options': 'nosniff' });
  res.end('It works');
};

/** Old jQuery from a CDN without SRI, plus a bundled lodash and AngularJS served from the app itself. */
export const oldLibraries: Handler = (req, res) => {
  if (methods(req, res)) return;
  if (req.url === '/js/vendor.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript' });
    res.end('/** @license Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE */\n;(function(){var VERSION="4.17.15";})();');
    return;
  }
  if (req.url === '/js/angular.min.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript' });
    res.end('/*\n AngularJS v1.5.8\n (c) 2010-2016 Google, Inc. http://angularjs.org\n License: MIT\n*/\n(function(){})();');
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(html([
    '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>',
    '<script src="https://cdn.example.net/widget.js"></script>',
    '<script src="https://cdn.jsdelivr.net/npm/dompurify@3.2.6/dist/purify.min.js" integrity="sha384-abc" crossorigin="anonymous"></script>',
    '<script src="/js/vendor.js"></script>',
    '<script src="/js/angular.min.js"></script>',
    '<!-- <script src="https://code.jquery.com/jquery-1.4.2.min.js"></script> -->',
  ].join('')));
};

/** Django runserver-like: csrftoken cookie, WSGIServer Server header. */
export const djangoLike: Handler = (req, res) => {
  if (methods(req, res, 'GET, HEAD, OPTIONS')) return;
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    Server: 'WSGIServer/0.2 CPython/3.12.4',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Set-Cookie': 'csrftoken=Zm9vYmFyYmF6cXV4cXV1eA; Path=/; SameSite=Lax',
  });
  res.end(html('', '<form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="x"></form>'));
};

/** ASP.NET-like: version headers and a session cookie. */
export const aspnetLike: Handler = (req, res) => {
  if (methods(req, res)) return;
  res.writeHead(200, {
    'Content-Type': 'text/html',
    'X-Powered-By': 'ASP.NET',
    'X-AspNet-Version': '4.0.30319',
    Server: 'Microsoft-IIS/10.0',
    'Set-Cookie': 'ASP.NET_SessionId=aspnetfixturesession; path=/; HttpOnly; SameSite=Lax',
  });
  res.end(html(''));
};

/** A well-configured app: every header, a strict CSP, a __Host- session cookie, TRACE refused. */
export const wellConfigured: Handler = (req, res) => {
  if (methods(req, res)) return;
  if (req.url === '/app.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript', 'X-Content-Type-Options': 'nosniff' });
    res.end('console.log("hello");');
    return;
  }
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Set-Cookie': '__Host-session=wellconfiguredsession; Path=/; Secure; HttpOnly; SameSite=Lax',
  });
  res.end(html('<script src="/app.js" defer></script>'));
};
