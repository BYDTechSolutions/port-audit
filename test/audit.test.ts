import { afterEach, describe, expect, it } from 'vitest';
import { auditPort, type Report } from '../src/index.js';
import { aspnetLike, djangoLike, expressNoHelmet, nextLike, oldLibraries, permissiveCors, serve, traceEnabled, wellConfigured, type Fixture } from './servers.js';

let fixture: Fixture | undefined;
afterEach(async () => {
  await fixture?.close();
  fixture = undefined;
});

const ids = (r: Report) => r.findings.map((f) => f.id);
const run = async (handler: Parameters<typeof serve>[0], options = {}) => {
  fixture = await serve(handler);
  return auditPort(fixture.url, { rate: 100, ...options });
};

describe('fixture apps', () => {
  it('Express without helmet: headers, cookie, X-Powered-By, and the Express snippet', async () => {
    const r = await run(expressNoHelmet);
    expect(r.frameworks[0]?.id).toBe('express');
    expect(r.frameworks[0]?.evidence.join(' ')).toMatch(/X-Powered-By: Express/i);
    expect(ids(r)).toEqual(expect.arrayContaining(['headers/csp-missing', 'headers/clickjacking', 'headers/nosniff', 'cookies/no-httponly', 'disclosure/version-header']));
    const csp = r.findings.find((f) => f.id === 'headers/csp-missing');
    expect(csp?.snippets[0]?.framework).toBe('express');
    expect(csp?.snippets[0]?.code).toContain('helmet');
    expect(csp?.mapping.top10).toEqual(['A02:2025']);
    expect(csp?.mapping.asvs).toEqual(['3.4.3']);
    expect(ids(r)).not.toContain('methods/trace');
  });

  it('Next.js-like: detects Next.js and flags the unsafe-inline CSP', async () => {
    const r = await run(nextLike);
    expect(r.frameworks.map((f) => f.id)).toContain('nextjs');
    const weak = r.findings.find((f) => f.id === 'headers/csp-weak');
    expect(weak?.evidence).toMatch(/unsafe-inline/);
    expect(weak?.snippets[0]?.framework).toBe('nextjs');
    expect(ids(r)).not.toContain('headers/clickjacking');
  });

  it('permissive CORS: reflected origin with credentials and null origin are fix now', async () => {
    const r = await run(permissiveCors);
    const reflected = r.findings.find((f) => f.id === 'cors/reflected-credentials');
    expect(reflected?.priority).toBe('fix-now');
    expect(reflected?.evidence).toContain('Access-Control-Allow-Credentials: true');
    expect(r.findings.find((f) => f.id === 'cors/null-origin')?.priority).toBe('fix-now');
    expect(fixture?.hits.some((h) => h.headers.origin === 'https://port-audit-origin.invalid')).toBe(true);
  });

  it('TRACE enabled and WebDAV methods advertised', async () => {
    const r = await run(traceEnabled);
    expect(ids(r)).toEqual(expect.arrayContaining(['methods/trace', 'methods/webdav', 'disclosure/version-header']));
    expect(r.frameworks.map((f) => f.id)).toContain('apache');
    const trace = r.findings.find((f) => f.id === 'methods/trace');
    expect(trace?.snippets.map((s) => s.framework)).toContain('apache');
    expect(trace?.mapping.asvs).toEqual(['13.4.4']);
  });

  it('old jQuery without SRI, bundled lodash and end-of-life AngularJS', async () => {
    const r = await run(oldLibraries);
    const sri = r.findings.find((f) => f.id === 'sri/missing-script');
    expect(sri?.details?.join('\n')).toContain('jquery-1.12.4.min.js');
    expect(sri?.details?.join('\n')).toContain('widget.js (not versioned');
    expect(sri?.details?.join('\n')).not.toContain('dompurify');
    const titles = r.findings.filter((f) => f.id === 'libraries/vulnerable').map((f) => f.title);
    expect(titles).toEqual(expect.arrayContaining([expect.stringMatching(/^jQuery 1\.12\.4 has \d+ known/), expect.stringMatching(/^Lodash 4\.17\.15 has/), expect.stringMatching(/^AngularJS 1\.5\.8 has/)]));
    expect(titles.join(' ')).not.toContain('1.4.2'); // commented out in the HTML
    expect(ids(r)).toContain('libraries/eol');
    // Third-party scripts are never fetched.
    expect(fixture?.hits.every((h) => !h.url.includes('jquery'))).toBe(true);
  });

  it('Django runserver-like: detection evidence and a development-server note', async () => {
    const r = await run(djangoLike);
    const django = r.frameworks.find((f) => f.id === 'django');
    expect(django?.evidence.join(' ')).toMatch(/csrftoken/);
    expect(r.devServer).toMatch(/WSGIServer/);
    expect(r.notes.join(' ')).toMatch(/development server/);
    expect(ids(r)).not.toContain('cookies/no-httponly'); // CSRF cookies may be read by JavaScript
  });

  it('ASP.NET-like: version headers', async () => {
    const r = await run(aspnetLike);
    expect(r.frameworks[0]?.id).toBe('aspnet');
    const d = r.findings.find((f) => f.id === 'disclosure/version-header');
    expect(d?.evidence).toMatch(/x-aspnet-version: 4\.0\.30319/);
    expect(d?.snippets[0]?.code).toContain('AddServerHeader');
  });

  it('a well-configured app gets no findings (low noise)', async () => {
    const r = await run(wellConfigured);
    expect(r.findings).toEqual([]);
    expect(r.passed.length).toBeGreaterThan(5);
    expect(r.coverage.find((c) => c.id === 'A01:2025')?.status).toBe('not-assessed');
  });

  it('extra --path pages are read and their header problems listed under one finding', async () => {
    fixture = await serve((req, res) => {
      if (req.url === '/admin') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!doctype html><html><head></head><body>admin</body></html>');
        return;
      }
      wellConfigured(req, res);
    });
    const r = await auditPort(fixture.url, { rate: 100, paths: ['/admin'] });
    const csp = r.findings.find((f) => f.id === 'headers/csp-missing');
    expect(csp?.url).toMatch(/\/admin$/);
    expect(fixture.hits.some((h) => h.url === '/admin')).toBe(true);
  });

  it('--framework overrides the detected snippets', async () => {
    const r = await run(expressNoHelmet, { framework: 'django' });
    expect(r.findings.find((f) => f.id === 'headers/csp-missing')?.snippets[0]?.framework).toBe('django');
  });

  it('a baseline hides known findings', async () => {
    const first = await run(expressNoHelmet);
    await fixture?.close();
    const second = await run(expressNoHelmet, { baseline: first.findings.map((f) => f.fingerprint) });
    expect(second.findings).toEqual([]);
    expect(second.suppressed).toBe(first.findings.length);
  });
});
