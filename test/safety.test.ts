import { afterEach, describe, expect, it } from 'vitest';
import { auditPort, formatReport, FORMATS, PortAuditError } from '../src/index.js';
import { Limiter } from '../src/net/client.js';
import { serve, traceEnabled, wellConfigured, type Fixture } from './servers.js';

const open: Fixture[] = [];
afterEach(async () => {
  await Promise.all(open.splice(0).map((f) => f.close()));
});
const start = async (handler: Parameters<typeof serve>[0]) => {
  const f = await serve(handler);
  open.push(f);
  return f;
};
const noLookup = async (): Promise<never> => {
  throw new Error('DNS must not be queried');
};

describe('allowed targets', () => {
  it('refuses a public host without --i-own-this, before any DNS lookup or request', async () => {
    const err = await auditPort('https://example.com/', { lookup: noLookup }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PortAuditError);
    expect((err as PortAuditError).code).toBe('REFUSED');
    expect((err as PortAuditError).message).toMatch(/--i-own-this example\.com/);
  });

  it('refuses public IP literals and addresses outside RFC 1918', async () => {
    for (const t of ['http://8.8.8.8/', 'http://172.32.0.1/', 'http://169.254.169.254/', 'http://[2001:db8::1]/', 'http://0.0.0.0:3000/']) {
      await expect(auditPort(t, { lookup: noLookup })).rejects.toMatchObject({ code: 'REFUSED' });
    }
  });

  it('refuses an allowed name that resolves to a public address', async () => {
    const lookup = async () => [{ address: '93.184.215.14', family: 4 }];
    await expect(auditPort('http://shop.test/', { lookup })).rejects.toMatchObject({ code: 'REFUSED', message: expect.stringMatching(/resolves to 93\.184\.215\.14/) });
  });

  it('--i-own-this must name exactly the target host', async () => {
    const lookup = async () => [{ address: '127.0.0.1', family: 4 }];
    await expect(auditPort('http://app.example.org/', { iOwnThis: 'example.org', lookup })).rejects.toMatchObject({ code: 'REFUSED' });
    await expect(auditPort('http://app.example.org/', { iOwnThis: 'other.example.org', lookup })).rejects.toMatchObject({ code: 'REFUSED' });
  });

  it('--i-own-this lets that one host through, and the report says so', async () => {
    const f = await start(wellConfigured);
    const lookup = async () => [{ address: '127.0.0.1', family: 4 }];
    const r = await auditPort(`http://staging.example.org:${f.port}/`, { iOwnThis: 'staging.example.org', lookup, rate: 100 });
    expect(r.notes.join(' ')).toMatch(/--i-own-this/);
    expect(f.hits[0]?.headers.host).toBe(`staging.example.org:${f.port}`);
  });

  it('says clearly when nothing is listening', async () => {
    const f = await start(wellConfigured);
    await f.close();
    open.length = 0;
    await expect(auditPort(f.url)).rejects.toMatchObject({ code: 'UNREACHABLE', message: expect.stringMatching(/Nothing is listening/) });
  });
});

describe('redirects', () => {
  it('follows a redirect on the same host', async () => {
    const f = await start((req, res) => {
      if (req.url === '/') {
        res.writeHead(302, { Location: '/home' });
        res.end();
        return;
      }
      wellConfigured(req, res);
    });
    const r = await auditPort(f.url, { rate: 100 });
    expect(f.hits.some((h) => h.url === '/home')).toBe(true);
    expect(r.findings).toEqual([]);
  });

  it('never follows a redirect to another host', async () => {
    const other = await start(wellConfigured);
    const f = await start((req, res) => {
      res.writeHead(302, { Location: `http://localhost:${other.port}/` });
      res.end();
    });
    const r = await auditPort(f.url, { rate: 100 });
    expect(other.hits).toHaveLength(0);
    expect(r.notes.join(' ')).toMatch(/redirects to http:\/\/localhost:\d+, another host; it was not followed/);
  });

  it('refuses a --path on another host', async () => {
    const f = await start(wellConfigured);
    await expect(auditPort(f.url, { paths: ['http://example.com/x'] })).rejects.toMatchObject({ code: 'REFUSED' });
  });
});

describe('politeness', () => {
  it('spaces requests to the rate (fake clock)', async () => {
    let now = 0;
    const waits: number[] = [];
    const limiter = new Limiter(10, 100, () => now, async (ms) => {
      waits.push(ms);
      now += ms;
    });
    for (let i = 0; i < 5; i++) await limiter.acquire();
    expect(waits).toEqual([100, 100, 100, 100]);
    limiter.backoff(3);
    await limiter.acquire();
    expect(waits.at(-1)).toBe(3000);
  });

  it('never exceeds the rate against a real server', async () => {
    const f = await start(wellConfigured);
    await auditPort(f.url, { rate: 20 });
    const gaps = f.hits.slice(1).map((h, i) => h.at - (f.hits[i] as { at: number }).at);
    expect(f.hits.length).toBeGreaterThan(4);
    // Sends are spaced exactly (see the fake-clock test); arrival times jitter a little in one process.
    const average = ((f.hits.at(-1) as { at: number }).at - (f.hits[0] as { at: number }).at) / gaps.length;
    expect(average).toBeGreaterThanOrEqual(45);
    expect(Math.min(...gaps)).toBeGreaterThanOrEqual(20);
  });

  it('stops at the request cap and says so', async () => {
    const f = await start(traceEnabled);
    const r = await auditPort(f.url, { rate: 100, maxRequests: 3 });
    expect(f.hits.length).toBeLessThanOrEqual(3);
    expect(r.requests.sent).toBe(3);
    expect(r.requests.skipped).toBeGreaterThan(0);
    expect(r.notes.join(' ')).toMatch(/request cap \(3\)/);
  });

  it('backs off on 429', async () => {
    const f = await start((req, res) => {
      if (req.method === 'OPTIONS') {
        res.writeHead(429, { 'Retry-After': '0' });
        res.end();
        return;
      }
      wellConfigured(req, res);
    });
    const r = await auditPort(f.url, { rate: 100 });
    expect(r.requests.backoffs).toBe(1);
    expect(r.notes.join(' ')).toMatch(/429 or 503/);
  });

  it('sends only passive methods', async () => {
    const f = await start(traceEnabled);
    await auditPort(f.url, { rate: 100, paths: ['/a', '/b'] });
    expect(new Set(f.hits.map((h) => h.method))).toEqual(new Set(['GET', 'OPTIONS', 'TRACE']));
  });
});

describe('redaction', () => {
  it('never prints --header values or cookie values the app set, in any format', async () => {
    const secret = 'hunter2-very-secret-session';
    const f = await start((req, res) => {
      if (req.method === 'GET') res.setHeader('Set-Cookie', 'sid=app-issued-cookie-value-123; Path=/');
      traceEnabled(req, res);
    });
    const r = await auditPort(f.url, { rate: 100, headers: { Cookie: `session=${secret}`, 'X-Api-Key': 'key-0123456789abcdef' } });
    // The secret was sent, and the TRACE echo carried it back.
    expect(f.hits.every((h) => String(h.headers.cookie).includes(secret))).toBe(true);
    expect(r.findings.some((x) => x.id === 'methods/trace')).toBe(true);
    for (const format of FORMATS) {
      const out = formatReport(r, format);
      expect(out).not.toContain(secret);
      expect(out).not.toContain('key-0123456789abcdef');
      expect(out).not.toContain('app-issued-cookie-value-123');
    }
  });
});
