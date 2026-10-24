/*
 * TLS against real handshakes. The certificate is generated per run with the
 * openssl CLI (no key is committed); the tests skip when openssl is missing.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { checkTls } from '../src/checks/tls.js';
import type { Ctx, RawFinding } from '../src/context.js';
import { auditPort } from '../src/index.js';
import { Limiter } from '../src/net/client.js';

let dir = '';
let key = '';
let cert = '';
let hasOpenssl = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  hasOpenssl = false;
}

beforeAll(() => {
  if (!hasOpenssl) return;
  dir = mkdtempSync(join(tmpdir(), 'port-audit-tls-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-days', '3', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  key = readFileSync(join(dir, 'key.pem'), 'utf8');
  cert = readFileSync(join(dir, 'cert.pem'), 'utf8');
});
afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

async function httpsServer(legacy: boolean): Promise<{ server: Server; port: number }> {
  const server = createServer({ key, cert, ...(legacy ? { minVersion: 'TLSv1' as const, ciphers: 'DEFAULT@SECLEVEL=0' } : {}) }, (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain', 'X-Content-Type-Options': 'nosniff', 'Strict-Transport-Security': 'max-age=600' });
    res.end('ok');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { server, port: (server.address() as AddressInfo).port };
}

describe.skipIf(!hasOpenssl)('TLS', () => {
  it('reads the certificate: expiring soon, self-signed noted (local), short HSTS', async () => {
    const { server, port } = await httpsServer(false);
    try {
      const r = await auditPort(`https://localhost:${port}/`, { rate: 100 });
      const ids = r.findings.map((f) => f.id);
      expect(ids).toContain('tls/cert-expiring');
      expect(ids).toContain('headers/hsts-short');
      expect(ids).not.toContain('tls/hostname-mismatch');
      expect(ids).not.toContain('tls/legacy-protocol');
      expect(r.notes.join(' ')).toMatch(/not trusted by Node/);
      expect(r.passed.map((p) => p.title).join(' ')).toMatch(/Negotiated TLSv1\.[23]/);
    } finally {
      server.close();
    }
  });

  it('flags a server that still accepts TLS 1.0/1.1', async () => {
    const { server, port } = await httpsServer(true);
    try {
      const r = await auditPort(`https://127.0.0.1:${port}/`, { rate: 100 });
      const legacy = r.findings.find((f) => f.id === 'tls/legacy-protocol');
      expect(legacy?.evidence).toMatch(/TLSv1(\.1)?/);
      expect(legacy?.mapping.asvs).toEqual(['12.1.1']);
    } finally {
      server.close();
    }
  });

  it('flags an expired certificate (clock moved forward)', async () => {
    const { server, port } = await httpsServer(false);
    try {
      const found: RawFinding[] = [];
      const ctx = {
        client: { limiter: new Limiter(100, 10) },
        base: new URL(`https://localhost:${port}/`),
        local: false,
        timeoutMs: 5000,
        address: () => '127.0.0.1',
        add: (f: RawFinding) => found.push(f),
        pass: () => undefined,
        note: () => undefined,
      } as unknown as Ctx;
      await checkTls(ctx, Date.now() + 10 * 86_400_000);
      const expired = found.find((f) => f.id === 'tls/cert-expired');
      expect(expired).toBeDefined();
      expect(expired?.priority).toBeUndefined(); // fix-now outside your machine
      expect(found.map((f) => f.id)).toContain('tls/untrusted');
    } finally {
      server.close();
    }
  });
});
