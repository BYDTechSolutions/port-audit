import { afterEach, describe, expect, it } from 'vitest';
import { main, type CliIo } from '../src/cli-main.js';
import { expressNoHelmet, permissiveCors, serve, wellConfigured, type Fixture } from './servers.js';

let fixture: Fixture | undefined;
afterEach(async () => {
  await fixture?.close();
  fixture = undefined;
});

function io(extra: Partial<CliIo> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const files = new Map<string, string>();
  const value: CliIo = {
    stdout: (t) => out.push(t),
    stderr: (t) => err.push(t),
    env: {},
    stdoutIsTTY: false,
    stderrIsTTY: false,
    writeFile: async (p, d) => void files.set(p, d),
    readFile: async (p) => files.get(p) ?? '',
    ...extra,
  };
  return { value, out: () => out.join(''), err: () => err.join(''), files };
}

describe('cli', () => {
  it('--port audits localhost and exits 0', async () => {
    fixture = await serve(wellConfigured);
    const t = io();
    expect(await main(['--port', String(fixture.port), '--rate', '50'], t.value)).toBe(0);
    expect(t.out()).toContain(`Port audit: http://localhost:${fixture.port}/`);
  });

  it('--fail-on exits 1 when the threshold is met', async () => {
    fixture = await serve(permissiveCors);
    const t = io();
    expect(await main([fixture.url, '--fail-on', 'fix-now', '--rate', '50'], t.value)).toBe(1);
    expect(t.err()).toMatch(/finding\(s\) at --fail-on fix-now/);
  });

  it('refuses a public host with exit 2 and a clear message', async () => {
    const t = io();
    expect(await main(['https://example.com'], t.value)).toBe(2);
    expect(t.err()).toMatch(/Refusing to scan example\.com.*--i-own-this example\.com/s);
  });

  it('prints the ownership reminder with --i-own-this', async () => {
    fixture = await serve(wellConfigured);
    const t = io({ auditOptions: { lookup: async () => [{ address: '127.0.0.1', family: 4 }] } });
    expect(await main([`http://mine.example.org:${fixture.port}/`, '--i-own-this', 'mine.example.org', '--rate', '50'], t.value)).toBe(0);
    expect(t.err()).toMatch(/Only scan systems you own/);
  });

  it('writes formats by extension, and a baseline from that file hides the findings', async () => {
    fixture = await serve(expressNoHelmet);
    const t = io();
    expect(await main([fixture.url, '--out', 'base.json', '--rate', '50'], t.value)).toBe(0);
    const path = [...t.files.keys()][0] as string;
    expect(JSON.parse(t.files.get(path) as string).findings.length).toBeGreaterThan(3);
    const t2 = io({ readFile: async () => t.files.get(path) as string });
    expect(await main([fixture.url, '--baseline', 'base.json', '--fail-on', 'should-fix', '--rate', '50'], t2.value)).toBe(0);
    expect(t2.out()).toMatch(/Nothing to report outside the baseline \(\d+ hidden\)/);
  });

  it('--format sarif and junit', async () => {
    fixture = await serve(expressNoHelmet);
    const s = io();
    await main([fixture.url, '-f', 'sarif', '--rate', '50'], s.value);
    expect(JSON.parse(s.out()).version).toBe('2.1.0');
    const j = io();
    await main([fixture.url, '-f', 'junit', '--rate', '50'], j.value);
    expect(j.out()).toMatch(/^<\?xml/);
  });

  it('redacts --header values in the output', async () => {
    fixture = await serve(expressNoHelmet);
    const t = io();
    await main([fixture.url, '--header', 'Cookie: session=cli-secret-value-42', '-f', 'json', '--rate', '50'], t.value);
    expect(fixture.hits[0]?.headers.cookie).toBe('session=cli-secret-value-42');
    expect(t.out()).not.toContain('cli-secret-value-42');
  });

  it('usage errors exit 2', async () => {
    for (const args of [[], ['--port', 'abc'], ['--port', '3000', 'http://localhost:3000'], ['3000', '--format', 'xml'], ['3000', '--fail-on', 'all'], ['3000', '--header', 'nocolon'], ['3000', '--rate', '0'], ['3000', '--framework', 'cobol'], ['3000', '--bogus']]) {
      const t = io();
      expect(await main(args, t.value), args.join(' ')).toBe(2);
      expect(t.err()).toMatch(/port-audit: /);
    }
  });

  it('--list-checks, --help and --version', async () => {
    const t = io();
    expect(await main(['--list-checks'], t.value)).toBe(0);
    expect(t.out()).toContain('cors/reflected-credentials');
    expect(t.out()).toContain('A02:2025 · API8:2023 · ASVS 3.4.2 · CWE-942');
    expect(t.out()).toContain('Not checked in this release');
    const h = io();
    expect(await main(['--help'], h.value)).toBe(0);
    expect(h.out()).toContain('Usage: port-audit');
    const v = io();
    expect(await main(['-v'], v.value)).toBe(0);
    expect(v.out()).toMatch(/^\d+\.\d+\.\d+\n$/);
  });
});
