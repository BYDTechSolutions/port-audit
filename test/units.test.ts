import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { cspWeaknesses } from '../src/checks/headers.js';
import { parseSetCookie } from '../src/checks/cookies.js';
import { fromBody, fromUrl } from '../src/checks/libraries.js';
import { looksVersioned } from '../src/checks/sri.js';
import { parseHeader } from '../src/cli-main.js';
import { inRanges } from '../src/facts/advisories.js';
import { extractTags } from '../src/html.js';
import { advisoriesFor, COVERAGE, FRAMEWORKS, isAllowedAddress, isAllowedHost, LIBRARIES, parseTarget, readBaseline, RULE_LIST, SNIPPETS, VERSION } from '../src/index.js';
import { envKeys, Redactor } from '../src/redact.js';

describe('allowed hosts', () => {
  it('allows only loopback, RFC 1918, *.localhost and *.test', () => {
    for (const h of ['localhost', 'app.localhost', 'shop.test', '127.0.0.1', '127.8.9.10', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.20', '::1', '[::1]', '::ffff:127.0.0.1', '0:0:0:0:0:0:0:1']) {
      expect(isAllowedHost(h), h).toBe(true);
    }
    for (const h of ['example.com', 'localhost.example.com', 'test', '8.8.8.8', '172.15.0.1', '172.32.0.1', '192.169.0.1', '169.254.169.254', '0.0.0.0', '::', 'fe80::1', 'fc00::1', '::ffff:8.8.8.8', '100.64.0.1']) {
      expect(isAllowedHost(h), h).toBe(false);
    }
    expect(isAllowedAddress('::ffff:7f00:1')).toBe(true);
  });

  it('parses ports, host:port and URLs', () => {
    expect(parseTarget(3000).href).toBe('http://localhost:3000/');
    expect(parseTarget('8080').href).toBe('http://localhost:8080/');
    expect(parseTarget('127.0.0.1:5173/app').href).toBe('http://127.0.0.1:5173/app');
    expect(parseTarget('https://localhost:8443/#x').href).toBe('https://localhost:8443/');
    expect(() => parseTarget('ftp://localhost/')).toThrow(/Only http and https/);
    expect(() => parseTarget('http://user:pw@localhost/')).toThrow(/--header/);
  });
});

describe('checks, unit level', () => {
  it('rates CSPs', () => {
    expect(cspWeaknesses("default-src 'self'; object-src 'none'; base-uri 'none'")).toEqual([]);
    expect(cspWeaknesses("script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'")).toEqual(["script-src allows 'unsafe-inline'", "script-src allows 'unsafe-eval'"]);
    expect(cspWeaknesses("script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'")).toEqual([]);
    expect(cspWeaknesses('img-src *')).toContain('no script-src or default-src, so scripts are not restricted');
  });

  it('parses Set-Cookie without keeping the value', () => {
    const c = parseSetCookie('__Host-s=secret; Path=/; Secure; HttpOnly; SameSite=Lax');
    expect(c.name).toBe('__Host-s');
    expect([...c.attrs.keys()]).toEqual(['path', 'secure', 'httponly', 'samesite']);
    expect(JSON.stringify([...c.attrs])).not.toContain('secret');
  });

  it('reads tags and ignores commented-out ones', () => {
    const tags = extractTags('<!-- <script src="old.js"></script> --><script src=a.js integrity="sha384-x"></script><link rel="stylesheet" href=\'b.css\'>');
    expect(tags.map((t) => t.attrs.src ?? t.attrs.href)).toEqual(['a.js', 'b.css']);
  });

  it('fingerprints library URLs without confusing look-alikes', () => {
    expect(fromUrl('https://code.jquery.com/jquery-3.4.1.min.js')).toEqual([{ id: 'jquery', version: '3.4.1' }]);
    expect(fromUrl('https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js')).toEqual([{ id: 'jquery', version: '2.2.4' }]);
    expect(fromUrl('https://code.jquery.com/ui/1.12.1/jquery-ui.min.js')).toEqual([{ id: 'jquery-ui', version: '1.12.1' }]);
    expect(fromUrl('https://cdn.jsdelivr.net/npm/jquery-migrate@3.0.0/dist/jquery-migrate.min.js')).toEqual([]);
    expect(fromUrl('https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js')).toEqual([{ id: 'bootstrap', version: '3.3.7' }]);
    expect(fromUrl('https://unpkg.com/react-bootstrap@2.0.0/dist/react-bootstrap.min.js')).toEqual([]);
    expect(fromUrl('https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js')).toEqual([{ id: 'angularjs', version: '1.8.2' }]);
    expect(fromUrl('https://cdn.jsdelivr.net/npm/moment-timezone@0.5.45/builds/moment-timezone.min.js')).toEqual([]);
  });

  it('fingerprints banners, and does not read Underscore\'s version as lodash\'s', () => {
    expect(fromBody('/*! jQuery v3.4.1 | (c) JS Foundation */')).toEqual([{ id: 'jquery', version: '3.4.1' }]);
    expect(fromBody('/*! jQuery UI - v1.13.2 - 2022-07-14')).toEqual([{ id: 'jquery-ui', version: '1.13.2' }]);
    expect(fromBody('/*!\n * Bootstrap v4.3.1 (https://getbootstrap.com/)')).toEqual([{ id: 'bootstrap', version: '4.3.1' }]);
    expect(fromBody('/** @license Lodash lodash.com/license | Underscore.js 1.8.3 */ var VERSION="4.17.21";')).toEqual([{ id: 'lodash', version: '4.17.21' }]);
    expect(fromBody('var VERSION="4.17.21";')).toEqual([]);
    expect(fromBody('/*! @license DOMPurify 3.2.4 | (c) Cure53 */')).toEqual([{ id: 'dompurify', version: '3.2.4' }]);
    expect(fromBody('function isMoment(){} f.version="2.29.1"')).toEqual([{ id: 'moment', version: '2.29.1' }]);
  });

  it('matches advisory ranges at their edges', () => {
    expect(inRanges('3.4.1', [['>=1.12.0', '<3.5.0']])).toBe(true);
    expect(inRanges('3.5.0', [['>=1.12.0', '<3.5.0']])).toBe(false);
    expect(inRanges('1.12.2', [['<1.12.2'], ['>=1.12.3', '<3.0.0']])).toBe(false);
    expect(advisoriesFor('jquery', '3.7.1')).toEqual([]);
    expect(advisoriesFor('lodash', '4.18.0')).toEqual([]);
    expect(advisoriesFor('bootstrap', '3.4.1').map((a) => a.cve)).toEqual(['CVE-2024-6485']);
    expect(advisoriesFor('bootstrap', '4.3.1')).toEqual([]);
  });

  it('flags SRI on versioned files first', () => {
    expect(looksVersioned('https://code.jquery.com/jquery-1.12.4.min.js')).toBe(true);
    expect(looksVersioned('https://cdn.jsdelivr.net/npm/x@2.1.0/dist/x.js')).toBe(true);
    expect(looksVersioned('https://js.example.net/v3/')).toBe(false);
  });
});

describe('redaction', () => {
  it('replaces known values and common secret shapes', () => {
    const r = new Redactor(['my-cookie-value']);
    const out = r.redact([
      'Cookie: s=my-cookie-value',
      'token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz',
      'AKIAIOSFODNN7EXAMPLE',
      'DATABASE_URL=postgres://app:pw123@db:5432/app',
      'API_KEY=abcd1234efgh',
      'Authorization: Bearer abcdefghijklmnop',
      'Access-Control-Allow-Credentials: true',
    ].join('\n'));
    for (const s of ['my-cookie-value', 'eyJhbGciOiJIUzI1NiJ9', 'AKIAIOSFODNN7EXAMPLE', 'pw123', 'abcd1234efgh', 'abcdefghijklmnop']) expect(out).not.toContain(s);
    expect(out).toContain('Access-Control-Allow-Credentials: true');
    expect(envKeys('A=1\nexport B_KEY=2\n# C=3')).toEqual(['A=<redacted>', 'B_KEY=<redacted>']);
  });
});

describe('catalog', () => {
  it('every rule has a valid mapping, sources, and IDs in the verified formats', () => {
    const ids = new Set<string>();
    for (const r of RULE_LIST) {
      expect(ids.has(r.id), r.id).toBe(false);
      ids.add(r.id);
      expect(r.id.startsWith(`${r.group}/`)).toBe(true);
      expect(r.sources.length).toBeGreaterThan(0);
      for (const s of r.sources) expect(s.url).toMatch(/^https:\/\//);
      for (const t of r.mapping.top10) expect(t).toMatch(/^A(0[1-9]|10):2025$/);
      for (const a of r.mapping.api) expect(a).toMatch(/^API([1-9]|10):2023$/);
      for (const v of r.mapping.asvs) expect(v).toMatch(/^\d{1,2}\.\d{1,2}\.\d{1,2}$/);
    }
    expect(COVERAGE.map((c) => c.id)).toEqual(['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'].map((a) => `${a}:2025`));
  });

  it('nothing in the catalog covers areas this release does not check', () => {
    expect(RULE_LIST.map((r) => r.group)).not.toEqual(expect.arrayContaining(['exposure']));
    const text = readFileSync(new URL('../src/facts/coverage.ts', import.meta.url), 'utf8');
    expect(text).toMatch(/does not check exposed files or endpoints, directory listing, error leakage, open redirects/);
  });

  it('every framework has snippets with an https source', () => {
    for (const fw of FRAMEWORKS) {
      const table = SNIPPETS[fw];
      expect(Object.keys(table).length, fw).toBeGreaterThan(0);
      for (const s of Object.values(table)) expect(s?.source.url).toMatch(/^https:\/\//);
    }
  });

  it('every advisory links a GHSA and a CVE', () => {
    for (const lib of LIBRARIES) for (const a of lib.advisories) {
      expect(a.ghsa).toMatch(/^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/);
      expect(a.cve).toMatch(/^CVE-\d{4}-\d{4,}$/);
    }
  });

  it('the version matches package.json', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });
});

describe('inputs', () => {
  it('parses --header and refuses header injection', () => {
    expect(parseHeader('Cookie: a=b; c=d')).toEqual(['Cookie', 'a=b; c=d']);
    expect(parseHeader('Authorization:Bearer x')).toEqual(['Authorization', 'Bearer x']);
    expect(parseHeader('no colon')).toBeNull();
    expect(parseHeader('Host: evil.example')).toBeNull();
    expect(parseHeader('X: a\r\nY: b')).toBeNull();
  });

  it('reads baselines from json reports, sarif logs and plain lists', () => {
    expect(readBaseline('{"findings":[{"fingerprint":"aa"}]}')).toEqual(['aa']);
    expect(readBaseline('{"runs":[{"results":[{"fingerprints":{"portAudit/v1":"bb"}}]}]}')).toEqual(['bb']);
    expect(readBaseline('{"fingerprints":["cc"]}')).toEqual(['cc']);
    expect(() => readBaseline('nope')).toThrow(/not valid JSON/);
  });
});
