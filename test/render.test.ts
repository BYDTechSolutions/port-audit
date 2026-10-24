import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sarifLocation } from '../src/render/sarif.js';
import { auditPort, formatJunit, formatMarkdown, formatSarif, formatText, RULE_LIST, type Report } from '../src/index.js';
import { expressNoHelmet, serve, wellConfigured, type Fixture } from './servers.js';

let dirty: Report;
let clean: Report;
const fixtures: Fixture[] = [];
beforeAll(async () => {
  const a = await serve(expressNoHelmet);
  const b = await serve(wellConfigured);
  fixtures.push(a, b);
  dirty = await auditPort(a.url, { rate: 100 });
  clean = await auditPort(b.url, { rate: 100 });
});
afterAll(async () => {
  await Promise.all(fixtures.map((f) => f.close()));
});

describe('text', () => {
  it('groups by priority and shows URL, evidence, why, fix, snippet and OWASP IDs', () => {
    const t = formatText(dirty);
    expect(t).toMatch(/^Port audit: http:\/\/127\.0\.0\.1:\d+\//);
    expect(t).toMatch(/Detected: Express \(/);
    expect(t).toContain('SHOULD FIX (');
    expect(t).toContain('NICE TO HAVE (');
    expect(t).toMatch(/\[A02:2025 · API8:2023 · ASVS 3\.4\.3\]/);
    expect(t).toMatch(/Saw: .*\n/);
    expect(t).toContain('Express:\n       import helmet');
    expect(t).toMatch(/Express: same snippet as #\d+/);
    expect(t).toContain('COVERAGE');
    expect(t).toContain('This release does not check exposed files or endpoints, directory listing, error leakage, open');
    expect(t).not.toMatch(/\u001b\[/);
  });

  it('a clean report never says "secure"', () => {
    const t = formatText(clean);
    expect(t).toContain('Nothing to report for the checks in this release.');
    expect(t).toContain('not a security sign-off');
    expect(t.toLowerCase()).not.toMatch(/\b(is secure|compliant)\b/);
  });
});

describe('markdown', () => {
  it('has headings, fenced snippets and the coverage table', () => {
    const md = formatMarkdown(dirty);
    expect(md).toMatch(/^# Port audit: /);
    expect(md).toContain('```js\nimport helmet');
    expect(md).toContain('| A01:2025 Broken Access Control | not checked |');
  });
});

describe('SARIF', () => {
  it('is a SARIF 2.1.0 log GitHub code scanning accepts', () => {
    const log = JSON.parse(formatSarif(dirty));
    expect(log.version).toBe('2.1.0');
    expect(log.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    const run = log.runs[0];
    expect(run.tool.driver.name).toBe('port-audit');
    expect(run.tool.driver.rules).toHaveLength(RULE_LIST.length);
    for (const rule of run.tool.driver.rules) {
      expect(rule.id).toMatch(/^[a-z]+\/[a-z0-9-]+$/);
      expect(typeof rule.properties['security-severity']).toBe('string');
      expect(Number(rule.properties['security-severity'])).toBeGreaterThan(0);
      expect(rule.properties.tags.length).toBeLessThanOrEqual(10);
      expect(rule.properties.tags).toContain('security');
      expect(rule.shortDescription.text.length).toBeLessThanOrEqual(1024);
    }
    expect(run.results.length).toBe(dirty.findings.length);
    for (const r of run.results) {
      expect(run.tool.driver.rules[r.ruleIndex].id).toBe(r.ruleId);
      expect(['error', 'warning', 'note']).toContain(r.level);
      expect(r.message.text.length).toBeGreaterThan(0);
      expect(r.locations[0].physicalLocation.artifactLocation.uri).toMatch(/^port-audit\/127\.0\.0\.1\//);
      expect(r.properties.url).toMatch(/^http:\/\//);
      expect(r.locations[0].physicalLocation.region.startLine).toBe(1);
      expect(r.partialFingerprints.primaryLocationLineHash).toMatch(/^[0-9a-f]{16}:1$/);
    }
    const tags = run.tool.driver.rules.find((x: { id: string }) => x.id === 'cors/reflected-credentials').properties.tags;
    expect(tags).toEqual(['owasp-top10-2025:A02', 'owasp-api-2023:API8', 'owasp-asvs-5.0.0:3.4.2', 'external/cwe/cwe-942', 'security']);
  });
});

describe('SARIF locations', () => {
  it('are relative and cannot be mistaken for repository files', () => {
    expect(sarifLocation('http://localhost:3000/')).toBe('port-audit/localhost/index');
    expect(sarifLocation('https://127.0.0.1:8443/a b/c?x=1')).toBe('port-audit/127.0.0.1/a%20b/c');
    expect(sarifLocation('http://[::1]:3000/x')).toBe('port-audit/%5B::1%5D/x');
  });
});

describe('JUnit', () => {
  it('has one suite per group with failures for findings and skips for nice-to-haves', () => {
    const xml = formatJunit(dirty);
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="port-audit"')).toBe(true);
    const failing = dirty.findings.filter((f) => f.priority !== 'nice-to-have').length;
    const skipped = dirty.findings.length - failing;
    expect(xml).toContain(`failures="${failing}"`);
    expect((xml.match(/<failure /g) ?? []).length).toBe(failing);
    expect((xml.match(/<skipped /g) ?? []).length).toBe(skipped);
    expect((xml.match(/<testsuite /g) ?? []).length).toBe((xml.match(/<\/testsuite>/g) ?? []).length);
    expect((xml.match(/<testcase /g) ?? []).length).toBe(dirty.findings.length + dirty.passed.length);
    expect(xml).toContain('<testsuite name="Security headers"');
    for (const m of xml.matchAll(/="([^"]*)"/g)) expect(m[1]).not.toMatch(/[<>&](?!amp;|lt;|gt;|quot;)/); // attributes escaped
  });

  it('a clean report has no failures', () => {
    expect(formatJunit(clean)).toContain('failures="0"');
  });
});

describe('JSON', () => {
  it('round-trips', () => {
    expect(JSON.parse(JSON.stringify(dirty))).toEqual(dirty);
  });
});
