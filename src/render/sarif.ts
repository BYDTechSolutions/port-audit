/**
 * SARIF 2.1.0 for GitHub code scanning. A port scan has no source files, so
 * each result's location is the URL it was seen on. Rules carry
 * `security-severity` (a string, as GitHub requires) and tags with the OWASP
 * IDs, kept within GitHub's 10-tag display limit.
 */
import { NOT_A_VERDICT, NOT_CHECKED } from '../facts/coverage.js';
import { RULE_LIST } from '../rules.js';
import type { Priority, Report, Rule } from '../types.js';
import { cleanLine } from './common.js';

/** GitHub: over 9.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low. */
export const SECURITY_SEVERITY: Record<Priority, string> = { 'fix-now': '8.5', 'should-fix': '5.5', 'nice-to-have': '3.0' };

const LEVEL: Record<Priority, 'error' | 'warning' | 'note'> = { 'fix-now': 'error', 'should-fix': 'warning', 'nice-to-have': 'note' };

/** SARIF tags for a rule: OWASP Top 10, API Top 10, ASVS and CWE, then `security`, at most 10. */
export function sarifTags(r: Rule): string[] {
  const m = r.mapping;
  const tags = [
    ...m.top10.map((t) => `owasp-top10-2025:${t.split(':')[0]}`),
    ...m.api.map((t) => `owasp-api-2023:${t.split(':')[0]}`),
    ...m.asvs.map((t) => `owasp-asvs-5.0.0:${t}`),
    ...m.cwe.map((n) => `external/cwe/cwe-${n}`),
  ].slice(0, 9);
  return [...tags, 'security'];
}

const pascal = (id: string) => id.split(/[/-]/).map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join('');

/** Renders a report as a SARIF 2.1.0 log. */
export function formatSarif(report: Report): string {
  const index = new Map(RULE_LIST.map((r, i) => [r.id, i]));
  const rules = RULE_LIST.map((r) => ({
    id: r.id,
    name: pascal(r.id),
    shortDescription: { text: r.title },
    fullDescription: { text: r.why },
    help: {
      text: `${r.why}\n\nFix: ${r.fix}\n\nSources: ${r.sources.map((s) => `${s.title} ${s.url}`).join('; ')}`,
      markdown: `${r.why}\n\n**Fix:** ${r.fix}\n\n**Sources:** ${r.sources.map((s) => `[${s.title}](${s.url})`).join(', ')}`,
    },
    helpUri: r.sources[0]?.url,
    defaultConfiguration: { level: LEVEL[r.priority] },
    properties: { tags: sarifTags(r), precision: 'high', 'security-severity': SECURITY_SEVERITY[r.priority] },
  }));
  const results = report.findings.map((f) => ({
    ruleId: f.id,
    ruleIndex: index.get(f.id),
    level: LEVEL[f.priority],
    message: { text: `${f.title}. ${f.evidence}${f.details?.length ? ` (${f.details.join('; ')})` : ''}` },
    locations: [{ physicalLocation: { artifactLocation: { uri: f.url }, region: { startLine: 1 } } }],
    partialFingerprints: { primaryLocationLineHash: `${f.fingerprint}:1` },
    fingerprints: { 'portAudit/v1': f.fingerprint },
    properties: { priority: f.priority, 'security-severity': SECURITY_SEVERITY[f.priority] },
  }));
  const log = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'port-audit', semanticVersion: report.tool.version, version: report.tool.version, informationUri: report.tool.url, rules } },
        automationDetails: { id: 'port-audit/' },
        invocations: [{ executionSuccessful: true, startTimeUtc: report.startedAt }],
        results,
        properties: {
          target: report.target,
          statement: report.findings.length ? NOT_A_VERDICT : cleanLine(report),
          notChecked: NOT_CHECKED,
          coverage: report.coverage,
        },
      },
    ],
  };
  return `${JSON.stringify(log, null, 2)}\n`;
}
