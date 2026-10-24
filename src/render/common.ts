import { frameworkName } from '../detect.js';
import { PRIORITIES, type Finding, type Mapping, type Priority, type Report } from '../types.js';

/** Findings bucketed by priority, in priority order. */
export function byPriority(report: Report): { priority: Priority; findings: Finding[] }[] {
  return PRIORITIES.map((priority) => ({ priority, findings: report.findings.filter((f) => f.priority === priority) }));
}

/** Counts per priority. */
export function counts(report: Report): Record<Priority, number> {
  const out: Record<Priority, number> = { 'fix-now': 0, 'should-fix': 0, 'nice-to-have': 0 };
  for (const f of report.findings) out[f.priority]++;
  return out;
}

/** `250 ms` or `1.2 s`. */
export function duration(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`;
}

/** `A02:2025 · API8:2023 · ASVS 3.4.2 · CWE-942`. */
export function mappingLine(m: Mapping): string {
  return [...m.top10, ...m.api, ...(m.asvs.length ? [`ASVS ${m.asvs.join(', ')}`] : []), ...m.cwe.map((c) => `CWE-${c}`)].join(' · ');
}

/** `Express (X-Powered-By: Express; connect.sid cookie)`, or a "not detected" line. */
export function detectedLine(report: Report): string {
  if (!report.frameworks.length) return 'No framework detected (fix snippets are skipped; pass --framework to pick one)';
  return report.frameworks.map((f) => `${f.name} (${f.evidence.join('; ')})`).join(', ');
}

/** The snippet heading, e.g. `Express`. */
export const snippetTitle = (id: Parameters<typeof frameworkName>[0]): string => frameworkName(id);

/** The closing line when nothing was found. */
export function cleanLine(report: Report): string {
  return report.suppressed
    ? `Nothing to report outside the baseline (${report.suppressed} hidden) for the checks in this release.`
    : 'Nothing to report for the checks in this release.';
}
