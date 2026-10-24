/**
 * JUnit XML for CI dashboards: one test suite per check group, a failing test
 * case per finding and a passing one per check that passed. Nice-to-have
 * findings are reported as skipped, so they show up without turning the
 * build red.
 */
import { GROUP_NAMES, GROUPS, type Report } from '../types.js';
import { mappingLine } from './common.js';

const xml = (s: string) => s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** Renders a report as JUnit XML. */
export function formatJunit(report: Report): string {
  const out: string[] = ['<?xml version="1.0" encoding="UTF-8"?>'];
  const suites = GROUPS.map((g) => ({ g, findings: report.findings.filter((f) => f.group === g), passed: report.passed.filter((p) => p.group === g) })).filter((s) => s.findings.length || s.passed.length);
  const total = report.findings.length + report.passed.length;
  const failures = report.findings.filter((f) => f.priority !== 'nice-to-have').length;
  const seconds = (report.durationMs / 1000).toFixed(3);
  out.push(`<testsuites name="port-audit" tests="${total}" failures="${failures}" errors="0" time="${seconds}">`);
  for (const s of suites) {
    const fails = s.findings.filter((f) => f.priority !== 'nice-to-have').length;
    const skipped = s.findings.length - fails;
    out.push(`  <testsuite name="${xml(GROUP_NAMES[s.g])}" tests="${s.findings.length + s.passed.length}" failures="${fails}" errors="0" skipped="${skipped}" timestamp="${report.startedAt.replace(/\.\d+Z$/, '')}">`);
    for (const f of s.findings) {
      out.push(`    <testcase classname="port-audit.${s.g}" name="${xml(`${f.id}: ${f.title}`)}">`);
      const body = `${f.url}\nSaw: ${f.evidence}${(f.details ?? []).map((d) => `\n- ${d}`).join('')}\nWhy: ${f.why}\nFix: ${f.fix}\nOWASP: ${mappingLine(f.mapping)}`;
      if (f.priority === 'nice-to-have') out.push(`      <skipped message="${xml(`Nice to have: ${f.title}`)}"/>`, `      <system-out>${xml(body)}</system-out>`);
      else out.push(`      <failure message="${xml(f.title)}" type="${f.priority}">${xml(body)}</failure>`);
      out.push('    </testcase>');
    }
    for (const p of s.passed) out.push(`    <testcase classname="port-audit.${s.g}" name="${xml(`${p.id}: ${p.title}`)}"/>`);
    out.push('  </testsuite>');
  }
  out.push('</testsuites>');
  return `${out.join('\n')}\n`;
}
