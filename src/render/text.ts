import { NOT_A_VERDICT, NOT_CHECKED } from '../facts/coverage.js';
import { PRIORITY_NAMES, type Priority, type Report } from '../types.js';
import { byPriority, cleanLine, counts, detectedLine, duration, mappingLine, snippetTitle } from './common.js';

/** Options for {@link formatText}. */
export interface TextOptions {
  /** ANSI colors. Default `false`. */
  color?: boolean;
  /** Wrap width. Default `100`. */
  width?: number;
}

function wrap(text: string, width: number, indent: string, firstIndent = indent): string {
  const words = text.replace(/\s+/g, ' ').trim().split(' ');
  const lines: string[] = [];
  let line = firstIndent;
  let has = false;
  for (const word of words) {
    if (has && line.length + 1 + word.length > width) {
      lines.push(line);
      line = indent + word;
    } else line += (has ? ' ' : '') + word;
    has = true;
  }
  lines.push(line);
  return lines.join('\n');
}

/** Renders a report for a terminal: findings grouped by priority, each with evidence, fix, snippet and OWASP mapping. */
export function formatText(report: Report, options: TextOptions = {}): string {
  const width = Math.max(60, options.width ?? 100);
  const on = options.color ?? false;
  const esc = (c: string) => (s: string) => (on ? `\u001b[${c}m${s}\u001b[0m` : s);
  const bold = esc('1');
  const dim = esc('2');
  const green = esc('32');
  const colorOf: Record<Priority, (s: string) => string> = { 'fix-now': esc('1;31'), 'should-fix': esc('1;33'), 'nice-to-have': esc('1;36') };
  const c = counts(report);
  const out: string[] = [];

  out.push(bold(`Port audit: ${report.target}`));
  out.push(wrap(`Detected: ${detectedLine(report)}`, width, '  ', ''));
  out.push(
    `${dim(`${report.requests.sent} requests in ${duration(report.durationMs)}`)}  ${colorOf['fix-now'](`${c['fix-now']} fix now`)} · ${colorOf['should-fix'](`${c['should-fix']} should fix`)} · ${colorOf['nice-to-have'](`${c['nice-to-have']} nice to have`)} · ${green(`${report.passed.length} passed`)}${report.suppressed ? dim(` · ${report.suppressed} in baseline`) : ''}`,
  );

  let n = 0;
  const shown = new Map<string, number>();
  for (const { priority, findings } of byPriority(report)) {
    if (!findings.length) continue;
    out.push('', colorOf[priority](`${PRIORITY_NAMES[priority].toUpperCase()} (${findings.length})`));
    for (const f of findings) {
      n++;
      out.push('');
      out.push(wrap(bold(`${n}. ${f.title}`), width + (on ? 8 : 0), '     ', '  '));
      out.push(dim(wrap(`${f.url}  [${mappingLine(f.mapping)}]`, width, '     ', '     ')));
      out.push(wrap(`Saw: ${f.evidence}`, width, '          ', '     '));
      for (const d of f.details ?? []) out.push(wrap(`- ${d}`, width, '         ', '       '));
      out.push(wrap(`Why: ${f.why}`, width, '          ', '     '));
      out.push(wrap(`Fix: ${f.fix}`, width, '          ', '     '));
      for (const s of f.snippets) {
        const key = `${s.framework}\n${s.code}`;
        const earlier = shown.get(key);
        if (earlier) {
          out.push(dim(`     ${snippetTitle(s.framework)}: same snippet as #${earlier}`));
          continue;
        }
        shown.set(key, n);
        out.push(`     ${snippetTitle(s.framework)}:`);
        for (const line of s.code.split('\n')) out.push(`       ${line}`);
        out.push(dim(`       (${s.source.url})`));
      }
      out.push(dim(`     Source: ${f.sources.map((s) => `${s.title} <${s.url}>`).join('; ')}`));
    }
  }
  if (!report.findings.length) out.push('', green(cleanLine(report)));

  if (report.passed.length) {
    out.push('', green(`PASSED (${report.passed.length})`));
    out.push(wrap(report.passed.map((p) => p.title).join(' · '), width, '  ', '  '));
  }
  if (report.notes.length) {
    out.push('', bold('NOTES'));
    for (const note of report.notes) out.push(wrap(`- ${note}`, width, '    ', '  '));
  }
  out.push('', bold('COVERAGE') + dim('  (OWASP Top 10:2025; details: --format md or json)'));
  const partly = report.coverage.filter((r) => r.status !== 'not-assessed');
  const not = report.coverage.filter((r) => r.status === 'not-assessed');
  out.push(wrap(`Checked in part: ${partly.map((r) => `${r.id.slice(0, 3)} ${r.name}`).join(', ')}.`, width, '    ', '  '));
  out.push(wrap(`Not checked: ${not.map((r) => `${r.id.slice(0, 3)} ${r.name}`).join(', ')}.`, width, '    ', '  '));
  out.push(wrap(NOT_CHECKED, width, '  ', '  '));
  out.push('', dim(NOT_A_VERDICT));
  out.push(dim(`${report.tool.name} ${report.tool.version} · ${report.tool.url}`));
  return `${out.join('\n')}\n`;
}
