import { NOT_A_VERDICT, NOT_CHECKED } from '../facts/coverage.js';
import { PRIORITY_NAMES, type Report } from '../types.js';
import { byPriority, cleanLine, counts, detectedLine, duration, mappingLine, snippetTitle } from './common.js';

const esc = (s: string) => s.replace(/([\\`*_[\]<>|])/g, '\\$1');
const link = (title: string, url: string) => (/^https?:\/\//.test(url) ? `[${esc(title)}](${url})` : esc(`${title} (${url})`));
const fence = (code: string) => (code.includes('```') ? '~~~~' : '```');

/** Renders a report as Markdown, for pull request comments and job summaries. */
export function formatMarkdown(report: Report): string {
  const c = counts(report);
  const out: string[] = [];
  out.push(`# Port audit: ${esc(report.target)}`, '');
  out.push(`**${c['fix-now']} fix now · ${c['should-fix']} should fix · ${c['nice-to-have']} nice to have · ${report.passed.length} passed**${report.suppressed ? ` · ${report.suppressed} in baseline` : ''}`, '');
  out.push(`Detected: ${esc(detectedLine(report))}. ${report.requests.sent} requests in ${duration(report.durationMs)}, ${report.startedAt.replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}.`, '');
  let n = 0;
  const shown = new Map<string, number>();
  for (const { priority, findings } of byPriority(report)) {
    if (!findings.length) continue;
    out.push(`## ${PRIORITY_NAMES[priority]} (${findings.length})`, '');
    for (const f of findings) {
      n++;
      out.push(`### ${n}. ${esc(f.title)}`, '');
      out.push(`- **URL:** ${esc(f.url)}`);
      out.push(`- **OWASP:** ${mappingLine(f.mapping)}`);
      out.push(`- **Saw:** ${esc(f.evidence)}`);
      for (const d of f.details ?? []) out.push(`  - ${esc(d)}`);
      out.push(`- **Why:** ${esc(f.why)}`);
      out.push(`- **Fix:** ${esc(f.fix)}`);
      out.push(`- **Sources:** ${f.sources.map((s) => link(s.title, s.url)).join(', ')}`, '');
      for (const s of f.snippets) {
        const key = `${s.framework}\n${s.code}`;
        const earlier = shown.get(key);
        if (earlier) {
          out.push(`${snippetTitle(s.framework)}: same snippet as finding ${earlier}.`, '');
          continue;
        }
        shown.set(key, n);
        const fc = fence(s.code);
        out.push(`${snippetTitle(s.framework)} (${link(s.source.title, s.source.url)}):`, '', `${fc}${s.lang}`, s.code, fc, '');
      }
    }
  }
  if (!report.findings.length) out.push(cleanLine(report), '');
  if (report.passed.length) {
    out.push(`## Passed (${report.passed.length})`, '');
    for (const p of report.passed) out.push(`- ${esc(p.title)}`);
    out.push('');
  }
  if (report.notes.length) {
    out.push('## Notes', '');
    for (const note of report.notes) out.push(`- ${esc(note)}`);
    out.push('');
  }
  out.push('## Coverage (OWASP Top 10:2025)', '', '| Category | Status | What this release looks at |', '|---|---|---|');
  for (const r of report.coverage) out.push(`| ${r.id} ${esc(r.name)} | ${r.status === 'not-assessed' ? 'not checked' : 'partly'} | ${esc(r.how)} |`);
  out.push('', esc(NOT_CHECKED), '', `_${esc(NOT_A_VERDICT)}_`, '', `${report.tool.name} ${report.tool.version} · ${report.tool.url}`, '');
  return out.join('\n');
}
