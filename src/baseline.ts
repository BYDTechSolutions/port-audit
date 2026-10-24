import { PortAuditError } from './errors.js';

/**
 * Reads finding fingerprints from an earlier `--format json` report, a
 * `--format sarif` log, or a plain `{ "fingerprints": [...] }` file.
 */
export function readBaseline(text: string): string[] {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new PortAuditError('INVALID_TARGET', 'The baseline file is not valid JSON. Create one with --format json --out port-audit-baseline.json.');
  }
  const o = v as { findings?: { fingerprint?: unknown }[]; fingerprints?: unknown[]; runs?: { results?: { fingerprints?: Record<string, unknown> }[] }[] };
  const strings = (xs: unknown[]) => xs.filter((x): x is string => typeof x === 'string');
  if (Array.isArray(o.fingerprints)) return strings(o.fingerprints);
  if (Array.isArray(o.findings)) return strings(o.findings.map((f) => f.fingerprint));
  if (Array.isArray(o.runs)) return strings(o.runs.flatMap((r) => (r.results ?? []).map((x) => x.fingerprints?.['portAudit/v1'])));
  throw new PortAuditError('INVALID_TARGET', 'The baseline file has no findings, SARIF results or fingerprints.');
}
