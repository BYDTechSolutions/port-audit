/*
 * Evidence is shown in terminals, CI logs and SARIF uploads, so it never
 * carries a secret: the values of headers the user passed, cookie values,
 * tokens and keys are replaced before a finding is stored.
 */

const PATTERNS: [RegExp, string | ((...m: string[]) => string)][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, '<redacted private key>'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '<redacted JWT>'],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, '<redacted AWS key>'],
  [/\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}/g, '<redacted key>'],
  [/\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}/g, '<redacted key>'],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}/g, '<redacted token>'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, '<redacted token>'],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, (_m, scheme) => `${scheme} <redacted>`],
  [/([a-z][a-z0-9+.-]*:\/\/[^:/\s@]+:)[^@\s/]+@/gi, (_m, head) => `${head}<redacted>@`],
  // KEY=value and "key": "value" where the name suggests a secret.
  [
    /\b([A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|private[_-]?key|access[_-]?key|credential|auth|session|cookie|dsn|database_url|conn(?:ection)?_?string)[A-Za-z0-9_.-]*)(["']?\s*[:=]\s*["']?)(?!(?:true|false|null|none|undefined)\b)([^"'\s,;&<>]{3,})/gi,
    (_m, name, sep) => `${name}${sep}<redacted>`,
  ],
];

/** Replaces secrets in text: the given values first, then common token and key patterns. */
export class Redactor {
  private readonly values: string[];
  constructor(secretValues: string[] = []) {
    // Longest first, so a value that contains another is replaced whole.
    this.values = [...new Set(secretValues.filter((v) => v.length >= 4))].sort((x, y) => y.length - x.length);
  }

  /** Adds values to redact (for example the cookie values a response set). */
  add(...values: string[]): void {
    for (const v of values) if (v.length >= 4 && !this.values.includes(v)) this.values.push(v);
    this.values.sort((x, y) => y.length - x.length);
  }

  redact(text: string): string {
    let out = text;
    for (const v of this.values) out = out.split(v).join('<redacted>');
    for (const [re, rep] of PATTERNS) out = out.replace(re, rep as never);
    return out;
  }
}

/** `NAME=value` lines from a .env-style file, as `NAME=<redacted>`; the names alone say what leaked. */
export function envKeys(text: string): string[] {
  return [...text.matchAll(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=/gm)].map((m) => `${m[1]}=<redacted>`);
}
