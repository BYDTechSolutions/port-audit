/*
 * The CLI, as a function: arguments and I/O in, exit code out. `cli.ts` wires
 * it to the real process; tests call it directly.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { auditPort, DEFAULT_MAX_REQUESTS, DEFAULT_RATE, DEFAULT_TIMEOUT_MS } from './audit.js';
import { readBaseline } from './baseline.js';
import { PortAuditError } from './errors.js';
import { counts, mappingLine } from './render/common.js';
import { FORMATS, formatReport, type ReportFormat } from './render/index.js';
import { RULE_LIST } from './rules.js';
import { bareHost, isAllowedHost, ownershipReminder, parseTarget } from './target.js';
import { FRAMEWORKS, GROUP_NAMES, PRIORITY_NAMES, type AuditOptions, type FrameworkId, type Priority } from './types.js';
import { VERSION } from './version.js';

/** What the CLI reads from and writes to. */
export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: Record<string, string | undefined>;
  stdoutIsTTY: boolean;
  stderrIsTTY: boolean;
  columns?: number;
  readFile?: (path: string) => Promise<string>;
  writeFile?: (path: string, data: string) => Promise<void>;
  /** Overrides for the audit (tests inject a DNS lookup). */
  auditOptions?: Partial<AuditOptions>;
}

export const HELP = `Usage: port-audit [url | port] [options]

Audits the app running on your machine for security problems anyone can see
from outside: security headers and CSP, cookie flags, CORS, TLS, TRACE and
WebDAV methods, third-party scripts without Subresource Integrity, front-end
libraries with known vulnerabilities, and version headers. Passive: it only
reads. Each finding has the evidence, why it matters, a fix snippet for the
framework it detects, and its OWASP Top 10:2025 / API Top 10 / ASVS 5.0 IDs.

Examples:
  npx @bydtech/port-audit --port 3000
  npx @bydtech/port-audit http://localhost:8080/app
  npx @bydtech/port-audit --port 3000 --path /dashboard --header "Cookie: session=..."
  npx @bydtech/port-audit --port 3000 --format sarif --out port-audit.sarif
  npx @bydtech/port-audit --port 3000 --fail-on fix-now        # CI gate

Options:
  -p, --port <n>           audit http://localhost:<n>/ (instead of a URL)
  -f, --format <fmt>       text (default), json, md, sarif or junit
  -o, --out <file>         write the report to a file (format from .json/.md/.sarif/.xml)
      --fail-on <level>    exit 1 if any finding is at this level or above: fix-now or should-fix
      --baseline <file>    hide findings already in this file (an earlier json or sarif report)
      --path <path>        also read this page on the same host (repeatable), e.g. /login
      --header <h>         send this header on every request (repeatable), e.g. "Cookie: s=..."
                           values are redacted in every report
      --rate <n>           requests per second (default ${DEFAULT_RATE})
      --max-requests <n>   hard cap on requests for the run (default ${DEFAULT_MAX_REQUESTS})
      --timeout <ms>       timeout per request (default ${DEFAULT_TIMEOUT_MS})
      --framework <id>     use this framework's fix snippets: ${FRAMEWORKS.join(', ')}
      --i-own-this <host>  allow one host outside localhost and private networks; it must
                           equal the target's host exactly. Only scan systems you own.
      --list-checks        print every check with its OWASP mapping and sources, then exit
      --no-color           plain text output (also honors NO_COLOR)
  -q, --quiet              no progress messages
  -h, --help               show this help
  -v, --version            show the version

Targets allowed without --i-own-this: localhost, *.localhost, *.test, 127.0.0.0/8,
::1, 10/8, 172.16/12 and 192.168/16.

Exit codes: 0 done, 1 --fail-on threshold met, 2 bad usage, refused target or no answer.
`;

const FAIL_LEVELS: Record<string, Priority[]> = { 'fix-now': ['fix-now'], 'should-fix': ['fix-now', 'should-fix'] };

/** Parses `Name: value` into a header pair, or `null`. */
export function parseHeader(text: string): [string, string] | null {
  const i = text.indexOf(':');
  if (i <= 0) return null;
  const name = text.slice(0, i).trim();
  const value = text.slice(i + 1).trim();
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n]/.test(value)) return null;
  if (/^(host|content-length|transfer-encoding|connection)$/i.test(name)) return null;
  return [name, value];
}

/** The `--list-checks` output. */
export function listChecks(): string {
  const out: string[] = [];
  let group = '';
  for (const r of RULE_LIST) {
    if (r.group !== group) {
      group = r.group;
      out.push('', GROUP_NAMES[r.group].toUpperCase());
    }
    out.push(`  ${r.id}  [${PRIORITY_NAMES[r.priority]}]`, `    ${r.title}`, `    ${mappingLine(r.mapping)}`, `    ${r.sources.map((s) => s.url).join('\n    ')}`);
  }
  out.push('', 'Not checked in this release: exposed files or endpoints, directory listing, error leakage, open redirects, injection, authentication, access control.');
  return `${out.join('\n').trimStart()}\n`;
}

/** Runs the CLI. Returns the exit code. */
export async function main(argv: string[], io: CliIo): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        port: { type: 'string', short: 'p' },
        format: { type: 'string', short: 'f' },
        out: { type: 'string', short: 'o' },
        'fail-on': { type: 'string' },
        baseline: { type: 'string' },
        path: { type: 'string', multiple: true },
        header: { type: 'string', multiple: true },
        rate: { type: 'string' },
        'max-requests': { type: 'string' },
        timeout: { type: 'string' },
        framework: { type: 'string' },
        'i-own-this': { type: 'string' },
        'list-checks': { type: 'boolean' },
        'no-color': { type: 'boolean' },
        quiet: { type: 'boolean', short: 'q' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
      },
    });
  } catch (error) {
    io.stderr(`port-audit: ${(error as Error).message}\nRun port-audit --help for usage.\n`);
    return 2;
  }
  const { values, positionals } = parsed;
  const usage = (message: string) => {
    io.stderr(`port-audit: ${message}\nRun port-audit --help for usage.\n`);
    return 2;
  };
  if (values.help) {
    io.stdout(HELP);
    return 0;
  }
  if (values.version) {
    io.stdout(`${VERSION}\n`);
    return 0;
  }
  if (values['list-checks']) {
    io.stdout(listChecks());
    return 0;
  }

  if (values.port && positionals.length) return usage('Give a URL or --port, not both.');
  if (!values.port && positionals.length !== 1) return usage(positionals.length ? 'Give exactly one URL or port.' : 'Give a port or URL to audit, e.g. port-audit --port 3000');
  if (values.port && !/^\d{1,5}$/.test(values.port)) return usage('--port must be a number, e.g. --port 3000.');
  const targetText = values.port ?? (positionals[0] as string);

  let format: ReportFormat = 'text';
  if (values.format) {
    if (!FORMATS.includes(values.format as ReportFormat)) return usage(`--format must be one of ${FORMATS.join(', ')}.`);
    format = values.format as ReportFormat;
  } else if (values.out) {
    const ext = extname(values.out).toLowerCase();
    format = ext === '.json' ? 'json' : ext === '.md' || ext === '.markdown' ? 'md' : ext === '.sarif' ? 'sarif' : ext === '.xml' ? 'junit' : 'text';
  }
  const failOn = values['fail-on'];
  if (failOn && !FAIL_LEVELS[failOn]) return usage('--fail-on must be fix-now or should-fix.');
  const num = (value: string | undefined, min: number, max: number, integer: boolean): number | undefined | null => {
    if (value === undefined) return undefined;
    const n = Number(value);
    return Number.isFinite(n) && n >= min && n <= max && (!integer || Number.isInteger(n)) ? n : null;
  };
  const rate = num(values.rate, 0.1, 100, false);
  if (rate === null) return usage('--rate must be a number from 0.1 to 100.');
  const maxRequests = num(values['max-requests'], 1, 100_000, true);
  if (maxRequests === null) return usage('--max-requests must be a whole number, 1 or more.');
  const timeoutMs = num(values.timeout, 500, 600_000, true);
  if (timeoutMs === null) return usage('--timeout must be a whole number of milliseconds, 500 or more.');
  if (values.framework && !FRAMEWORKS.includes(values.framework as FrameworkId)) return usage(`--framework must be one of ${FRAMEWORKS.join(', ')}.`);
  const headers: Record<string, string> = {};
  for (const h of values.header ?? []) {
    const pair = parseHeader(h);
    if (!pair) return usage(`--header must look like "Name: value" (got ${JSON.stringify(h.replace(/:.*/, ': ...'))}).`);
    headers[pair[0]] = pair[1];
  }

  const read = io.readFile ?? ((p: string) => readFile(p, 'utf8'));
  let baseline: string[] | undefined;
  if (values.baseline) {
    try {
      baseline = readBaseline(await read(resolve(values.baseline)));
    } catch (error) {
      return usage(error instanceof PortAuditError ? error.message : `Could not read the baseline: ${(error as Error).message}`);
    }
  }

  let host: string;
  try {
    host = bareHost(parseTarget(targetText).hostname);
  } catch (error) {
    return usage((error as Error).message);
  }
  const iOwnThis = values['i-own-this'];
  if (iOwnThis && bareHost(iOwnThis) === host && !isAllowedHost(host)) io.stderr(`port-audit: ${ownershipReminder(host)}\n`);

  const showProgress = io.stderrIsTTY && !values.quiet;
  let lastLen = 0;
  const progress = (message: string) => {
    if (!showProgress) return;
    const line = `  ${message}`.slice(0, Math.max(20, (io.columns ?? 80) - 1));
    io.stderr(`\r${line}${' '.repeat(Math.max(0, lastLen - line.length))}`);
    lastLen = line.length;
  };
  const clearProgress = () => {
    if (showProgress && lastLen) io.stderr(`\r${' '.repeat(lastLen)}\r`);
    lastLen = 0;
  };

  let report;
  try {
    report = await auditPort(targetText, {
      paths: values.path,
      headers,
      rate,
      maxRequests,
      timeoutMs,
      iOwnThis,
      framework: values.framework as FrameworkId | undefined,
      baseline,
      onProgress: progress,
      ...io.auditOptions,
    });
  } catch (error) {
    clearProgress();
    if (error instanceof PortAuditError) {
      io.stderr(`port-audit: ${error.message}\n`);
      return 2;
    }
    io.stderr(`port-audit: unexpected error: ${(error as Error).stack ?? error}\n`);
    return 2;
  }
  clearProgress();

  const color = format === 'text' && !values.out && io.stdoutIsTTY && !values['no-color'] && !io.env.NO_COLOR;
  const output = formatReport(report, format, { color, width: Math.min(110, io.columns ?? 100) });
  const c = counts(report);
  if (values.out) {
    const path = resolve(values.out);
    try {
      await (io.writeFile ?? ((p: string, d: string) => writeFile(p, d, 'utf8')))(path, output);
    } catch (error) {
      io.stderr(`port-audit: could not write ${path}: ${(error as Error).message}\n`);
      return 2;
    }
    io.stderr(`port-audit: wrote ${path} (${c['fix-now']} fix now, ${c['should-fix']} should fix, ${c['nice-to-have']} nice to have)\n`);
  } else {
    io.stdout(output);
  }
  if (failOn) {
    const levels = FAIL_LEVELS[failOn] as Priority[];
    const hit = report.findings.filter((f) => levels.includes(f.priority)).length;
    if (hit) {
      io.stderr(`port-audit: ${hit} finding(s) at --fail-on ${failOn} or above.\n`);
      return 1;
    }
  }
  return 0;
}
