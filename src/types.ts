/**
 * The shapes `auditPort` takes and returns. A report is plain data: it
 * survives `JSON.stringify` and can be rendered later, anywhere.
 */

/**
 * How soon a finding deserves attention.
 *
 * - `fix-now`: anyone who can reach the app can read secrets, run code, or act as a signed-in user.
 * - `should-fix`: a real weakness with a known cost, but not an open door on its own.
 * - `nice-to-have`: hardening, or a choice worth confirming.
 */
export type Priority = 'fix-now' | 'should-fix' | 'nice-to-have';

/** Priorities from most to least urgent. */
export const PRIORITIES: readonly Priority[] = ['fix-now', 'should-fix', 'nice-to-have'];

/** Human names for the priorities. */
export const PRIORITY_NAMES: Record<Priority, string> = {
  'fix-now': 'Fix now',
  'should-fix': 'Should fix',
  'nice-to-have': 'Nice to have',
};

/** The families of checks, in report order. */
export type Group = 'headers' | 'cookies' | 'cors' | 'tls' | 'methods' | 'sri' | 'libraries' | 'disclosure';

/** Every group, in report order. */
export const GROUPS: readonly Group[] = ['headers', 'cookies', 'cors', 'tls', 'methods', 'sri', 'libraries', 'disclosure'];

/** Human names for the groups. */
export const GROUP_NAMES: Record<Group, string> = {
  headers: 'Security headers',
  cookies: 'Cookies',
  cors: 'CORS',
  tls: 'TLS',
  methods: 'HTTP methods',
  sri: 'Subresource Integrity',
  libraries: 'Front-end libraries',
  disclosure: 'Version disclosure',
};

/** The stacks the tool recognizes and has fix snippets for. */
export type FrameworkId = 'express' | 'nextjs' | 'nestjs' | 'django' | 'flask' | 'fastapi' | 'rails' | 'laravel' | 'spring' | 'aspnet' | 'nginx' | 'apache';

/** Every framework id. */
export const FRAMEWORKS: readonly FrameworkId[] = ['express', 'nextjs', 'nestjs', 'django', 'flask', 'fastapi', 'rails', 'laravel', 'spring', 'aspnet', 'nginx', 'apache'];

/** What a fix snippet is about. */
export type FixTopic = 'headers' | 'cookies' | 'cors' | 'version' | 'methods';

/** A page a rule relies on. */
export interface Source {
  title: string;
  url: string;
}

/** Where a rule sits in OWASP's lists. Every ID was checked against OWASP's own pages. */
export interface Mapping {
  /** OWASP Top 10:2025, e.g. `A02:2025`. */
  top10: string[];
  /** OWASP API Security Top 10 2023, e.g. `API8:2023`. */
  api: string[];
  /** ASVS 5.0.0 requirement IDs, e.g. `3.4.1` (cite as `v5.0.0-3.4.1`). */
  asvs: string[];
  /** MITRE CWE numbers. */
  cwe: number[];
}

/** One check the tool can report: what it means, why, how to fix it, and where it maps. */
export interface Rule {
  /** Stable id, `group/rule`, e.g. `headers/csp-missing`. */
  id: string;
  group: Group;
  /** Default priority; a check can lower or raise it for one finding and says so. */
  priority: Priority;
  title: string;
  why: string;
  fix: string;
  /** Which framework snippet answers this rule, if any. */
  topic?: FixTopic;
  mapping: Mapping;
  sources: Source[];
}

/** A short configuration snippet for one framework. */
export interface Snippet {
  framework: FrameworkId;
  /** Language for syntax hints in Markdown, e.g. `js`, `python`, `nginx`. */
  lang: string;
  code: string;
  source: Source;
}

/** One thing to fix, with the evidence for it. */
export interface Finding {
  id: string;
  group: Group;
  priority: Priority;
  title: string;
  /** The URL the evidence came from. */
  url: string;
  /** What was seen, with values (secrets redacted). */
  evidence: string;
  /** Supporting lines, capped by the check. */
  details?: string[];
  why: string;
  fix: string;
  /** Fix snippets for the detected frameworks (empty when none was detected). */
  snippets: Snippet[];
  mapping: Mapping;
  sources: Source[];
  /** Stable across runs and ports: rule id, URL path and key. Used by `--baseline`. */
  fingerprint: string;
}

/** A check that ran and found nothing to report. */
export interface Passed {
  id: string;
  group: Group;
  title: string;
}

/** A framework or server the responses point to, and why. */
export interface Detection {
  id: FrameworkId;
  name: string;
  kind: 'app' | 'server';
  evidence: string[];
}

/** How much of one OWASP Top 10:2025 category a passive scan can see. */
export interface CoverageRow {
  id: string;
  name: string;
  status: 'checked' | 'partly' | 'not-assessed';
  how: string;
}

/** The result of one audit. */
export interface Report {
  tool: { name: string; version: string; url: string };
  /** The URL that was audited, normalized. */
  target: string;
  startedAt: string;
  durationMs: number;
  /** Requests sent, the cap, and how many planned requests the cap skipped. */
  requests: { sent: number; cap: number; skipped: number; backoffs: number };
  frameworks: Detection[];
  /** True when the responses look like a development server (dev servers show more on purpose). */
  devServer: string | null;
  findings: Finding[];
  passed: Passed[];
  notes: string[];
  coverage: CoverageRow[];
  /** Findings hidden by a baseline. */
  suppressed: number;
}

/** Options for {@link auditPort}. */
export interface AuditOptions {
  /** Extra pages on the same host to read (GET only): their headers, CORS answers and scripts are checked too. */
  paths?: string[];
  /** Extra request headers, e.g. a session cookie for a signed-in page. Redacted in every report. */
  headers?: Record<string, string>;
  /** Requests per second. Default 10. */
  rate?: number;
  /** Hard cap on requests for the whole run. Default 300. */
  maxRequests?: number;
  /** Timeout per request in milliseconds. Default 10000. */
  timeoutMs?: number;
  /** A host outside the private ranges that you own and allow the scan to reach. Must equal the target's host exactly. */
  iOwnThis?: string;
  /** Use this framework's snippets instead of the detected ones. */
  framework?: FrameworkId;
  /** Fingerprints of findings to hide (from an earlier report). */
  baseline?: string[];
  /** Progress messages. */
  onProgress?: (message: string) => void;
  /** DNS lookup, for tests. Defaults to `dns.promises.lookup`. */
  lookup?: (host: string) => Promise<{ address: string; family: number }[]>;
}
