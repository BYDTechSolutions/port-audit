/**
 * Point it at your running app on a local port and get the security problems
 * visible from outside, mapped to OWASP Top 10:2025, API Security Top 10 2023
 * and ASVS 5.0, each with a fix snippet for the framework it detects.
 * Passive, no telemetry, and only your own machine and private networks by
 * default.
 *
 * @packageDocumentation
 */
export { auditPort, DEFAULT_MAX_REQUESTS, DEFAULT_RATE, DEFAULT_TIMEOUT_MS, fingerprint } from './audit.js';
export { readBaseline } from './baseline.js';
export { detectFrameworks, frameworkName } from './detect.js';
export { PortAuditError, type PortAuditErrorCode } from './errors.js';
export { advisoriesFor, LIBRARIES, type Advisory, type Library } from './facts/advisories.js';
export { COVERAGE, NOT_A_VERDICT, NOT_CHECKED } from './facts/coverage.js';
export { SNIPPETS, snippetFor } from './facts/snippets.js';
export { FACTS_VERIFIED_ON, SOURCES } from './facts/sources.js';
export { FORMATS, formatJunit, formatMarkdown, formatReport, formatSarif, formatText, type ReportFormat, type TextOptions } from './render/index.js';
export { RULE_LIST, RULES } from './rules.js';
export { isAllowedAddress, isAllowedHost, parseTarget } from './target.js';
export {
  FRAMEWORKS,
  GROUP_NAMES,
  GROUPS,
  PRIORITIES,
  PRIORITY_NAMES,
  type AuditOptions,
  type CoverageRow,
  type Detection,
  type Finding,
  type FixTopic,
  type FrameworkId,
  type Group,
  type Mapping,
  type Passed,
  type Priority,
  type Report,
  type Rule,
  type Snippet,
  type Source,
} from './types.js';
export { REPO_URL, USER_AGENT, VERSION } from './version.js';
