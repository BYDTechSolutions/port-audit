/*
 * A small advisory list for front-end libraries, shipped in the package so
 * the scan never fetches anything. Each entry was checked against its GitHub
 * Advisory Database page on FACTS_VERIFIED_ON; ranges are the npm ranges as
 * GitHub lists them. Withdrawn advisories are left out. This is not a
 * replacement for `npm audit` on your lockfile: it only sees what the browser
 * is served.
 */

/** One advisory: affected ranges (any of them), each a list of comparators that must all hold. */
export interface Advisory {
  ghsa: string;
  cve: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** e.g. [['>=1.12.0', '<3.5.0']] */
  ranges: string[][];
  patched: string | null;
  summary: string;
}

/** A library the scan can fingerprint. */
export interface Library {
  id: string;
  name: string;
  /** Set when the whole line is end-of-life. */
  eol?: string;
  advisories: Advisory[];
}

const a = (ghsa: string, cve: string, severity: Advisory['severity'], ranges: string[][], patched: string | null, summary: string): Advisory => ({ ghsa, cve, severity, ranges, patched, summary });

export const LIBRARIES: readonly Library[] = [
  {
    id: 'jquery', name: 'jQuery',
    advisories: [
      a('GHSA-gxr4-xjj5-5px2', 'CVE-2020-11022', 'medium', [['>=1.12.0', '<3.5.0']], '3.5.0', 'Passing untrusted HTML to DOM methods can run script (htmlPrefilter)'),
      a('GHSA-jpcq-cgw6-v4j6', 'CVE-2020-11023', 'medium', [['>=1.0.3', '<3.5.0']], '3.5.0', 'Untrusted HTML with <option> elements can run script'),
      a('GHSA-6c3j-c64m-qhgq', 'CVE-2019-11358', 'medium', [['>=1.1.4', '<3.4.0']], '3.4.0', 'Prototype pollution through $.extend(true, ...)'),
      a('GHSA-rmxg-73gg-4p98', 'CVE-2015-9251', 'medium', [['<1.12.2'], ['>=1.12.3', '<3.0.0']], '3.0.0', 'Cross-domain ajax responses are executed as script'),
      a('GHSA-2pqj-h3vj-pqgw', 'CVE-2012-6708', 'medium', [['<=1.8.3']], '1.9.0', '$(string) treats any string containing < as HTML'),
    ],
  },
  {
    id: 'jquery-ui', name: 'jQuery UI',
    advisories: [
      a('GHSA-h6gj-6jjq-h8g9', 'CVE-2022-31160', 'medium', [['<1.13.2']], '1.13.2', 'checkboxradio turns label text into markup (XSS)'),
      a('GHSA-9gj3-hwp5-pmwc', 'CVE-2021-41182', 'medium', [['<1.13.0']], '1.13.0', 'Datepicker altField option runs untrusted code'),
      a('GHSA-j7qv-pgf6-hvh4', 'CVE-2021-41183', 'medium', [['<1.13.0']], '1.13.0', 'Datepicker *Text options run untrusted code'),
      a('GHSA-gpqq-952q-5327', 'CVE-2021-41184', 'medium', [['<1.13.0']], '1.13.0', '.position() "of" option runs untrusted code'),
      a('GHSA-hpcf-8vf9-q4gj', 'CVE-2016-7103', 'medium', [['<1.12.0']], '1.12.0', 'Dialog closeText XSS'),
    ],
  },
  {
    id: 'angularjs', name: 'AngularJS', eol: 'AngularJS support officially ended in January 2022; 1.8.3 is the last release and its advisories have no fix.',
    advisories: [
      a('GHSA-4w4v-5hc9-xrr2', 'CVE-2024-21490', 'high', [['>=1.3.0', '<=1.8.3']], null, 'ng-srcset regular expression causes ReDoS'),
      a('GHSA-prc3-vjfx-vhm9', 'CVE-2022-25869', 'medium', [['<=1.8.3']], null, 'XSS through textarea caching in old browsers'),
      a('GHSA-2vrf-hf26-jrp5', 'CVE-2023-26116', 'medium', [['<=1.8.3']], null, 'angular.copy() ReDoS'),
      a('GHSA-89mq-4x47-5v83', 'CVE-2019-10768', 'high', [['<1.7.9']], '1.7.9', 'Prototype pollution through merge()'),
      a('GHSA-mhp6-pxh8-r675', 'CVE-2020-7676', 'medium', [['<1.8.0']], '1.8.0', 'XSS through <option>/<select> handling in jqLite'),
    ],
  },
  {
    id: 'bootstrap', name: 'Bootstrap',
    advisories: [
      a('GHSA-9v3m-8fp8-mj99', 'CVE-2019-8331', 'medium', [['>=3.0.0', '<3.4.1'], ['>=4.0.0', '<4.3.1']], '3.4.1 / 4.3.1', 'Tooltip/popover data-template allows XSS'),
      a('GHSA-3wqf-4x89-9g79', 'CVE-2018-14040', 'medium', [['>=2.3.0', '<3.4.0'], ['>=4.0.0', '<4.1.2']], '3.4.0 / 4.1.2', 'collapse data-parent XSS'),
      a('GHSA-7mvr-5x2g-wfc8', 'CVE-2018-14042', 'medium', [['>=2.3.0', '<3.4.0'], ['>=4.0.0', '<4.1.2']], '3.4.0 / 4.1.2', 'tooltip data-container XSS'),
      a('GHSA-pj7m-g53m-7638', 'CVE-2018-14041', 'medium', [['>=4.0.0', '<4.1.2']], '4.1.2', 'scrollspy data-target XSS'),
      a('GHSA-vxmc-5x29-h64v', 'CVE-2024-6485', 'medium', [['>=1.4.0', '<=3.4.1']], null, 'Button data-loading-text XSS (Bootstrap 3 is end-of-life)'),
    ],
  },
  {
    id: 'lodash', name: 'Lodash',
    advisories: [
      a('GHSA-jf85-cpcp-j695', 'CVE-2019-10744', 'critical', [['<4.17.12']], '4.17.12', 'Prototype pollution in defaultsDeep'),
      a('GHSA-p6mc-m468-83gw', 'CVE-2020-8203', 'high', [['>=3.7.0', '<4.17.19']], '4.17.19', 'Prototype pollution in zipObjectDeep'),
      a('GHSA-35jh-r3h4-6jhm', 'CVE-2021-23337', 'high', [['<4.17.21']], '4.17.21', 'Code injection through _.template'),
      a('GHSA-xxjr-mmjv-4gpg', 'CVE-2025-13465', 'medium', [['>=4.0.0', '<=4.17.22']], '4.17.23', 'Prototype pollution in _.unset and _.omit'),
      a('GHSA-r5fr-rjxr-66jc', 'CVE-2026-4800', 'high', [['>=4.0.0', '<=4.17.23']], '4.18.0', 'Code injection through _.template imports key names'),
    ],
  },
  {
    id: 'moment', name: 'Moment.js',
    advisories: [
      a('GHSA-wc69-rhjr-hc9g', 'CVE-2022-31129', 'high', [['>=2.18.0', '<2.29.4']], '2.29.4', 'RFC 2822 date parsing ReDoS (can freeze the page)'),
    ],
  },
  {
    id: 'dompurify', name: 'DOMPurify',
    advisories: [
      a('GHSA-p3vf-v8qc-cwcr', 'CVE-2024-48910', 'critical', [['<2.4.2']], '2.4.2', 'Prototype pollution leading to sanitizer bypass'),
      a('GHSA-mmhx-hmjr-r674', 'CVE-2024-45801', 'high', [['<2.5.4'], ['>=3.0.0', '<3.1.3']], '2.5.4 / 3.1.3', 'Nesting-depth check bypass allows XSS'),
      a('GHSA-vhxf-7vqr-mrjg', 'CVE-2025-26791', 'medium', [['<3.2.4']], '3.2.4', 'Incorrect template literal handling allows mXSS'),
    ],
  },
];

/** Parses `1.2.3` (pre-release tags are dropped) into numbers, or `null`. */
export function parseVersion(v: string): [number, number, number] | null {
  const m = /^v?(\d+)\.(\d+)(?:\.(\d+))?/.exec(v.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)] : null;
}

/** -1, 0 or 1. */
export function compareVersions(x: string, y: string): number {
  const a = parseVersion(x);
  const b = parseVersion(y);
  if (!a || !b) return 0;
  for (let i = 0; i < 3; i++) {
    if ((a[i] as number) !== (b[i] as number)) return (a[i] as number) < (b[i] as number) ? -1 : 1;
  }
  return 0;
}

/** True when `version` satisfies one comparator such as `>=1.2.0` or `<3.5.0`. */
function satisfies(version: string, comparator: string): boolean {
  const m = /^(>=|<=|>|<|=)?\s*(.+)$/.exec(comparator.trim());
  if (!m) return false;
  const c = compareVersions(version, m[2] as string);
  switch (m[1] ?? '=') {
    case '>=': return c >= 0;
    case '<=': return c <= 0;
    case '>': return c > 0;
    case '<': return c < 0;
    default: return c === 0;
  }
}

/** True when `version` falls in any of the ranges. */
export function inRanges(version: string, ranges: string[][]): boolean {
  if (!parseVersion(version)) return false;
  return ranges.some((all) => all.every((c) => satisfies(version, c)));
}

/** The advisories that apply to one library version. */
export function advisoriesFor(libraryId: string, version: string): Advisory[] {
  const lib = LIBRARIES.find((l) => l.id === libraryId);
  return lib ? lib.advisories.filter((adv) => inRanges(version, adv.ranges)) : [];
}
