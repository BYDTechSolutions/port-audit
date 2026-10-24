/*
 * Front-end library versions, from two places only: the script URLs the
 * pages already reference, and the banners of same-origin scripts the pages
 * load. Third-party scripts are never fetched; their version comes from the
 * URL or not at all.
 */
import { capList, type Ctx } from '../context.js';
import { advisoriesFor, LIBRARIES } from '../facts/advisories.js';

interface Fingerprint {
  id: string;
  url: RegExp[];
  body: (text: string) => string | null;
}

const first = (re: RegExp) => (text: string) => re.exec(text)?.[1] ?? null;

/** How each library shows its version in a URL or in its distributed file. */
export const FINGERPRINTS: readonly Fingerprint[] = [
  { id: 'jquery', url: [/\/jquery[-.@/]v?(\d+\.\d+\.\d+)(?=[./-]|$)/i], body: first(/jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)/) },
  { id: 'jquery-ui', url: [/\/jquery[-.]?ui(?:-dist)?[-.@/]v?(\d+\.\d+\.\d+)/i, /code\.jquery\.com\/ui\/(\d+\.\d+\.\d+)\//i], body: first(/jQuery UI - v(\d+\.\d+\.\d+)/) },
  { id: 'angularjs', url: [/\/angular(?:\.js|js)?[-.@/]v?(1\.\d+\.\d+)/i], body: first(/AngularJS v(1\.\d+\.\d+)/) },
  { id: 'bootstrap', url: [/(?:\/|twitter-)bootstrap[-.@/]v?(\d+\.\d+\.\d+)/i], body: first(/Bootstrap v(\d+\.\d+\.\d+)/) },
  {
    id: 'lodash', url: [/\/lodash(?:\.js)?[-.@/]v?(\d+\.\d+\.\d+)/i],
    body: (t) => /lodash (\d+\.\d+\.\d+) \(Custom Build\)/i.exec(t)?.[1] ?? (/@license\s+Lodash|lodash\.com\/license/i.test(t) ? /\bVERSION\s*=\s*["'](4\.\d+\.\d+)["']/.exec(t)?.[1] ?? null : null),
  },
  {
    id: 'moment', url: [/\/moment(?:\.js)?[-.@/]v?(\d+\.\d+\.\d+)/i],
    body: (t) => /\/\/! version : (\d+\.\d+\.\d+)/.exec(t)?.[1] ?? (/isMoment/.test(t) ? /\.version\s*=\s*"(2\.\d+\.\d+)"/.exec(t)?.[1] ?? null : null),
  },
  { id: 'dompurify', url: [/\/dompurify[-.@/]v?(\d+\.\d+\.\d+)/i], body: first(/DOMPurify (\d+\.\d+\.\d+)/) },
];

/** Library versions named by one script URL. */
export function fromUrl(url: string): { id: string; version: string }[] {
  const out: { id: string; version: string }[] = [];
  for (const f of FINGERPRINTS) {
    for (const re of f.url) {
      const v = re.exec(url)?.[1];
      if (v) {
        out.push({ id: f.id, version: v });
        break;
      }
    }
  }
  return out;
}

/** Library versions announced in a script's text (banners and version constants). */
export function fromBody(text: string): { id: string; version: string }[] {
  const out: { id: string; version: string }[] = [];
  for (const f of FINGERPRINTS) {
    const v = f.body(text);
    if (v) out.push({ id: f.id, version: v });
  }
  return out;
}

/** Flags library versions in the bundled advisory list, and end-of-life lines. */
export async function checkLibraries(ctx: Ctx): Promise<void> {
  const found = new Map<string, { id: string; version: string; where: string }>();
  for (const s of await ctx.scripts()) {
    const hits = [...fromUrl(s.url), ...(s.body ? fromBody(s.body) : [])];
    for (const h of hits) {
      const key = `${h.id}@${h.version}`;
      if (!found.has(key)) found.set(key, { ...h, where: s.url });
    }
  }
  for (const { id, version, where } of found.values()) {
    const lib = LIBRARIES.find((l) => l.id === id);
    if (!lib) continue;
    const advisories = advisoriesFor(id, version);
    if (lib.eol) {
      ctx.add({ id: 'libraries/eol', url: where, key: id, title: `${lib.name} ${version} is end-of-life`, evidence: `${lib.name} ${version} found in ${where}. ${lib.eol}` });
    }
    if (advisories.length) {
      const worst = advisories.some((a) => a.severity === 'critical' || a.severity === 'high') ? 'high or critical' : 'medium';
      ctx.add({
        id: 'libraries/vulnerable', url: where, key: `${id}@${version}`,
        title: `${lib.name} ${version} has ${advisories.length} known ${advisories.length === 1 ? 'vulnerability' : 'vulnerabilities'}`,
        evidence: `${lib.name} ${version} found in ${where}; highest severity ${worst}.`,
        details: capList(advisories.map((a) => `${a.cve} (${a.severity}): ${a.summary}. Fixed in ${a.patched ?? 'no version'}. https://github.com/advisories/${a.ghsa}`), 6),
      });
    } else if (!lib.eol) {
      ctx.pass(`libraries/${id}`, `${lib.name} ${version}: no advisory in the bundled list`);
    }
  }
}
