/*
 * Just enough HTML reading for the checks: the attributes of <script>,
 * <link> and <meta> tags. Comments are dropped first so commented-out tags
 * are not reported.
 */

/** One start tag and its attributes (names lowercase). */
export interface Tag {
  name: 'script' | 'link' | 'meta';
  attrs: Record<string, string>;
}

/** Parses an attribute string such as `src="a.js" defer integrity='sha384-...'`. */
export function parseAttrs(text: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  for (const m of text.matchAll(re)) {
    const name = (m[1] as string).toLowerCase();
    if (!(name in attrs)) attrs[name] = (m[2] ?? m[3] ?? m[4] ?? '').trim();
  }
  return attrs;
}

/** The script, link and meta tags of a document. */
export function extractTags(html: string): Tag[] {
  const clean = html.replace(/<!--[\s\S]*?-->/g, '');
  const tags: Tag[] = [];
  for (const m of clean.matchAll(/<(script|link|meta)\b([^>]*)>/gi)) {
    tags.push({ name: (m[1] as string).toLowerCase() as Tag['name'], attrs: parseAttrs(m[2] ?? '') });
  }
  return tags;
}

/** True when the response is an HTML document. */
export function isHtml(contentType: string | undefined, body: string): boolean {
  if (contentType) return /text\/html|application\/xhtml/i.test(contentType);
  return /^\s*(<!doctype html|<html)/i.test(body);
}
