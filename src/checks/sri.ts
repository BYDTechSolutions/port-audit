import { capList, type Ctx } from '../context.js';

/** True when the URL path carries a version (`@1.2.3`, `/1.2.3/`, `-1.2.3.min.js`), so its content should never change. */
export function looksVersioned(url: string): boolean {
  try {
    return /(?:[@/-]v?\d+\.\d+(?:\.\d+)?(?:[./-]|$))/.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

/** Third-party <script> and stylesheet tags without an integrity attribute, read from the HTML the app serves. */
export async function checkSri(ctx: Ctx): Promise<void> {
  const scripts = new Map<string, string>();
  const styles = new Map<string, string>();
  let thirdParty = 0;
  for (const page of ctx.pages) {
    if (!page.html) continue;
    const origin = new URL(page.res.url).origin;
    for (const t of page.tags) {
      const isScript = t.name === 'script' && t.attrs.src;
      const isStyle = t.name === 'link' && /(^|\s)stylesheet(\s|$)/i.test(t.attrs.rel ?? '') && t.attrs.href;
      if (!isScript && !isStyle) continue;
      let url: URL;
      try {
        url = new URL((isScript ? t.attrs.src : t.attrs.href) as string, page.res.url);
      } catch {
        continue;
      }
      if (url.origin === origin || (url.protocol !== 'http:' && url.protocol !== 'https:')) continue;
      thirdParty++;
      if (t.attrs.integrity) continue;
      (isScript ? scripts : styles).set(url.href, page.res.url);
    }
  }
  const describe = (list: string[]) => list.map((u) => (looksVersioned(u) ? u : `${u} (not versioned: SRI needs a fixed file; self-host it or record why not)`));
  if (scripts.size) {
    const list = [...scripts.keys()];
    const versioned = list.filter(looksVersioned).length;
    ctx.add({
      id: 'sri/missing-script', url: [...scripts.values()][0] as string,
      evidence: `${list.length} third-party script(s) without integrity${versioned ? `, ${versioned} of them versioned` : ''}.`,
      details: capList(describe(list)),
      priority: versioned ? undefined : 'nice-to-have',
    });
  }
  if (styles.size) {
    const list = [...styles.keys()];
    ctx.add({ id: 'sri/missing-style', url: [...styles.values()][0] as string, evidence: `${list.length} third-party stylesheet(s) without integrity.`, details: capList(describe(list)) });
  }
  if (thirdParty && !scripts.size && !styles.size) ctx.pass('sri/integrity', `${thirdParty} third-party script(s)/stylesheet(s) carry integrity hashes`);
  if (!thirdParty && ctx.pages.some((p) => p.html)) ctx.pass('sri/integrity', 'No third-party scripts or stylesheets in the HTML');
}
