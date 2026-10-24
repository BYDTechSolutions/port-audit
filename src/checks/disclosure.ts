import type { Ctx } from '../context.js';
import { headerCase } from '../detect.js';

/** Server and framework names with versions in any response header seen during the run. */
export async function checkDisclosure(ctx: Ctx): Promise<void> {
  const seen = new Map<string, string>();
  let url = ctx.base.href;
  for (const r of ctx.responses) {
    for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
      const value = r.headers[name];
      if (!value) continue;
      // Server without a version ("nginx", "cloudflare") is fine; X-Powered-By is flagged whatever it says.
      if (name === 'server' && !/\d/.test(value)) continue;
      const key = `${headerCase(name)}: ${value}`;
      if (!seen.has(key)) {
        if (!seen.size) url = r.url;
        seen.set(key, r.url);
      }
    }
  }
  if (seen.size) ctx.add({ id: 'disclosure/version-header', url, evidence: [...seen.keys()].join('; ') });
  else ctx.pass('disclosure/version-header', 'No version numbers or X-Powered-By in response headers');
}
