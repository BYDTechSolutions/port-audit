import type { Ctx } from '../context.js';

/** A made-up origin under the reserved .invalid TLD (RFC 2606): it can never resolve or belong to anyone. */
export const PROBE_ORIGIN = 'https://port-audit-origin.invalid';

/**
 * Two reads per path, each with an Origin header: a foreign origin and
 * `null`. Nothing else is sent; a reflected value in Access-Control-Allow-Origin
 * is the finding.
 */
export async function checkCors(ctx: Ctx): Promise<void> {
  const paths = [ctx.base.pathname + ctx.base.search, ...ctx.paths];
  let flagged = false;
  for (const path of [...new Set(paths)].slice(0, 6)) {
    for (const origin of [PROBE_ORIGIN, 'null']) {
      const res = await ctx.fetch(path, { headers: { Origin: origin } });
      if (!res) continue;
      const acao = (res.headers['access-control-allow-origin'] ?? '').trim();
      const creds = (res.headers['access-control-allow-credentials'] ?? '').trim().toLowerCase() === 'true';
      const ev = `Request with "Origin: ${origin}" got "Access-Control-Allow-Origin: ${acao}"${creds ? ' and "Access-Control-Allow-Credentials: true"' : ''}.`;
      if (origin === PROBE_ORIGIN && acao === PROBE_ORIGIN && creds) {
        ctx.add({ id: 'cors/reflected-credentials', url: res.url, evidence: ev, key: path });
        flagged = true;
      } else if (origin === 'null' && acao === 'null') {
        ctx.add({ id: 'cors/null-origin', url: res.url, evidence: ev, key: path, priority: creds ? 'fix-now' : undefined });
        flagged = true;
      } else if (origin === PROBE_ORIGIN && acao === '*' && creds) {
        ctx.add({ id: 'cors/wildcard-credentials', url: res.url, evidence: ev, key: path });
        flagged = true;
      }
    }
  }
  if (!flagged) ctx.pass('cors/origin', 'CORS does not reflect foreign or null origins with credentials');
}
