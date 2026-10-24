import { clip, type Ctx } from '../context.js';

const WEBDAV = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'SEARCH'];

/** One OPTIONS and one TRACE request to the audited path. Neither changes anything on the server. */
export async function checkMethods(ctx: Ctx): Promise<void> {
  const path = ctx.base.pathname + ctx.base.search;
  const options = await ctx.fetch(path, { method: 'OPTIONS' });
  if (options) {
    const allow = (options.headers.allow ?? options.headers['public'] ?? '').toUpperCase().split(/[\s,]+/).filter(Boolean);
    const odd = allow.filter((m) => WEBDAV.includes(m) || m === 'CONNECT' || m === 'TRACK');
    if (odd.length) ctx.add({ id: 'methods/webdav', url: options.url, evidence: `OPTIONS answered "Allow: ${allow.join(', ')}"; unexpected: ${odd.join(', ')}.` });
    else if (allow.length) ctx.pass('methods/webdav', `OPTIONS lists ${allow.join(', ')}`);
  }
  const trace = await ctx.fetch(path, { method: 'TRACE', headers: { 'X-Port-Audit-Trace': 'echo-check' } });
  if (trace) {
    const echoed = trace.status >= 200 && trace.status < 300 && (/message\/http/i.test(trace.headers['content-type'] ?? '') || /^TRACE \S+ HTTP\/1\.[01]/m.test(trace.text) || trace.text.includes('echo-check'));
    if (echoed) ctx.add({ id: 'methods/trace', url: trace.url, evidence: `TRACE returned HTTP ${trace.status} and echoed the request: ${clip(trace.text, 120)}` });
    else ctx.pass('methods/trace', `TRACE is refused (HTTP ${trace.status})`);
  }
}
