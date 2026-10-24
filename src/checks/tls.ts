import type { Ctx } from '../context.js';
import { acceptsLegacyTls, inspectTls } from '../net/tls.js';

const DAY = 86_400_000;

/** Certificate and protocol checks when the target is https. Two handshakes, each counted against the cap. */
export async function checkTls(ctx: Ctx, now = Date.now()): Promise<void> {
  const url = ctx.base;
  if (url.protocol !== 'https:') {
    if (!ctx.local) ctx.add({ id: 'tls/no-https', url: url.href, evidence: `The target is ${url.origin}, plain HTTP.` });
    return;
  }
  const port = Number(url.port || 443);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!(await ctx.client.limiter.acquire())) return;
  let info;
  try {
    info = await inspectTls(ctx.address(), port, host, ctx.timeoutMs);
  } catch (error) {
    ctx.note(`TLS handshake failed: ${(error as Error).message}`);
    return;
  }
  const where = url.origin;
  if (info.validTo) {
    const expires = Date.parse(info.validTo);
    const days = Math.floor((expires - now) / DAY);
    if (expires < now) ctx.add({ id: 'tls/cert-expired', url: where, evidence: `Certificate expired on ${info.validTo} (subject ${info.subject ?? 'unknown'}).`, priority: ctx.local ? 'should-fix' : undefined });
    else if (days < 14) ctx.add({ id: 'tls/cert-expiring', url: where, evidence: `Certificate expires on ${info.validTo}, in ${days} day(s).` });
    else ctx.pass('tls/expiry', `Certificate valid until ${info.validTo}`);
  }
  if (info.hostnameError) ctx.add({ id: 'tls/hostname-mismatch', url: where, evidence: info.hostnameError, priority: ctx.local ? 'nice-to-have' : undefined });
  if (!info.authorized && info.authorizationError && !/CERT_HAS_EXPIRED/.test(info.authorizationError)) {
    if (ctx.local) ctx.note(`The certificate is not trusted by Node (${info.authorizationError}); that is normal for a development certificate. Production needs a publicly trusted one.`);
    else ctx.add({ id: 'tls/untrusted', url: where, evidence: `Certificate not trusted: ${info.authorizationError} (issuer ${info.issuer ?? 'unknown'}).` });
  }
  if (info.protocol) ctx.pass('tls/protocol', `Negotiated ${info.protocol}`);

  if (!(await ctx.client.limiter.acquire())) return;
  const legacy = await acceptsLegacyTls(ctx.address(), port, host, ctx.timeoutMs);
  if (legacy) ctx.add({ id: 'tls/legacy-protocol', url: where, evidence: `A handshake offering only TLS 1.0 and 1.1 succeeded with ${legacy}.` });
  else ctx.pass('tls/legacy', 'TLS 1.0 and 1.1 are refused');
}
