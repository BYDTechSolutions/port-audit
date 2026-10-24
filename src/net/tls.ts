/*
 * Two TLS handshakes, no HTTP: one with Node's defaults to read the
 * certificate and negotiated protocol, one offering only TLS 1.0/1.1 to see
 * whether the server still accepts them. Each counts as a request.
 */
import { isIP } from 'node:net';
import tls from 'node:tls';

/** What the handshake showed. */
export interface TlsInfo {
  protocol: string | null;
  authorized: boolean;
  authorizationError: string | null;
  validTo: string | null;
  validFrom: string | null;
  subject: string | null;
  issuer: string | null;
  /** `null` when the certificate matches the host, else the reason. */
  hostnameError: string | null;
  selfSigned: boolean;
}

function handshake(address: string, port: number, host: string, timeoutMs: number, extra: tls.ConnectionOptions): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: address, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, ...extra });
    socket.setTimeout(timeoutMs, () => socket.destroy(new Error(`timed out after ${timeoutMs} ms`)));
    socket.once('secureConnect', () => resolve(socket));
    socket.once('error', reject);
  });
}

/** Reads the certificate and protocol with Node's default settings. */
export async function inspectTls(address: string, port: number, host: string, timeoutMs: number): Promise<TlsInfo> {
  const socket = await handshake(address, port, host, timeoutMs, {});
  try {
    const cert = socket.getPeerCertificate();
    const has = cert && Object.keys(cert).length > 0;
    let hostnameError: string | null = null;
    if (has) {
      const err = tls.checkServerIdentity(host, cert);
      hostnameError = err ? err.message : null;
    }
    const authError = socket.authorizationError ? String(socket.authorizationError) : null;
    const name = (o: Record<string, unknown> | undefined) => (o ? Object.entries(o).map(([k, v]) => `${k}=${String(v)}`).join(', ') : null);
    return {
      protocol: socket.getProtocol(),
      authorized: socket.authorized,
      authorizationError: authError,
      validTo: has ? cert.valid_to : null,
      validFrom: has ? cert.valid_from : null,
      subject: has ? name(cert.subject as unknown as Record<string, unknown>) : null,
      issuer: has ? name(cert.issuer as unknown as Record<string, unknown>) : null,
      hostnameError,
      selfSigned: /SELF_SIGNED/.test(authError ?? ''),
    };
  } finally {
    socket.destroy();
  }
}

/** Returns the protocol when the server completes a handshake offering only TLS 1.0 and 1.1, else `null`. */
export async function acceptsLegacyTls(address: string, port: number, host: string, timeoutMs: number): Promise<string | null> {
  try {
    const socket = await handshake(address, port, host, timeoutMs, { minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT@SECLEVEL=0' });
    const protocol = socket.getProtocol();
    socket.destroy();
    return protocol;
  } catch {
    return null;
  }
}
