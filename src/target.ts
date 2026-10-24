/*
 * The safety boundary: which hosts a scan may reach. By default only your own
 * machine and private networks; any other host needs `iOwnThis` naming it
 * exactly. The check runs on the name, again on every address the name
 * resolves to, and the client then connects only to an address that passed.
 */
import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { PortAuditError } from './errors.js';

/** Parses dotted-quad IPv4 into four numbers, or `null`. */
function v4(text: string): number[] | null {
  const parts = text.split('.');
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return null;
  return parts.map(Number);
}

/** True for 127.0.0.0/8 and the RFC 1918 ranges (10/8, 172.16/12, 192.168/16). */
export function isAllowedIPv4(text: string): boolean {
  const o = v4(text);
  if (!o) return false;
  const [a = 0, b = 0] = o;
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/** True for `::1`, and for IPv4-mapped addresses (`::ffff:a.b.c.d`) whose IPv4 address is allowed. */
export function isAllowedIPv6(text: string): boolean {
  const t = text.toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  if (isIP(t) !== 6) return false;
  if (/^(0{0,4}:){1,7}0{0,3}1$/.test(t) || t === '::1') return true;
  const mapped = /^(?:0{0,4}:){0,5}:?ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(t);
  if (mapped) return isAllowedIPv4(mapped[1] as string);
  const hex = /^(?:0{0,4}:){0,5}:?ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(t);
  if (hex) {
    const hi = parseInt(hex[1] as string, 16);
    const lo = parseInt(hex[2] as string, 16);
    return isAllowedIPv4([hi >> 8, hi & 255, lo >> 8, lo & 255].join('.'));
  }
  return false;
}

/** True when an IP address (v4 or v6) is in the default allowed ranges. */
export function isAllowedAddress(address: string): boolean {
  return isIP(address.replace(/^\[|\]$/g, '')) === 6 ? isAllowedIPv6(address) : isAllowedIPv4(address);
}

/**
 * True when a hostname is allowed by default: `localhost`, `*.localhost`,
 * `*.test`, or an IP literal in 127.0.0.0/8, `::1` or RFC 1918.
 */
export function isAllowedHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.test')) return true;
  return isIP(host) ? isAllowedAddress(host) : false;
}

/**
 * Turns what the user typed into a URL: a port (`3000`), `host:port`, or a
 * full http(s) URL. Bare ports and hosts get `http://`, as dev servers mostly
 * speak plain HTTP.
 */
export function parseTarget(input: string | number): URL {
  let text = String(input).trim();
  if (/^\d{1,5}$/.test(text)) text = `http://localhost:${text}/`;
  else if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = `http://${text}`;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new PortAuditError('INVALID_TARGET', `Not a valid URL or port: ${input}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new PortAuditError('INVALID_TARGET', `Only http and https targets can be audited, not ${url.protocol.replace(':', '')}.`);
  }
  if (url.username || url.password) throw new PortAuditError('INVALID_TARGET', 'Put credentials in --header, not in the URL.');
  const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new PortAuditError('INVALID_TARGET', `Not a valid port: ${url.port}`);
  url.hash = '';
  return url;
}

/** Lowercase host without IPv6 brackets or a trailing dot. */
export function bareHost(hostname: string): string {
  return hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

/** A target that passed the guard: the addresses the client may connect to. */
export interface ResolvedTarget {
  url: URL;
  host: string;
  addresses: string[];
  /** True when `iOwnThis` let a host outside the default ranges through. */
  owned: boolean;
}

/**
 * Checks the target against the safety rules and resolves it. Throws
 * `REFUSED` for a host outside the allowed ranges (unless `iOwnThis` names
 * exactly that host), and for an allowed name that resolves to an address
 * outside them.
 */
export async function resolveTarget(
  url: URL,
  iOwnThis: string | undefined,
  lookup: (host: string) => Promise<{ address: string; family: number }[]> = (host) => dnsLookup(host, { all: true, verbatim: true }),
): Promise<ResolvedTarget> {
  const host = bareHost(url.hostname);
  const owned = !!iOwnThis && bareHost(iOwnThis) === host;
  if (!owned && !isAllowedHost(host)) {
    const hint = iOwnThis ? ` (--i-own-this names ${iOwnThis}, which is not this host)` : '';
    throw new PortAuditError(
      'REFUSED',
      `Refusing to scan ${host}: only localhost, 127.0.0.0/8, ::1, private networks (10/8, 172.16/12, 192.168/16), *.localhost and *.test are allowed by default${hint}. If you own ${host}, pass --i-own-this ${host}.`,
    );
  }
  let addresses: string[];
  if (isIP(host)) addresses = [host];
  else {
    try {
      addresses = (await lookup(host)).map((a) => a.address);
    } catch (error) {
      throw new PortAuditError('UNREACHABLE', `Could not resolve ${host}: ${(error as Error).message}`);
    }
    if (!addresses.length) throw new PortAuditError('UNREACHABLE', `Could not resolve ${host}.`);
  }
  if (!owned) {
    const bad = addresses.find((a) => !isAllowedAddress(a));
    if (bad) {
      throw new PortAuditError('REFUSED', `Refusing to scan ${host}: it resolves to ${bad}, which is outside the allowed ranges. If you own it, pass --i-own-this ${host}.`);
    }
  }
  return { url, host, addresses, owned };
}

/** The reminder printed when `iOwnThis` lets a host through. */
export function ownershipReminder(host: string): string {
  return `Scanning ${host} because you said you own it. Only scan systems you own or have written permission to test; scanning others' systems may be illegal.`;
}
