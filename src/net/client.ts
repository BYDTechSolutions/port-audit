/*
 * Every request goes through `Client`: only to the target's host, only to an
 * address that passed the guard, at most `rate` per second, at most
 * `maxRequests` in total, with a body cap and a timeout. It never follows a
 * redirect by itself; `get` follows same-host redirects only when asked.
 *
 * node:http rather than fetch: fetch refuses TRACE, normalizes paths (so a
 * malformed or overlong path cannot be sent as is) and hides TLS details.
 */
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { PortAuditError } from '../errors.js';
import { bareHost } from '../target.js';
import { USER_AGENT } from '../version.js';

/** The methods this tool ever sends. No method that changes state is in the list. */
export type Method = 'GET' | 'HEAD' | 'OPTIONS' | 'TRACE' | 'POST';

/** A response, read up to the cap. */
export interface Response {
  url: string;
  method: Method;
  status: number;
  /** Lowercase header names; repeated headers joined with `, ` (except set-cookie). */
  headers: Record<string, string>;
  setCookies: string[];
  body: Buffer;
  text: string;
  truncated: boolean;
}

export interface RequestOptions {
  method?: Method;
  headers?: Record<string, string>;
  /** A request body; only used for the one malformed-JSON read on a `POST` path the user named. */
  body?: string;
  maxBytes?: number;
}

/** Spaces requests to a rate, backs off on 429/503, and stops at a hard cap. */
export class Limiter {
  sent = 0;
  skipped = 0;
  backoffs = 0;
  private interval: number;
  private next = 0;
  constructor(rate: number, readonly cap: number, private readonly now = () => Date.now(), private readonly sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))) {
    this.interval = 1000 / rate;
  }
  /** Waits for the next slot. Resolves `false` (and counts a skip) once the cap is reached. */
  async acquire(): Promise<boolean> {
    if (this.sent >= this.cap) {
      this.skipped++;
      return false;
    }
    this.sent++;
    const now = this.now();
    const at = Math.max(now, this.next);
    this.next = at + this.interval;
    if (at > now) await this.sleep(at - now);
    return true;
  }
  /** Slows down after a 429 or 503: doubles the spacing (up to 2 s) and waits out Retry-After (up to 10 s). */
  backoff(retryAfterSeconds?: number): void {
    this.backoffs++;
    this.interval = Math.min(2000, this.interval * 2);
    const wait = Math.min(10_000, Math.max(this.interval, (retryAfterSeconds ?? 0) * 1000));
    this.next = Math.max(this.next, this.now() + wait);
  }
}

export interface ClientOptions {
  host: string;
  addresses: string[];
  limiter: Limiter;
  timeoutMs: number;
  extraHeaders: Record<string, string>;
  maxBytes?: number;
}

/** Sends requests to one host. */
export class Client {
  /** The address that answered; the first one tried until something connects. */
  private address: string;
  readonly host: string;
  readonly limiter: Limiter;
  private readonly opts: ClientOptions;
  /** Network errors seen on probes, by message, for the notes. */
  readonly errors = new Map<string, number>();

  constructor(opts: ClientOptions) {
    this.opts = opts;
    this.host = opts.host;
    this.limiter = opts.limiter;
    this.address = opts.addresses[0] as string;
  }

  /** The address requests go to (the one that answered first). */
  get currentAddress(): string {
    return this.address;
  }

  /** Throws `REFUSED` unless the URL is on the target's host. Redirects and extra paths go through this too. */
  assertSameHost(url: URL): void {
    if (bareHost(url.hostname) !== this.host) {
      throw new PortAuditError('REFUSED', `Refusing to request ${url.origin}: only ${this.host} is in scope.`);
    }
  }

  /**
   * Tries each resolved address until one accepts a connection, then sticks
   * to it. Used once, for the first request.
   */
  async connect(url: URL): Promise<Response> {
    let last: Error | undefined;
    for (const address of this.opts.addresses) {
      this.address = address;
      try {
        const res = await this.request(url, { method: 'GET' });
        if (res) return res;
        throw new PortAuditError('UNREACHABLE', 'Request cap reached before the first request.');
      } catch (error) {
        last = error as Error;
        const code = (error as { code?: string }).code;
        if (code !== 'ECONNREFUSED' && code !== 'EADDRNOTAVAIL' && code !== 'EHOSTUNREACH' && code !== 'ENETUNREACH') break;
      }
    }
    const code = (last as { code?: string } | undefined)?.code;
    if (code === 'ECONNREFUSED') {
      throw new PortAuditError('UNREACHABLE', `Nothing is listening at ${url.host}. Start your app first, then run the audit again.`);
    }
    if (/EPROTO|SSL|wrong version/i.test(last?.message ?? '') && url.protocol === 'https:') {
      throw new PortAuditError('UNREACHABLE', `Could not speak TLS to ${url.host} (${last?.message}). If your server speaks plain HTTP, use http://${url.host}/`);
    }
    throw new PortAuditError('UNREACHABLE', `Could not reach ${url.href}: ${last?.message ?? 'unknown error'}`);
  }

  /**
   * Sends one request. Returns `null` when the request cap is reached. Throws
   * on network errors (the caller decides whether that matters).
   */
  async request(url: URL, options: RequestOptions = {}): Promise<Response | null> {
    this.assertSameHost(url);
    if (!(await this.limiter.acquire())) return null;
    const method = options.method ?? 'GET';
    const res = await this.send(url, method, options);
    if (res.status === 429 || res.status === 503) {
      const retry = Number(res.headers['retry-after']);
      this.limiter.backoff(Number.isFinite(retry) ? retry : undefined);
    }
    return res;
  }

  /** Like `request`, but network errors are counted for the notes and turned into `null`. */
  async probe(url: URL, options: RequestOptions = {}): Promise<Response | null> {
    try {
      return await this.request(url, options);
    } catch (error) {
      if (error instanceof PortAuditError) throw error;
      const message = (error as Error).message.replace(/\s+/g, ' ').slice(0, 120);
      this.errors.set(message, (this.errors.get(message) ?? 0) + 1);
      return null;
    }
  }

  /**
   * GET that follows redirects on the same host (at most 5). A redirect to
   * another host is not followed; the 3xx is returned with `offHost` set.
   */
  async get(url: URL): Promise<{ res: Response | null; hops: string[]; offHost?: string }> {
    const hops: string[] = [];
    let current = url;
    for (let i = 0; i <= 5; i++) {
      const res = await this.probe(current);
      if (!res) return { res, hops };
      const location = res.headers.location;
      if (![301, 302, 303, 307, 308].includes(res.status) || !location) return { res, hops };
      let next: URL;
      try {
        next = new URL(location, current);
      } catch {
        return { res, hops };
      }
      if (bareHost(next.hostname) !== this.host || (next.protocol !== 'http:' && next.protocol !== 'https:')) return { res, hops, offHost: next.origin };
      hops.push(`${res.status} ${current.href} -> ${next.href}`);
      current = next;
    }
    return { res: null, hops };
  }

  private send(url: URL, method: Method, options: RequestOptions): Promise<Response> {
    const lib = url.protocol === 'https:' ? https : http;
    const maxBytes = options.maxBytes ?? this.opts.maxBytes ?? 1_000_000;
    const headers: Record<string, string> = {
      'User-Agent': USER_AGENT,
      Accept: '*/*',
      ...this.opts.extraHeaders,
      ...options.headers,
      Host: url.host,
    };
    if (options.body !== undefined) headers['Content-Length'] = String(Buffer.byteLength(options.body));
    const servername = isIP(this.host) ? undefined : this.host;
    return new Promise<Response>((resolve, reject) => {
      const req = lib.request(
        {
          host: this.address,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: `${url.pathname}${url.search}`,
          method,
          headers,
          setHost: false,
          agent: false,
          timeout: this.opts.timeoutMs,
          // Dev servers use self-signed certificates; the TLS check reports trust separately.
          ...(url.protocol === 'https:' ? { rejectUnauthorized: false, servername } : {}),
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          let truncated = false;
          res.on('data', (chunk: Buffer) => {
            if (truncated) return;
            if (size + chunk.length > maxBytes) {
              chunks.push(chunk.subarray(0, maxBytes - size));
              size = maxBytes;
              truncated = true;
              res.destroy();
              finish();
              return;
            }
            chunks.push(chunk);
            size += chunk.length;
          });
          let done = false;
          const finish = () => {
            if (done) return;
            done = true;
            const flat: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (k === 'set-cookie' || v === undefined) continue;
              flat[k] = Array.isArray(v) ? v.join(', ') : v;
            }
            const body = Buffer.concat(chunks);
            resolve({
              url: url.href,
              method,
              status: res.statusCode ?? 0,
              headers: flat,
              setCookies: res.headers['set-cookie'] ?? [],
              body,
              text: body.toString('utf8'),
              truncated,
            });
          };
          res.on('end', finish);
          res.on('close', finish);
          res.on('error', (e) => (done ? undefined : reject(e)));
        },
      );
      req.on('timeout', () => req.destroy(Object.assign(new Error(`timed out after ${this.opts.timeoutMs} ms`), { code: 'ETIMEDOUT' })));
      req.on('error', reject);
      if (options.body !== undefined) req.write(options.body);
      req.end();
    });
  }
}
