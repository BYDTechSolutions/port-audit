/*
 * What every check gets: the client, the target, the responses so far, and
 * `add` / `pass` / `note` to report. Checks never build a full Finding; the
 * audit fills in the rule text, snippets, redaction and fingerprint.
 */
import type { Tag } from './html.js';
import type { Client, RequestOptions, Response } from './net/client.js';
import type { Priority } from './types.js';

/** What a check reports; the rest comes from the rule. */
export interface RawFinding {
  id: string;
  url: string;
  evidence: string;
  details?: string[];
  /** Overrides the rule's priority for this finding. */
  priority?: Priority;
  /** Overrides the rule's title for this finding. */
  title?: string;
  /** Distinguishes findings of one rule on one path (e.g. the parameter name). */
  key?: string;
}

/** A page the audit read: the main page, and any extra --path pages. */
export interface Page {
  res: Response;
  /** Script, link and meta tags (empty when the page is not HTML). */
  tags: Tag[];
  html: boolean;
}

/** A script the pages load: its URL, whether it is same-origin, and its body when it was read. */
export interface Script {
  url: string;
  sameOrigin: boolean;
  /** The first bytes of a same-origin script; `null` for third-party scripts, which are never fetched. */
  body: string | null;
}

export interface Ctx {
  client: Client;
  /** The audited URL after same-host redirects. */
  base: URL;
  /** True when the host is in the default allowed ranges (your machine or a private network). */
  local: boolean;
  /** The main page first, then the extra --path pages that answered. */
  pages: Page[];
  /** Extra paths the user asked to include (GET only). */
  paths: string[];
  timeoutMs: number;
  /** The resolved address the client connects to, for the TLS handshakes. */
  address: () => string;
  /** Every response so far, for detection, cookies and disclosure. */
  responses: Response[];
  /** Sends a request to a path on the target and records the response; `null` on cap or network error. */
  fetch: (path: string, options?: RequestOptions) => Promise<Response | null>;
  /** The scripts the pages load; same-origin ones are read once (capped), third-party ones never. */
  scripts: () => Promise<Script[]>;
  add: (f: RawFinding) => void;
  pass: (id: string, title: string) => void;
  note: (message: string) => void;
}

/** At most `n` lines, with a "... and N more" line. */
export function capList(items: string[], n = 8): string[] {
  return items.length <= n ? items : [...items.slice(0, n), `... and ${items.length - n} more`];
}

/** Shortens text for evidence. */
export function clip(text: string, n = 160): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}
