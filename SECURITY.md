# Security policy

## Reporting a vulnerability

Please email **sales.bydtech@gmail.com** with the details, instead of opening a
public issue. We will acknowledge the report and keep you posted on the fix.

## Scope

`port-audit` sends a small number of passive HTTP reads (GET, OPTIONS, TRACE)
and, for https targets, two TLS handshakes to the one host you name. By default
that host must be your own machine or a private network; any other host needs
`--i-own-this` naming it exactly. It re-checks every resolved address, never
follows a redirect to another host, never fetches third-party URLs, sends no
telemetry, and writes only the report you ask for.

Especially welcome:

- any way to make it send a request to a host other than the target, or to a
  public address without `--i-own-this` (DNS tricks, redirects, crafted URLs or
  paths);
- any way to make it send something other than a passive read;
- output that carries a raw `--header` value, cookie value or token (every
  format is meant to redact them);
- a crafted response that makes it crash, hang or exceed the request cap.

It is a narrow, passive scanner. A vulnerability it does not look for is
expected, not a security issue in the tool, but an issue with the example is
still useful.
