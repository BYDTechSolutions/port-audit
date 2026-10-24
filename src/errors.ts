/**
 * Why an audit could not run.
 *
 * - `INVALID_TARGET`: the target is not an http(s) URL or port.
 * - `REFUSED`: the target is outside the allowed hosts (see the safety rules).
 * - `UNREACHABLE`: nothing answered at the target.
 */
export type PortAuditErrorCode = 'INVALID_TARGET' | 'REFUSED' | 'UNREACHABLE';

/** The one error type `auditPort` throws on purpose. */
export class PortAuditError extends Error {
  readonly code: PortAuditErrorCode;
  constructor(code: PortAuditErrorCode, message: string) {
    super(message);
    this.name = 'PortAuditError';
    this.code = code;
  }
}
