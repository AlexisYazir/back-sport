import type { Request } from 'express';

export type HttpAuditRequest = Request<
  Record<string, string>,
  unknown,
  unknown
> & {
  session?: unknown;
};

export function isAuditRecord(
  value: unknown,
): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
