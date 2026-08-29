/** The common schema every parser has to produce. Everything downstream — rules,
 *  correlation, the UI — only ever sees this shape, never raw log text. */

export type SourceKind = 'ssh' | 'web' | 'windows' | 'firewall';

/** Deliberately small. Parsers squash vendor-specific outcomes into these so a
 *  rule can say `status = failure` without caring who emitted the line. */
export type Status = 'success' | 'failure' | 'blocked' | 'allowed' | 'error' | 'info';

export interface LogEvent {
  /** epoch ms */
  ts: number;
  source: SourceKind;
  /** normalised verb: login, request, connection, sudo, priv_assigned, ... */
  action: string;
  status: Status;
  raw: string;

  srcIp?: string;
  dstIp?: string;
  port?: number;
  user?: string;
  host?: string;
  proto?: string;

  // web
  method?: string;
  path?: string;
  httpStatus?: number;
  bytes?: number;
  userAgent?: string;

  // windows
  eventId?: number;
  process?: string;

  /** free-text remainder, handy for signature rules */
  msg?: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export interface ParseResult {
  events: LogEvent[];
  /** lines the parser could not make sense of, with 1-based line numbers */
  skipped: { line: number; text: string }[];
}
