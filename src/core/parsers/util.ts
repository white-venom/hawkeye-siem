/** Shared bits for the parsers. Everything here is pure - no Date.now(), no DOM. */

const MONTHS: Record<string, number> = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};

export interface ParseOptions {
  /** syslog lines carry no year, so callers have to supply one */
  year?: number;
}

/** "Mar 12 08:14:22" -> epoch ms, treated as UTC.
 *
 * Real syslog is in the host's local zone, but pinning to UTC keeps the tests
 * (and anyone else's machine) honest. Noted in the README.
 */
export function syslogTs(month: string, day: string, time: string, year: number): number {
  const m = MONTHS[month.slice(0, 3).toLowerCase()];
  if (m === undefined) return Number.NaN;
  const [hh, mm, ss] = time.split(':').map(Number);
  return Date.UTC(year, m, Number(day), hh, mm, ss);
}

/** "12/Mar/2025:08:14:22 +0000" (CLF) -> epoch ms */
export function clfTs(s: string): number {
  const m = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$/.exec(s.trim());
  if (!m) return Number.NaN;
  const mon = MONTHS[m[2].toLowerCase()];
  if (mon === undefined) return Number.NaN;
  const base = Date.UTC(Number(m[3]), mon, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6]));
  if (!m[7]) return base;
  const sign = m[7][0] === '-' ? 1 : -1;
  const offMin = Number(m[7].slice(1, 3)) * 60 + Number(m[7].slice(3, 5));
  return base + sign * offMin * 60_000;
}

export function lines(text: string): string[] {
  return text.split(/\r?\n/);
}

/** Pull KEY=VALUE pairs out of a line (iptables, sudo, pam all do this). */
export function kv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([A-Za-z_][A-Za-z0-9_]*)=([^\s]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) out[m[1]] = m[2];
  return out;
}

export function toInt(v: string | undefined): number | undefined {
  if (v === undefined) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}
