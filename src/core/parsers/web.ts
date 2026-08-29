import type { LogEvent, ParseResult, Status } from '../types.js';
import { clfTs, lines } from './util.js';

// NCSA combined - what nginx and apache both emit by default.
const COMBINED =
  /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)(?:\s+(\S+))?"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

function statusOf(code: number): Status {
  if (code >= 500) return 'error';
  if (code >= 400) return 'failure';
  return 'success';
}

export function parseWeb(text: string): ParseResult {
  const events: LogEvent[] = [];
  const skipped: ParseResult['skipped'] = [];

  lines(text).forEach((line, idx) => {
    if (!line.trim()) return;
    const m = COMBINED.exec(line);
    if (!m) {
      skipped.push({ line: idx + 1, text: line });
      return;
    }
    const ts = clfTs(m[4]);
    if (Number.isNaN(ts)) {
      skipped.push({ line: idx + 1, text: line });
      return;
    }
    const code = Number(m[8]);
    const e: LogEvent = {
      ts,
      source: 'web',
      action: 'request',
      status: statusOf(code),
      raw: line,
      srcIp: m[1],
      method: m[5],
      // signature rules run against the decoded path; attackers url-encode
      path: safeDecode(m[6]),
      httpStatus: code,
      msg: m[5] + ' ' + m[6] + ' -> ' + code,
    };
    if (m[3] && m[3] !== '-') e.user = m[3];
    if (m[9] && m[9] !== '-') e.bytes = Number(m[9]);
    if (m[11] && m[11] !== '-') e.userAgent = m[11];
    events.push(e);
  });

  return { events, skipped };
}

function safeDecode(p: string): string {
  try {
    return decodeURIComponent(p.replace(/\+/g, ' '));
  } catch {
    return p; // malformed %-escapes are themselves a signal, keep the original
  }
}
