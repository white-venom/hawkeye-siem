import type { LogEvent, ParseResult, Status } from '../types.js';
import { clfTs, lines } from './util.js';

// NCSA combined - what nginx and apache both emit by default.
//
// The request is captured as one quoted blob rather than method/path/proto,
// because nginx logs the request line verbatim and attack traffic is full of
// unencoded spaces: `GET /x?id=1' OR 1=1-- HTTP/1.1`. Splitting on whitespace
// drops exactly the lines you most want to keep.
const COMBINED =
  /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

const REQUEST = /^([A-Z]+)\s+(.*?)(?:\s+(HTTP\/[\d.]+))?$/;

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
    const code = Number(m[6]);
    const req = REQUEST.exec(m[5]);
    // a request line that isn't even method + path is itself worth keeping
    const method = req ? req[1] : '-';
    const rawPath = req ? req[2] : m[5];

    const e: LogEvent = {
      ts,
      source: 'web',
      action: 'request',
      status: statusOf(code),
      raw: line,
      srcIp: m[1],
      method,
      // signature rules run against the decoded path; attackers url-encode
      path: safeDecode(rawPath),
      httpStatus: code,
      msg: method + ' ' + rawPath + ' -> ' + code,
    };
    if (m[3] && m[3] !== '-') e.user = m[3];
    if (m[7] && m[7] !== '-') e.bytes = Number(m[7]);
    if (m[9] && m[9] !== '-') e.userAgent = m[9];
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
