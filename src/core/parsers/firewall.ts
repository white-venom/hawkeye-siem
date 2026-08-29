import type { LogEvent, ParseResult, Status } from '../types.js';
import { kv, lines, syslogTs, toInt, type ParseOptions } from './util.js';

const SYSLOG = /^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$/;

// Linux: netfilter/UFW kernel lines with a KEY=VALUE tail.
const UFW = /^kernel:\s*\[?(UFW|IPTABLES)\s+([A-Z]+)\]?\s*(.*)$/;

// Cisco ASA: the two message IDs worth parsing for detection work.
const ASA_DENY =
  /%ASA-\d-106023:\s*Deny\s+(\w+)\s+src\s+\S+:([\d.]+)\/(\d+)\s+dst\s+\S+:([\d.]+)\/(\d+)/;
const ASA_TEARDOWN =
  /%ASA-\d-302014:\s*Teardown\s+(\w+)\s+connection\s+\d+\s+for\s+\S+:([\d.]+)\/(\d+)\s+to\s+\S+:([\d.]+)\/(\d+)\s+duration\s+\S+\s+bytes\s+(\d+)/;

const VERDICTS: Record<string, Status> = {
  BLOCK: 'blocked',
  DENY: 'blocked',
  DROP: 'blocked',
  REJECT: 'blocked',
  ALLOW: 'allowed',
  ACCEPT: 'allowed',
  AUDIT: 'info',
};

/** Two device families, one normalised shape: netfilter/UFW on Linux hosts and
 *  Cisco ASA at the edge. ASA is the only one of the two that reports byte
 *  counts, which is what the exfil rule needs. */
export function parseFirewall(text: string, opts: ParseOptions = {}): ParseResult {
  const year = opts.year ?? new Date().getUTCFullYear();
  const events: LogEvent[] = [];
  const skipped: ParseResult['skipped'] = [];

  lines(text).forEach((line, idx) => {
    if (!line.trim()) return;
    const s = SYSLOG.exec(line);
    if (!s) {
      skipped.push({ line: idx + 1, text: line });
      return;
    }
    const ts = syslogTs(s[1], s[2], s[3], year);
    const host = s[4];
    const rest = s[5];
    if (Number.isNaN(ts)) {
      skipped.push({ line: idx + 1, text: line });
      return;
    }

    const e = ufw(rest, ts, host, line) ?? asa(rest, ts, host, line);
    if (e) events.push(e);
    else skipped.push({ line: idx + 1, text: line });
  });

  return { events, skipped };
}

function ufw(rest: string, ts: number, host: string, raw: string): LogEvent | null {
  const m = UFW.exec(rest);
  if (!m) return null;
  const f = kv(m[3]);
  if (!f.SRC) return null;
  const verdict = m[2];
  return {
    ts,
    source: 'firewall',
    action: 'connection',
    status: VERDICTS[verdict] ?? 'info',
    raw,
    host,
    srcIp: f.SRC,
    dstIp: f.DST,
    port: toInt(f.DPT),
    proto: f.PROTO,
    msg:
      verdict.toLowerCase() +
      ' ' +
      (f.PROTO ?? 'ip') +
      ' ' +
      f.SRC +
      ' -> ' +
      (f.DST ?? '?') +
      (f.DPT ? ':' + f.DPT : ''),
  };
}

function asa(rest: string, ts: number, host: string, raw: string): LogEvent | null {
  const d = ASA_DENY.exec(rest);
  if (d) {
    return {
      ts,
      source: 'firewall',
      action: 'connection',
      status: 'blocked',
      raw,
      host,
      proto: d[1].toUpperCase(),
      srcIp: d[2],
      dstIp: d[4],
      port: Number(d[5]),
      msg: 'deny ' + d[1] + ' ' + d[2] + ' -> ' + d[4] + ':' + d[5],
    };
  }

  const t = ASA_TEARDOWN.exec(rest);
  if (t) {
    return {
      ts,
      source: 'firewall',
      action: 'connection',
      status: 'allowed',
      raw,
      host,
      proto: t[1].toUpperCase(),
      srcIp: t[2],
      dstIp: t[4],
      port: Number(t[5]),
      bytes: Number(t[6]),
      msg: 'flow closed ' + t[2] + ' -> ' + t[4] + ':' + t[5] + ' ' + t[6] + ' bytes',
    };
  }

  return null;
}
