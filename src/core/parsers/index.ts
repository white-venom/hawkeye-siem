import type { LogEvent, ParseResult, SourceKind } from '../types.js';
import type { ParseOptions } from './util.js';
import { parseSsh } from './ssh.js';
import { parseWeb } from './web.js';
import { parseWindows } from './windows.js';
import { parseFirewall } from './firewall.js';

export type ParserId = 'ssh' | 'web' | 'windows' | 'firewall';

export interface ParserInfo {
  id: ParserId;
  label: string;
  source: SourceKind;
  hint: string;
  parse: (text: string, opts?: ParseOptions) => ParseResult;
}

export const PARSERS: ParserInfo[] = [
  {
    id: 'ssh',
    label: 'Linux auth.log (OpenSSH + sudo)',
    source: 'ssh',
    hint: 'Mar 12 08:14:22 web-01 sshd[24196]: Failed password for root from 203.0.113.45 port 51234 ssh2',
    parse: parseSsh,
  },
  {
    id: 'web',
    label: 'Nginx / Apache access log (combined)',
    source: 'web',
    hint: '203.0.113.45 - - [12/Mar/2025:08:14:22 +0000] "GET /index.php HTTP/1.1" 200 512 "-" "curl/8.4.0"',
    parse: parseWeb,
  },
  {
    id: 'windows',
    label: 'Windows Security log (JSON lines)',
    source: 'windows',
    hint: '{"@timestamp":"2025-03-12T08:14:22Z","event_id":4625,"computer":"DC-01","target_user":"admin","ip":"203.0.113.45"}',
    parse: parseWindows,
  },
  {
    id: 'firewall',
    label: 'Firewall (UFW/iptables + Cisco ASA)',
    source: 'firewall',
    hint: 'Mar 12 08:14:22 fw-edge kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.45 DST=10.10.4.22 PROTO=TCP SPT=51234 DPT=22',
    parse: parseFirewall,
  },
];

export function getParser(id: ParserId): ParserInfo {
  const p = PARSERS.find((x) => x.id === id);
  if (!p) throw new Error('no such parser: ' + id);
  return p;
}

/** Cheap format sniffing for pasted text. Good enough to pre-select the
 *  dropdown; the user can always override. */
export function detectParser(text: string): ParserId | null {
  const sample = text
    .split(/\r?\n/)
    .filter((l) => l.trim())
    .slice(0, 40);
  if (!sample.length) return null;

  const score: Record<ParserId, number> = { ssh: 0, web: 0, windows: 0, firewall: 0 };
  for (const l of sample) {
    if (/^\s*[[{]/.test(l) && /event_?id|EventID/i.test(l)) score.windows += 2;
    if (/kernel:.*SRC=/.test(l) || /%ASA-\d-\d{6}/.test(l)) score.firewall += 2;
    if (/sshd\[\d+\]|sudo:/.test(l)) score.ssh += 2;
    if (/"\s*(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH)\s+\S+/.test(l) && /\[\d{2}\/\w{3}\/\d{4}/.test(l)) {
      score.web += 2;
    }
  }
  const best = (Object.keys(score) as ParserId[]).sort((a, b) => score[b] - score[a])[0];
  return score[best] > 0 ? best : null;
}

export function sortByTime(events: LogEvent[]): LogEvent[] {
  return [...events].sort((a, b) => a.ts - b.ts);
}

export { parseSsh, parseWeb, parseWindows, parseFirewall };
export type { ParseOptions };
