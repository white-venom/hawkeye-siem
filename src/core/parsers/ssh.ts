import type { LogEvent, ParseResult } from '../types.js';
import { kv, lines, syslogTs, type ParseOptions } from './util.js';

const SYSLOG = /^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w.\-/]+)(?:\[(\d+)\])?:\s*(.*)$/;

// Ordered - first match wins, so put the specific patterns above the loose ones.
const PATTERNS: {
  re: RegExp;
  apply: (m: RegExpExecArray, e: LogEvent) => void;
}[] = [
  {
    re: /^Accepted (\w+) for (?:invalid user )?(\S+) from (\S+) port (\d+)/,
    apply: (m, e) => {
      e.action = 'login';
      e.status = 'success';
      e.user = m[2];
      e.srcIp = m[3];
      e.port = Number(m[4]);
      e.msg = m[1] + ' auth accepted';
    },
  },
  {
    re: /^Failed (\w+) for (invalid user )?(\S+) from (\S+) port (\d+)/,
    apply: (m, e) => {
      e.action = 'login';
      e.status = 'failure';
      e.user = m[3];
      e.srcIp = m[4];
      e.port = Number(m[5]);
      e.msg = m[2] ? 'failed auth for unknown account' : 'failed auth';
    },
  },
  {
    re: /^Invalid user (\S+) from (\S+)(?: port (\d+))?/,
    apply: (m, e) => {
      e.action = 'invalid_user';
      e.status = 'failure';
      e.user = m[1];
      e.srcIp = m[2];
      if (m[3]) e.port = Number(m[3]);
      e.msg = 'unknown account probed';
    },
  },
  {
    re: /^error: maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+) port (\d+)/,
    apply: (m, e) => {
      e.action = 'login';
      e.status = 'failure';
      e.user = m[1];
      e.srcIp = m[2];
      e.port = Number(m[3]);
      e.msg = 'max auth attempts exceeded';
    },
  },
  {
    // pam_unix spells the same failure a second way; both show up in real logs
    re: /^pam_unix\(sshd:auth\): authentication failure;.*rhost=(\S+)\s+user=(\S+)/,
    apply: (m, e) => {
      e.action = 'login';
      e.status = 'failure';
      e.srcIp = m[1];
      e.user = m[2];
      e.msg = 'pam authentication failure';
    },
  },
  {
    re: /^Connection closed by (?:authenticating user (\S+) )?(\S+) port (\d+)/,
    apply: (m, e) => {
      e.action = 'disconnect';
      e.status = 'info';
      if (m[1]) e.user = m[1];
      e.srcIp = m[2];
      e.port = Number(m[3]);
      e.msg = 'connection closed';
    },
  },
  {
    re: /^Disconnected from (?:authenticating user (\S+) )?(\S+) port (\d+)/,
    apply: (m, e) => {
      e.action = 'disconnect';
      e.status = 'info';
      if (m[1]) e.user = m[1];
      e.srcIp = m[2];
      e.port = Number(m[3]);
      e.msg = 'disconnected';
    },
  },
];

/** OpenSSH + sudo lines from /var/log/auth.log (Debian/Ubuntu flavour). */
export function parseSsh(text: string, opts: ParseOptions = {}): ParseResult {
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
    const [, mon, day, time, host, prog, , rest] = s;
    const ts = syslogTs(mon, day, time, year);
    if (Number.isNaN(ts)) {
      skipped.push({ line: idx + 1, text: line });
      return;
    }

    const e: LogEvent = { ts, source: 'ssh', action: 'other', status: 'info', raw: line, host };

    if (prog.startsWith('sudo')) {
      applySudo(rest, e);
      events.push(e);
      return;
    }
    if (!prog.startsWith('sshd')) {
      skipped.push({ line: idx + 1, text: line });
      return;
    }

    const hit = PATTERNS.find((p) => p.re.test(rest));
    if (!hit) {
      skipped.push({ line: idx + 1, text: line });
      return;
    }
    hit.apply(hit.re.exec(rest)!, e);
    events.push(e);
  });

  return { events, skipped };
}

function applySudo(rest: string, e: LogEvent): void {
  // deploy : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/bin/cat /etc/shadow
  const who = /^(\S+)\s*:/.exec(rest);
  if (who) e.user = who[1];
  const fields = kv(rest);
  e.action = 'sudo';
  e.process = /COMMAND=(.*)$/.exec(rest)?.[1]?.trim();
  if (/incorrect password attempt|authentication failure|not in the sudoers/.test(rest)) {
    e.status = 'failure';
    e.msg = 'sudo denied';
  } else {
    e.status = 'success';
    e.msg = 'sudo to ' + (fields.USER ?? 'root');
  }
}
