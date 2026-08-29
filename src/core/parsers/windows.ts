import type { LogEvent, ParseResult, Status } from '../types.js';
import { lines } from './util.js';

/** Event ID -> (action, status, blurb). Only the IDs a small SOC actually
 *  watches; anything else falls through as a generic 'wineventlog' event. */
const IDS: Record<number, { action: string; status: Status; label: string }> = {
  4624: { action: 'login', status: 'success', label: 'account logged on' },
  4625: { action: 'login', status: 'failure', label: 'account failed to log on' },
  4634: { action: 'logoff', status: 'info', label: 'account logged off' },
  4648: { action: 'login', status: 'info', label: 'logon with explicit credentials' },
  4672: { action: 'priv_assigned', status: 'success', label: 'special privileges assigned to new logon' },
  4688: { action: 'process_create', status: 'info', label: 'new process created' },
  4720: { action: 'account_created', status: 'success', label: 'user account created' },
  4728: { action: 'group_add', status: 'success', label: 'member added to security-enabled global group' },
  4732: { action: 'group_add', status: 'success', label: 'member added to security-enabled local group' },
  4740: { action: 'account_lockout', status: 'failure', label: 'user account locked out' },
  1102: { action: 'log_cleared', status: 'success', label: 'audit log cleared' },
  7045: { action: 'service_install', status: 'success', label: 'service installed' },
};

interface RawWinEvent {
  '@timestamp'?: string;
  timestamp?: string;
  event_id?: number | string;
  EventID?: number | string;
  computer?: string;
  channel?: string;
  target_user?: string;
  subject_user?: string;
  user?: string;
  ip?: string;
  src_ip?: string;
  logon_type?: number;
  process?: string;
  message?: string;
  privileges?: string;
  [k: string]: unknown;
}

/** Accepts JSON-lines (one object per line) or a single JSON array.
 *  Shape follows what winlogbeat/NXLog ship. */
export function parseWindows(text: string): ParseResult {
  const events: LogEvent[] = [];
  const skipped: ParseResult['skipped'] = [];

  const trimmed = text.trim();
  if (trimmed.startsWith('[')) {
    let arr: unknown;
    try {
      arr = JSON.parse(trimmed);
    } catch {
      return { events, skipped: [{ line: 1, text: trimmed.slice(0, 200) }] };
    }
    (arr as RawWinEvent[]).forEach((o, i) => {
      const e = convert(o, JSON.stringify(o));
      if (e) events.push(e);
      else skipped.push({ line: i + 1, text: JSON.stringify(o).slice(0, 200) });
    });
    return { events, skipped };
  }

  lines(trimmed).forEach((line, idx) => {
    if (!line.trim()) return;
    let obj: RawWinEvent;
    try {
      obj = JSON.parse(line);
    } catch {
      skipped.push({ line: idx + 1, text: line });
      return;
    }
    const e = convert(obj, line);
    if (e) events.push(e);
    else skipped.push({ line: idx + 1, text: line });
  });

  return { events, skipped };
}

function convert(o: RawWinEvent, raw: string): LogEvent | null {
  const tsStr = o['@timestamp'] ?? o.timestamp;
  const ts = tsStr ? Date.parse(tsStr) : Number.NaN;
  const id = Number(o.event_id ?? o.EventID);
  if (Number.isNaN(ts) || !Number.isFinite(id)) return null;

  const known = IDS[id];
  const e: LogEvent = {
    ts,
    source: 'windows',
    action: known?.action ?? 'wineventlog',
    status: known?.status ?? 'info',
    raw,
    eventId: id,
    host: o.computer,
    msg: o.message ?? known?.label,
  };

  const user = o.target_user ?? o.user ?? o.subject_user;
  if (user && user !== '-') e.user = user;
  const ip = o.ip ?? o.src_ip;
  if (ip && ip !== '-' && ip !== '::1') e.srcIp = ip;
  if (o.process) e.process = o.process;

  return e;
}
