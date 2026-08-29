/** Everything in the console reads UTC - the samples are UTC and a SOC that
 *  quietly renders in the analyst's local zone is how timelines get argued
 *  about for an hour. */

const pad = (n: number) => String(n).padStart(2, '0');

export function hhmmss(ts: number): string {
  const d = new Date(ts);
  return pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds());
}

export function hhmm(ts: number): string {
  const d = new Date(ts);
  return pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());
}

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export function dayTime(ts: number): string {
  const d = new Date(ts);
  return d.getUTCDate() + ' ' + MON[d.getUTCMonth()] + ' ' + hhmm(ts);
}

export function num(n: number): string {
  return n.toLocaleString('en-US');
}

/** 12.4K / 1.2M - for axis ticks and stat notes where width is tight */
export function compact(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return (n / 1000).toFixed(n < 10_000 ? 1 : 0) + 'K';
  return (n / 1_000_000).toFixed(1) + 'M';
}

export function bytes(n: number): string {
  if (n < 1024) return n + ' B';
  if (n < 1_048_576) return (n / 1024).toFixed(0) + ' KB';
  if (n < 1_073_741_824) return (n / 1_048_576).toFixed(1) + ' MB';
  return (n / 1_073_741_824).toFixed(2) + ' GB';
}

export function pct(part: number, whole: number): string {
  if (!whole) return '0%';
  const p = (part / whole) * 100;
  return (p >= 10 || p === 0 ? p.toFixed(0) : p.toFixed(1)) + '%';
}

/** Escapes for the few places raw log text lands in innerHTML. */
export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}
