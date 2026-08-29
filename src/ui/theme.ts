import type { Severity, SourceKind } from '../core/types.js';

/** Series colours for the four log sources.
 *
 * Order matters: these were checked for adjacent-pair colourblind separation on
 * a white surface (worst pair dE 10.9 tritan / 19.7 normal) and the stacked
 * chart draws them in this order. Re-ordering or swapping a hue by eye breaks
 * that, so re-run the validator if you touch it. None of the four sits in the
 * same hue family as a severity colour, so a series can never impersonate a
 * status.
 */
export const SOURCE_COLOR: Record<SourceKind, string> = {
  ssh: '#0891a5',
  windows: '#4a3aa7',
  web: '#eb6834',
  firewall: '#c2358c',
};

export const SOURCE_ORDER: SourceKind[] = ['ssh', 'windows', 'web', 'firewall'];

export const SOURCE_LABEL: Record<SourceKind, string> = {
  ssh: 'ssh',
  windows: 'windows',
  web: 'web',
  firewall: 'firewall',
};

/** Status palette - reserved, never reused for a series, and always shipped
 *  next to the severity word so colour is never carrying it alone. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#d03b3b',
  high: '#ec835a',
  medium: '#fab219',
  low: '#0ca30c',
  info: '#8a9ba1',
};

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const INK = {
  primary: '#0c1417',
  secondary: '#4a5c63',
  muted: '#8a9ba1',
  grid: '#dde7ea',
  axis: '#c6d6db',
  surface: '#ffffff',
  accent: '#0891a5',
  accentLift: '#22b8cf',
};

export const MONO = "500 10px 'IBM Plex Mono', ui-monospace, Menlo, Consolas, monospace";
