import type { Severity } from '../types.js';

/** Three detector shapes cover every rule we ship. Anything more exotic would
 *  be a sign the DSL is trying to become a programming language. */
export type Detect =
  /** N matching events inside a sliding window, grouped by some key. `distinct`
   *  counts unique values of a field instead of rows (port scans); `sum` totals
   *  a numeric field instead (bytes out the door). Either way `count` is the
   *  number that has to be reached. */
  | {
      type: 'threshold';
      where: string;
      groupBy: string[];
      within: string;
      count: number;
      distinct?: string;
      sum?: string;
    }
  /** Ordered steps that all have to land inside one window for the same key.
   *  This is what turns "lots of failures" into "they got in". */
  | {
      type: 'sequence';
      groupBy: string[];
      within: string;
      steps: { label: string; where: string; count?: number }[];
    }
  /** Same principal, two locations, not enough time in between. */
  | {
      type: 'geo_velocity';
      where: string;
      groupBy: string[];
      within: string;
      minKm: number;
      minKmh: number;
    };

export interface MitreRef {
  id: string;
  name: string;
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  mitre: MitreRef;
  /** why an analyst should care, in one or two sentences */
  description: string;
  /** alert headline, with {placeholders} filled from the match */
  narrative: string;
  detect: Detect;
  /** shipped rules default to on; the UI can flip this */
  enabled?: boolean;
}
