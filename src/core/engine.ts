import type { LogEvent, Severity, SourceKind } from './types.js';
import type { Detect, MitreRef, Rule } from './rules/types.js';
import { ms, where } from './rules/dsl.js';
import { geoLookup, haversineKm, type GeoResolver } from './geo.js';

export interface Match {
  ruleId: string;
  entity: Record<string, string>;
  entityKey: string;
  firstSeen: number;
  lastSeen: number;
  evidence: LogEvent[];
  /** values available to the rule's narrative template */
  vars: Record<string, string | number>;
}

export interface Alert {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  mitre: MitreRef;
  description: string;
  entity: Record<string, string>;
  firstSeen: number;
  lastSeen: number;
  narrative: string;
  evidence: LogEvent[];
  sources: SourceKind[];
}

export interface EvalContext {
  geo: GeoResolver;
}

const DEFAULT_CTX: EvalContext = { geo: geoLookup };

function keyOf(e: LogEvent, fields: string[]): string | null {
  const parts: string[] = [];
  for (const f of fields) {
    const v = (e as unknown as Record<string, unknown>)[f];
    if (v === undefined || v === null || v === '') return null;
    parts.push(String(v));
  }
  return parts.join('|');
}

function entityOf(e: LogEvent, fields: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of fields) out[f] = String((e as unknown as Record<string, unknown>)[f]);
  return out;
}

/** Bucket events by the rule's groupBy key, each bucket sorted by time.
 *  Events missing any part of the key are dropped - a port-scan rule keyed on
 *  srcIp has nothing to say about an event with no source address. */
function group(events: LogEvent[], fields: string[]): Map<string, LogEvent[]> {
  const m = new Map<string, LogEvent[]>();
  for (const e of events) {
    const k = keyOf(e, fields);
    if (k === null) continue;
    const arr = m.get(k);
    if (arr) arr.push(e);
    else m.set(k, [e]);
  }
  for (const arr of m.values()) arr.sort((a, b) => a.ts - b.ts);
  return m;
}

export function humanSpan(msSpan: number): string {
  if (msSpan < 1000) return msSpan + 'ms';
  const s = Math.round(msSpan / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return rs ? m + 'm' + rs + 's' : m + 'm';
  const h = Math.floor(m / 60);
  return h + 'h' + (m % 60) + 'm';
}

function uniq<T>(xs: T[]): T[] {
  return [...new Set(xs)];
}

function commonVars(evidence: LogEvent[]): Record<string, string | number> {
  const span = evidence[evidence.length - 1].ts - evidence[0].ts;
  return {
    count: evidence.length,
    span: humanSpan(span),
    users: uniq(evidence.map((e) => e.user).filter(Boolean) as string[]).slice(0, 6).join(', '),
    ports: uniq(evidence.map((e) => e.port).filter((p): p is number => p !== undefined))
      .slice(0, 12)
      .join(', '),
    paths: uniq(evidence.map((e) => e.path).filter(Boolean) as string[]).slice(0, 4).join(', '),
  };
}

function runThreshold(rule: Rule, d: Extract<Detect, { type: 'threshold' }>, events: LogEvent[]): Match[] {
  const pred = where(d.where);
  const win = ms(d.within);
  const out: Match[] = [];

  const tally = (slice: LogEvent[]): number => {
    if (d.distinct) {
      return new Set(
        slice
          .map((e) => (e as unknown as Record<string, unknown>)[d.distinct!])
          .filter((v) => v !== undefined && v !== null),
      ).size;
    }
    if (d.sum) {
      return slice.reduce((acc, e) => {
        const v = (e as unknown as Record<string, unknown>)[d.sum!];
        return acc + (typeof v === 'number' ? v : 0);
      }, 0);
    }
    return slice.length;
  };

  for (const [key, bucket] of group(events.filter(pred), d.groupBy)) {
    let start = 0;
    for (let j = 0; j < bucket.length; j++) {
      while (bucket[j].ts - bucket[start].ts > win) start++;
      if (tally(bucket.slice(start, j + 1)) < d.count) continue;

      // stretch the window as far as it will go so the alert carries the whole
      // burst, then jump past it - overlapping alerts help nobody
      let end = j;
      while (end + 1 < bucket.length && bucket[end + 1].ts - bucket[start].ts <= win) end++;
      const evidence = bucket.slice(start, end + 1);
      const vars = commonVars(evidence);
      if (d.distinct) vars.distinct = tally(evidence);
      if (d.sum) {
        const total = tally(evidence);
        vars.sum = total;
        vars.mb = (total / 1_048_576).toFixed(1);
      }
      out.push({
        ruleId: rule.id,
        entity: entityOf(evidence[0], d.groupBy),
        entityKey: key,
        firstSeen: evidence[0].ts,
        lastSeen: evidence[evidence.length - 1].ts,
        evidence,
        vars,
      });
      start = end + 1;
      j = end;
    }
  }
  return out;
}

function runSequence(rule: Rule, d: Extract<Detect, { type: 'sequence' }>, events: LogEvent[]): Match[] {
  const steps = d.steps.map((s) => ({ ...s, pred: where(s.where), need: s.count ?? 1 }));
  const win = ms(d.within);
  const out: Match[] = [];

  for (const [key, bucket] of group(events, d.groupBy)) {
    let i = 0;
    while (i < bucket.length) {
      if (!steps[0].pred(bucket[i])) {
        i++;
        continue;
      }
      const anchor = bucket[i].ts;
      const evidence: LogEvent[] = [];
      let stepIdx = 0;
      let got = 0;
      let j = i;
      let doneAt = -1;

      for (; j < bucket.length && bucket[j].ts - anchor <= win; j++) {
        if (!steps[stepIdx].pred(bucket[j])) continue;
        evidence.push(bucket[j]);
        got++;
        if (got < steps[stepIdx].need) continue;
        stepIdx++;
        got = 0;
        if (stepIdx === steps.length) {
          doneAt = j;
          break;
        }
      }

      if (doneAt === -1) {
        i++;
        continue;
      }
      const vars = commonVars(evidence);
      // per-step counts, so a narrative can say "12 failures then 1 success"
      steps.forEach((s) => {
        vars[s.label] = evidence.filter((e) => s.pred(e)).length;
      });
      const last = evidence[evidence.length - 1];
      if (last.user) vars.user = last.user;
      out.push({
        ruleId: rule.id,
        entity: entityOf(evidence[0], d.groupBy),
        entityKey: key,
        firstSeen: evidence[0].ts,
        lastSeen: last.ts,
        evidence,
        vars,
      });
      i = doneAt + 1;
    }
  }
  return out;
}

function runGeoVelocity(
  rule: Rule,
  d: Extract<Detect, { type: 'geo_velocity' }>,
  events: LogEvent[],
  ctx: EvalContext,
): Match[] {
  const pred = where(d.where);
  const win = ms(d.within);
  const out: Match[] = [];

  for (const [key, bucket] of group(events.filter(pred), d.groupBy)) {
    for (let i = 1; i < bucket.length; i++) {
      const prev = bucket[i - 1];
      const cur = bucket[i];
      if (!prev.srcIp || !cur.srcIp || prev.srcIp === cur.srcIp) continue;
      const dt = cur.ts - prev.ts;
      if (dt <= 0 || dt > win) continue;
      const a = ctx.geo(prev.srcIp);
      const b = ctx.geo(cur.srcIp);
      if (!a || !b) continue;
      const km = haversineKm(a, b);
      if (km < d.minKm) continue;
      const kmh = km / (dt / 3_600_000);
      if (kmh < d.minKmh) continue;

      const evidence = [prev, cur];
      out.push({
        ruleId: rule.id,
        entity: entityOf(cur, d.groupBy),
        entityKey: key,
        firstSeen: prev.ts,
        lastSeen: cur.ts,
        evidence,
        vars: {
          ...commonVars(evidence),
          from: a.city + ', ' + a.cc,
          to: b.city + ', ' + b.cc,
          fromIp: prev.srcIp,
          toIp: cur.srcIp,
          km: Math.round(km),
          kmh: Math.round(kmh),
          gap: humanSpan(dt),
        },
      });
    }
  }
  return out;
}

export function evaluate(rule: Rule, events: LogEvent[], ctx: EvalContext = DEFAULT_CTX): Match[] {
  switch (rule.detect.type) {
    case 'threshold':
      return runThreshold(rule, rule.detect, events);
    case 'sequence':
      return runSequence(rule, rule.detect, events);
    case 'geo_velocity':
      return runGeoVelocity(rule, rule.detect, events, ctx);
  }
}

export function render(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (whole, k: string) => {
    const v = vars[k];
    return v === undefined ? whole : String(v);
  });
}

/** Matches -> alerts. Two matches from the same rule about the same entity get
 *  folded together when their windows touch, so one long brute-force run is a
 *  single card in the feed instead of forty. */
export function correlate(rules: Rule[], matches: Match[]): Alert[] {
  const byRule = new Map(rules.map((r) => [r.id, r]));
  const open = new Map<string, Alert>();
  const out: Alert[] = [];

  for (const m of [...matches].sort((a, b) => a.firstSeen - b.firstSeen)) {
    const rule = byRule.get(m.ruleId);
    if (!rule) continue;
    const gap = ms(rule.detect.within);
    const k = m.ruleId + '::' + m.entityKey;
    const cur = open.get(k);

    if (cur && m.firstSeen - cur.lastSeen <= gap) {
      cur.lastSeen = Math.max(cur.lastSeen, m.lastSeen);
      const seen = new Set(cur.evidence.map((e) => e.raw + '@' + e.ts));
      for (const e of m.evidence) {
        if (!seen.has(e.raw + '@' + e.ts)) cur.evidence.push(e);
      }
      cur.evidence.sort((a, b) => a.ts - b.ts);
      cur.sources = uniq(cur.evidence.map((e) => e.source));
      cur.narrative = render(rule.narrative, {
        ...m.vars,
        ...m.entity,
        ...commonVars(cur.evidence),
        count: cur.evidence.length,
      });
      continue;
    }

    const alert: Alert = {
      id: k + '::' + m.firstSeen,
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      mitre: rule.mitre,
      description: rule.description,
      entity: m.entity,
      firstSeen: m.firstSeen,
      lastSeen: m.lastSeen,
      narrative: render(rule.narrative, { ...m.vars, ...m.entity }),
      evidence: m.evidence,
      sources: uniq(m.evidence.map((e) => e.source)),
    };
    open.set(k, alert);
    out.push(alert);
  }

  return out;
}

/** The whole pipeline: events in, alerts out. */
export function detect(rules: Rule[], events: LogEvent[], ctx: EvalContext = DEFAULT_CTX): Alert[] {
  const active = rules.filter((r) => r.enabled !== false);
  const matches = active.flatMap((r) => evaluate(r, events, ctx));
  return correlate(active, matches);
}
