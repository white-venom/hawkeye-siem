/** End-to-end over the bundled data: raw text in, alerts out. This is what
 *  catches a sample file drifting out of step with a rule threshold. */
import { describe, expect, it } from 'vitest';
import { DATASETS, REPLAY, SAMPLE_YEAR } from '../src/data/index.js';
import { getParser, sortByTime } from '../src/core/parsers/index.js';
import { detect } from '../src/core/engine.js';
import { RULES } from '../src/core/rules/index.js';
import type { LogEvent } from '../src/core/types.js';

const opts = { year: SAMPLE_YEAR };

function loadSamples(): { events: LogEvent[]; skipped: number; total: number } {
  let skipped = 0;
  let total = 0;
  const events: LogEvent[] = [];
  for (const d of DATASETS) {
    const r = getParser(d.parser).parse(d.text, opts);
    events.push(...r.events);
    skipped += r.skipped.length;
    total += r.events.length + r.skipped.length;
  }
  return { events: sortByTime(events), skipped, total };
}

function loadReplay(): LogEvent[] {
  const events: LogEvent[] = [];
  for (const step of REPLAY) {
    events.push(...getParser(step.parser).parse(step.line, opts).events);
  }
  return sortByTime(events);
}

const firedIds = (events: LogEvent[]) => new Set(detect(RULES, events).map((a) => a.ruleId));

describe('bundled datasets', () => {
  it('parse cleanly - only the deliberate pam noise is dropped', () => {
    const { events, skipped, total } = loadSamples();
    expect(events.length).toBeGreaterThan(1000);
    expect(skipped / total).toBeLessThan(0.05);
  });

  it('all land on the same March 2025 day', () => {
    const { events } = loadSamples();
    const day = (ts: number) => new Date(ts).toISOString().slice(0, 10);
    expect(new Set(events.map((e) => day(e.ts)))).toEqual(new Set(['2025-03-12']));
  });

  it('cover every source', () => {
    const { events } = loadSamples();
    expect(new Set(events.map((e) => e.source))).toEqual(new Set(['ssh', 'web', 'windows', 'firewall']));
  });

  it('trip exactly the rules the scenarios were written for', () => {
    const fired = firedIds(loadSamples().events);
    expect([...fired].sort()).toEqual(
      [
        'admin-group-change',
        'firewall-port-scan',
        'impossible-travel',
        'ssh-password-spray',
        'web-content-discovery',
        'web-path-traversal',
        'web-sqli',
        'web-xss',
      ].sort(),
    );
  });

  it('name the right actors in the alerts', () => {
    const alerts = detect(RULES, loadSamples().events);
    const by = (id: string) => alerts.find((a) => a.ruleId === id)!;
    expect(by('impossible-travel').entity.user).toBe('j.harper');
    expect(by('impossible-travel').narrative).toMatch(/London.*Singapore/);
    expect(by('firewall-port-scan').entity.srcIp).toBe('185.220.101.42');
    expect(by('ssh-password-spray').entity.srcIp).toBe('45.83.220.19');
    expect(by('web-content-discovery').entity.srcIp).toBe('198.51.100.23');
    expect(by('web-sqli').entity.srcIp).toBe('91.219.236.88');
  });

  it('do not fire the noisy volume rules on ordinary background traffic', () => {
    const fired = firedIds(loadSamples().events);
    expect(fired.has('data-exfil-volume')).toBe(false);
    expect(fired.has('privilege-escalation-burst')).toBe(false);
    expect(fired.has('ssh-brute-force')).toBe(false);
  });
});

describe('replay incident', () => {
  it('every scripted line parses', () => {
    for (const step of REPLAY) {
      const r = getParser(step.parser).parse(step.line, opts);
      expect(r.events, step.line).toHaveLength(1);
    }
  });

  it('walks the phases in order', () => {
    const seen: string[] = [];
    for (const s of REPLAY) if (seen.at(-1) !== s.phase) seen.push(s.phase);
    expect(seen).toEqual([
      'Reconnaissance',
      'Credential access',
      'Privilege escalation',
      'Persistence',
      'Exfiltration',
      'Defence evasion',
    ]);
    // one pass through each phase, no flip-flopping
    expect(new Set(seen).size).toBe(seen.length);
  });

  it('lights up the whole kill chain when replayed on top of the samples', () => {
    const fired = firedIds([...loadSamples().events, ...loadReplay()]);
    for (const id of [
      'firewall-port-scan',
      'ssh-brute-force',
      'privilege-escalation-burst',
      'admin-group-change',
      'data-exfil-volume',
      'audit-log-cleared',
    ]) {
      expect(fired.has(id), id + ' did not fire').toBe(true);
    }
  });

  it('produces a critical alert for the exfil, with the volume in the headline', () => {
    const alerts = detect(RULES, loadReplay());
    const exfil = alerts.find((a) => a.ruleId === 'data-exfil-volume')!;
    expect(exfil.severity).toBe('critical');
    expect(exfil.entity.srcIp).toBe('10.10.4.22');
    expect(Number(exfil.narrative.split(' ')[0])).toBeGreaterThan(20);
  });

  it('finishes in under two minutes of wall time', () => {
    const total = REPLAY.reduce((a, s) => a + s.delay, 0);
    expect(total).toBeGreaterThan(10_000);
    expect(total).toBeLessThan(120_000);
  });
});
