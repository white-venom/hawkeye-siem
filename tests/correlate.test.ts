import { describe, expect, it } from 'vitest';
import { correlate, detect, evaluate, humanSpan, render } from '../src/core/engine.js';
import type { Rule } from '../src/core/rules/types.js';
import type { LogEvent } from '../src/core/types.js';

const T0 = Date.UTC(2025, 2, 12, 9, 0, 0);
const min = (n: number) => n * 60_000;

const RULE: Rule = {
  id: 'test-burst',
  name: 'Test burst',
  severity: 'high',
  mitre: { id: 'T1110', name: 'Brute Force' },
  description: 'Three or more failures from one address inside five minutes. Test fixture.',
  narrative: '{count} failures from {srcIp} in {span}',
  detect: { type: 'threshold', where: 'status = failure', groupBy: ['srcIp'], within: '5m', count: 3 },
};

const fail = (atMin: number, ip = '203.0.113.45'): LogEvent => ({
  ts: T0 + min(atMin),
  source: 'ssh',
  action: 'login',
  status: 'failure',
  srcIp: ip,
  raw: 'fail@' + atMin + ' ' + ip,
});

describe('correlation', () => {
  it('folds overlapping bursts for one entity into a single alert', () => {
    // two bursts a minute apart - one incident, not two cards
    const events = [0, 0.5, 1, 1.5, 2, 2.5].map((m) => fail(m));
    const alerts = detect([RULE], events);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].evidence).toHaveLength(6);
    expect(alerts[0].firstSeen).toBe(T0);
    expect(alerts[0].lastSeen).toBe(T0 + min(2.5));
  });

  it('opens a second alert once the window has gone cold', () => {
    const events = [...[0, 0.5, 1].map((m) => fail(m)), ...[40, 40.5, 41].map((m) => fail(m))];
    const alerts = detect([RULE], events);
    expect(alerts).toHaveLength(2);
    expect(alerts[1].firstSeen).toBe(T0 + min(40));
  });

  it('keeps different entities apart', () => {
    const events = [
      ...[0, 0.5, 1].map((m) => fail(m, '203.0.113.45')),
      ...[0, 0.5, 1].map((m) => fail(m, '198.51.100.9')),
    ];
    const alerts = detect([RULE], events);
    expect(alerts).toHaveLength(2);
    expect(new Set(alerts.map((a) => a.entity.srcIp))).toEqual(new Set(['203.0.113.45', '198.51.100.9']));
  });

  it('never double-counts an event that lands in two matches', () => {
    const events = [0, 0.5, 1, 1.5, 2].map((m) => fail(m));
    const alerts = detect([RULE], events);
    const keys = alerts[0].evidence.map((e) => e.raw);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('carries severity, MITRE tag and contributing sources onto the alert', () => {
    const mixed = [fail(0), { ...fail(0.5), source: 'windows' as const }, fail(1)];
    const [alert] = detect([RULE], mixed);
    expect(alert.severity).toBe('high');
    expect(alert.mitre.id).toBe('T1110');
    expect(alert.ruleName).toBe('Test burst');
    expect(new Set(alert.sources)).toEqual(new Set(['ssh', 'windows']));
  });

  it('renders the narrative from the match', () => {
    const [alert] = detect([RULE], [0, 0.5, 1].map((m) => fail(m)));
    expect(alert.narrative).toBe('3 failures from 203.0.113.45 in 1m');
  });

  it('skips disabled rules', () => {
    expect(detect([{ ...RULE, enabled: false }], [0, 0.5, 1].map((m) => fail(m)))).toHaveLength(0);
  });

  it('produces nothing from an empty stream', () => {
    expect(detect([RULE], [])).toEqual([]);
    expect(correlate([RULE], [])).toEqual([]);
  });

  it('is order-independent - shuffled input gives the same alerts', () => {
    const events = [0, 0.5, 1, 1.5, 2].map((m) => fail(m));
    const shuffled = [events[3], events[0], events[4], events[1], events[2]];
    expect(detect([RULE], shuffled)).toEqual(detect([RULE], events));
  });

  it('leaves alerts in first-seen order for the feed to re-sort', () => {
    const events = [...[0, 0.5, 1].map((m) => fail(m)), ...[40, 40.5, 41].map((m) => fail(m, '198.51.100.9'))];
    const alerts = detect([RULE], events);
    expect(alerts[0].firstSeen).toBeLessThan(alerts[1].firstSeen);
  });
});

describe('sliding window edges', () => {
  const at = (ms: number) => ({ ...fail(0), ts: T0 + ms });

  it('counts an event exactly on the window boundary', () => {
    const alerts = detect([RULE], [at(0), at(min(2.5)), at(min(5))]);
    expect(alerts).toHaveLength(1);
  });

  it('does not count one a millisecond past it', () => {
    const alerts = detect([RULE], [at(0), at(min(2.5)), at(min(5) + 1)]);
    expect(alerts).toHaveLength(0);
  });
});

describe('helpers', () => {
  it('formats spans the way an analyst reads them', () => {
    expect(humanSpan(400)).toBe('400ms');
    expect(humanSpan(45_000)).toBe('45s');
    expect(humanSpan(180_000)).toBe('3m');
    expect(humanSpan(194_000)).toBe('3m14s');
    expect(humanSpan(3_900_000)).toBe('1h5m');
  });

  it('leaves unknown placeholders alone rather than printing undefined', () => {
    expect(render('{a} and {b}', { a: 1 })).toBe('1 and {b}');
  });

  it('evaluate on an unknown-shaped stream is a no-op, not a throw', () => {
    expect(evaluate(RULE, [{ ts: T0, source: 'web', action: 'request', status: 'success', raw: '' }])).toEqual([]);
  });
});
