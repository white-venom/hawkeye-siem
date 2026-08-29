import { describe, expect, it } from 'vitest';
import { DslError, ms, where } from '../src/core/rules/dsl.js';
import type { LogEvent } from '../src/core/types.js';

const base: LogEvent = {
  ts: 0,
  source: 'web',
  action: 'request',
  status: 'failure',
  raw: 'x',
  srcIp: '203.0.113.5',
  path: '/api/v1/orders?id=1 UNION SELECT null',
  httpStatus: 404,
  user: 'J.Harper',
};

const ev = (o: Partial<LogEvent> = {}): LogEvent => ({ ...base, ...o });

describe('dsl', () => {
  it('compares strings case-insensitively', () => {
    expect(where('user = j.harper')(ev())).toBe(true);
    expect(where('user = "J.HARPER"')(ev())).toBe(true);
    expect(where('user != root')(ev())).toBe(true);
  });

  it('compares numbers written as either type', () => {
    expect(where('httpStatus = 404')(ev())).toBe(true);
    expect(where('httpStatus = "404"')(ev())).toBe(true);
    expect(where('httpStatus >= 400')(ev())).toBe(true);
    expect(where('httpStatus > 404')(ev())).toBe(false);
  });

  it('binds and tighter than or', () => {
    // false and false or true  ==  (false and false) or true
    expect(where('source = ssh and status = success or httpStatus = 404')(ev())).toBe(true);
    expect(where('source = ssh and (status = success or httpStatus = 404)')(ev())).toBe(false);
  });

  it('handles not and parens', () => {
    expect(where('not source = ssh')(ev())).toBe(true);
    expect(where('not (source = web and httpStatus = 404)')(ev())).toBe(false);
  });

  it('matches regex and substrings', () => {
    expect(where('path ~ "union\\s+select"')(ev())).toBe(true);
    expect(where('path ~ "union\\s+select"')(ev({ path: '/api/v1/orders' }))).toBe(false);
    expect(where('path !~ "union"')(ev({ path: '/health' }))).toBe(true);
    expect(where('path contains "/api/"')(ev())).toBe(true);
  });

  it('supports in-lists and exists', () => {
    expect(where('httpStatus in [401, 403, 404]')(ev())).toBe(true);
    expect(where('httpStatus in [200, 301]')(ev())).toBe(false);
    expect(where('user exists')(ev())).toBe(true);
    expect(where('dstIp exists')(ev())).toBe(false);
  });

  it('treats a missing field as no match rather than an error', () => {
    expect(where('eventId = 4625')(ev())).toBe(false);
    expect(where('eventId > 0')(ev())).toBe(false);
  });

  it('rejects nonsense with a position', () => {
    expect(() => where('source = = ssh')).toThrow(DslError);
    expect(() => where('source ssh')).toThrow(DslError);
    expect(() => where('(source = ssh')).toThrow(DslError);
    expect(() => where('source = "unterminated')).toThrow(DslError);
    expect(() => where('source = ssh trailing')).toThrow(DslError);
  });

  it('parses durations', () => {
    expect(ms('30s')).toBe(30_000);
    expect(ms('5m')).toBe(300_000);
    expect(ms('2h')).toBe(7_200_000);
    expect(ms(1234)).toBe(1234);
    expect(() => ms('5 fortnights')).toThrow();
  });
});
