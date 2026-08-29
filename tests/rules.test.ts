import { describe, expect, it } from 'vitest';
import { evaluate } from '../src/core/engine.js';
import { RULES, ruleById } from '../src/core/rules/index.js';
import type { LogEvent, SourceKind, Status } from '../src/core/types.js';

const T0 = Date.UTC(2025, 2, 12, 9, 0, 0);
const min = (n: number) => n * 60_000;

function ev(o: Partial<LogEvent> & { source: SourceKind; action: string; status: Status }): LogEvent {
  return { ts: T0, raw: 'synthetic', ...o };
}

/** run one shipped rule over a hand-built event list */
const fire = (id: string, events: LogEvent[]) => evaluate(ruleById(id)!, events);

describe('rule content', () => {
  it('every rule has a severity, a MITRE tag and a compilable detector', () => {
    for (const r of RULES) {
      expect(r.id).toMatch(/^[a-z0-9-]+$/);
      expect(r.mitre.id).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(r.description.length).toBeGreaterThan(30);
      // narrative placeholders should be real words, not leftovers like {}
      expect(r.narrative).not.toMatch(/\{\s*\}/);
      expect(() => evaluate(r, [])).not.toThrow();
    }
  });

  it('has no duplicate rule ids', () => {
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
  });
});

describe('ssh-brute-force', () => {
  const fails = (n: number, ip = '203.0.113.45', startMin = 0) =>
    Array.from({ length: n }, (_, i) =>
      ev({ source: 'ssh', action: 'login', status: 'failure', srcIp: ip, user: 'root', ts: T0 + min(startMin + i * 0.2) }),
    );
  const win = (atMin: number, ip = '203.0.113.45') =>
    ev({ source: 'ssh', action: 'login', status: 'success', srcIp: ip, user: 'root', ts: T0 + min(atMin) });

  it('fires when the failures are followed by a success', () => {
    const m = fire('ssh-brute-force', [...fails(10), win(2.5)]);
    expect(m).toHaveLength(1);
    expect(m[0].entity.srcIp).toBe('203.0.113.45');
    expect(m[0].vars.user).toBe('root');
    expect(m[0].vars.failed).toBe(10);
    expect(m[0].evidence.at(-1)!.status).toBe('success');
  });

  it('stays quiet on failures alone', () => {
    expect(fire('ssh-brute-force', fails(30))).toHaveLength(0);
  });

  it('stays quiet below the failure threshold', () => {
    expect(fire('ssh-brute-force', [...fails(7), win(2)])).toHaveLength(0);
  });

  it('stays quiet when the success is outside the window', () => {
    expect(fire('ssh-brute-force', [...fails(10), win(45)])).toHaveLength(0);
  });

  it('does not stitch together two different sources', () => {
    expect(fire('ssh-brute-force', [...fails(10, '203.0.113.45'), win(2, '198.51.100.9')])).toHaveLength(0);
  });

  it('ignores a normal login day', () => {
    const normal = Array.from({ length: 40 }, (_, i) =>
      ev({ source: 'ssh', action: 'login', status: 'success', srcIp: '10.10.4.31', user: 'deploy', ts: T0 + min(i * 3) }),
    );
    expect(fire('ssh-brute-force', normal)).toHaveLength(0);
  });
});

describe('ssh-password-spray', () => {
  const spray = (users: string[]) =>
    users.map((u, i) =>
      ev({ source: 'ssh', action: 'invalid_user', status: 'failure', srcIp: '45.83.220.19', user: u, ts: T0 + min(i * 0.5) }),
    );

  it('fires on many accounts from one source', () => {
    const m = fire('ssh-password-spray', spray(['admin', 'oracle', 'git', 'test', 'ubuntu', 'nagios']));
    expect(m).toHaveLength(1);
    expect(m[0].vars.distinct).toBe(6);
  });

  it('stays quiet on repeated failures for a single account', () => {
    expect(fire('ssh-password-spray', spray(['admin', 'admin', 'admin', 'admin', 'admin', 'admin', 'admin']))).toHaveLength(0);
  });

  it('stays quiet when the same accounts are spread over hours', () => {
    const slow = ['admin', 'oracle', 'git', 'test', 'ubuntu', 'nagios'].map((u, i) =>
      ev({ source: 'ssh', action: 'login', status: 'failure', srcIp: '45.83.220.19', user: u, ts: T0 + min(i * 30) }),
    );
    expect(fire('ssh-password-spray', slow)).toHaveLength(0);
  });
});

describe('firewall-port-scan', () => {
  const scan = (ports: number[], ip = '185.220.101.42') =>
    ports.map((p, i) =>
      ev({ source: 'firewall', action: 'connection', status: 'blocked', srcIp: ip, port: p, ts: T0 + min(i * 0.1) }),
    );

  it('fires on a horizontal sweep', () => {
    const m = fire('firewall-port-scan', scan([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432]));
    expect(m).toHaveLength(1);
    expect(Number(m[0].vars.distinct)).toBeGreaterThanOrEqual(15);
  });

  it('stays quiet when the same few ports are retried', () => {
    expect(fire('firewall-port-scan', scan(Array.from({ length: 40 }, (_, i) => [22, 443, 3389][i % 3])))).toHaveLength(0);
  });

  it('ignores traffic the firewall allowed', () => {
    const allowed = scan([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389]).map((e) => ({
      ...e,
      status: 'allowed' as const,
    }));
    expect(fire('firewall-port-scan', allowed)).toHaveLength(0);
  });
});

describe('web-content-discovery', () => {
  const sweep = (n: number, code = 404) =>
    Array.from({ length: n }, (_, i) =>
      ev({
        source: 'web',
        action: 'request',
        status: code >= 400 ? 'failure' : 'success',
        srcIp: '198.51.100.23',
        path: '/probe-' + i,
        httpStatus: code,
        ts: T0 + min(i * 0.1),
      }),
    );

  it('fires on a wall of 404s across distinct paths', () => {
    expect(fire('web-content-discovery', sweep(25))).toHaveLength(1);
  });

  it('stays quiet when the same requests succeed', () => {
    expect(fire('web-content-discovery', sweep(40, 200))).toHaveLength(0);
  });

  it('stays quiet on a handful of 404s', () => {
    expect(fire('web-content-discovery', sweep(8))).toHaveLength(0);
  });
});

describe('web signatures', () => {
  const req = (path: string) =>
    ev({ source: 'web', action: 'request', status: 'success', srcIp: '91.219.236.88', path, httpStatus: 200 });

  const benign = [
    req('/api/v1/orders?page=2'),
    req('/docs/getting-started'),
    req('/search?q=union%20jack%20flag'),
    req('/blog/how-to-select-from-a-dropdown'),
    req('/static/app.4f2a.js'),
  ];

  it('sqli fires on real payloads', () => {
    for (const p of [
      "/api/v1/orders?id=1' OR 1=1--",
      '/api/v1/orders?id=1 UNION SELECT null,version()--',
      '/search?q=1 union/**/select username from users',
      '/api/v1/orders?id=1 AND SLEEP(5)',
      '/x?q=select password from information_schema.tables',
    ]) {
      expect(fire('web-sqli', [req(p)]), p).toHaveLength(1);
    }
  });

  it('sqli stays quiet on ordinary traffic', () => {
    expect(fire('web-sqli', benign)).toHaveLength(0);
  });

  it('xss fires on script and handler payloads', () => {
    for (const p of [
      '/search?q=<script>alert(1)</script>',
      '/profile?name=<img src=x onerror=fetch(1)>',
      '/comment?body=<svg onload=alert(1)>',
      '/r?to=javascript:alert(document.domain)',
    ]) {
      expect(fire('web-xss', [req(p)]), p).toHaveLength(1);
    }
  });

  it('xss stays quiet on ordinary traffic', () => {
    expect(fire('web-xss', benign)).toHaveLength(0);
  });

  it('traversal fires on decoded paths', () => {
    for (const p of ['/download?file=../../../../etc/passwd', '/view?tpl=../../../proc/self/environ']) {
      expect(fire('web-path-traversal', [req(p)]), p).toHaveLength(1);
    }
  });

  it('traversal stays quiet on ordinary traffic', () => {
    expect(fire('web-path-traversal', [...benign, req('/static/../app.js')])).toHaveLength(0);
  });

  it('groups a burst of payloads from one source into one match', () => {
    const m = fire('web-sqli', [
      req("/a?id=1' OR 1=1--"),
      { ...req('/b?id=1 UNION SELECT null--'), ts: T0 + min(1) },
      { ...req('/c?id=1 AND SLEEP(5)'), ts: T0 + min(2) },
    ]);
    expect(m).toHaveLength(1);
    expect(m[0].evidence).toHaveLength(3);
  });
});

describe('impossible-travel', () => {
  const login = (ip: string, atMin: number, user = 'j.harper') =>
    ev({ source: 'ssh', action: 'login', status: 'success', srcIp: ip, user, ts: T0 + min(atMin) });

  it('fires for London then Singapore sixteen minutes apart', () => {
    const m = fire('impossible-travel', [login('82.102.20.14', 0), login('103.21.244.10', 16)]);
    expect(m).toHaveLength(1);
    expect(m[0].vars.from).toContain('London');
    expect(m[0].vars.to).toContain('Singapore');
    expect(Number(m[0].vars.kmh)).toBeGreaterThan(900);
  });

  it('stays quiet for two addresses in the same city', () => {
    expect(fire('impossible-travel', [login('82.102.20.14', 0), login('82.102.21.90', 16)])).toHaveLength(0);
  });

  it('stays quiet when there was time to fly', () => {
    expect(fire('impossible-travel', [login('82.102.20.14', 0), login('103.21.244.10', 13 * 60)])).toHaveLength(0);
  });

  it('does not mix two different accounts', () => {
    expect(fire('impossible-travel', [login('82.102.20.14', 0, 'j.harper'), login('103.21.244.10', 16, 'm.singh')])).toHaveLength(0);
  });

  it('stays quiet when an address is not in the geo table', () => {
    expect(fire('impossible-travel', [login('82.102.20.14', 0), login('198.18.7.7', 16)])).toHaveLength(0);
  });
});

describe('privilege-escalation-burst', () => {
  const priv = (n: number, user = 'svc_backup', spacingMin = 0.5) =>
    Array.from({ length: n }, (_, i) =>
      ev({ source: 'windows', action: 'priv_assigned', status: 'success', user, eventId: 4672, ts: T0 + min(i * spacingMin) }),
    );

  it('fires on a burst of privilege grants', () => {
    const m = fire('privilege-escalation-burst', priv(8));
    expect(m).toHaveLength(1);
    expect(m[0].entity.user).toBe('svc_backup');
  });

  it('correlates windows privilege grants with linux sudo for the same account', () => {
    const mixed = [
      ...priv(3, 'root'),
      ...Array.from({ length: 3 }, (_, i) =>
        ev({ source: 'ssh', action: 'sudo', status: 'success', user: 'root', ts: T0 + min(2 + i * 0.3) }),
      ),
    ];
    const m = fire('privilege-escalation-burst', mixed);
    expect(m).toHaveLength(1);
    expect(new Set(m[0].evidence.map((e) => e.source))).toEqual(new Set(['windows', 'ssh']));
  });

  it('stays quiet just under the threshold', () => {
    expect(fire('privilege-escalation-burst', priv(5))).toHaveLength(0);
  });

  it('stays quiet when the same grants are spread across the morning', () => {
    expect(fire('privilege-escalation-burst', priv(8, 'svc_backup', 20))).toHaveLength(0);
  });

  it('stays quiet for denied sudo', () => {
    const denied = Array.from({ length: 8 }, (_, i) =>
      ev({ source: 'ssh', action: 'sudo', status: 'failure', user: 'mallory', ts: T0 + min(i * 0.3) }),
    );
    expect(fire('privilege-escalation-burst', denied)).toHaveLength(0);
  });
});

describe('windows housekeeping rules', () => {
  it('admin-group-change fires on a group add', () => {
    const m = fire('admin-group-change', [
      ev({ source: 'windows', action: 'group_add', status: 'success', user: 'sys_helper', eventId: 4728, host: 'DC-01' }),
    ]);
    expect(m).toHaveLength(1);
    expect(m[0].entity.user).toBe('sys_helper');
  });

  it('admin-group-change ignores ordinary logons', () => {
    expect(
      fire('admin-group-change', [
        ev({ source: 'windows', action: 'login', status: 'success', user: 'j.harper', eventId: 4624 }),
      ]),
    ).toHaveLength(0);
  });

  it('audit-log-cleared fires on 1102 and nothing else', () => {
    expect(
      fire('audit-log-cleared', [
        ev({ source: 'windows', action: 'log_cleared', status: 'success', user: 'sys_helper', eventId: 1102, host: 'DC-01' }),
      ]),
    ).toHaveLength(1);
    expect(
      fire('audit-log-cleared', [
        ev({ source: 'windows', action: 'login', status: 'failure', user: 'admin', eventId: 4625, host: 'DC-01' }),
      ]),
    ).toHaveLength(0);
  });
});

describe('data-exfil-volume', () => {
  const flows = (n: number, bytes: number, spacingMin = 0.2) =>
    Array.from({ length: n }, (_, i) =>
      ev({
        source: 'firewall',
        action: 'connection',
        status: 'allowed',
        srcIp: '10.10.4.22',
        dstIp: '77.83.36.19',
        port: 443,
        bytes,
        ts: T0 + min(i * spacingMin),
      }),
    );

  it('fires once the window total crosses the threshold', () => {
    const m = fire('data-exfil-volume', flows(10, 4_000_000));
    expect(m).toHaveLength(1);
    expect(Number(m[0].vars.sum)).toBeGreaterThanOrEqual(20_000_000);
    expect(String(m[0].vars.mb)).toMatch(/^\d+\.\d$/);
  });

  it('stays quiet for ordinary browsing volume', () => {
    expect(fire('data-exfil-volume', flows(30, 200_000))).toHaveLength(0);
  });

  it('stays quiet when the same volume is spread over hours', () => {
    expect(fire('data-exfil-volume', flows(10, 4_000_000, 20))).toHaveLength(0);
  });

  it('does not add up flows from different hosts', () => {
    const spread = flows(10, 4_000_000).map((e, i) => ({ ...e, srcIp: '10.10.4.' + (20 + i) }));
    expect(fire('data-exfil-volume', spread)).toHaveLength(0);
  });
});
