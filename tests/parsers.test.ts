import { describe, expect, it } from 'vitest';
import { detectParser, parseFirewall, parseSsh, parseWeb, parseWindows } from '../src/core/parsers/index.js';

const Y = { year: 2025 };

describe('ssh / auth.log', () => {
  it('pulls user, source and outcome off a failed password', () => {
    const { events } = parseSsh(
      'Mar 12 08:14:22 web-01 sshd[24196]: Failed password for root from 203.0.113.45 port 51234 ssh2',
      Y,
    );
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      source: 'ssh',
      action: 'login',
      status: 'failure',
      user: 'root',
      srcIp: '203.0.113.45',
      port: 51234,
      host: 'web-01',
      ts: Date.UTC(2025, 2, 12, 8, 14, 22),
    });
  });

  it('separates accepted from failed', () => {
    const { events } = parseSsh(
      'Mar 12 08:15:02 web-01 sshd[24198]: Accepted publickey for deploy from 10.10.4.31 port 51290 ssh2: RSA SHA256:abc',
      Y,
    );
    expect(events[0]).toMatchObject({ action: 'login', status: 'success', user: 'deploy' });
  });

  it('flags unknown accounts', () => {
    const { events } = parseSsh('Mar 12 08:15:41 web-02 sshd[9]: Invalid user oracle from 45.83.220.19 port 44100', Y);
    expect(events[0]).toMatchObject({ action: 'invalid_user', status: 'failure', user: 'oracle' });
  });

  it('reads pam failures, which spell the same thing differently', () => {
    const { events } = parseSsh(
      'Mar 12 08:16:00 web-01 sshd[7]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.45  user=root',
      Y,
    );
    expect(events[0]).toMatchObject({ status: 'failure', srcIp: '203.0.113.45', user: 'root' });
  });

  it('handles sudo both ways round', () => {
    const ok = parseSsh(
      'Mar 12 08:20:03 web-01 sudo: deploy : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/bin/systemctl restart api',
      Y,
    ).events[0];
    expect(ok).toMatchObject({ action: 'sudo', status: 'success', user: 'deploy' });
    expect(ok.process).toBe('/bin/systemctl restart api');

    const denied = parseSsh(
      'Mar 12 08:21:03 web-01 sudo: mallory : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash',
      Y,
    ).events[0];
    expect(denied).toMatchObject({ action: 'sudo', status: 'failure', user: 'mallory' });
  });

  it('reports lines it cannot use instead of inventing events', () => {
    const r = parseSsh(
      [
        'Mar 12 08:14:22 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2',
        'Mar 12 08:14:23 web-01 sshd[1]: pam_unix(sshd:session): session opened for user deploy by (uid=0)',
        'this is not a log line',
      ].join('\n'),
      Y,
    );
    expect(r.events).toHaveLength(1);
    expect(r.skipped.map((s) => s.line)).toEqual([2, 3]);
  });

  it('round-trips: re-parsing an event raw gives back the same event', () => {
    const text = [
      'Mar 12 08:14:22 web-01 sshd[24196]: Failed password for root from 203.0.113.45 port 51234 ssh2',
      'Mar 12 08:20:03 web-01 sudo: deploy : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/bin/ls',
    ].join('\n');
    for (const e of parseSsh(text, Y).events) {
      expect(parseSsh(e.raw, Y).events[0]).toEqual(e);
    }
  });
});

describe('web / access.log', () => {
  const line =
    '198.51.100.23 - - [12/Mar/2025:08:40:02 +0000] "GET /admin/login.php HTTP/1.1" 404 162 "-" "gobuster/3.6"';

  it('parses the combined format', () => {
    const { events } = parseWeb(line);
    expect(events[0]).toMatchObject({
      source: 'web',
      action: 'request',
      status: 'failure',
      srcIp: '198.51.100.23',
      method: 'GET',
      path: '/admin/login.php',
      httpStatus: 404,
      bytes: 162,
      userAgent: 'gobuster/3.6',
      ts: Date.UTC(2025, 2, 12, 8, 40, 2),
    });
  });

  it('maps 2xx/4xx/5xx onto the shared status vocabulary', () => {
    const codes = (c: number) =>
      parseWeb(`1.2.3.4 - - [12/Mar/2025:08:40:02 +0000] "GET / HTTP/1.1" ${c} 10 "-" "-"`).events[0].status;
    expect(codes(200)).toBe('success');
    expect(codes(302)).toBe('success');
    expect(codes(403)).toBe('failure');
    expect(codes(502)).toBe('error');
  });

  it('applies the timezone offset', () => {
    const { events } = parseWeb('1.2.3.4 - - [12/Mar/2025:10:40:02 +0200] "GET / HTTP/1.1" 200 10 "-" "-"');
    expect(events[0].ts).toBe(Date.UTC(2025, 2, 12, 8, 40, 2));
  });

  it('decodes the path so signatures see through url-encoding', () => {
    const { events } = parseWeb(
      '1.2.3.4 - - [12/Mar/2025:08:40:02 +0000] "GET /view?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" 200 10 "-" "-"',
    );
    expect(events[0].path).toBe('/view?f=../../etc/passwd');
    expect(events[0].raw).toContain('%2e%2e%2f');
  });

  it('keeps a malformed escape rather than throwing', () => {
    const { events } = parseWeb('1.2.3.4 - - [12/Mar/2025:08:40:02 +0000] "GET /a%zz HTTP/1.1" 400 10 "-" "-"');
    expect(events[0].path).toBe('/a%zz');
  });

  it('round-trips', () => {
    const e = parseWeb(line).events[0];
    expect(parseWeb(e.raw).events[0]).toEqual(e);
  });
});

describe('windows / security.jsonl', () => {
  const l = (o: Record<string, unknown>) => JSON.stringify({ '@timestamp': '2025-03-12T08:14:22Z', ...o });

  it('maps the event IDs it knows about', () => {
    const text = [
      l({ event_id: 4624, computer: 'DC-01', target_user: 'j.harper', ip: '10.10.5.11' }),
      l({ event_id: 4625, computer: 'DC-01', target_user: 'admin', ip: '203.0.113.45' }),
      l({ event_id: 4672, computer: 'DC-01', target_user: 'svc_backup' }),
      l({ event_id: 1102, computer: 'DC-01', subject_user: 'sys_helper' }),
    ].join('\n');
    const { events } = parseWindows(text);
    expect(events.map((e) => [e.action, e.status])).toEqual([
      ['login', 'success'],
      ['login', 'failure'],
      ['priv_assigned', 'success'],
      ['log_cleared', 'success'],
    ]);
    expect(events[1].srcIp).toBe('203.0.113.45');
    expect(events[3].user).toBe('sys_helper');
  });

  it('keeps unknown IDs instead of dropping them', () => {
    const { events, skipped } = parseWindows(l({ event_id: 5158, computer: 'DC-01' }));
    expect(skipped).toHaveLength(0);
    expect(events[0]).toMatchObject({ action: 'wineventlog', eventId: 5158 });
  });

  it('accepts a JSON array as well as JSON lines', () => {
    const arr = JSON.stringify([
      { '@timestamp': '2025-03-12T08:14:22Z', event_id: 4624, computer: 'DC-01' },
      { '@timestamp': '2025-03-12T08:15:22Z', event_id: 4634, computer: 'DC-01' },
    ]);
    expect(parseWindows(arr).events).toHaveLength(2);
  });

  it('skips garbage lines', () => {
    const { events, skipped } = parseWindows(['{not json', l({ event_id: 4624 }), '{"no":"timestamp"}'].join('\n'));
    expect(events).toHaveLength(1);
    expect(skipped).toHaveLength(2);
  });
});

describe('firewall', () => {
  it('reads UFW blocks', () => {
    const { events } = parseFirewall(
      'Mar 12 08:20:05 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e SRC=185.220.101.42 DST=10.10.4.22 LEN=44 TTL=48 ID=1 PROTO=TCP SPT=51234 DPT=3389 WINDOW=1024 SYN URGP=0',
      Y,
    );
    expect(events[0]).toMatchObject({
      source: 'firewall',
      status: 'blocked',
      srcIp: '185.220.101.42',
      dstIp: '10.10.4.22',
      port: 3389,
      proto: 'TCP',
    });
  });

  it('reads ASA denies and teardowns, including byte counts', () => {
    const { events } = parseFirewall(
      [
        'Mar 12 08:21:05 fw-edge %ASA-4-106023: Deny tcp src outside:192.0.2.9/44100 dst inside:203.0.113.9/3389 by access-group "outside_access_in" [0x0, 0x0]',
        'Mar 12 12:24:00 fw-edge %ASA-6-302014: Teardown TCP connection 418822 for inside:10.10.4.22/44112 to outside:77.83.36.19/443 duration 0:00:31 bytes 4183264 TCP FINs',
      ].join('\n'),
      Y,
    );
    expect(events[0]).toMatchObject({ status: 'blocked', srcIp: '192.0.2.9', port: 3389 });
    expect(events[1]).toMatchObject({
      status: 'allowed',
      srcIp: '10.10.4.22',
      dstIp: '77.83.36.19',
      port: 443,
      bytes: 4183264,
    });
  });

  it('round-trips', () => {
    const raw =
      'Mar 12 08:20:05 web-01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.42 DST=10.10.4.22 PROTO=TCP SPT=1 DPT=22';
    const e = parseFirewall(raw, Y).events[0];
    expect(parseFirewall(e.raw, Y).events[0]).toEqual(e);
  });
});

describe('format sniffing', () => {
  it('picks the right parser for each shape', () => {
    expect(detectParser('Mar 12 08:14:22 web-01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2')).toBe('ssh');
    expect(detectParser('1.2.3.4 - - [12/Mar/2025:08:40:02 +0000] "GET / HTTP/1.1" 200 10 "-" "-"')).toBe('web');
    expect(detectParser('{"@timestamp":"2025-03-12T08:14:22Z","event_id":4625}')).toBe('windows');
    expect(detectParser('Mar 12 08:20:05 web-01 kernel: [UFW BLOCK] SRC=1.2.3.4 DST=5.6.7.8 DPT=22')).toBe('firewall');
    expect(detectParser('hello world')).toBeNull();
  });
});
