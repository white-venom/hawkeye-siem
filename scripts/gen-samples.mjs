/* Builds the bundled sample logs and the replay script.
 *
 * Everything is synthetic and seeded, so re-running this produces byte-identical
 * files - the datasets are committed, this is just how they got there. Public
 * IPs are either RFC5737 documentation ranges or hosting/VPN ranges that appear
 * in the bundled geo table; nothing here points at a real victim.
 *
 *   node scripts/gen-samples.mjs
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'data', 'samples');
mkdirSync(OUT, { recursive: true });

// --- seeded rng -------------------------------------------------------------
let seed = 0x5ee5;
function rnd() {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = (a) => a[Math.floor(rnd() * a.length)];
const int = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));

// --- time -------------------------------------------------------------------
const DAY = Date.UTC(2025, 2, 12); // Wed 12 Mar 2025, everything is UTC
const T = (h, m, s) => DAY + h * 3600e3 + m * 60e3 + s * 1000;
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const p2 = (n) => String(n).padStart(2, '0');

function syslog(ts) {
  const d = new Date(ts);
  return `${MON[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`;
}
function clf(ts) {
  const d = new Date(ts);
  return `${p2(d.getUTCDate())}/${MON[d.getUTCMonth()]}/${d.getUTCFullYear()}:${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} +0000`;
}
const iso = (ts) => new Date(ts).toISOString().replace('.000Z', 'Z');

// --- cast -------------------------------------------------------------------
const STAFF = ['deploy', 'ansible', 'j.harper', 'm.singh', 'r.okafor', 'svc_backup', 'a.novak'];
const HOSTS = ['web-01', 'web-02', 'app-01', 'db-01'];
const INTERNAL = () => `10.10.4.${int(20, 60)}`;
const B64 = () => {
  let s = '';
  const cs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < 43; i++) s += cs[int(0, cs.length - 1)];
  return s;
};

/** collects {ts, line} and emits them time-sorted, which is how a real log looks */
function sink() {
  const rows = [];
  return {
    add: (ts, line) => rows.push({ ts, line }),
    text: () =>
      rows
        .sort((a, b) => a.ts - b.ts)
        .map((r) => r.line)
        .join('\n') + '\n',
    rows,
  };
}

// ---------------------------------------------------------------------------
// auth.log - OpenSSH + sudo
// ---------------------------------------------------------------------------
function authLog() {
  const s = sink();
  const pid = () => int(1200, 32000);
  const ssh = (ts, host, msg) => s.add(ts, `${syslog(ts)} ${host} sshd[${pid()}]: ${msg}`);
  const sudo = (ts, host, msg) => s.add(ts, `${syslog(ts)} ${host} sudo: ${msg}`);

  // ordinary day: key-based logins from the office range, some sudo, a few fat-finger failures
  for (let ts = T(6, 0, 0); ts < T(12, 0, 0); ts += int(55, 190) * 1000) {
    const host = pick(HOSTS);
    const user = pick(['deploy', 'ansible', 'j.harper', 'm.singh', 'r.okafor']);
    const ip = INTERNAL();
    const roll = rnd();
    if (roll < 0.42) {
      ssh(ts, host, `Accepted publickey for ${user} from ${ip} port ${int(40000, 60000)} ssh2: RSA SHA256:${B64()}`);
      if (rnd() < 0.35) {
        // pam session lines are noise the parser deliberately drops
        s.add(ts + 1, `${syslog(ts + 1)} ${host} sshd[${pid()}]: pam_unix(sshd:session): session opened for user ${user} by (uid=0)`);
      }
    } else if (roll < 0.62) {
      sudo(ts, host, `${user} : TTY=pts/${int(0, 3)} ; PWD=/home/${user} ; USER=root ; COMMAND=${pick([
        '/usr/bin/systemctl restart nginx',
        '/usr/bin/apt-get update',
        '/usr/bin/tail -f /var/log/syslog',
        '/bin/journalctl -u api',
        '/usr/bin/docker ps',
      ])}`);
    } else if (roll < 0.72) {
      ssh(ts, host, `Failed password for ${user} from ${ip} port ${int(40000, 60000)} ssh2`);
    } else if (roll < 0.85) {
      ssh(ts, host, `Connection closed by authenticating user ${user} ${ip} port ${int(40000, 60000)} [preauth]`);
    } else {
      ssh(ts, host, `Disconnected from user ${user} ${ip} port ${int(40000, 60000)}`);
    }
    if (rnd() < 0.12) {
      // cron and systemd write to auth.log too - the ssh parser has nothing to
      // say about them and reports them as skipped, which is the honest answer
      s.add(ts + 3, `${syslog(ts + 3)} ${host} CRON[${pid()}]: pam_unix(cron:session): session opened for user root by (uid=0)`);
    }
  }

  // 07:42 London, 07:58 Singapore. Same account, same day, no plane that fast.
  ssh(T(7, 42, 10), 'web-01', 'Accepted password for j.harper from 82.102.20.14 port 55210 ssh2');
  s.add(T(7, 42, 11), `${syslog(T(7, 42, 11))} web-01 sudo: j.harper : TTY=pts/1 ; PWD=/home/j.harper ; USER=root ; COMMAND=/usr/bin/less /var/log/nginx/access.log`);
  ssh(T(7, 58, 33), 'web-01', 'Accepted password for j.harper from 103.21.244.10 port 49222 ssh2');

  // 09:20 spray - one source, many accounts, one guess each. Never trips a lockout.
  const sprayUsers = ['admin', 'oracle', 'postgres', 'jenkins', 'git', 'ubuntu', 'test', 'ftpuser', 'nagios'];
  let t = T(9, 20, 4);
  for (const u of sprayUsers) {
    ssh(t, 'web-02', `Invalid user ${u} from 45.83.220.19 port ${int(40000, 60000)}`);
    ssh(t + 2, 'web-02', `Failed password for invalid user ${u} from 45.83.220.19 port ${int(40000, 60000)} ssh2`);
    t += int(18, 34) * 1000;
  }

  return s.text();
}

// ---------------------------------------------------------------------------
// access.log - nginx combined
// ---------------------------------------------------------------------------
const UA_REAL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Version/17.3 Mobile/15E148 Safari/604.1',
];
const GOOD_PATHS = [
  '/', '/pricing', '/docs/getting-started', '/api/v1/orders', '/api/v1/orders?page=2',
  '/api/v1/customers/8812', '/static/app.4f2a.js', '/static/main.9c1b.css', '/health',
  '/login', '/dashboard', '/api/v1/reports/daily', '/favicon.ico', '/robots.txt',
];
const WORDLIST = [
  '/.env', '/.git/config', '/admin', '/admin/login.php', '/wp-login.php', '/wp-admin/',
  '/phpmyadmin/', '/backup.zip', '/backup.sql', '/db.sql', '/config.php.bak', '/.svn/entries',
  '/server-status', '/actuator/health', '/actuator/env', '/api/swagger.json', '/swagger-ui.html',
  '/cgi-bin/test.cgi', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '/old/', '/new/',
  '/test.php', '/info.php', '/phpinfo.php', '/.aws/credentials', '/.ssh/id_rsa', '/web.config',
  '/console', '/jenkins/login', '/solr/admin/cores', '/manager/html', '/_ignition/execute-solution',
];

function accessLog() {
  const s = sink();
  const line = (ts, ip, user, method, path, code, bytes, ua, ref = '-') =>
    s.add(ts, `${ip} - ${user} [${clf(ts)}] "${method} ${path} HTTP/1.1" ${code} ${bytes} "${ref}" "${ua}"`);

  for (let ts = T(6, 0, 0); ts < T(12, 0, 0); ts += int(20, 90) * 1000) {
    const ip = rnd() < 0.5 ? INTERNAL() : `192.0.2.${int(2, 250)}`;
    const path = pick(GOOD_PATHS);
    const code = rnd() < 0.9 ? 200 : pick([301, 302, 304, 404, 500]);
    line(ts, ip, rnd() < 0.2 ? pick(STAFF) : '-', rnd() < 0.15 ? 'POST' : 'GET', path, code, int(180, 24000), pick(UA_REAL));
  }

  // 08:40 gobuster sweep - distinct paths, all 404, from one client
  let t = T(8, 40, 2);
  for (const p of WORDLIST) {
    line(t, '198.51.100.23', '-', 'GET', p, 404, int(120, 320), 'gobuster/3.6');
    t += int(6, 16) * 1000;
  }

  // 09:05 hands-on-keyboard probing from a Moscow VPS
  const atk = '91.219.236.88';
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36';
  const probes = [
    ["/api/v1/orders?id=1' OR 1=1--", 500],
    ['/api/v1/orders?id=1%20UNION%20SELECT%20null,version()--', 500],
    ["/search?q=1' UNION SELECT username,password FROM users--", 200],
    ['/api/v1/customers?sort=id;%20DROP%20TABLE%20sessions--', 400],
    ['/api/v1/orders?id=1%20AND%20SLEEP(5)', 200],
    ['/search?q=<script>alert(document.domain)</script>', 200],
    ['/profile?name=%3Cimg%20src%3Dx%20onerror%3Dfetch(%27//91.219.236.88/c%27)%3E', 200],
    ['/comment?body=<svg onload=alert(1)>', 400],
    ['/download?file=../../../../etc/passwd', 403],
    ['/static/../../../../etc/passwd', 404],
    ['/view?tpl=%2e%2e%2f%2e%2e%2f%2e%2e%2fproc%2fself%2fenviron', 500],
  ];
  t = T(9, 5, 11);
  for (const [p, code] of probes) {
    line(t, atk, '-', 'GET', p, code, int(0, 900), ua, 'https://shop.example.com/');
    t += int(9, 28) * 1000;
  }

  return s.text();
}

// ---------------------------------------------------------------------------
// security.jsonl - Windows Security channel, winlogbeat-ish shape
// ---------------------------------------------------------------------------
function securityJsonl() {
  const s = sink();
  const ev = (ts, o) =>
    s.add(ts, JSON.stringify({ '@timestamp': iso(ts), channel: 'Security', ...o }));

  for (let ts = T(6, 0, 0); ts < T(12, 0, 0); ts += int(70, 250) * 1000) {
    const roll = rnd();
    const who = pick(['j.harper', 'm.singh', 'r.okafor', 'a.novak', 'svc_backup']);
    const comp = pick(['DC-01', 'FS-01', 'WEB-01']);
    if (roll < 0.4) {
      ev(ts, { event_id: 4624, computer: comp, target_user: who, ip: `10.10.5.${int(10, 90)}`, logon_type: 3, message: 'An account was successfully logged on.' });
    } else if (roll < 0.55) {
      ev(ts, { event_id: 4634, computer: comp, target_user: who, message: 'An account was logged off.' });
    } else if (roll < 0.7) {
      ev(ts, { event_id: 4688, computer: comp, target_user: who, process: pick(['C:\\Windows\\System32\\cmd.exe', 'C:\\Program Files\\Git\\bin\\git.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe']), message: 'A new process has been created.' });
    } else if (roll < 0.85) {
      ev(ts, { event_id: 4625, computer: comp, target_user: who, ip: `10.10.5.${int(10, 90)}`, logon_type: 2, message: 'An account failed to log on.' });
    } else {
      ev(ts, { event_id: 4672, computer: comp, target_user: pick(['Administrator', 'svc_backup']), message: 'Special privileges assigned to new logon.' });
    }
  }

  // 09:36 a new account appears and is immediately made an admin
  ev(T(9, 36, 12), { event_id: 4720, computer: 'DC-01', subject_user: 'a.novak', target_user: 'helpdesk_svc', message: 'A user account was created.' });
  ev(T(9, 37, 1), { event_id: 4728, computer: 'DC-01', subject_user: 'a.novak', target_user: 'helpdesk_svc', group: 'Domain Admins', message: 'A member was added to a security-enabled global group.' });

  return s.text();
}

// ---------------------------------------------------------------------------
// ufw.log - netfilter on the web tier
// ---------------------------------------------------------------------------
function ufwLog() {
  const s = sink();
  const block = (ts, host, src, dst, proto, spt, dpt) =>
    s.add(ts, `${syslog(ts)} ${host} kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:4a:2b:11 SRC=${src} DST=${dst} LEN=${int(40, 60)} TOS=0x00 PREC=0x00 TTL=${int(40, 64)} ID=${int(1000, 65000)} PROTO=${proto} SPT=${spt} DPT=${dpt} WINDOW=${int(1024, 65535)} RES=0x00 SYN URGP=0`);

  for (let ts = T(6, 0, 0); ts < T(12, 0, 0); ts += int(40, 200) * 1000) {
    block(ts, pick(['web-01', 'web-02']), `192.0.2.${int(2, 250)}`, INTERNAL(), pick(['TCP', 'UDP']), int(1024, 65000), pick([23, 445, 3389, 5900, 1433, 8080, 8291]));
  }

  // 08:20 straight horizontal sweep from a Tor exit
  const ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8081, 8443, 9200, 11211, 27017, 5601];
  let t = T(8, 20, 5);
  for (const p of ports) {
    block(t, 'web-01', '185.220.101.42', '10.10.4.22', 'TCP', int(40000, 60000), p);
    t += int(3, 9) * 1000;
  }

  return s.text();
}

// ---------------------------------------------------------------------------
// asa.log - edge firewall. The only source that reports byte counts.
// ---------------------------------------------------------------------------
function asaLog() {
  const s = sink();
  const teardown = (ts, src, sp, dst, dp, bytes, secs) =>
    s.add(ts, `${syslog(ts)} fw-edge %ASA-6-302014: Teardown TCP connection ${int(100000, 999999)} for inside:${src}/${sp} to outside:${dst}/${dp} duration 0:${p2(Math.floor(secs / 60))}:${p2(secs % 60)} bytes ${bytes} TCP FINs`);
  const deny = (ts, src, sp, dst, dp) =>
    s.add(ts, `${syslog(ts)} fw-edge %ASA-4-106023: Deny tcp src outside:${src}/${sp} dst inside:${dst}/${dp} by access-group "outside_access_in" [0x0, 0x0]`);

  for (let ts = T(6, 0, 0); ts < T(12, 0, 0); ts += int(30, 120) * 1000) {
    if (rnd() < 0.75) {
      teardown(ts, INTERNAL(), int(40000, 60000), `192.0.2.${int(2, 250)}`, pick([443, 443, 443, 80, 22]), int(1200, 380000), int(1, 90));
    } else {
      deny(ts, `192.0.2.${int(2, 250)}`, int(1024, 65000), '203.0.113.9', pick([22, 3389, 445]));
    }
  }

  return s.text();
}

// ---------------------------------------------------------------------------
// replay - one scripted intrusion, streamed through the same parsers
// ---------------------------------------------------------------------------
function replayScript() {
  const steps = [];
  const push = (phase, parser, line, delay) => steps.push({ phase, parser, line, delay });
  const pid = () => int(1200, 32000);

  // 1. recon
  const atk = '77.83.36.19';
  const ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 11211, 27017, 5601, 15672];
  let t = T(12, 5, 0);
  ports.forEach((p, i) => {
    push('Reconnaissance', 'firewall',
      `${syslog(t)} web-01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:4a:2b:11 SRC=${atk} DST=10.10.4.22 LEN=44 TOS=0x00 PREC=0x00 TTL=48 ID=${int(1000, 65000)} PROTO=TCP SPT=${int(40000, 60000)} DPT=${p} WINDOW=1024 RES=0x00 SYN URGP=0`,
      i === 0 ? 400 : 70);
    t += 4000;
  });

  // 2. credential access
  t = T(12, 11, 0);
  for (let i = 0; i < 14; i++) {
    push('Credential access', 'ssh',
      `${syslog(t)} web-01 sshd[${pid()}]: Failed password for root from ${atk} port ${int(40000, 60000)} ssh2`,
      i === 0 ? 1100 : 110);
    t += 11000;
  }
  push('Credential access', 'ssh', `${syslog(t)} web-01 sshd[${pid()}]: Accepted password for root from ${atk} port ${int(40000, 60000)} ssh2`, 700);

  // 3. escalation, on both sides of the estate
  t = T(12, 16, 10);
  for (let i = 0; i < 5; i++) {
    push('Privilege escalation', 'ssh',
      `${syslog(t)} web-01 sudo: root : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=${pick(['/bin/cat /etc/shadow', '/usr/bin/id', '/bin/cp /bin/bash /tmp/.b', '/usr/bin/chmod u+s /tmp/.b', '/usr/sbin/useradd -M sys_helper'])}`,
      i === 0 ? 1200 : 140);
    t += 20000;
  }
  t = T(12, 17, 5);
  push('Privilege escalation', 'windows', JSON.stringify({ '@timestamp': iso(t), channel: 'Security', event_id: 4625, computer: 'DC-01', target_user: 'svc_backup', ip: atk, logon_type: 3, message: 'An account failed to log on.' }), 200);
  t += 22000;
  push('Privilege escalation', 'windows', JSON.stringify({ '@timestamp': iso(t), channel: 'Security', event_id: 4624, computer: 'DC-01', target_user: 'svc_backup', ip: atk, logon_type: 3, message: 'An account was successfully logged on.' }), 200);
  for (let i = 0; i < 8; i++) {
    t += 16000;
    push('Privilege escalation', 'windows', JSON.stringify({ '@timestamp': iso(t), channel: 'Security', event_id: 4672, computer: 'DC-01', target_user: 'svc_backup', message: 'Special privileges assigned to new logon.' }), 150);
  }

  // 4. persistence
  t = T(12, 20, 30);
  push('Persistence', 'windows', JSON.stringify({ '@timestamp': iso(t), channel: 'Security', event_id: 4720, computer: 'DC-01', subject_user: 'svc_backup', target_user: 'sys_helper', message: 'A user account was created.' }), 1200);
  t += 41000;
  push('Persistence', 'windows', JSON.stringify({ '@timestamp': iso(t), channel: 'Security', event_id: 4728, computer: 'DC-01', subject_user: 'svc_backup', target_user: 'sys_helper', group: 'Domain Admins', message: 'A member was added to a security-enabled global group.' }), 300);
  t += 25000;
  push('Persistence', 'windows', JSON.stringify({ '@timestamp': iso(t), channel: 'Security', event_id: 7045, computer: 'DC-01', target_user: 'sys_helper', process: 'C:\\Windows\\Temp\\svcupd.exe', message: 'A service was installed in the system.' }), 300);

  // 5. exfil - 45 flows out to the same box that ran the scan
  t = T(12, 24, 0);
  for (let i = 0; i < 45; i++) {
    const bytes = int(2_600_000, 5_400_000);
    push('Exfiltration', 'firewall',
      `${syslog(t)} fw-edge %ASA-6-302014: Teardown TCP connection ${int(100000, 999999)} for inside:10.10.4.22/${int(40000, 60000)} to outside:${atk}/443 duration 0:00:${p2(int(8, 44))} bytes ${bytes} TCP FINs`,
      i === 0 ? 1300 : 90);
    t += 11000;
  }

  // 6. cleanup
  t = T(12, 35, 20);
  push('Defence evasion', 'windows', JSON.stringify({ '@timestamp': iso(t), channel: 'Security', event_id: 1102, computer: 'DC-01', subject_user: 'sys_helper', message: 'The audit log was cleared.' }), 1400);
  t += 9000;
  push('Defence evasion', 'ssh', `${syslog(t)} web-01 sudo: root : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/bin/rm -f /var/log/auth.log.1`, 500);

  return JSON.stringify(steps, null, 1) + '\n';
}

// ---------------------------------------------------------------------------
const files = {
  'auth.log': authLog(),
  'access.log': accessLog(),
  'security.jsonl': securityJsonl(),
  'ufw.log': ufwLog(),
  'asa.log': asaLog(),
  'replay.json': replayScript(),
};

for (const [name, body] of Object.entries(files)) {
  writeFileSync(join(OUT, name), body);
  console.log(name.padEnd(18), body.split('\n').length - 1, 'lines');
}
