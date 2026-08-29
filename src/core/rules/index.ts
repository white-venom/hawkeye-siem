import type { Rule } from './types.js';

/** The shipped detection content.
 *
 * Thresholds are tuned for a demo, not for a real estate with real traffic -
 * on a production edge you'd want the port-scan count an order of magnitude
 * higher and a suppression list for your own scanners. Comments call out the
 * ones that would need re-tuning first.
 */
export const RULES: Rule[] = [
  {
    id: 'ssh-brute-force',
    name: 'SSH brute force succeeded',
    severity: 'critical',
    mitre: { id: 'T1110.001', name: 'Brute Force: Password Guessing' },
    description:
      'A run of failed SSH logins from one address followed by a success. The failures alone are noise; the success is the incident.',
    narrative:
      '{failed} failed SSH logins from {srcIp} in {span}, then a successful login as {user}',
    detect: {
      type: 'sequence',
      groupBy: ['srcIp'],
      within: '10m',
      steps: [
        { label: 'failed', where: 'source = ssh and status = failure', count: 8 },
        { label: 'accepted', where: 'source = ssh and action = login and status = success' },
      ],
    },
  },
  {
    id: 'ssh-password-spray',
    name: 'SSH password spraying',
    severity: 'high',
    mitre: { id: 'T1110.003', name: 'Brute Force: Password Spraying' },
    description:
      'One source trying a handful of passwords against many different accounts. Stays under per-account lockout thresholds, which is the whole point.',
    narrative: '{srcIp} failed against {distinct} different accounts in {span} ({users})',
    detect: {
      type: 'threshold',
      where: 'source = ssh and status = failure',
      groupBy: ['srcIp'],
      distinct: 'user',
      within: '10m',
      count: 6,
    },
  },
  {
    id: 'firewall-port-scan',
    name: 'Horizontal port scan',
    severity: 'medium',
    mitre: { id: 'T1046', name: 'Network Service Discovery' },
    description:
      'One address hitting many destination ports in a short window. Almost always recon; occasionally your own vulnerability scanner, so allowlist those.',
    narrative: '{srcIp} touched {distinct} distinct ports in {span}',
    detect: {
      type: 'threshold',
      where: 'source = firewall and status = blocked',
      groupBy: ['srcIp'],
      distinct: 'port',
      within: '5m',
      count: 15,
    },
  },
  {
    id: 'web-content-discovery',
    name: 'Web content discovery',
    severity: 'medium',
    mitre: { id: 'T1595.003', name: 'Active Scanning: Wordlist Scanning' },
    description:
      'A wall of 404s across distinct paths from one client - gobuster, dirb, feroxbuster and friends.',
    narrative: '{srcIp} requested {distinct} missing paths in {span}',
    detect: {
      type: 'threshold',
      where: 'source = web and httpStatus = 404',
      groupBy: ['srcIp'],
      distinct: 'path',
      within: '5m',
      count: 20,
    },
  },
  {
    id: 'web-sqli',
    name: 'SQL injection attempt',
    severity: 'high',
    mitre: { id: 'T1190', name: 'Exploit Public-Facing Application' },
    description:
      'Classic SQLi tells in the request path or query string. Signature-based, so it catches the lazy attempts and the noisy tools, not a careful blind injection.',
    narrative: '{count} SQL injection payloads from {srcIp} ({paths})',
    detect: {
      type: 'threshold',
      groupBy: ['srcIp'],
      within: '10m',
      count: 1,
      where:
        "path ~ \"(union[\\s/*]+select|select.+from\\s+information_schema|\\bor\\b\\s+1\\s*=\\s*1|sleep\\s*\\(\\s*\\d|benchmark\\s*\\(|';\\s*(drop|update|insert)\\s)\"",
    },
  },
  {
    id: 'web-xss',
    name: 'Cross-site scripting attempt',
    severity: 'medium',
    mitre: { id: 'T1059.007', name: 'Command and Scripting Interpreter: JavaScript' },
    description: 'Script tags or inline event handlers reflected through a query parameter.',
    narrative: '{count} XSS payloads from {srcIp} ({paths})',
    detect: {
      type: 'threshold',
      groupBy: ['srcIp'],
      within: '10m',
      count: 1,
      where:
        'path ~ "(<script|<\\s*img[^>]+onerror|javascript:|onload\\s*=|onerror\\s*=|<svg[^>]+on)"',
    },
  },
  {
    id: 'web-path-traversal',
    name: 'Path traversal / local file inclusion',
    severity: 'high',
    mitre: { id: 'T1083', name: 'File and Directory Discovery' },
    description:
      'Attempts to climb out of the web root. The decoded path is what gets matched, so %2e%2e%2f is caught too.',
    narrative: '{count} traversal attempts from {srcIp} ({paths})',
    detect: {
      type: 'threshold',
      groupBy: ['srcIp'],
      within: '10m',
      count: 1,
      where: 'path ~ "(\\.\\./\\.\\./|/etc/passwd|/proc/self/environ|c:\\\\windows\\\\win.ini)"',
    },
  },
  {
    id: 'impossible-travel',
    name: 'Impossible travel',
    severity: 'critical',
    mitre: { id: 'T1078', name: 'Valid Accounts' },
    description:
      'The same account authenticating from two places too far apart for the time between them. Strong signal for a stolen credential - and a reliable false positive generator for anyone on a VPN.',
    narrative:
      '{user} logged in from {from} then {to} {gap} later - {km} km apart, {kmh} km/h',
    detect: {
      type: 'geo_velocity',
      where: 'action = login and status = success',
      groupBy: ['user'],
      within: '4h',
      minKm: 700,
      minKmh: 900,
    },
  },
  {
    id: 'privilege-escalation-burst',
    name: 'Privilege escalation burst',
    severity: 'high',
    mitre: { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
    description:
      'Repeated privilege grants for one principal in a short window, across Windows special-privilege logons and Linux sudo. Normal admin work is bursty too, so this one wants tuning per environment.',
    narrative: '{user} picked up elevated rights {count} times in {span}',
    detect: {
      type: 'threshold',
      where: 'action = priv_assigned or (action = sudo and status = success)',
      groupBy: ['user'],
      within: '5m',
      count: 6,
    },
  },
  {
    id: 'admin-group-change',
    name: 'Account added to privileged group',
    severity: 'high',
    mitre: { id: 'T1136.001', name: 'Create Account: Local Account' },
    description:
      'Someone was added to a security-enabled group. Legitimate most days; during an incident it is how the attacker keeps the keys.',
    narrative: 'group membership changed for {user} ({count} events in {span})',
    detect: {
      type: 'threshold',
      where: 'source = windows and eventId in [4728, 4732, 4720]',
      groupBy: ['user'],
      within: '15m',
      count: 1,
    },
  },
  {
    id: 'audit-log-cleared',
    name: 'Security audit log cleared',
    severity: 'critical',
    mitre: { id: 'T1070.001', name: 'Indicator Removal: Clear Windows Event Logs' },
    description:
      'Event 1102. There is almost no benign reason for this on a server, and it usually shows up right at the end of an intrusion.',
    narrative: 'audit log cleared on {host} by {user}',
    detect: {
      type: 'threshold',
      where: 'source = windows and eventId = 1102',
      groupBy: ['host'],
      within: '1h',
      count: 1,
    },
  },
  {
    id: 'data-exfil-volume',
    name: 'Large outbound transfer',
    severity: 'critical',
    mitre: { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' },
    description:
      'Sustained outbound volume from a single internal host. Byte counts come straight off the firewall LEN field, so a backup job will trip it - baseline before you alert on this.',
    narrative: '{mb} MB left {srcIp} in {span} across {count} allowed flows',
    detect: {
      type: 'threshold',
      where: 'source = firewall and status = allowed and bytes exists',
      groupBy: ['srcIp'],
      sum: 'bytes',
      within: '10m',
      count: 20_000_000,
    },
  },
];

export function ruleById(id: string): Rule | undefined {
  return RULES.find((r) => r.id === id);
}

export { type Rule } from './types.js';
