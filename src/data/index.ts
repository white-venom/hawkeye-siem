import authLog from './samples/auth.log?raw';
import accessLog from './samples/access.log?raw';
import securityJsonl from './samples/security.jsonl?raw';
import ufwLog from './samples/ufw.log?raw';
import asaLog from './samples/asa.log?raw';
import replayScript from './samples/replay.json';
import type { ParserId } from '../core/parsers/index.js';

export interface Dataset {
  id: string;
  name: string;
  file: string;
  parser: ParserId;
  blurb: string;
  text: string;
}

/** All five ship enabled; the sidebar can drop any of them and the whole
 *  pipeline recomputes. Timestamps are 12 Mar 2025 UTC across the board. */
export const DATASETS: Dataset[] = [
  {
    id: 'auth',
    name: 'auth.log',
    file: 'web-01,web-02,app-01,db-01',
    parser: 'ssh',
    blurb: 'OpenSSH + sudo, 06:00-12:00',
    text: authLog,
  },
  {
    id: 'access',
    name: 'access.log',
    file: 'nginx edge',
    parser: 'web',
    blurb: 'nginx combined format',
    text: accessLog,
  },
  {
    id: 'security',
    name: 'security.jsonl',
    file: 'DC-01,FS-01,WEB-01',
    parser: 'windows',
    blurb: 'Windows Security channel',
    text: securityJsonl,
  },
  {
    id: 'ufw',
    name: 'ufw.log',
    file: 'web-01',
    parser: 'firewall',
    blurb: 'netfilter host firewall',
    text: ufwLog,
  },
  {
    id: 'asa',
    name: 'asa.log',
    file: 'fw-edge',
    parser: 'firewall',
    blurb: 'Cisco ASA, with byte counts',
    text: asaLog,
  },
];

export interface ReplayStep {
  phase: string;
  parser: ParserId;
  line: string;
  /** ms to wait before pushing this line, so the incident unfolds at a watchable pace */
  delay: number;
}

export const REPLAY: ReplayStep[] = replayScript as ReplayStep[];

export const REPLAY_PHASES: string[] = [...new Set(REPLAY.map((s) => s.phase))];
