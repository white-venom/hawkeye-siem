/** A tiny filter language so detection rules read like something a human wrote:
 *
 *    source = ssh and action = login and status = failure
 *    path ~ "union\s+select" or path contains "../"
 *    eventId in [4624, 4625] and not user = SYSTEM
 *
 * Recursive descent, no dependencies. Compiles to a predicate over LogEvent.
 * Kept apart from the rules themselves so it can be tested on its own.
 */
import type { LogEvent } from '../types.js';

type Tok =
  | { t: 'ident'; v: string; pos: number }
  | { t: 'str'; v: string; pos: number }
  | { t: 'num'; v: number; pos: number }
  | { t: 'op'; v: string; pos: number }
  | { t: 'punc'; v: string; pos: number }
  | { t: 'eof'; pos: number };

const OPS = ['>=', '<=', '!=', '!~', '=', '>', '<', '~'];
const KEYWORDS = new Set(['and', 'or', 'not', 'in', 'contains', 'exists']);

export class DslError extends Error {
  readonly pos: number;
  constructor(msg: string, pos: number) {
    super(msg + ' (at ' + pos + ')');
    this.name = 'DslError';
    this.pos = pos;
  }
}

function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      const quote = c;
      let j = i + 1;
      let buf = '';
      while (j < src.length && src[j] !== quote) {
        if (src[j] === '\\' && j + 1 < src.length) {
          // keep the backslash - regex sources need it - but \" still unescapes
          buf += src[j + 1] === quote ? quote : src[j] + src[j + 1];
          j += 2;
          continue;
        }
        buf += src[j++];
      }
      if (j >= src.length) throw new DslError('unterminated string', i);
      out.push({ t: 'str', v: buf, pos: i });
      i = j + 1;
      continue;
    }
    if (c === '(' || c === ')' || c === '[' || c === ']' || c === ',') {
      out.push({ t: 'punc', v: c, pos: i });
      i++;
      continue;
    }
    const op = OPS.find((o) => src.startsWith(o, i));
    if (op) {
      out.push({ t: 'op', v: op, pos: i });
      i += op.length;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9.]/.test(src[j])) j++;
      out.push({ t: 'num', v: Number(src.slice(i, j)), pos: i });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_.\-/]/.test(src[j])) j++;
      out.push({ t: 'ident', v: src.slice(i, j), pos: i });
      i = j;
      continue;
    }
    throw new DslError('unexpected character ' + JSON.stringify(c), i);
  }
  out.push({ t: 'eof', pos: src.length });
  return out;
}

type Node =
  | { k: 'and'; l: Node; r: Node }
  | { k: 'or'; l: Node; r: Node }
  | { k: 'not'; n: Node }
  | { k: 'cmp'; field: string; op: string; value: string | number }
  | { k: 'in'; field: string; values: (string | number)[] }
  | { k: 'exists'; field: string };

function parse(toks: Tok[]): Node {
  let p = 0;
  const peek = () => toks[p];
  const isKw = (w: string) => {
    const t = toks[p];
    return t.t === 'ident' && t.v.toLowerCase() === w;
  };
  const eat = () => toks[p++];

  function parseOr(): Node {
    let l = parseAnd();
    while (isKw('or')) {
      eat();
      l = { k: 'or', l, r: parseAnd() };
    }
    return l;
  }

  function parseAnd(): Node {
    let l = parseUnary();
    while (isKw('and')) {
      eat();
      l = { k: 'and', l, r: parseUnary() };
    }
    return l;
  }

  function parseUnary(): Node {
    if (isKw('not')) {
      eat();
      return { k: 'not', n: parseUnary() };
    }
    const t = peek();
    if (t.t === 'punc' && t.v === '(') {
      eat();
      const inner = parseOr();
      const close = eat();
      if (!(close.t === 'punc' && close.v === ')')) throw new DslError('expected )', close.pos);
      return inner;
    }
    return parseCmp();
  }

  function parseValue(): string | number {
    const t = eat();
    if (t.t === 'str') return t.v;
    if (t.t === 'num') return t.v;
    if (t.t === 'ident') return t.v;
    throw new DslError('expected a value', t.pos);
  }

  function parseCmp(): Node {
    const f = eat();
    if (f.t !== 'ident' || KEYWORDS.has(f.v.toLowerCase())) {
      throw new DslError('expected a field name', f.pos);
    }
    if (isKw('exists')) {
      eat();
      return { k: 'exists', field: f.v };
    }
    if (isKw('in')) {
      eat();
      const open = eat();
      if (!(open.t === 'punc' && open.v === '[')) throw new DslError('expected [', open.pos);
      const values: (string | number)[] = [];
      for (;;) {
        values.push(parseValue());
        const t = eat();
        if (t.t === 'punc' && t.v === ',') continue;
        if (t.t === 'punc' && t.v === ']') break;
        throw new DslError('expected , or ]', t.pos);
      }
      return { k: 'in', field: f.v, values };
    }
    if (isKw('contains')) {
      eat();
      return { k: 'cmp', field: f.v, op: 'contains', value: parseValue() };
    }
    const op = eat();
    if (op.t !== 'op') throw new DslError('expected an operator', op.pos);
    return { k: 'cmp', field: f.v, op: op.v, value: parseValue() };
  }

  const root = parseOr();
  const end = peek();
  if (end.t !== 'eof') throw new DslError('trailing input', end.pos);
  return root;
}

export type Predicate = (e: LogEvent) => boolean;

const reCache = new Map<string, RegExp>();
function rx(src: string): RegExp {
  let r = reCache.get(src);
  if (!r) {
    r = new RegExp(src, 'i');
    reCache.set(src, r);
  }
  return r;
}

function field(e: LogEvent, name: string): unknown {
  return (e as unknown as Record<string, unknown>)[name];
}

/** Loose on purpose: "404" written in a rule should match httpStatus 404. */
function looseEq(a: unknown, b: string | number): boolean {
  if (a === undefined || a === null) return false;
  if (typeof a === 'number' && typeof b === 'string') return String(a) === b;
  if (typeof a === 'string' && typeof b === 'number') return a === String(b);
  if (typeof a === 'string' && typeof b === 'string') return a.toLowerCase() === b.toLowerCase();
  return a === b;
}

function num(v: unknown): number {
  return typeof v === 'number' ? v : Number.NaN;
}

function compileNode(n: Node): Predicate {
  switch (n.k) {
    case 'and': {
      const l = compileNode(n.l);
      const r = compileNode(n.r);
      return (e) => l(e) && r(e);
    }
    case 'or': {
      const l = compileNode(n.l);
      const r = compileNode(n.r);
      return (e) => l(e) || r(e);
    }
    case 'not': {
      const inner = compileNode(n.n);
      return (e) => !inner(e);
    }
    case 'exists':
      return (e) => {
        const v = field(e, n.field);
        return v !== undefined && v !== null;
      };
    case 'in':
      return (e) => {
        const v = field(e, n.field);
        return n.values.some((x) => looseEq(v, x));
      };
    case 'cmp': {
      const f = n.field;
      const value = n.value;
      switch (n.op) {
        case '=':
          return (e) => looseEq(field(e, f), value);
        case '!=':
          return (e) => !looseEq(field(e, f), value);
        case '>':
          return (e) => num(field(e, f)) > Number(value);
        case '<':
          return (e) => num(field(e, f)) < Number(value);
        case '>=':
          return (e) => num(field(e, f)) >= Number(value);
        case '<=':
          return (e) => num(field(e, f)) <= Number(value);
        case '~':
          return (e) => {
            const v = field(e, f);
            return typeof v === 'string' && rx(String(value)).test(v);
          };
        case '!~':
          return (e) => {
            const v = field(e, f);
            return !(typeof v === 'string' && rx(String(value)).test(v));
          };
        case 'contains':
          return (e) => {
            const v = field(e, f);
            return typeof v === 'string' && v.toLowerCase().includes(String(value).toLowerCase());
          };
        default:
          throw new DslError('unknown operator ' + n.op, 0);
      }
    }
  }
}

const compiled = new Map<string, Predicate>();

/** Compile (and memoise) a filter expression. Throws DslError on bad syntax. */
export function where(expr: string): Predicate {
  const hit = compiled.get(expr);
  if (hit) return hit;
  const fn = compileNode(parse(lex(expr)));
  compiled.set(expr, fn);
  return fn;
}

/** "5m" / "90s" / "2h" / "1d" -> milliseconds. Numbers are already ms. */
export function ms(d: string | number): number {
  if (typeof d === 'number') return d;
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h|d)$/.exec(d.trim());
  if (!m) throw new Error('bad duration: ' + d);
  const units: Record<string, number> = { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000 };
  return Number(m[1]) * units[m[2]];
}
