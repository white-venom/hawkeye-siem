import './styles.css';

import type { LogEvent, Severity, SourceKind } from './core/types.js';
import type { Rule } from './core/rules/types.js';
import type { Alert } from './core/engine.js';
import { detect } from './core/engine.js';
import { RULES } from './core/rules/index.js';
import { PARSERS, detectParser, getParser, type ParserId } from './core/parsers/index.js';
import { geoLookup } from './core/geo.js';
import { DATASETS, REPLAY, SAMPLE_YEAR, type ReplayStep } from './data/index.js';
import { SEVERITIES, SEVERITY_COLOR, SOURCE_COLOR, SOURCE_LABEL, SOURCE_ORDER } from './ui/theme.js';
import { bucketEvents, drawTalkers, drawTimeline, type Bucket, type TalkerRow, type TimelineLayout } from './ui/charts.js';
import { bytes, compact, dayTime, esc, hhmm, hhmmss, num, pct } from './ui/format.js';

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

/* ------------------------------------------------------------------ state -- */

interface Feed {
  id: string;
  label: string;
  sub: string;
  parser: ParserId;
  events: LogEvent[];
  lines: number;
  skipped: number;
  enabled: boolean;
  removable: boolean;
}

const feeds: Feed[] = [];
const ruleOn = new Map<string, boolean>(RULES.map((r) => [r.id, true]));

const filters = {
  severity: new Set<Severity>(),
  source: new Set<SourceKind>(),
  q: '',
};

let alertSort: 'severity' | 'recent' = 'severity';
let events: LogEvent[] = [];
let alerts: Alert[] = [];

/** Events pushed since the last paint, so the tail can flash them once. */
const freshEvents = new Set<LogEvent>();
const knownAlerts = new Set<string>();
const openAlerts = new Set<string>();

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/* ---------------------------------------------------------------- compute -- */

let computeTimer: number | null = null;

function activeRules(): Rule[] {
  return RULES.map((r) => ({ ...r, enabled: ruleOn.get(r.id) !== false }));
}

function compute(): void {
  events = feeds
    .filter((f) => f.enabled)
    .flatMap((f) => f.events)
    .sort((a, b) => a.ts - b.ts);
  alerts = detect(activeRules(), events);
  render();
}

/** Coalesce the burst of pushes a replay produces into one recompute. */
function scheduleCompute(): void {
  if (computeTimer !== null) return;
  computeTimer = window.setTimeout(() => {
    computeTimer = null;
    compute();
  }, 220);
}

/* ---------------------------------------------------------------- filters -- */

function matchesQuery(hay: (string | undefined)[], q: string): boolean {
  if (!q) return true;
  return hay.some((h) => h && h.toLowerCase().includes(q));
}

function visibleEvents(): LogEvent[] {
  const q = filters.q;
  const srcs = filters.source;
  if (!q && !srcs.size) return events;
  return events.filter(
    (e) =>
      (!srcs.size || srcs.has(e.source)) &&
      matchesQuery([e.srcIp, e.dstIp, e.user, e.path, e.action, e.host, e.msg, e.raw], q),
  );
}

function visibleAlerts(): Alert[] {
  const q = filters.q;
  const out = alerts.filter(
    (a) =>
      (!filters.severity.size || filters.severity.has(a.severity)) &&
      (!filters.source.size || a.sources.some((s) => filters.source.has(s))) &&
      matchesQuery([a.ruleName, a.ruleId, a.narrative, a.mitre.id, a.mitre.name, ...Object.values(a.entity)], q),
  );
  out.sort((x, y) =>
    alertSort === 'recent'
      ? y.lastSeen - x.lastSeen
      : SEV_RANK[x.severity] - SEV_RANK[y.severity] || y.lastSeen - x.lastSeen,
  );
  return out;
}

/* ----------------------------------------------------------------- render -- */

let lastBuckets: Bucket[] = [];
let lastLayout: TimelineLayout | null = null;
let lastTalkers: TalkerRow[] = [];
let talkerTops: number[] = [];
let hoverBucket: number | null = null;
let hoverTalker: number | null = null;

function render(): void {
  const ev = visibleEvents();
  const al = visibleAlerts();
  renderPipeline(ev, al);
  renderWindow(ev);
  renderFilterChips(ev, al);
  renderFeeds();
  renderRules();
  renderTimeline(ev);
  renderTalkers(ev);
  renderSeverity(al);
  renderEvents(ev);
  renderAlerts(al);
  freshEvents.clear();
}

function renderPipeline(ev: LogEvent[], al: Alert[]): void {
  const on = feeds.filter((f) => f.enabled);
  const lines = on.reduce((a, f) => a + f.lines, 0);
  const skipped = on.reduce((a, f) => a + f.skipped, 0);
  const armed = RULES.filter((r) => ruleOn.get(r.id) !== false).length;
  const crit = al.filter((a) => a.severity === 'critical').length;
  const high = al.filter((a) => a.severity === 'high').length;

  $('stat-lines').textContent = num(lines);
  $('stat-lines-note').textContent = on.length + (on.length === 1 ? ' source' : ' sources');
  $('stat-events').textContent = num(events.length);
  $('stat-events-note').textContent = skipped ? num(skipped) + ' lines not understood' : 'every line understood';
  $('stat-rules').textContent = String(armed);
  $('stat-rules-note').textContent = armed === RULES.length ? 'all enabled' : armed + ' of ' + RULES.length + ' enabled';
  $('stat-alerts').textContent = num(al.length);
  $('stat-alerts-note').textContent = al.length
    ? crit + ' critical · ' + high + ' high'
    : 'nothing has matched';
  if (ev.length !== events.length) {
    $('stat-events-note').textContent = num(ev.length) + ' match the filter';
  }
}

function renderWindow(ev: LogEvent[]): void {
  const el = $('window-label');
  if (!events.length) {
    el.textContent = 'no data loaded';
    return;
  }
  const lo = events[0].ts;
  const hi = events[events.length - 1].ts;
  el.innerHTML =
    esc(dayTime(lo)) + ' &rarr; ' + esc(hhmm(hi)) + ' UTC<br><b>' + num(ev.length) + '</b> events in view';
}

function renderFilterChips(ev: LogEvent[], al: Alert[]): void {
  const sevWrap = $('filter-severity');
  const sevCounts = new Map<Severity, number>();
  for (const a of alerts) sevCounts.set(a.severity, (sevCounts.get(a.severity) ?? 0) + 1);
  sevWrap.innerHTML = SEVERITIES.filter((s) => sevCounts.get(s) || filters.severity.has(s))
    .map(
      (s) =>
        `<button class="chip" type="button" data-sev="${s}" aria-pressed="${filters.severity.has(s)}">` +
        `<i class="swatch" style="background:${SEVERITY_COLOR[s]}"></i>${s}<span class="n">${sevCounts.get(s) ?? 0}</span></button>`,
    )
    .join('');
  if (!sevWrap.innerHTML) sevWrap.innerHTML = '<span class="hint">no alerts yet</span>';

  const srcWrap = $('filter-source');
  const srcCounts = new Map<SourceKind, number>();
  for (const e of events) srcCounts.set(e.source, (srcCounts.get(e.source) ?? 0) + 1);
  srcWrap.innerHTML = SOURCE_ORDER.filter((s) => srcCounts.has(s) || filters.source.has(s))
    .map(
      (s) =>
        `<button class="chip" type="button" data-src="${s}" aria-pressed="${filters.source.has(s)}">` +
        `<i class="swatch" style="background:${SOURCE_COLOR[s]}"></i>${SOURCE_LABEL[s]}` +
        `<span class="n">${compact(srcCounts.get(s) ?? 0)}</span></button>`,
    )
    .join('');

  $('filter-reset').hidden = !filters.severity.size && !filters.source.size && !filters.q;
  void ev;
  void al;
}

function renderFeeds(): void {
  $('dataset-list').innerHTML = feeds
    .map(
      (f) =>
        `<button class="row-toggle" type="button" data-feed="${esc(f.id)}" aria-pressed="${f.enabled}">` +
        `<span class="box"></span>` +
        `<span class="row-main"><span class="row-name">${esc(f.label)}</span>` +
        `<span class="row-sub">${esc(f.sub)}</span></span>` +
        `<span class="row-n">${compact(f.events.length)}</span></button>`,
    )
    .join('');
}

/** The rule panel is read-only on purpose: it shows the DSL a rule is actually
 *  built from, which is the point, without pretending to be an editor. */
function dslBlock(r: Rule): string {
  const d = r.detect;
  const line = (k: string, v: string) => `<b>${k.padEnd(7)}</b>${esc(v)}`;
  if (d.type === 'threshold') {
    const what = d.distinct
      ? `${d.count} distinct ${d.distinct}`
      : d.sum
        ? `${bytes(d.count)} of ${d.sum}`
        : `${d.count} event${d.count === 1 ? '' : 's'}`;
    return [line('where', d.where), line('group', d.groupBy.join(', ')), line('count', what), line('within', d.within)].join('\n');
  }
  if (d.type === 'sequence') {
    return [
      line('group', d.groupBy.join(', ')),
      line('within', d.within),
      ...d.steps.map((s, i) => line('step ' + (i + 1), '×' + (s.count ?? 1) + '  ' + s.where)),
    ].join('\n');
  }
  return [
    line('where', d.where),
    line('group', d.groupBy.join(', ')),
    line('travel', `≥${d.minKm} km at ≥${d.minKmh} km/h`),
    line('within', d.within),
  ].join('\n');
}

function renderRules(): void {
  const hits = new Map<string, number>();
  for (const a of alerts) hits.set(a.ruleId, (hits.get(a.ruleId) ?? 0) + 1);
  const armed = RULES.filter((r) => ruleOn.get(r.id) !== false).length;
  $('rule-count').textContent = armed + '/' + RULES.length;

  $('rule-list').innerHTML = RULES.map((r) => {
    const on = ruleOn.get(r.id) !== false;
    const n = hits.get(r.id) ?? 0;
    return (
      `<details class="rule" data-rule="${r.id}" data-off="${!on}">` +
      `<summary>` +
      `<span class="rule-check" data-ruletoggle="${r.id}" role="checkbox" aria-checked="${on}" tabindex="0" ` +
      `aria-label="${on ? 'Disable' : 'Enable'} ${esc(r.name)}"><span class="box"></span></span>` +
      `<span class="rule-name" title="${esc(r.name)}">${esc(r.name)}</span>` +
      (n ? `<span class="row-n">${n}</span>` : '') +
      `<span class="sev-tag sev-${r.severity}">${r.severity}</span>` +
      `</summary>` +
      `<div class="rule-body"><p>${esc(r.description)}</p>` +
      `<pre class="dsl">${dslBlock(r)}</pre>` +
      `<span class="mitre">${esc(r.mitre.id)} · ${esc(r.mitre.name)}</span></div></details>`
    );
  }).join('');
}

function renderTimeline(ev: LogEvent[]): void {
  lastBuckets = bucketEvents(ev, 60);
  lastLayout = drawTimeline($<HTMLCanvasElement>('timeline'), lastBuckets, hoverBucket);

  $('timeline-legend').innerHTML = SOURCE_ORDER.map(
    (s) => `<span><i style="background:${SOURCE_COLOR[s]}"></i>${SOURCE_LABEL[s]}</span>`,
  ).join('');

  if (!$('timeline-table').hidden) renderTimelineTable(ev);
}

function renderTimelineTable(ev: LogEvent[]): void {
  const rows = bucketEvents(ev, 12);
  $('timeline-table').innerHTML =
    '<table><thead><tr><th>From</th>' +
    SOURCE_ORDER.map((s) => `<th>${SOURCE_LABEL[s]}</th>`).join('') +
    '<th>Total</th></tr></thead><tbody>' +
    rows
      .map(
        (b) =>
          `<tr><td>${hhmm(b.t0)}</td>` +
          SOURCE_ORDER.map((s) => `<td>${b.counts[s] || '·'}</td>`).join('') +
          `<td>${b.total}</td></tr>`,
      )
      .join('') +
    '</tbody></table>';
}

function renderTalkers(ev: LogEvent[]): void {
  const counts = new Map<string, number>();
  for (const e of ev) if (e.srcIp) counts.set(e.srcIp, (counts.get(e.srcIp) ?? 0) + 1);
  lastTalkers = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([ip, count]) => {
      const g = geoLookup(ip);
      return { ip, count, geo: g ? g.city + ', ' + g.cc + ' · ' + g.org : 'not in geo table' };
    });
  talkerTops = drawTalkers($<HTMLCanvasElement>('talkers'), lastTalkers, hoverTalker);
  $('talkers-note').textContent = counts.size ? num(counts.size) + ' distinct addresses' : '';
}

function renderSeverity(al: Alert[]): void {
  const counts = SEVERITIES.map((s) => ({ s, n: al.filter((a) => a.severity === s).length }));
  const total = al.length;
  const strip = counts
    .filter((c) => c.n)
    .map((c) => `<span style="flex:${c.n};background:${SEVERITY_COLOR[c.s]}"></span>`)
    .join('');

  // which rules are actually carrying the load - the question an analyst asks
  // straight after "how bad is it"
  const byRule = new Map<string, { name: string; sev: Severity; n: number }>();
  for (const a of al) {
    const cur = byRule.get(a.ruleId);
    if (cur) cur.n++;
    else byRule.set(a.ruleId, { name: a.ruleName, sev: a.severity, n: 1 });
  }
  const firing = [...byRule.values()].sort((a, b) => SEV_RANK[a.sev] - SEV_RANK[b.sev] || b.n - a.n);

  $('severity-bd').innerHTML =
    `<div class="sev-strip">${strip}</div>` +
    '<div class="sev-rows">' +
    counts
      .map(
        (c) =>
          `<div class="sev-row${c.n ? '' : ' zero'}"><i style="background:${SEVERITY_COLOR[c.s]}"></i>` +
          `<span>${c.s}</span><b>${c.n}${c.n ? ` <span class="count">${pct(c.n, total)}</span>` : ''}</b></div>`,
      )
      .join('') +
    '</div>' +
    (firing.length
      ? '<div class="sev-firing"><span class="firing-label">Firing rules</span>' +
        firing
          .map(
            (r) =>
              `<div class="firing-row"><i style="background:${SEVERITY_COLOR[r.sev]}"></i>` +
              `<span title="${esc(r.name)}">${esc(r.name)}</span><b>${r.n}</b></div>`,
          )
          .join('') +
        '</div>'
      : '');
}

const MAX_ROWS = 200;

function renderEvents(ev: LogEvent[]): void {
  const rows = ev.slice(-MAX_ROWS).reverse();
  $('stream-note').textContent =
    ev.length > MAX_ROWS ? 'newest ' + MAX_ROWS + ' of ' + num(ev.length) : num(ev.length) + ' rows';

  $('event-rows').innerHTML = rows
    .map((e) => {
      const fresh = freshEvents.has(e) ? ' class="fresh"' : '';
      return (
        `<tr${fresh} title="${esc(e.raw)}">` +
        `<td>${hhmmss(e.ts)}</td>` +
        `<td><span class="src-tag"><i style="background:${SOURCE_COLOR[e.source]}"></i>${SOURCE_LABEL[e.source]}</span></td>` +
        `<td class="c-ip">${esc(e.srcIp ?? '—')}</td>` +
        `<td class="c-user">${esc(e.user ?? '—')}</td>` +
        `<td>${esc(e.action)}</td>` +
        `<td class="st st-${e.status}">${e.status}</td>` +
        `<td class="c-detail">${esc(e.msg ?? e.raw.slice(0, 120))}</td></tr>`
      );
    })
    .join('');
}

function evidenceRow(e: LogEvent): string {
  return (
    '<tr><td>' +
    hhmmss(e.ts) +
    '</td><td>' +
    SOURCE_LABEL[e.source] +
    '</td><td>' +
    esc(e.srcIp ?? '—') +
    '</td><td>' +
    esc(e.user ?? '—') +
    '</td><td>' +
    esc(e.msg ?? e.action) +
    '</td></tr>'
  );
}

function renderAlerts(al: Alert[]): void {
  $('alert-count').textContent = al.length ? String(al.length) : '';
  const list = $('alert-list');

  if (!al.length) {
    list.innerHTML =
      '<div class="empty"><b>No alerts in view.</b>' +
      (alerts.length
        ? 'Nothing matches the current filter.'
        : RULES.filter((r) => ruleOn.get(r.id) !== false).length +
          ' rules are armed and quiet. Hit <em>Replay attack</em> to push an intrusion through them.') +
      '</div>';
    return;
  }

  list.innerHTML = al
    .map((a) => {
      const isNew = !knownAlerts.has(a.id);
      const evid = a.evidence.slice(-14);
      const entity = Object.entries(a.entity)
        .map(([k, v]) => `<code>${esc(k)}=${esc(v)}</code>`)
        .join(' ');
      const g = a.entity.srcIp ? geoLookup(a.entity.srcIp) : undefined;
      return (
        `<details class="alert${isNew ? ' new' : ''}" data-sev="${a.severity}" data-id="${esc(a.id)}"${openAlerts.has(a.id) ? ' open' : ''}>` +
        `<summary>` +
        `<div class="alert-top"><span class="sev-tag sev-${a.severity}">${a.severity}</span>` +
        `<span class="alert-rule">${esc(a.ruleName)}</span>` +
        `<span class="alert-when">${hhmm(a.lastSeen)}</span></div>` +
        `<div class="alert-why">${esc(a.narrative)}</div>` +
        `<div class="alert-meta">${entity}` +
        (g ? `<span>${esc(g.city)}, ${esc(g.cc)}</span>` : '') +
        `<span>${esc(a.mitre.id)}</span>` +
        `<span>${a.evidence.length} evidence rows</span>` +
        `<span>${a.sources.map((s) => SOURCE_LABEL[s]).join(' + ')}</span></div>` +
        `</summary>` +
        `<div class="alert-evidence"><table><tbody>${evid.map(evidenceRow).join('')}</tbody></table>` +
        (a.evidence.length > evid.length
          ? `<div class="more">showing the last ${evid.length} of ${a.evidence.length}</div>`
          : '') +
        `</div></details>`
      );
    })
    .join('');

  for (const a of al) knownAlerts.add(a.id);
}

/* ------------------------------------------------------------ interaction -- */

function bindFilters(): void {
  $('filter-severity').addEventListener('click', (e) => {
    const b = (e.target as HTMLElement).closest<HTMLElement>('[data-sev]');
    if (!b) return;
    const s = b.dataset.sev as Severity;
    filters.severity.has(s) ? filters.severity.delete(s) : filters.severity.add(s);
    render();
  });

  $('filter-source').addEventListener('click', (e) => {
    const b = (e.target as HTMLElement).closest<HTMLElement>('[data-src]');
    if (!b) return;
    const s = b.dataset.src as SourceKind;
    filters.source.has(s) ? filters.source.delete(s) : filters.source.add(s);
    render();
  });

  let qTimer: number | null = null;
  $<HTMLInputElement>('filter-q').addEventListener('input', (e) => {
    const v = (e.target as HTMLInputElement).value.trim().toLowerCase();
    if (qTimer) window.clearTimeout(qTimer);
    qTimer = window.setTimeout(() => {
      filters.q = v;
      render();
    }, 140);
  });

  $('filter-reset').addEventListener('click', () => {
    filters.severity.clear();
    filters.source.clear();
    filters.q = '';
    $<HTMLInputElement>('filter-q').value = '';
    render();
  });

  $('dataset-list').addEventListener('click', (e) => {
    const b = (e.target as HTMLElement).closest<HTMLElement>('[data-feed]');
    if (!b) return;
    const f = feeds.find((x) => x.id === b.dataset.feed);
    if (!f) return;
    f.enabled = !f.enabled;
    compute();
  });

  const toggleRule = (t: HTMLElement) => {
    const id = t.dataset.ruletoggle!;
    ruleOn.set(id, ruleOn.get(id) === false);
    compute();
  };

  $('rule-list').addEventListener('click', (e) => {
    const t = (e.target as HTMLElement).closest<HTMLElement>('[data-ruletoggle]');
    if (!t) return;
    e.preventDefault(); // don't let the click fall through and open the details
    toggleRule(t);
  });

  $('rule-list').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const t = (e.target as HTMLElement).closest<HTMLElement>('[data-ruletoggle]');
    if (!t) return;
    e.preventDefault();
    toggleRule(t);
  });

  $('alert-list').addEventListener('toggle', (e) => {
    const d = e.target as HTMLDetailsElement;
    if (!d.dataset.id) return;
    d.open ? openAlerts.add(d.dataset.id) : openAlerts.delete(d.dataset.id);
  }, true);

  $<HTMLSelectElement>('alert-sort').addEventListener('change', (e) => {
    alertSort = (e.target as HTMLSelectElement).value as 'severity' | 'recent';
    render();
  });

  const tableBtn = $('timeline-table-btn');
  tableBtn.addEventListener('click', () => {
    const show = $('timeline-table').hidden;
    $('timeline-table').hidden = !show;
    (document.querySelector('#timeline')!.parentElement as HTMLElement).hidden = show;
    tableBtn.setAttribute('aria-pressed', String(show));
    render();
  });
}

function bindChartHover(): void {
  const tl = $<HTMLCanvasElement>('timeline');
  const tip = $('timeline-tip');

  tl.addEventListener('mousemove', (e) => {
    if (!lastLayout || !lastBuckets.length) return;
    const r = tl.getBoundingClientRect();
    const x = e.clientX - r.left;
    const i = lastLayout.bands.findIndex((b) => x >= b.x && x < b.x + b.w);
    if (i === hoverBucket) {
      if (i >= 0) placeTip(tip, e.clientX - r.left, r);
      return;
    }
    hoverBucket = i >= 0 ? i : null;
    drawTimeline(tl, lastBuckets, hoverBucket);
    if (hoverBucket === null) {
      tip.hidden = true;
      return;
    }
    const b = lastBuckets[hoverBucket];
    tip.innerHTML =
      `<b>${hhmm(b.t0)} – ${hhmm(b.t1)}</b>` +
      SOURCE_ORDER.filter((s) => b.counts[s])
        .map(
          (s) =>
            `<span class="r"><span><i style="background:${SOURCE_COLOR[s]}"></i>${SOURCE_LABEL[s]}</span><span>${b.counts[s]}</span></span>`,
        )
        .join('') +
      `<span class="r"><span>total</span><span>${b.total}</span></span>`;
    tip.hidden = false;
    placeTip(tip, x, r);
  });

  tl.addEventListener('mouseleave', () => {
    hoverBucket = null;
    tip.hidden = true;
    if (lastBuckets.length) drawTimeline(tl, lastBuckets, null);
  });

  const tk = $<HTMLCanvasElement>('talkers');
  const ttip = $('talkers-tip');
  tk.addEventListener('mousemove', (e) => {
    if (!lastTalkers.length) return;
    const r = tk.getBoundingClientRect();
    const y = e.clientY - r.top;
    let i = -1;
    for (let k = talkerTops.length - 1; k >= 0; k--) if (y >= talkerTops[k]) { i = k; break; }
    if (i !== hoverTalker) {
      hoverTalker = i >= 0 ? i : null;
      drawTalkers(tk, lastTalkers, hoverTalker);
    }
    if (hoverTalker === null) {
      ttip.hidden = true;
      return;
    }
    const row = lastTalkers[hoverTalker];
    ttip.innerHTML = `<b>${esc(row.ip)}</b><span class="r"><span>events</span><span>${num(row.count)}</span></span><span class="r"><span>${esc(row.geo ?? '')}</span></span>`;
    ttip.hidden = false;
    placeTip(ttip, e.clientX - r.left, r, y + 14);
  });
  tk.addEventListener('mouseleave', () => {
    hoverTalker = null;
    ttip.hidden = true;
    if (lastTalkers.length) drawTalkers(tk, lastTalkers, null);
  });
}

function placeTip(tip: HTMLElement, x: number, r: DOMRect, top = 8): void {
  const w = tip.offsetWidth || 150;
  tip.style.left = Math.max(0, Math.min(x + 12, r.width - w - 4)) + 'px';
  tip.style.top = top + 'px';
}

/* ---------------------------------------------------------------- ingest -- */

function bindIngest(): void {
  const sel = $<HTMLSelectElement>('ingest-parser');
  sel.innerHTML =
    '<option value="">Detect format automatically</option>' +
    PARSERS.map((p) => `<option value="${p.id}">${esc(p.label)}</option>`).join('');

  const area = $<HTMLTextAreaElement>('ingest-text');
  const status = $('ingest-status');

  area.addEventListener('input', () => {
    const guess = detectParser(area.value);
    status.textContent = area.value.trim() ? (guess ? 'looks like ' + guess : 'format not recognised') : '';
  });

  const readFile = (file: File) => {
    file.text().then((t) => {
      area.value = t;
      area.dispatchEvent(new Event('input'));
    });
  };

  for (const evName of ['dragover', 'dragenter'] as const) {
    area.addEventListener(evName, (e) => {
      e.preventDefault();
      area.classList.add('dropping');
    });
  }
  for (const evName of ['dragleave', 'drop'] as const) {
    area.addEventListener(evName, () => area.classList.remove('dropping'));
  }
  area.addEventListener('drop', (e) => {
    e.preventDefault();
    const f = e.dataTransfer?.files?.[0];
    if (f) readFile(f);
  });

  $('ingest-add').addEventListener('click', () => {
    const text = area.value.trim();
    if (!text) {
      status.textContent = 'nothing to parse';
      return;
    }
    const id = (sel.value as ParserId) || detectParser(text);
    if (!id) {
      status.textContent = 'no parser matches this - pick one from the list';
      return;
    }
    const p = getParser(id);
    const r = p.parse(text, { year: SAMPLE_YEAR });
    if (!r.events.length) {
      status.textContent = 'parsed 0 events with ' + id + ' - wrong parser?';
      return;
    }
    const n = feeds.filter((f) => !f.removable).length;
    feeds.push({
      id: 'pasted-' + n,
      label: 'pasted-' + n,
      sub: p.label,
      parser: id,
      events: r.events,
      lines: r.events.length + r.skipped.length,
      skipped: r.skipped.length,
      enabled: true,
      removable: true,
    });
    status.textContent = num(r.events.length) + ' events in, ' + r.skipped.length + ' skipped';
    area.value = '';
    compute();
  });
}

/* ---------------------------------------------------------------- replay -- */

let replayTimer: number | null = null;
let replayIndex = 0;

const PHASES: string[] = [...new Set(REPLAY.map((s) => s.phase))];

function replayFeed(): Feed {
  let f = feeds.find((x) => x.id === 'replay');
  if (!f) {
    f = {
      id: 'replay',
      label: 'replay',
      sub: 'scripted intrusion',
      parser: 'ssh',
      events: [],
      lines: 0,
      skipped: 0,
      enabled: true,
      removable: true,
    };
    feeds.push(f);
  }
  return f;
}

function renderPhases(current: number): void {
  const rail = $('phase-rail');
  rail.hidden = current < 0;
  if (current < 0) {
    rail.innerHTML = '';
    return;
  }
  rail.innerHTML = PHASES.map((p, i) => {
    const cls = i === current ? 'phase active' : i < current ? 'phase done' : 'phase';
    return `<span class="${cls}"><i>${i + 1}</i>${esc(p)}</span>`;
  }).join('');
}

function stopReplay(finished: boolean): void {
  if (replayTimer !== null) window.clearTimeout(replayTimer);
  replayTimer = null;
  const btn = $('replay-btn');
  btn.classList.remove('running');
  $('replay-label').textContent = finished ? 'Replay again' : 'Replay attack';
  if (finished) renderPhases(PHASES.length - 1);
  compute();
}

function pushStep(step: ReplayStep): void {
  const f = replayFeed();
  const r = getParser(step.parser).parse(step.line, { year: SAMPLE_YEAR });
  f.lines += 1;
  f.skipped += r.skipped.length;
  for (const e of r.events) {
    f.events.push(e);
    freshEvents.add(e);
  }
}

function tick(): void {
  if (replayIndex >= REPLAY.length) {
    stopReplay(true);
    return;
  }
  const step = REPLAY[replayIndex++];
  pushStep(step);
  renderPhases(PHASES.indexOf(step.phase));
  scheduleCompute();
  const next = REPLAY[replayIndex];
  replayTimer = window.setTimeout(tick, next ? next.delay : 400);
}

function startReplay(): void {
  const f = replayFeed();
  f.events = [];
  f.lines = 0;
  f.skipped = 0;
  f.enabled = true;
  replayIndex = 0;
  const btn = $('replay-btn');
  btn.classList.add('running');
  $('replay-label').textContent = 'Stop replay';
  renderPhases(0);
  compute();
  replayTimer = window.setTimeout(tick, REPLAY[0]?.delay ?? 300);
}

function bindReplay(): void {
  $('replay-btn').addEventListener('click', () => {
    if (replayTimer !== null) stopReplay(false);
    else startReplay();
  });
}

/* ------------------------------------------------------------------- boot -- */

function loadSamples(): void {
  for (const d of DATASETS) {
    const r = getParser(d.parser).parse(d.text, { year: SAMPLE_YEAR });
    feeds.push({
      id: d.id,
      label: d.name,
      sub: d.blurb,
      parser: d.parser,
      events: r.events,
      lines: r.events.length + r.skipped.length,
      skipped: r.skipped.length,
      enabled: true,
      removable: false,
    });
  }
}

function bindResize(): void {
  let t: number | null = null;
  window.addEventListener('resize', () => {
    if (t) window.clearTimeout(t);
    t = window.setTimeout(() => {
      renderTimeline(visibleEvents());
      renderTalkers(visibleEvents());
    }, 120);
  });
}

loadSamples();
bindFilters();
bindChartHover();
bindIngest();
bindReplay();
bindResize();
compute();

// fonts land after first paint and canvas text is measured, not reflowed
document.fonts?.ready.then(() => {
  renderTimeline(visibleEvents());
  renderTalkers(visibleEvents());
});
