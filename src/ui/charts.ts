import type { LogEvent, SourceKind } from '../core/types.js';
import { INK, MONO, SOURCE_COLOR, SOURCE_ORDER } from './theme.js';
import { compact, hhmm, num } from './format.js';

/** Canvas charts, drawn by hand. Two rules from the house style get enforced
 *  here rather than left to taste: marks stay thin (bars capped at 24px, the
 *  band's leftover is air) and touching fills are separated by a 2px gap in the
 *  surface colour instead of a stroke. */

const GAP = 2;
const MAX_BAR = 24;

export interface Bucket {
  t0: number;
  t1: number;
  counts: Record<SourceKind, number>;
  total: number;
}

/** Split a time range into `n` even buckets and tally each source. */
export function bucketEvents(events: LogEvent[], n: number): Bucket[] {
  if (!events.length) return [];
  let lo = Infinity;
  let hi = -Infinity;
  for (const e of events) {
    if (e.ts < lo) lo = e.ts;
    if (e.ts > hi) hi = e.ts;
  }
  if (hi === lo) hi = lo + 60_000;
  const width = (hi - lo) / n;
  const out: Bucket[] = Array.from({ length: n }, (_, i) => ({
    t0: lo + i * width,
    t1: lo + (i + 1) * width,
    counts: { ssh: 0, web: 0, windows: 0, firewall: 0 },
    total: 0,
  }));
  for (const e of events) {
    const i = Math.min(n - 1, Math.floor((e.ts - lo) / width));
    out[i].counts[e.source]++;
    out[i].total++;
  }
  return out;
}

interface Fitted {
  ctx: CanvasRenderingContext2D;
  w: number;
  h: number;
}

/** Match the backing store to the CSS box so text stays crisp on HiDPI. */
function fit(canvas: HTMLCanvasElement): Fitted | null {
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = canvas.clientWidth;
  const h = canvas.clientHeight || Number(canvas.getAttribute('height'));
  if (!w || !h) return null;
  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(h * dpr);
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  return { ctx, w, h };
}

/** Nice round y-axis ceiling, so ticks read 0 / 20 / 40 rather than 0 / 17 / 34.
 *  The step list is deliberately fine-grained - with only 1/2/5/10 a peak of 52
 *  rounds all the way to 100 and the plot spends half its height empty. */
function niceMax(v: number): number {
  if (v <= 4) return 4;
  const mag = 10 ** Math.floor(Math.log10(v));
  for (const step of [1, 1.2, 1.6, 2, 2.4, 3, 4, 5, 6, 8, 10]) {
    const m = step * mag;
    if (m >= v) return m;
  }
  return 10 * mag;
}

function roundTop(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number): void {
  const rr = Math.min(r, w / 2, Math.max(0, h));
  ctx.beginPath();
  ctx.moveTo(x, y + h);
  ctx.lineTo(x, y + rr);
  ctx.quadraticCurveTo(x, y, x + rr, y);
  ctx.lineTo(x + w - rr, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + rr);
  ctx.lineTo(x + w, y + h);
  ctx.closePath();
  ctx.fill();
}

function roundEnd(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number): void {
  const rr = Math.min(r, w, h / 2);
  ctx.beginPath();
  ctx.moveTo(x, y);
  ctx.lineTo(x + w - rr, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + rr);
  ctx.lineTo(x + w, y + h - rr);
  ctx.quadraticCurveTo(x + w, y + h, x + w - rr, y + h);
  ctx.lineTo(x, y + h);
  ctx.closePath();
  ctx.fill();
}

export interface TimelineHit {
  index: number;
  x: number;
  bucket: Bucket;
}

export interface TimelineLayout {
  bands: { x: number; w: number }[];
  plotTop: number;
  plotBottom: number;
}

/** Stacked columns, one band per bucket, segments in SOURCE_ORDER. */
export function drawTimeline(
  canvas: HTMLCanvasElement,
  buckets: Bucket[],
  hover: number | null,
): TimelineLayout | null {
  const f = fit(canvas);
  if (!f) return null;
  const { ctx, w, h } = f;
  const padL = 36;
  const padR = 6;
  const padT = 8;
  const padB = 20;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;
  const bands: { x: number; w: number }[] = [];

  if (!buckets.length) {
    ctx.fillStyle = INK.muted;
    ctx.font = MONO;
    ctx.textAlign = 'center';
    ctx.fillText('no events in range', w / 2, h / 2);
    return { bands, plotTop: padT, plotBottom: padT + plotH };
  }

  const max = niceMax(Math.max(...buckets.map((b) => b.total)));
  const y = (v: number) => padT + plotH - (v / max) * plotH;

  // hairline grid, solid, one step off the surface
  ctx.strokeStyle = INK.grid;
  ctx.lineWidth = 1;
  ctx.font = MONO;
  ctx.fillStyle = INK.muted;
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  for (let i = 0; i <= 4; i++) {
    const v = (max / 4) * i;
    const yy = Math.round(y(v)) + 0.5;
    ctx.beginPath();
    ctx.moveTo(padL, yy);
    ctx.lineTo(w - padR, yy);
    ctx.stroke();
    if (i % 2 === 0 || max <= 10) ctx.fillText(compact(v), padL - 7, yy);
  }

  const band = plotW / buckets.length;
  // never fill the band - the leftover is the air that keeps columns readable
  const barW = Math.min(MAX_BAR, Math.max(2, band * 0.66));

  buckets.forEach((b, i) => {
    const x = padL + i * band + (band - barW) / 2;
    bands.push({ x: padL + i * band, w: band });
    if (hover === i) {
      ctx.fillStyle = '#f1f7f9';
      ctx.fillRect(padL + i * band, padT, band, plotH);
    }
    if (!b.total) return;

    let cursor = padT + plotH;
    const stack = SOURCE_ORDER.filter((s) => b.counts[s] > 0);
    stack.forEach((s, si) => {
      const raw = (b.counts[s] / max) * plotH;
      // the 2px separator is taken out of the segment, not drawn on top of it
      const isTop = si === stack.length - 1;
      const seg = Math.max(1, raw - (isTop ? 0 : GAP));
      const top = cursor - raw;
      ctx.fillStyle = SOURCE_COLOR[s];
      if (isTop) roundTop(ctx, x, top, barW, seg, 4);
      else ctx.fillRect(x, top + (raw - seg), barW, seg);
      cursor = top;
    });
  });

  // baseline
  ctx.strokeStyle = INK.axis;
  ctx.beginPath();
  ctx.moveTo(padL, Math.round(padT + plotH) + 0.5);
  ctx.lineTo(w - padR, Math.round(padT + plotH) + 0.5);
  ctx.stroke();

  // x ticks - five at most, first and last pinned to the data range
  ctx.fillStyle = INK.muted;
  ctx.textBaseline = 'top';
  const ticks = Math.min(5, buckets.length);
  for (let i = 0; i < ticks; i++) {
    const bi = Math.round((i / (ticks - 1)) * (buckets.length - 1));
    const cx = padL + bi * band + band / 2;
    ctx.textAlign = i === 0 ? 'left' : i === ticks - 1 ? 'right' : 'center';
    const tx = i === 0 ? padL : i === ticks - 1 ? w - padR : cx;
    ctx.fillText(hhmm(buckets[bi].t0), tx, padT + plotH + 6);
  }

  return { bands, plotTop: padT, plotBottom: padT + plotH };
}

export interface TalkerRow {
  ip: string;
  count: number;
  geo?: string;
}

/** Horizontal bars, one colour - length carries the magnitude, so a value ramp
 *  here would just double-encode what the bar already says. */
export function drawTalkers(canvas: HTMLCanvasElement, rows: TalkerRow[], hover: number | null): number[] {
  const f = fit(canvas);
  const tops: number[] = [];
  if (!f) return tops;
  const { ctx, w, h } = f;

  if (!rows.length) {
    ctx.fillStyle = INK.muted;
    ctx.font = MONO;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('no traffic in range', w / 2, h / 2);
    return tops;
  }

  const labelW = 108;
  const valueW = 40;
  const barMax = w - labelW - valueW - 8;
  const max = Math.max(...rows.map((r) => r.count));
  const slot = h / rows.length;
  const barH = Math.min(MAX_BAR, slot - 6);

  ctx.font = MONO;
  ctx.textBaseline = 'middle';

  rows.forEach((r, i) => {
    const cy = i * slot + slot / 2;
    tops.push(i * slot);
    if (hover === i) {
      ctx.fillStyle = '#f1f7f9';
      ctx.fillRect(0, i * slot, w, slot);
    }

    ctx.fillStyle = INK.secondary;
    ctx.textAlign = 'left';
    ctx.fillText(r.ip, 0, cy);

    const len = Math.max(2, (r.count / max) * barMax);
    const grad = ctx.createLinearGradient(labelW, 0, labelW + len, 0);
    grad.addColorStop(0, INK.accentLift);
    grad.addColorStop(1, INK.accent);
    ctx.fillStyle = grad;
    roundEnd(ctx, labelW, cy - barH / 2, len, barH, 4);

    // value at the tip, in ink - never in the series colour
    ctx.fillStyle = INK.primary;
    ctx.textAlign = 'left';
    ctx.fillText(num(r.count), labelW + len + 6, cy);
  });

  return tops;
}
