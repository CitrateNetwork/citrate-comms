"use client";

/**
 * Citrate triangle loading animation — ported 1:1 from the user's claude.ai/design project
 * "Citrate triangle loading animation" (Citrate Loader.dc.html). The brand triangle's facets
 * peel off into a spinning ring and reassemble, continuously. Pure SVG + requestAnimationFrame
 * (no canvas, no deps). Used as the await-state so mermaid/chart blocks never flash code.
 */
import { useEffect, useRef } from "react";

// Tuned values from the design project's configured defaults.
const N = 160;
const SPEED = 2.1;
const CYCLE = 11000;
const TURNS = 1;
const HOLD = 0.008;
const RAMP = 0.09;
const RING = 52;
const SWEEP = 26;
const THICK = 18;

// The 11 facets of the Citrate mark (brand SVG, viewBox 11.63 2.14 100 100).
const FACETS = [
  "M40.05,65c2.21-.14,4.02-.63,5.3-1.1-1.94-2.21-3.88-4.41-5.82-6.62l-4.27,7.4c1.23.24,2.87.43,4.79.31Z",
  "M41.7,73.61c4.34-.04,7.98-.72,10.68-1.44-2.03-2.28-4.06-4.56-6.1-6.84-1.4.54-3.41,1.14-5.88,1.35-2.41.2-4.45-.04-5.9-.32l-3.47,6.01c2.71.66,6.35,1.28,10.68,1.24Z",
  "M53.37,74.02c-2.94.76-6.87,1.48-11.53,1.53-4.65.05-8.58-.59-11.53-1.28-.86,1.5-1.73,2.99-2.59,4.49-1.03,1.78.26,4.01,2.32,4.01h30.93c-2.53-2.92-5.06-5.83-7.59-8.75Z",
  "M62.58,47.91c.69-.85,1.4-1.69,2.13-2.51,1.49-1.69,3.08-3.3,4.81-4.74.92-.76,1.98-1.39,3.04-1.95.16-.08.32-.16.48-.25l-8.79-15.22c-1.03-1.78-3.6-1.78-4.63,0l-8.62,14.93c3.86,3.25,7.72,6.49,11.57,9.74Z",
  "M75.24,58.35c.44-.33.9-.66,1.37-.96,1.4-.89,2.8-1.77,4.27-2.56.5-.27,1.01-.53,1.52-.78l-8-13.85c-.86.42-1.69.9-2.48,1.43-.94.63-1.78,1.4-2.6,2.17-1.62,1.53-3.09,3.2-4.51,4.91-.17.2-.33.41-.5.61,3.64,3.01,7.29,6.02,10.93,9.03Z",
  "M79.77,57.69c-1.14.7-2.12,1.42-2.94,2.1,6.07,5.26,12.14,10.51,18.21,15.77l-11.43-19.8c-1.14.46-2.45,1.09-3.84,1.93Z",
  "M75.19,61.37s-.01.01-.02.01c-2.22,1.74-3.69,3.28-4.22,3.82-1.88,1.93-2.99,3.07-4.71,4.26-2.4,1.66-4.66,2.49-6.6,3.21-1.3.48-2.41.82-3.23,1.04,2.62,3.04,5.25,6.07,7.87,9.11h29.33c1.77,0,2.96-1.64,2.61-3.23-7.01-6.07-14.02-12.15-21.03-18.22Z",
  "M55.03,71.84c.12-.03.3-.07.51-.12,1.32-.33,3.76-.93,5.99-1.92,2.95-1.31,5-3.05,5.84-3.82,1.21-1.1,1.45-1.58,3.58-3.65,1.16-1.12,2.15-2,2.82-2.59-3.57-2.95-7.14-5.89-10.71-8.84-2.36,2.93-4.65,5.92-7.3,8.61-2.08,2.1-4.39,3.99-7.03,5.26l6.29,7.07Z",
  "M47.12,63.06c3.38-1.53,6.18-4.17,8.64-6.92,1.95-2.18,3.73-4.49,5.56-6.76-3.81-3.2-7.61-6.4-11.42-9.6l-9.21,15.96c2.14,2.44,4.29,4.88,6.43,7.32Z",
];

interface Pt { x: number; y: number }
interface Piece {
  path: SVGPathElement;
  src: Pt[];
  srcPolar: { r: number; a: number }[];
  order: number;
  slot: number;
  offset: number;
  rad: number;
  cw: number;
}

export function CitrateLoader({ size = 72 }: { size?: number }) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    let raf = 0;
    let cancelled = false;
    let pieces: Piece[] = [];
    let Cx = 61.63;
    let Cy = 52.14;
    let arc: { rad: number; ang: number }[] = [];
    let arcKey = "";
    let arcSign = 0;

    const signedArea = (pts: Pt[]) => {
      let s = 0;
      for (let i = 0; i < pts.length; i++) {
        const a = pts[i]!, b = pts[(i + 1) % pts.length]!;
        s += a.x * b.y - b.x * a.y;
      }
      return s / 2;
    };

    const resample = (pts: Pt[], M: number): Pt[] => {
      const seg: number[] = [];
      let total = 0;
      for (let i = 0; i < pts.length; i++) {
        const a = pts[i]!, b = pts[(i + 1) % pts.length]!;
        const d = Math.hypot(b.x - a.x, b.y - a.y);
        seg.push(d); total += d;
      }
      const out: Pt[] = [];
      const step = total / M;
      let i = 0, acc = 0;
      for (let j = 0; j < M; j++) {
        const dist = j * step;
        while (i < seg.length - 1 && acc + seg[i]! < dist) { acc += seg[i]!; i++; }
        const a = pts[i]!, b = pts[(i + 1) % pts.length]!;
        const f = seg[i] ? (dist - acc) / seg[i]! : 0;
        out.push({ x: a.x + (b.x - a.x) * f, y: a.y + (b.y - a.y) * f });
      }
      return out;
    };

    const buildArc = (R: number, sweepDeg: number, tMax: number) => {
      const sweep = (sweepDeg * Math.PI) / 180;
      const M = 200;
      const dense: Pt[] = [];
      const thick = (s: number) => tMax * Math.pow(s, 0.62);
      for (let k = 0; k <= M; k++) {
        const s = k / M, ang = -sweep / 2 + sweep * s, ro = R + thick(s) / 2;
        dense.push({ x: ro * Math.cos(ang), y: ro * Math.sin(ang) });
      }
      const ang1 = sweep / 2;
      const rad = { x: Math.cos(ang1), y: Math.sin(ang1) };
      const tan = { x: -Math.sin(ang1), y: Math.cos(ang1) };
      const Cc = { x: R * Math.cos(ang1), y: R * Math.sin(ang1) };
      const cr = tMax / 2, CAP = 26;
      for (let k = 1; k < CAP; k++) {
        const phi = (Math.PI * k) / CAP;
        dense.push({ x: Cc.x + cr * (Math.cos(phi) * rad.x + Math.sin(phi) * tan.x), y: Cc.y + cr * (Math.cos(phi) * rad.y + Math.sin(phi) * tan.y) });
      }
      for (let k = M; k >= 0; k--) {
        const s = k / M, ang = -sweep / 2 + sweep * s, ri = R - thick(s) / 2;
        dense.push({ x: ri * Math.cos(ang), y: ri * Math.sin(ang) });
      }
      const res = resample(dense, N);
      arcSign = signedArea(res);
      return res.map((pt) => ({ rad: Math.hypot(pt.x, pt.y), ang: Math.atan2(pt.y, pt.x) }));
    };

    const ease = (p: number) => { p = Math.max(0, Math.min(1, p)); return p * p * p * (p * (p * 6 - 15) + 10); };

    const alignOffsets = () => {
      const D = Math.PI / 180;
      for (const pc of pieces) {
        const base = pc.slot * D;
        const tx = new Float64Array(N), ty = new Float64Array(N);
        for (let i = 0; i < N; i++) { const a = base + arc[i]!.ang; tx[i] = Cx + arc[i]!.rad * Math.cos(a); ty[i] = Cy + arc[i]!.rad * Math.sin(a); }
        let best = 0, bestErr = Infinity;
        for (let o = 0; o < N; o++) {
          let err = 0;
          for (let k = 0; k < N; k += 4) { const s = pc.src[k]!, j = (k + o) % N; const dx = s.x - tx[j]!, dy = s.y - ty[j]!; err += dx * dx + dy * dy; if (err >= bestErr) break; }
          if (err < bestErr) { bestErr = err; best = o; }
        }
        pc.offset = best;
      }
    };

    const loop = () => {
      if (cancelled) return;
      const now = performance.now();
      const key = `${RING}|${SWEEP}|${THICK}`;
      if (key !== arcKey) { arc = buildArc(RING, SWEEP, THICK); arcKey = key; alignOffsets(); }
      const T = CYCLE / SPEED;
      const phase = (now % T) / T;
      const hold = HOLD, ramp = RAMP, n = pieces.length;
      const span = Math.max(0.05, (1 - 2 * hold) / 2);
      const downStart = hold, upStart = downStart + span + hold;
      const spin = 360 * TURNS * phase;
      const D = Math.PI / 180;
      for (const pc of pieces) {
        const m = pc.order;
        const outAt = downStart + (m / n) * (span - ramp);
        const inAt = upStart + (m / n) * (span - ramp);
        let ep: number;
        if (phase < outAt) ep = 0;
        else if (phase < outAt + ramp) ep = ease((phase - outAt) / ramp);
        else if (phase < inAt) ep = 1;
        else if (phase < inAt + ramp) ep = ease(1 - (phase - inAt) / ramp);
        else ep = 0;
        const midAng = (pc.slot + spin) * D;
        const off = pc.offset || 0;
        let d = "M";
        for (let k = 0; k < N; k++) {
          const ai = (k + off) % N;
          const rr = arc[ai]!.rad, ar = midAng + arc[ai]!.ang;
          const hp = pc.srcPolar[k]!;
          const r = hp.r + (rr - hp.r) * ep;
          let dA = ar - hp.a; dA = Math.atan2(Math.sin(dA), Math.cos(dA));
          const a = hp.a + dA * ep;
          d += (k ? "L" : "") + (Cx + r * Math.cos(a)).toFixed(2) + " " + (Cy + r * Math.sin(a)).toFixed(2);
        }
        d += "Z";
        pc.path.setAttribute("d", d);
      }
      raf = requestAnimationFrame(loop);
    };

    const start = () => {
      if (cancelled) return;
      const paths = Array.from(svg.querySelectorAll<SVGPathElement>(".pc"));
      if (!paths.length || !paths[0]!.getTotalLength) { raf = requestAnimationFrame(start); return; }
      buildArc(30, 30, 11);
      const targetSign = arcSign;
      pieces = paths.map((path) => {
        const L = path.getTotalLength();
        const src: Pt[] = [];
        for (let j = 0; j < N; j++) { const pt = path.getPointAtLength((L * j) / N); src.push({ x: pt.x, y: pt.y }); }
        if (Math.sign(signedArea(src)) !== Math.sign(targetSign)) src.reverse();
        return { path, src } as unknown as Piece;
      });
      let gx = 0, gy = 0, gc = 0;
      for (const pc of pieces) for (const p of pc.src) { gx += p.x; gy += p.y; gc++; }
      Cx = gx / gc; Cy = gy / gc;
      for (const pc of pieces) {
        let sx = 0, sy = 0;
        for (const p of pc.src) { sx += p.x; sy += p.y; }
        const cx = sx / pc.src.length, cy = sy / pc.src.length;
        pc.rad = Math.hypot(cx - Cx, cy - Cy);
        const ang = (Math.atan2(cy - Cy, cx - Cx) * 180) / Math.PI;
        pc.cw = (((ang + 90) % 360) + 360) % 360;
      }
      const byAngle = [...pieces].sort((a, b) => a.cw - b.cw);
      const center = pieces.reduce((mn, pc) => (pc.rad < mn.rad ? pc : mn), pieces[0]!);
      const peel = byAngle.filter((pc) => pc !== center).concat([center]);
      const n = peel.length, step = 360 / n;
      peel.forEach((pc, m) => { pc.order = m; pc.slot = -90 + m * step; });
      for (const pc of pieces) {
        pc.srcPolar = pc.src.map((p) => ({ r: Math.hypot(p.x - Cx, p.y - Cy), a: Math.atan2(p.y - Cy, p.x - Cx) }));
      }
      loop();
    };

    start();
    return () => {
      cancelled = true;
      cancelAnimationFrame(raf);
    };
  }, []);

  return (
    <svg ref={svgRef} viewBox="11.63 2.14 100 100" width={size} height={size} style={{ display: "block", overflow: "visible" }} aria-label="Loading" role="img">
      <g>
        {FACETS.map((d, i) => (
          <path key={i} className="pc" d={d} fill="#8ecc09" />
        ))}
      </g>
    </svg>
  );
}
