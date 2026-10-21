// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from "react";

/*
 * Faint "digital rain" behind the landing hero and the sign-in page (never behind analytical
 * screens). Decorative only: aria-hidden, no pointer events, content is complete without it.
 * The brightest glyph alpha (--rain-max) is capped so the muted hero text keeps 4.5:1 even where
 * that glyph sits directly behind it (measured in the redesign notes). It draws nothing and
 * runs no loop when the visitor prefers reduced motion, and it pauses while the tab is hidden or
 * the hero is scrolled out of view.
 */

const GLYPHS = "01010101ABCDEF0123456789{}<>/$#;=";
const CELL_W = 18;
const CELL_H = 20;
const TRAIL = 14;
const FPS = 26;

/**
 * Colours come from CSS (--rain-head, --rain-trail as "r g b" triples, --rain-max as the brightest
 * composited alpha) so the rain follows the theme: lime on black and on the graphite hero, dark
 * green and fainter on ivory. Defaults apply where styles are unavailable.
 */
interface Palette {
  head: string;
  trail: string;
  max: number;
}
function readPalette(host: Element): Palette {
  const style = getComputedStyle(host);
  const triple = (name: string, fallback: string) => (style.getPropertyValue(name).trim() || fallback).replace(/\s+/g, ",");
  const max = Number.parseFloat(style.getPropertyValue("--rain-max"));
  return {
    head: triple("--rain-head", "198 239 155"),
    trail: triple("--rain-trail", "140 228 189"),
    max: Number.isFinite(max) ? max : 0.28,
  };
}

interface Column {
  /** Head position in rows, fractional. */
  y: number;
  speed: number;
  chars: string[];
}

const pick = () => GLYPHS.charAt(Math.floor(Math.random() * GLYPHS.length));

function makeColumn(rows: number, scatter: boolean): Column {
  return {
    y: scatter ? Math.random() * (rows + TRAIL) : -Math.random() * rows,
    speed: 6 + Math.random() * 10,
    chars: Array.from({ length: TRAIL + 1 }, pick),
  };
}

function reducedMotion(): boolean {
  // No matchMedia (old engines, test environments) means no animation: the safe default.
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return true;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function useAnimationAllowed(): boolean {
  const [allowed, setAllowed] = useState(() => !reducedMotion());
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => {
      setAllowed(!query.matches);
    };
    query.addEventListener("change", update);
    return () => {
      query.removeEventListener("change", update);
    };
  }, []);
  return allowed;
}

function Rain() {
  const box = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const host = box.current;
    const cv = canvas.current;
    const ctx = cv?.getContext("2d");
    if (!host || !cv || !ctx) return;

    let columns: Column[] = [];
    let rows = 0;
    let width = 0;
    let height = 0;
    let frame = 0;
    let last = 0;
    let onScreen = true;
    let disposed = false;

    const resize = () => {
      const rect = host.getBoundingClientRect();
      width = Math.max(1, Math.floor(rect.width));
      height = Math.max(1, Math.floor(rect.height));
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      cv.width = Math.floor(width * dpr);
      cv.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.font = `${CELL_H - 6}px "IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace`;
      ctx.textBaseline = "top";
      rows = Math.ceil(height / CELL_H);
      const count = Math.ceil(width / CELL_W);
      columns = Array.from({ length: count }, (_, i) => columns[i] ?? makeColumn(rows, true));
    };

    const draw = (dt: number) => {
      const palette = readPalette(host);
      ctx.clearRect(0, 0, width, height);
      columns.forEach((col, i) => {
        col.y += col.speed * dt;
        if (col.y - TRAIL > rows) Object.assign(col, makeColumn(rows, false));
        if (Math.random() < 0.08) col.chars[Math.floor(Math.random() * col.chars.length)] = pick();
        const headRow = Math.floor(col.y);
        for (let k = 0; k <= TRAIL; k += 1) {
          const row = headRow - k;
          if (row < 0 || row > rows) continue;
          const x = i * CELL_W + 2;
          const y = row * CELL_H;
          const glyph = col.chars[k] ?? "0";
          if (k === 0) {
            ctx.fillStyle = `rgb(${palette.head})`;
            ctx.globalAlpha = palette.max;
          } else {
            ctx.fillStyle = `rgb(${palette.trail})`;
            ctx.globalAlpha = palette.max * 0.8 * (1 - k / (TRAIL + 1)) ** 1.6;
          }
          ctx.fillText(glyph, x, y);
        }
      });
      ctx.globalAlpha = 1;
    };

    const tick = (now: number) => {
      frame = 0;
      if (disposed || !onScreen || document.hidden) return;
      frame = requestAnimationFrame(tick);
      const elapsed = now - last;
      if (elapsed < 1000 / FPS) return;
      draw(Math.min(elapsed, 100) / 1000);
      last = now;
    };
    const start = () => {
      if (frame || disposed || !onScreen || document.hidden) return;
      last = performance.now();
      frame = requestAnimationFrame(tick);
    };
    const stop = () => {
      if (frame) cancelAnimationFrame(frame);
      frame = 0;
    };

    resize();
    const resizeObserver = typeof ResizeObserver === "function" ? new ResizeObserver(resize) : null;
    resizeObserver?.observe(host);
    const intersection =
      typeof IntersectionObserver === "function"
        ? new IntersectionObserver((entries) => {
            onScreen = entries.some((entry) => entry.isIntersecting);
            if (onScreen) start();
            else stop();
          })
        : null;
    intersection?.observe(host);
    const onVisibility = () => {
      if (document.hidden) stop();
      else start();
    };
    document.addEventListener("visibilitychange", onVisibility);
    start();

    return () => {
      disposed = true;
      stop();
      resizeObserver?.disconnect();
      intersection?.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return (
    <div ref={box} aria-hidden="true" data-testid="code-rain" className="pointer-events-none absolute inset-0 overflow-hidden">
      <canvas ref={canvas} className="block size-full" />
    </div>
  );
}

/** Mount inside a `relative` container, before the content; the content needs `relative` to sit above it. */
export function CodeRain() {
  const allowed = useAnimationAllowed();
  return allowed ? <Rain /> : null;
}
