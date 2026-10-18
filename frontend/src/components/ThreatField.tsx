// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef } from "react";

/*
 * "Threat field" background: a binary data stream drifting left, a few rain columns with
 * glowing heads, a slow network of linked nodes, and a wandering red threat glow that turns
 * nearby nodes red and sends out a scan ring now and then. Decorative only.
 */
const CELL = 22; // CSS pixels per binary glyph
const TICK_MS = 33; // about 30 frames a second
const LINK = 150; // max distance (px) at which two nodes are linked
const RAIN_TAIL = 10;

type Node = { x: number; y: number; vx: number; vy: number };
type Drop = { col: number; y: number; speed: number };
type Palette = {
  dark: boolean;
  binary: string;
  binaryAlpha: number;
  link: (alpha: number) => string;
  node: string;
  threat: (alpha: number) => string;
  rain: (hue: number, alpha: number) => string;
};

function palette(): Palette {
  const style = getComputedStyle(document.documentElement);
  const dark = style.colorScheme.includes("dark");
  // Holographic retune: violet data, cyan links and nodes, a magenta-red threat.
  return dark
    ? {
        dark,
        binary: "hsl(265 70% 74%)",
        binaryAlpha: 0.14,
        link: (a) => `hsl(196 90% 66% / ${(a * 0.8).toFixed(3)})`,
        node: "hsl(190 100% 74%)",
        threat: (a) => `hsl(348 100% 60% / ${a.toFixed(3)})`,
        rain: (h, a) => `hsl(${h.toFixed(0)} 95% 72% / ${(a * 0.8).toFixed(3)})`,
      }
    : {
        dark,
        binary: "hsl(268 40% 35%)",
        binaryAlpha: 0.07,
        link: (a) => `hsl(255 50% 45% / ${(a * 0.4).toFixed(3)})`,
        node: "hsl(250 50% 45% / 0.45)",
        threat: (a) => `hsl(345 85% 52% / ${(a * 0.4).toFixed(3)})`,
        rain: (h, a) => `hsl(${h.toFixed(0)} 55% 42% / ${(a * 0.3).toFixed(3)})`,
      };
}

function binaryTile(width: number, height: number, colour: string): HTMLCanvasElement {
  const tile = document.createElement("canvas");
  tile.width = width;
  tile.height = height;
  const ctx = tile.getContext("2d");
  if (!ctx) return tile;
  ctx.font = `${String(CELL - 6)}px "IBM Plex Mono", ui-monospace, monospace`;
  ctx.fillStyle = colour;
  for (let y = CELL; y < height; y += CELL) {
    for (let x = 0; x < width; x += CELL * 0.75) {
      if (Math.random() < 0.18) continue; // gaps make the stream read as data, not a wall
      ctx.globalAlpha = 0.35 + Math.random() * 0.65;
      ctx.fillText(Math.random() < 0.5 ? "0" : "1", x, y);
    }
  }
  return tile;
}

export function ThreatField() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let colors = palette();
    let width = 0;
    let height = 0;
    let tile = binaryTile(1, 1, colors.binary);
    let nodes: Node[] = [];
    let drops: Drop[] = [];
    let offset = 0;
    let frame = 0;
    let last = 0;
    let t = 0;
    let ringStart = 0;

    const build = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      tile = binaryTile(Math.ceil(width), Math.ceil(height), colors.binary);
      const count = Math.min(110, Math.round((width * height) / 16000));
      nodes = Array.from({ length: count }, () => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.35,
        vy: (Math.random() - 0.5) * 0.35,
      }));
      const columns = Math.floor(width / CELL);
      drops = Array.from({ length: Math.max(4, Math.floor(columns / 5)) }, () => ({
        col: Math.floor(Math.random() * columns),
        y: -Math.random() * height,
        speed: 1.2 + Math.random() * 2.2,
      }));
    };

    const restyle = () => {
      colors = palette();
      tile = binaryTile(Math.ceil(width), Math.ceil(height), colors.binary);
    };

    const draw = () => {
      t += 1;
      // The page background shows through; the canvas only adds light.
      ctx.globalCompositeOperation = "source-over";
      ctx.globalAlpha = 1;
      ctx.clearRect(0, 0, width, height);

      // Binary stream drifting left, erased toward the left edge.
      offset = (offset + 0.25) % width;
      ctx.globalAlpha = colors.binaryAlpha;
      ctx.drawImage(tile, -offset, 0, width, height);
      ctx.drawImage(tile, width - offset, 0, width, height);
      ctx.globalAlpha = 1;
      const fade = ctx.createLinearGradient(0, 0, width * 0.6, 0);
      fade.addColorStop(0, "rgb(0 0 0 / 1)");
      fade.addColorStop(1, "rgb(0 0 0 / 0)");
      ctx.globalCompositeOperation = "destination-out";
      ctx.fillStyle = fade;
      ctx.fillRect(0, 0, width * 0.6, height);
      ctx.globalCompositeOperation = "source-over";

      // The threat wanders on a slow Lissajous path, mostly through the right half.
      const hx = width * (0.62 + 0.26 * Math.sin(t / 900));
      const hy = height * (0.5 + 0.3 * Math.sin(t / 640 + 1.3));
      const reach = Math.max(180, Math.min(width, height) * 0.32);

      // Rain columns with glowing heads; hue runs green -> cyan -> violet across the screen.
      ctx.font = `${String(CELL - 6)}px "IBM Plex Mono", ui-monospace, monospace`;
      for (const drop of drops) {
        drop.y += drop.speed;
        if (drop.y - RAIN_TAIL * CELL > height) {
          drop.y = -Math.random() * height * 0.5;
          drop.col = Math.floor(Math.random() * (width / CELL));
        }
        const x = drop.col * CELL;
        // Retuned for the holographic palette: cyan -> violet -> magenta.
        const hue = 185 + (x / width) * 140;
        for (let k = 0; k < RAIN_TAIL; k++) {
          const alpha = k === 0 ? 0.9 : 0.55 * (1 - k / RAIN_TAIL);
          ctx.fillStyle = k === 0 ? colors.rain(hue, alpha * 1.1) : colors.rain(hue, alpha);
          ctx.fillText(Math.random() < 0.5 ? "0" : "1", x, drop.y - k * CELL);
        }
      }

      // Network: nodes drift and bounce; links fade with distance; nodes near the threat turn red.
      for (const n of nodes) {
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < 0 || n.x > width) n.vx *= -1;
        if (n.y < 0 || n.y > height) n.vy *= -1;
      }
      ctx.lineWidth = 0.8;
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        if (!a) continue;
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          if (!b) continue;
          const d = Math.hypot(a.x - b.x, a.y - b.y);
          if (d > LINK) continue;
          const near = Math.hypot((a.x + b.x) / 2 - hx, (a.y + b.y) / 2 - hy) < reach;
          const alpha = (1 - d / LINK) * 0.5;
          ctx.strokeStyle = near ? colors.threat(alpha) : colors.link(alpha);
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
      for (const n of nodes) {
        const near = Math.hypot(n.x - hx, n.y - hy) < reach;
        ctx.fillStyle = near ? colors.threat(0.95) : colors.node;
        ctx.beginPath();
        ctx.arc(n.x, n.y, near ? 2.4 : 1.6, 0, Math.PI * 2);
        ctx.fill();
      }

      // Threat glow, plus a scan ring every few seconds.
      ctx.globalCompositeOperation = colors.dark ? "lighter" : "source-over";
      const glow = ctx.createRadialGradient(hx, hy, 0, hx, hy, reach);
      glow.addColorStop(0, colors.threat(0.42));
      glow.addColorStop(0.35, colors.threat(0.14));
      glow.addColorStop(1, colors.threat(0));
      ctx.fillStyle = glow;
      ctx.fillRect(hx - reach, hy - reach, reach * 2, reach * 2);
      if (t - ringStart > 220) ringStart = t;
      const progress = (t - ringStart) / 220;
      ctx.strokeStyle = colors.threat(0.35 * (1 - progress));
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.arc(hx, hy, reach * 0.2 + progress * reach * 1.4, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalCompositeOperation = "source-over";
    };

    const loop = (now: number) => {
      frame = requestAnimationFrame(loop);
      if (document.hidden || now - last < TICK_MS) return;
      last = now;
      draw();
    };

    build();
    if (reduced) draw();
    else frame = requestAnimationFrame(loop);

    const redrawIfStill = () => {
      if (reduced) draw();
    };
    const onTheme = () => {
      restyle();
      redrawIfStill();
    };
    const onResize = () => {
      build();
      redrawIfStill();
    };
    const themeObserver = new MutationObserver(onTheme);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    const scheme = window.matchMedia("(prefers-color-scheme: dark)");
    scheme.addEventListener("change", onTheme);
    window.addEventListener("resize", onResize);
    return () => {
      cancelAnimationFrame(frame);
      themeObserver.disconnect();
      scheme.removeEventListener("change", onTheme);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return <canvas ref={ref} className="threat-field" aria-hidden="true" tabIndex={-1} data-testid="threat-field" />;
}
