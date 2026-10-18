// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef } from "react";
import { cx } from "./ui";

/*
 * Holographic globe: a sphere of linked points drawn on a 2D canvas with a perspective
 * projection. It turns slowly, leans toward the pointer and can be dragged. A few points
 * light up red as threats, pulse while the threat spreads along their links, then a cyan
 * ring contains them and they turn cyan: the detect -> explain -> repair story in one loop.
 * Decorative only (aria-hidden). It pauses offscreen and in hidden tabs, caps the pixel
 * ratio at 2, and draws a single still frame when reduced motion is requested.
 */

const POINTS = 240;
const NEIGHBOURS = 3;
const THREATS = 4;
const CAMERA = 3.2; // camera distance in sphere radii
const ACTIVE_MS = 3600; // a threat spreads for this long
const CONTAIN_MS = 1400; // then a containment ring sweeps it
const CALM_MS = 4200; // then it rests as contained before a new threat appears
const CYCLE_MS = ACTIVE_MS + CONTAIN_MS + CALM_MS;

type Vec = [number, number, number];
type Threat = { index: number; start: number };

function fibonacciSphere(count: number): Vec[] {
  const points: Vec[] = [];
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / (count - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const theta = golden * i;
    points.push([Math.cos(theta) * r, y, Math.sin(theta) * r]);
  }
  return points;
}

function buildEdges(points: Vec[]): [number, number][] {
  const seen = new Set<string>();
  const edges: [number, number][] = [];
  points.forEach((a, i) => {
    const nearest = points
      .map((b, j) => ({ j, d: j === i ? -Infinity : a[0] * b[0] + a[1] * b[1] + a[2] * b[2] }))
      .sort((p, q) => q.d - p.d)
      .slice(0, NEIGHBOURS);
    for (const { j } of nearest) {
      const key = i < j ? `${String(i)}-${String(j)}` : `${String(j)}-${String(i)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      edges.push([i, j]);
    }
  });
  return edges;
}

/** Triangle wave in [0, 1]; keeps the hue sweep continuous without a hard seam. */
function tri(u: number): number {
  const f = u - Math.floor(u);
  return f < 0.5 ? f * 2 : 2 - f * 2;
}

function isDark(): boolean {
  return getComputedStyle(document.documentElement).colorScheme.includes("dark");
}

export function HoloGlobe({ className }: { className?: string }) {
  const wrap = useRef<HTMLDivElement>(null);
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const host = wrap.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !host || !ctx) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const points = fibonacciSphere(POINTS);
    const edges = buildEdges(points);
    const adjacency = points.map(() => [] as number[]);
    for (const [a, b] of edges) {
      adjacency[a]?.push(b);
      adjacency[b]?.push(a);
    }

    let dark = isDark();
    let size = 0;
    let yaw = 0.6;
    let pitch = -0.32;
    let spin = 0.0018; // radians per frame at 60 fps
    let leanX = 0;
    let leanY = 0;
    let targetLeanX = 0;
    let targetLeanY = 0;
    let dragging: { x: number; y: number } | null = null;
    let visible = true;
    let frame = 0;
    let last = 0;
    let clock = 0;

    // Stagger the threats so the scene always shows some active and some contained.
    const threats: Threat[] = Array.from({ length: THREATS }, (_, k) => ({
      index: Math.floor(((k + 0.5) / THREATS) * POINTS * 0.9),
      start: -k * (CYCLE_MS / THREATS),
    }));

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      size = Math.max(1, Math.min(host.clientWidth, host.clientHeight || host.clientWidth));
      canvas.width = Math.floor(size * dpr);
      canvas.height = Math.floor(size * dpr);
      canvas.style.width = `${String(size)}px`;
      canvas.style.height = `${String(size)}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const draw = () => {
      const c = size / 2;
      const radius = size * 0.36;
      ctx.clearRect(0, 0, size, size);

      const ay = yaw + leanX;
      const ax = pitch + leanY;
      const cy = Math.cos(ay);
      const sy = Math.sin(ay);
      const cx = Math.cos(ax);
      const sx = Math.sin(ax);

      const projected = points.map(([x, y, z]) => {
        const x1 = x * cy + z * sy;
        const z1 = -x * sy + z * cy;
        const y2 = y * cx - z1 * sx;
        const z2 = y * sx + z1 * cx;
        const s = CAMERA / (CAMERA - z2);
        return { x: c + x1 * radius * s, y: c + y2 * radius * s, z: z2, s };
      });

      // Threat state per point: 0 none, 1 active, 2 being contained, 3 contained.
      const state = new Uint8Array(POINTS);
      const strength = new Float32Array(POINTS);
      for (const threat of threats) {
        const age = (((clock - threat.start) % CYCLE_MS) + CYCLE_MS) % CYCLE_MS;
        const phase = age < ACTIVE_MS ? 1 : age < ACTIVE_MS + CONTAIN_MS ? 2 : 3;
        state[threat.index] = phase;
        strength[threat.index] = 1;
        if (phase === 1) {
          const reach = age / ACTIVE_MS;
          for (const n of adjacency[threat.index] ?? []) {
            state[n] = 1;
            strength[n] = Math.max(strength[n] ?? 0, reach);
          }
        } else if (phase === 2) {
          for (const n of adjacency[threat.index] ?? []) state[n] = 3;
        }
      }

      // Soft core glow.
      const glow = ctx.createRadialGradient(c, c, radius * 0.1, c, c, radius * 1.45);
      glow.addColorStop(0, dark ? "hsl(275 90% 60% / 0.22)" : "hsl(275 90% 60% / 0.12)");
      glow.addColorStop(0.55, dark ? "hsl(195 90% 55% / 0.08)" : "hsl(195 90% 50% / 0.05)");
      glow.addColorStop(1, "hsl(195 90% 55% / 0)");
      ctx.fillStyle = glow;
      ctx.fillRect(0, 0, size, size);

      // Orbit rings, tilted with the globe.
      ctx.lineWidth = 1;
      for (let k = 0; k < 2; k++) {
        ctx.save();
        ctx.translate(c, c);
        ctx.rotate(-0.42 + k * 0.84 + leanX * 0.5);
        ctx.beginPath();
        ctx.ellipse(0, 0, radius * (1.32 + k * 0.1), radius * (0.3 + k * 0.06), 0, 0, Math.PI * 2);
        const ring = ctx.createLinearGradient(-radius * 1.4, 0, radius * 1.4, 0);
        const alpha = dark ? 0.42 : 0.32;
        ring.addColorStop(0, `hsl(190 95% ${dark ? "65%" : "40%"} / ${String(alpha)})`);
        ring.addColorStop(0.5, `hsl(285 90% ${dark ? "70%" : "45%"} / ${String(alpha * 0.4)})`);
        ring.addColorStop(1, `hsl(330 95% ${dark ? "68%" : "45%"} / ${String(alpha)})`);
        ctx.strokeStyle = ring;
        ctx.stroke();
        ctx.restore();
      }

      const light = dark ? 68 : 46;
      const hueAt = (i: number) => {
        const p = projected[i];
        if (!p) return 200;
        const u = Math.atan2(p.y - c, p.x - c) / (Math.PI * 2) + clock / 24000;
        // Cyan -> violet -> magenta and back. Red is reserved for threats, so the sweep stops short of it.
        return 186 + 134 * tri(u);
      };

      // Links, back to front by depth.
      for (const [a, b] of edges) {
        const pa = projected[a];
        const pb = projected[b];
        if (!pa || !pb) continue;
        const depth = (pa.z + pb.z) / 2; // -1 back, 1 front
        const fade = 0.08 + 0.5 * ((depth + 1) / 2);
        const sa = state[a] ?? 0;
        const sb = state[b] ?? 0;
        if (sa === 1 && sb === 1) {
          ctx.strokeStyle = `hsl(352 95% ${String(dark ? 62 : 50)}% / ${(fade * 1.5).toFixed(3)})`;
          ctx.lineWidth = 1.3;
        } else if (sa >= 2 && sb >= 2) {
          ctx.strokeStyle = `hsl(188 95% ${String(dark ? 62 : 40)}% / ${(fade * 1.3).toFixed(3)})`;
          ctx.lineWidth = 1.2;
        } else {
          ctx.strokeStyle = `hsl(${hueAt(a).toFixed(0)} 85% ${String(light)}% / ${(fade * 0.55).toFixed(3)})`;
          ctx.lineWidth = 0.7;
        }
        ctx.beginPath();
        ctx.moveTo(pa.x, pa.y);
        ctx.lineTo(pb.x, pb.y);
        ctx.stroke();
      }

      // Points.
      const pulse = 0.5 + 0.5 * Math.sin(clock / 180);
      projected.forEach((p, i) => {
        const front = (p.z + 1) / 2;
        const s = state[i] ?? 0;
        let r = (0.9 + front * 1.6) * p.s;
        let colour = `hsl(${hueAt(i).toFixed(0)} 90% ${String(light + front * 10)}% / ${(0.25 + front * 0.75).toFixed(3)})`;
        if (s === 1) {
          r += (strength[i] ?? 0) * (1.2 + pulse * 1.6);
          colour = `hsl(355 100% ${String(dark ? 64 : 50)}% / ${(0.55 + front * 0.45).toFixed(3)})`;
        } else if (s >= 2) {
          r += 0.8;
          colour = `hsl(186 100% ${String(dark ? 66 : 38)}% / ${(0.55 + front * 0.45).toFixed(3)})`;
        }
        ctx.fillStyle = colour;
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fill();
      });

      // Threat halos and containment rings, only for threats on the visible side.
      for (const threat of threats) {
        const p = projected[threat.index];
        if (!p || p.z < -0.15) continue;
        const age = (((clock - threat.start) % CYCLE_MS) + CYCLE_MS) % CYCLE_MS;
        if (age < ACTIVE_MS) {
          const halo = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, 26 + pulse * 10);
          halo.addColorStop(0, `hsl(355 100% 60% / ${dark ? "0.55" : "0.35"})`);
          halo.addColorStop(1, "hsl(355 100% 60% / 0)");
          ctx.fillStyle = halo;
          ctx.beginPath();
          ctx.arc(p.x, p.y, 36, 0, Math.PI * 2);
          ctx.fill();
        } else if (age < ACTIVE_MS + CONTAIN_MS) {
          const k = (age - ACTIVE_MS) / CONTAIN_MS;
          ctx.strokeStyle = `hsl(186 100% ${dark ? "65%" : "40%"} / ${(0.9 * (1 - k)).toFixed(3)})`;
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.arc(p.x, p.y, 6 + k * 46, 0, Math.PI * 2);
          ctx.stroke();
        } else {
          ctx.strokeStyle = `hsl(186 100% ${dark ? "65%" : "40%"} / 0.55)`;
          ctx.lineWidth = 1.2;
          ctx.beginPath();
          ctx.arc(p.x, p.y, 7, 0, Math.PI * 2);
          ctx.stroke();
        }
      }
    };

    const reassign = () => {
      // A threat that finished its cycle reappears somewhere else on the globe.
      for (const threat of threats) {
        const age = clock - threat.start;
        if (age >= CYCLE_MS) {
          threat.start += CYCLE_MS * Math.floor(age / CYCLE_MS);
          threat.index = Math.floor(Math.random() * POINTS);
        }
      }
    };

    const tick = (now: number) => {
      frame = requestAnimationFrame(tick);
      const dt = last ? Math.min(64, now - last) : 16;
      last = now;
      clock += dt;
      if (!dragging) {
        yaw += spin * (dt / 16.7);
        spin += (0.0018 - spin) * 0.02; // ease back to the resting speed after a fling
      }
      leanX += (targetLeanX - leanX) * 0.05;
      leanY += (targetLeanY - leanY) * 0.05;
      reassign();
      draw();
    };

    const start = () => {
      if (reduced || frame || !visible || document.hidden) return;
      last = 0;
      frame = requestAnimationFrame(tick);
    };
    const stop = () => {
      cancelAnimationFrame(frame);
      frame = 0;
    };

    resize();
    if (reduced) {
      clock = ACTIVE_MS * 0.7; // one still frame: some threats active, some contained
      draw();
    } else {
      start();
    }

    const onPointerMove = (event: PointerEvent) => {
      if (reduced) return;
      if (dragging) {
        const dx = event.clientX - dragging.x;
        const dy = event.clientY - dragging.y;
        dragging = { x: event.clientX, y: event.clientY };
        yaw += dx * 0.008;
        pitch = Math.max(-1.1, Math.min(1.1, pitch + dy * 0.006));
        spin = dx * 0.0016;
        return;
      }
      if (event.pointerType !== "mouse") return;
      const rect = canvas.getBoundingClientRect();
      const nx = (event.clientX - (rect.left + rect.width / 2)) / window.innerWidth;
      const ny = (event.clientY - (rect.top + rect.height / 2)) / window.innerHeight;
      targetLeanX = Math.max(-0.35, Math.min(0.35, nx * 0.7));
      targetLeanY = Math.max(-0.25, Math.min(0.25, ny * 0.5));
    };
    const onPointerDown = (event: PointerEvent) => {
      if (reduced) return;
      dragging = { x: event.clientX, y: event.clientY };
      canvas.setPointerCapture(event.pointerId);
    };
    const onPointerUp = (event: PointerEvent) => {
      dragging = null;
      if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
    };
    const onVisibility = () => {
      if (document.hidden) stop();
      else start();
    };
    const onTheme = () => {
      dark = isDark();
      if (reduced) draw();
    };

    canvas.addEventListener("pointerdown", onPointerDown);
    canvas.addEventListener("pointerup", onPointerUp);
    canvas.addEventListener("pointercancel", onPointerUp);
    window.addEventListener("pointermove", onPointerMove, { passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    const themeObserver = new MutationObserver(onTheme);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    const scheme = window.matchMedia("(prefers-color-scheme: dark)");
    scheme.addEventListener("change", onTheme);

    const onResize = () => {
      resize();
      if (reduced) draw();
    };
    let resizeObserver: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      resizeObserver = new ResizeObserver(onResize);
      resizeObserver.observe(host);
    } else {
      window.addEventListener("resize", onResize);
    }
    let io: IntersectionObserver | null = null;
    if (typeof IntersectionObserver !== "undefined") {
      io = new IntersectionObserver((entries) => {
        visible = entries.some((entry) => entry.isIntersecting);
        if (visible) start();
        else stop();
      });
      io.observe(host);
    }

    return () => {
      stop();
      canvas.removeEventListener("pointerdown", onPointerDown);
      canvas.removeEventListener("pointerup", onPointerUp);
      canvas.removeEventListener("pointercancel", onPointerUp);
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("resize", onResize);
      document.removeEventListener("visibilitychange", onVisibility);
      themeObserver.disconnect();
      scheme.removeEventListener("change", onTheme);
      resizeObserver?.disconnect();
      io?.disconnect();
    };
  }, []);

  return (
    <div
      ref={wrap}
      className={cx("relative grid aspect-square w-full place-items-center", className)}
      aria-hidden="true"
      data-testid="holo-globe"
    >
      <canvas ref={ref} tabIndex={-1} className="block cursor-grab touch-pan-y active:cursor-grabbing" />
    </div>
  );
}
