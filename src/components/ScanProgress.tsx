import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";

interface ScanProgressProps {
  value: number; // 0–100
  active?: boolean; // animate live zig-zag energy pulse
  className?: string;
  height?: number; // px, default 8
}

/**
 * High-tech animated zig-zag progress bar.
 * - When active, renders an animated electric sawtooth/zig-zag waveform
 * - Has an energetic forward-scrolling phase pulse
 * - The leading edge has a bright glowing laser spark
 * - Even at 0%, an ambient radar pulse sweeps across the track so it never feels frozen!
 */
export function ScanProgress({ value, active = false, className, height = 8 }: ScanProgressProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef = useRef<number>(0);
  const offsetRef = useRef<number>(0);
  const sweepRef = useRef<number>(0);
  const smoothValRef = useRef<number>(value);

  // Smoothly interpolate current value to target value so it never jerks
  useEffect(() => {
    smoothValRef.current = Math.max(0, Math.min(100, value));
  }, [value]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !active) return;

    let displayVal = smoothValRef.current;

    const draw = () => {
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const W = canvas.width;
      const H = canvas.height;

      // Smooth lerp toward target value
      displayVal += (smoothValRef.current - displayVal) * 0.12;

      ctx.clearRect(0, 0, W, H);

      // 1. Background Track
      ctx.fillStyle = "rgba(255, 255, 255, 0.05)";
      ctx.beginPath();
      ctx.roundRect(0, 0, W, H, H / 2);
      ctx.fill();

      // Subtle track border
      ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
      ctx.lineWidth = 1;
      ctx.stroke();

      // 2. Ambient scanning radar pulse (sweeps across entire bar continuously)
      sweepRef.current = (sweepRef.current + 2.4) % (W + 80);
      const sweepX = sweepRef.current - 40;
      const sweepGrad = ctx.createLinearGradient(sweepX - 40, 0, sweepX + 40, 0);
      sweepGrad.addColorStop(0, "rgba(251, 107, 74, 0)");
      sweepGrad.addColorStop(0.5, "rgba(251, 107, 74, 0.18)");
      sweepGrad.addColorStop(1, "rgba(251, 107, 74, 0)");
      ctx.fillStyle = sweepGrad;
      ctx.beginPath();
      ctx.roundRect(0, 0, W, H, H / 2);
      ctx.fill();

      // 3. Filled Progress Portion
      const fillW = Math.max(H, (displayVal / 100) * W);

      if (displayVal > 0.5) {
        ctx.save();
        ctx.beginPath();
        ctx.roundRect(0, 0, fillW, H, H / 2);
        ctx.clip();

        // Neon cyber fill gradient
        const fillGrad = ctx.createLinearGradient(0, 0, fillW, 0);
        fillGrad.addColorStop(0, "rgba(215, 68, 38, 0.7)");
        fillGrad.addColorStop(0.5, "rgba(251, 107, 74, 0.95)");
        fillGrad.addColorStop(1, "rgba(255, 140, 105, 1)");
        ctx.fillStyle = fillGrad;
        ctx.fillRect(0, 0, fillW, H);

        // 4. Scrolling Zig-Zag / Sawtooth Waveform Overlay
        const zigW = Math.max(12, H * 2.4); // wavelength
        const zigH = H * 0.72; // amplitude
        const midY = H / 2;
        const speed = 1.2; // scroll speed

        offsetRef.current = (offsetRef.current + speed) % zigW;
        const startX = -zigW + (offsetRef.current % zigW);

        // Draw multiple zig-zag passes for neon glow effect
        // Base glow pass
        ctx.beginPath();
        ctx.moveTo(startX, midY);
        for (let x = startX; x < fillW + zigW; x += zigW) {
          ctx.lineTo(x + zigW * 0.25, midY - zigH / 2);
          ctx.lineTo(x + zigW * 0.5, midY + zigH / 2);
          ctx.lineTo(x + zigW * 0.75, midY - zigH / 2);
          ctx.lineTo(x + zigW, midY);
        }
        ctx.strokeStyle = "rgba(255, 230, 210, 0.75)";
        ctx.lineWidth = 1.6;
        ctx.lineJoin = "round";
        ctx.lineCap = "round";
        ctx.stroke();

        // Core bright line pass
        ctx.beginPath();
        ctx.moveTo(startX, midY);
        for (let x = startX; x < fillW + zigW; x += zigW) {
          ctx.lineTo(x + zigW * 0.25, midY - zigH / 2);
          ctx.lineTo(x + zigW * 0.5, midY + zigH / 2);
          ctx.lineTo(x + zigW * 0.75, midY - zigH / 2);
          ctx.lineTo(x + zigW, midY);
        }
        ctx.strokeStyle = "rgba(255, 255, 255, 0.9)";
        ctx.lineWidth = 0.8;
        ctx.stroke();

        // 5. Leading-edge high-intensity pulse
        const edgeW = Math.min(36, fillW);
        const edgeGrad = ctx.createLinearGradient(fillW - edgeW, 0, fillW, 0);
        edgeGrad.addColorStop(0, "rgba(255, 255, 255, 0)");
        edgeGrad.addColorStop(0.8, "rgba(255, 255, 255, 0.6)");
        edgeGrad.addColorStop(1, "rgba(255, 255, 255, 0.95)");
        ctx.fillStyle = edgeGrad;
        ctx.fillRect(fillW - edgeW, 0, edgeW, H);

        ctx.restore();
      }
    };

    const loop = () => {
      draw();
      rafRef.current = requestAnimationFrame(loop);
    };
    rafRef.current = requestAnimationFrame(loop);

    return () => cancelAnimationFrame(rafRef.current);
  }, [active]);

  // Sync high-DPI canvas resolution
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = Math.max(1, rect.width * dpr);
      canvas.height = Math.max(1, rect.height * dpr);
      const ctx = canvas.getContext("2d");
      if (ctx) ctx.scale(dpr, dpr);
    };

    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    return () => ro.disconnect();
  }, []);

  if (!active) {
    return (
      <div
        className={cn("relative w-full overflow-hidden rounded-full bg-primary/15 border border-border/40", className)}
        style={{ height }}
      >
        <div
          className="h-full rounded-full bg-primary transition-all duration-300"
          style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
        />
      </div>
    );
  }

  return (
    <canvas
      ref={canvasRef}
      className={cn("w-full rounded-full block", className)}
      style={{ height }}
      aria-label={`Scan progress ${Math.round(value)}%`}
    />
  );
}
