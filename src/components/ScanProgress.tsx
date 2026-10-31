import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";

interface ScanProgressProps {
  value: number;       // 0–100
  active?: boolean;    // show animated zig-zag pulse when true
  className?: string;
  height?: number;     // px, default 6
}

/**
 * Animated zig-zag progress bar.
 * When `active` is true, renders a Canvas-drawn chevron/sawtooth waveform
 * that scrolls forward, giving a live "energy pulse" feel.
 * When inactive (complete/paused) it falls back to a plain filled bar.
 */
export function ScanProgress({ value, active = false, className, height = 6 }: ScanProgressProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef = useRef<number>(0);
  const offsetRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !active) return;

    const draw = () => {
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const W = canvas.width;
      const H = canvas.height;
      const fillW = (value / 100) * W;

      ctx.clearRect(0, 0, W, H);

      // Filled background bar (dim)
      ctx.fillStyle = "rgba(255,255,255,0.06)";
      ctx.beginPath();
      ctx.roundRect(0, 0, W, H, H / 2);
      ctx.fill();

      if (fillW <= 0) return;

      // Clip to filled portion
      ctx.save();
      ctx.beginPath();
      ctx.roundRect(0, 0, fillW, H, H / 2);
      ctx.clip();

      // Base fill glow
      const grad = ctx.createLinearGradient(0, 0, fillW, 0);
      grad.addColorStop(0, "rgba(251,107,74,0.55)");
      grad.addColorStop(0.6, "rgba(251,107,74,0.85)");
      grad.addColorStop(1, "rgba(251,140,100,1)");
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, fillW, H);

      // Zig-zag overlay
      const zigH = H * 0.75;
      const zigW = H * 2.2;           // one full zig-zag wavelength
      const midY = H / 2;
      const speed = 0.7;              // px per frame

      offsetRef.current = (offsetRef.current + speed) % zigW;
      const startX = -zigW + (offsetRef.current % zigW);

      ctx.beginPath();
      ctx.moveTo(startX, midY);

      for (let x = startX; x < fillW + zigW; x += zigW) {
        ctx.lineTo(x + zigW * 0.25, midY - zigH / 2);
        ctx.lineTo(x + zigW * 0.5, midY + zigH / 2);
        ctx.lineTo(x + zigW * 0.75, midY - zigH / 2);
        ctx.lineTo(x + zigW, midY);
      }

      ctx.strokeStyle = "rgba(255,255,255,0.35)";
      ctx.lineWidth = 1.1;
      ctx.lineJoin = "round";
      ctx.stroke();

      // Bright leading-edge pulse
      const pulseGrad = ctx.createLinearGradient(Math.max(0, fillW - 30), 0, fillW, 0);
      pulseGrad.addColorStop(0, "rgba(255,255,255,0)");
      pulseGrad.addColorStop(1, "rgba(255,255,255,0.45)");
      ctx.fillStyle = pulseGrad;
      ctx.fillRect(Math.max(0, fillW - 30), 0, 30, H);

      ctx.restore();
    };

    const loop = () => {
      draw();
      rafRef.current = requestAnimationFrame(loop);
    };
    rafRef.current = requestAnimationFrame(loop);

    return () => cancelAnimationFrame(rafRef.current);
  }, [value, active]);

  // Sync canvas size to its CSS size on mount and resize
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ro = new ResizeObserver(() => {
      canvas.width = canvas.offsetWidth * devicePixelRatio;
      canvas.height = canvas.offsetHeight * devicePixelRatio;
      const ctx = canvas.getContext("2d");
      if (ctx) ctx.scale(devicePixelRatio, devicePixelRatio);
    });
    ro.observe(canvas);
    return () => ro.disconnect();
  }, []);

  if (!active) {
    // Static filled bar for non-running states
    return (
      <div
        className={cn("relative w-full overflow-hidden rounded-full bg-primary/15", className)}
        style={{ height }}
      >
        <div
          className="h-full rounded-full bg-primary transition-all duration-300"
          style={{ width: `${value}%` }}
        />
      </div>
    );
  }

  return (
    <canvas
      ref={canvasRef}
      className={cn("w-full rounded-full", className)}
      style={{ height, display: "block" }}
      aria-label={`Scan progress ${value}%`}
    />
  );
}
