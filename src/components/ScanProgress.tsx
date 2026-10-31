import { cn } from "@/lib/utils";

interface ScanProgressProps {
  value: number; // 0–100
  active?: boolean;
  className?: string;
  height?: number; // px, default 10
}

/**
 * High-performance, GPU-accelerated zig-zag progress bar.
 * - Thin, crisp outer lining (border & subtle track)
 * - Inside, the bar smoothly moves towards completion (CSS transition)
 * - Inside the bar, a vibrant vector zig-zag (up and down) waveform scrolls forward
 * - 0% JS/Canvas CPU overhead — buttery smooth 60fps on all devices
 */
export function ScanProgress({ value, active = false, className, height = 10 }: ScanProgressProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(value)));

  return (
    <div
      className={cn(
        "relative w-full rounded-full border border-primary/35 bg-black/40 p-[2px] shadow-[inset_0_1px_3px_rgba(0,0,0,0.5)] overflow-hidden",
        active && "border-primary/60 shadow-[0_0_10px_rgba(251,107,74,0.2)]",
        className
      )}
      style={{ height: height + 6 }}
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      {/* Subtle guide track */}
      <div className="absolute inset-0 bg-white/[0.02] rounded-full pointer-events-none" />

      {/* Progress fill bar */}
      <div
        className="relative h-full rounded-full overflow-hidden transition-[width] duration-500 ease-out flex items-center bg-gradient-to-r from-primary/80 via-primary to-orange-400"
        style={{ width: `${clamped}%`, minWidth: clamped > 0 ? height : 0 }}
      >
        {/* Zig-zag up-and-down wave pattern moving inside the bar */}
        <div
          className={cn(
            "absolute inset-0 w-full h-full opacity-90",
            active && "animate-zigzag"
          )}
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='14' viewBox='0 0 24 14'%3E%3Cpath d='M0 11 L6 3 L12 11 L18 3 L24 11' fill='none' stroke='rgba(255,255,255,0.9)' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")`,
            backgroundRepeat: "repeat-x",
            backgroundPosition: "center",
            backgroundSize: "24px 100%",
          }}
        />

        {/* Leading edge bright glowing scanner tip */}
        {active && clamped > 0 && clamped < 100 && (
          <div className="absolute right-0 top-0 bottom-0 w-2.5 bg-white rounded-full shadow-[0_0_8px_#fff]" />
        )}
      </div>

      {/* Ambient scanning laser across track when active & low */}
      {active && clamped < 12 && (
        <div className="absolute inset-y-0 w-10 bg-gradient-to-r from-transparent via-primary/30 to-transparent animate-laser-sweep pointer-events-none" />
      )}
    </div>
  );
}
