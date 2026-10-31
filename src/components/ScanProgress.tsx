import { cn } from "@/lib/utils";

interface ScanProgressProps {
  value: number; // 0–100
  active?: boolean;
  className?: string;
  height?: number; // px, default 16
  variant?: "primary" | "success" | "auto";
}

/**
 * Animated diagonal-striped progress bar (barber-pole / candy-stripe style)
 * Matches the exact UI reference:
 * - Rounded pill container with soft subtle track
 * - Solid colored fill (coral/terracotta while scanning, emerald green when complete)
 * - Clean diagonal darker stripes angled at 45deg
 * - Continuous smooth CSS keyframe scrolling when active
 * - Smooth width expansion towards completion
 * - 100% GPU accelerated, 0% JS overhead
 */
export function ScanProgress({
  value,
  active = false,
  className,
  height = 14,
  variant = "auto",
}: ScanProgressProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(value)));
  const isComplete = clamped >= 100;

  // Color selection: emerald green when complete, warm coral/terracotta while running
  const colorClass =
    variant === "success" || (variant === "auto" && isComplete && !active)
      ? "bg-[#25b57f]" // clean emerald green matching reference
      : "bg-[#e25744]"; // warm coral/terracotta matching reference

  const stripeSize = height <= 8 ? "16px 16px" : "28px 28px";

  return (
    <div
      className={cn(
        "relative w-full rounded-full bg-white/10 dark:bg-white/[0.08] p-[3px] border border-white/10 overflow-hidden shadow-inner",
        className
      )}
      style={{ height: height + 6 }}
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      {/* Moving progress fill */}
      <div
        className={cn(
          "relative h-full rounded-full overflow-hidden transition-[width] duration-400 ease-out flex items-center shadow-sm",
          colorClass
        )}
        style={{
          width: `${clamped}%`,
          minWidth: clamped > 0 ? Math.max(8, height) : 0,
        }}
      >
        {/* Diagonal stripes pattern */}
        <div
          className={cn(
            "absolute inset-0 w-full h-full",
            active ? "animate-stripes" : "opacity-85"
          )}
          style={{
            backgroundImage: `linear-gradient(
              45deg,
              rgba(0, 0, 0, 0.16) 25%,
              transparent 25%,
              transparent 50%,
              rgba(0, 0, 0, 0.16) 50%,
              rgba(0, 0, 0, 0.16) 75%,
              transparent 75%,
              transparent
            )`,
            backgroundSize: stripeSize,
          }}
        />
      </div>
    </div>
  );
}
