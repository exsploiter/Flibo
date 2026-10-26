import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";

export function LogConsole({ logs, className }: { logs: string[]; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight });
  }, [logs.length]);

  return (
    <div
      ref={ref}
      className={cn(
        "terminal-scroll h-full overflow-y-auto rounded-2xl border border-border/50 bg-background/80 p-4 font-mono text-[12.5px] leading-relaxed",
        className,
      )}
    >
      {logs.length === 0 && (
        <div className="text-muted-foreground/60">// waiting for agent output…</div>
      )}
      {logs.map((l, i) => (
        <div key={i} className="flex gap-3">
          <span className="select-none text-muted-foreground/40">{String(i + 1).padStart(3, "0")}</span>
          <span className={cn("whitespace-pre-wrap", /Discovered|Found|Match|locked/i.test(l) ? "text-primary" : "text-foreground/85")}>
            {l}
          </span>
        </div>
      ))}
    </div>
  );
}
