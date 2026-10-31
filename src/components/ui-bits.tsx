import type { AgentStatus, ScanStatus, Severity } from "@/lib/types";
import { Loader2, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "border-critical/30 bg-critical/12 text-critical",
  high: "border-high/30 bg-high/12 text-high",
  medium: "border-medium/30 bg-medium/12 text-medium",
  low: "border-low/30 bg-low/12 text-low",
  info: "border-info/30 bg-info/12 text-info",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-lg border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider",
        SEVERITY_STYLES[severity],
        className,
      )}
    >
      {severity}
    </span>
  );
}

export const SCAN_STATUS_LABEL: Record<ScanStatus, string> = {
  running: "Running",
  complete: "Complete",
  partial: "Partial failure",
  failed: "Failed",
  cancelled: "Cancelled",
};

export function ScanStatusPill({ status, paused }: { status: ScanStatus; paused?: boolean | undefined }) {
  const style =
    status === "running"
      ? paused
        ? "border-medium/40 bg-medium/10 text-medium"
        : "border-low/40 bg-low/10 text-low"
      : status === "complete"
        ? "border-primary/40 bg-primary/10 text-primary"
        : status === "partial" || status === "failed"
          ? "border-critical/40 bg-critical/10 text-critical"
          : "border-border bg-muted/40 text-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 font-mono text-[10px] font-semibold uppercase tracking-wider",
        style,
      )}
    >
      {status === "running" && !paused && <Loader2 className="size-3 animate-spin" />}
      {status === "running" && paused ? "Paused" : SCAN_STATUS_LABEL[status]}
    </span>
  );
}

export const AGENT_STATUS_LABEL: Record<AgentStatus, string> = {
  queued: "Queued",
  running: "Running",
  complete: "Complete",
  failed: "Failed",
};

export function AgentStatusDot({ status }: { status: AgentStatus }) {
  if (status === "running")
    return <Loader2 className="size-3.5 shrink-0 animate-spin text-primary" />;
  return (
    <span
      className={cn(
        "size-2.5 shrink-0 rounded-full",
        status === "complete" && "bg-low",
        status === "queued" && "bg-muted-foreground/40",
        status === "failed" && "bg-critical",
      )}
    />
  );
}

export function EmptyState({
  icon: Icon,
  title,
  body,
}: {
  icon: LucideIcon;
  title: string;
  body: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-3xl border border-dashed border-border/70 bg-muted/30 px-6 py-14 text-center">
      <div className="flex size-12 items-center justify-center rounded-2xl bg-primary/10 text-primary">
        <Icon className="size-5" />
      </div>
      <h3 className="mt-4 text-base font-semibold">{title}</h3>
      <p className="mt-1 max-w-sm text-sm text-muted-foreground">{body}</p>
    </div>
  );
}
