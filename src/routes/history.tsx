import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { formatDistanceToNow } from "date-fns";
import {
  Bookmark,
  Eye,
  History,
  RotateCcw,
  Search,
  Trash2,
} from "lucide-react";
import { deleteScan, togglePin, useScans } from "@/lib/store";
import { countBySeverity } from "@/lib/synthesis";
import type { ScanStatus } from "@/lib/types";
import { EmptyState, ScanStatusPill, SeverityBadge } from "@/components/ui-bits";
import { Button } from "@/components/ui/button";
import { useMounted } from "@/lib/hooks";

export const Route = createFileRoute("/history")({
  component: HistoryPage,
  head: () => ({
    meta: [
      { title: "Scan History — Flibo" },
      { name: "description", content: "Search, re-run, pin and manage past recon scans." },
      { property: "og:title", content: "Scan History — Flibo" },

      { property: "og:description", content: "Search, re-run, pin and manage past recon scans." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

const STATUS_FILTERS: { id: "all" | ScanStatus; label: string }[] = [
  { id: "all", label: "All" },
  { id: "running", label: "Running" },
  { id: "complete", label: "Complete" },
  { id: "partial", label: "Partial" },
  { id: "cancelled", label: "Cancelled" },
];

function HistoryPage() {
  const mounted = useMounted();
  const navigate = useNavigate();
  const scans = useScans();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<"all" | ScanStatus>("all");

  const filtered = useMemo(
    () =>
      [...scans]
        .filter((s) => status === "all" || s.status === status)
        .filter(
          (s) =>
            !q ||
            s.name.toLowerCase().includes(q.toLowerCase()) ||
            s.target.toLowerCase().includes(q.toLowerCase()) ||
            s.tags.some((t) => t.toLowerCase().includes(q.toLowerCase())),
        )
        .sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || b.createdAt - a.createdAt),
    [scans, q, status],
  );

  function reRun(s: (typeof scans)[number]) {
    const newId = `scan-${Date.now()}`;
    import("@/lib/store").then(({ addScan }) => {
      addScan({
        ...s,
        id: newId,
        name: `${s.name} (re-run)`,
        status: "running",
        paused: false,
        createdAt: Date.now(),
        finishedAt: undefined,
        findings: [],
        agents: s.agents.map((a, i) => ({ ...a, status: i === 0 ? "running" : "queued", progress: 0, logs: [], error: undefined })),
      });
      import("@/lib/runner").then(({ ensureRunner }) => ensureRunner(newId));
      toast.success("Re-running with same config");
      void navigate({ to: "/scan/$id", params: { id: newId } });
    });
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Scan history</h1>
          <p className="mt-1 text-sm text-muted-foreground">Every sweep you've run, searchable and re-runnable.</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 size-4 text-muted-foreground" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search target, name, tag…"
              className="w-64 rounded-xl border border-input bg-background/70 py-2 pl-9 pr-3 text-sm outline-none focus:ring-1 focus:ring-primary/50"
            />
          </div>
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {STATUS_FILTERS.map((f) => (
          <button
            key={f.id}
            onClick={() => setStatus(f.id)}
            className={`rounded-lg border px-3 py-1.5 font-mono text-xs transition-colors ${
              status === f.id
                ? "border-primary/50 bg-primary/10 text-primary"
                : "border-border/50 text-muted-foreground hover:text-foreground"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {mounted && filtered.length === 0 ? (
        <EmptyState
          icon={History}
          title="No scans match"
          body={q || status !== "all" ? "Try clearing the search or status filter." : "Run your first scan to populate history."}
        />
      ) : (
        <div className="overflow-hidden rounded-2xl border border-border/50 bg-card shadow-panel">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/40 bg-muted/20 font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-2.5 text-left">Scan</th>
                <th className="px-4 py-2.5 text-left">Status</th>
                <th className="hidden px-4 py-2.5 text-left md:table-cell">Severity</th>
                <th className="hidden px-4 py-2.5 text-left lg:table-cell">Launched</th>
                <th className="px-4 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {(mounted ? filtered : []).map((s) => {
                const c = countBySeverity(s.findings);
                return (
                  <tr key={s.id} className="border-b border-border/30 last:border-0 hover:bg-accent/20">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {s.pinned && <Bookmark className="size-3.5 shrink-0 fill-primary text-primary" />}
                        <Link to="/scan/$id" params={{ id: s.id }} className="font-medium hover:text-primary">
                          {s.name}
                        </Link>
                      </div>
                      <div className="mt-0.5 flex items-center gap-2">
                        <span className="font-mono text-[11px] text-muted-foreground">{s.target}</span>
                        {s.tags.slice(0, 3).map((t) => (
                          <span key={t} className="rounded border border-border/50 px-1 font-mono text-[10px] text-muted-foreground">
                            #{t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3"><ScanStatusPill status={s.status} paused={s.paused} /></td>
                    <td className="hidden px-4 py-3 md:table-cell">
                      <div className="flex gap-1">
                        {(["critical", "high", "medium"] as const).map(
                          (sev) => (c[sev] > 0 ? <SeverityBadge key={sev} severity={sev} /> : null),
                        )}
                      </div>
                    </td>
                    <td className="hidden px-4 py-3 font-mono text-[11px] text-muted-foreground lg:table-cell">
                      {formatDistanceToNow(s.createdAt, { addSuffix: true })}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon" className="size-8 rounded-lg" asChild>
                          <Link to="/scan/$id" params={{ id: s.id }} aria-label="View scan">
                            <Eye className="size-3.5" />
                          </Link>
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8 rounded-lg"
                          aria-label="Re-run scan"
                          onClick={() => reRun(s)}
                        >
                          <RotateCcw className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8 rounded-lg"
                          aria-label="Pin scan"
                          onClick={() => {
                            togglePin(s.id);
                            toast.success(s.pinned ? "Unpinned" : "Pinned");
                          }}
                        >
                          <Bookmark className={`size-3.5 ${s.pinned ? "fill-primary text-primary" : ""}`} />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8 rounded-lg text-critical hover:bg-critical/10"
                          aria-label="Delete scan"
                          onClick={() => {
                            if (confirm(`Delete "${s.name}" from history?`)) {
                              deleteScan(s.id);
                              toast.success("Scan deleted");
                            }
                          }}
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
