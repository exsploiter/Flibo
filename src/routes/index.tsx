import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { formatDistanceToNow } from "date-fns";
import {
  ArrowUpRight,
  Crosshair,
  ExternalLink,
  Shield,
  Layers,
  Terminal,
} from "lucide-react";
import { useScans } from "@/lib/store";
import { aggregateProgress, countBySeverity, riskScore, synthesizeVectors } from "@/lib/synthesis";
import { SEVERITY_ORDER, type Scan, type Severity, type Finding } from "@/lib/types";
import { useMounted } from "@/lib/hooks";

export const Route = createFileRoute("/")({
  component: Dashboard,
  head: () => ({
    meta: [
      { title: "Flibo — Recon Dashboard" },
      {
        name: "description",
        content: "Reconnaissance inventory, live agent operations, and attack surface findings.",
      },
      { property: "og:title", content: "Flibo — Recon Dashboard" },
      {
        property: "og:description",
        content: "Reconnaissance inventory, live agent operations, and attack surface findings.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

function StatusDot({ status, paused }: { status: Scan["status"]; paused?: boolean }) {
  if (status === "running") {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-foreground">
        <span className="relative flex size-2">
          <span className="absolute inline-flex size-full animate-ping rounded-full bg-primary opacity-60" />
          <span className="relative inline-flex size-2 rounded-full bg-primary" />
        </span>
        {paused ? "Paused" : "Running"}
      </span>
    );
  }
  if (status === "complete") {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
        <span className="size-1.5 rounded-full bg-muted-foreground/60" />
        Complete
      </span>
    );
  }
  if (status === "partial" || status === "failed") {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-critical">
        <span className="size-1.5 rounded-full bg-critical" />
        {status === "partial" ? "Partial" : "Failed"}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground/60">
      <span className="size-1.5 rounded-full bg-muted-foreground/30" />
      Cancelled
    </span>
  );
}

function FindingsSummary({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return <span className="font-mono text-xs tabular-nums text-muted-foreground/60">0</span>;
  }
  const c = countBySeverity(findings);
  return (
    <div className="flex items-center gap-2 font-mono text-xs tabular-nums">
      <span className="font-medium text-foreground">{findings.length}</span>
      {(c.critical > 0 || c.high > 0) && (
        <span className="text-[11px] text-muted-foreground">
          ({c.critical > 0 && <span className="text-critical font-medium">{c.critical} crit</span>}
          {c.critical > 0 && c.high > 0 && ", "}
          {c.high > 0 && <span className="text-high font-medium">{c.high} high</span>})
        </span>
      )}
    </div>
  );
}

function Dashboard() {
  const mounted = useMounted();
  const navigate = useNavigate();
  const scans = useScans();

  const findings = scans.flatMap((s) => s.findings);
  const counts = countBySeverity(findings);
  const vectors = synthesizeVectors(findings).slice(0, 5);
  const active = scans.filter((s) => s.status === "running");
  const recent = [...scans]
    .sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || b.createdAt - a.createdAt);

  const maxSev = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s]));
  const sevBar: Record<Severity, string> = {
    critical: "bg-critical",
    high: "bg-high",
    medium: "bg-medium",
    low: "bg-low",
    info: "bg-info",
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-baseline justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">Recon Dashboard</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Target perimeter inventory and vulnerability correlation.
          </p>
        </div>
        <Link
          to="/new-scan"
          className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-xs font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
        >
          <Crosshair className="size-3.5" />
          New scan
        </Link>
      </div>

      {/* Single Compact Status Strip */}
      <div className="grid grid-cols-2 divide-y divide-border/60 rounded-xl border border-border/60 bg-card/40 sm:grid-cols-5 sm:divide-x sm:divide-y-0">
        <div className="p-3.5 text-center sm:text-left sm:pl-4">
          <div className="text-xs text-muted-foreground">Monitored Targets</div>
          <div className="mt-1 font-mono text-lg font-semibold tabular-nums text-foreground">
            {mounted ? scans.length : "—"}
          </div>
        </div>

        <div className="p-3.5 text-center sm:text-left sm:pl-4">
          <div className="text-xs text-muted-foreground">Active Operations</div>
          <div className="mt-1 flex items-center justify-center gap-2 font-mono text-lg font-semibold tabular-nums text-foreground sm:justify-start">
            {mounted && active.length > 0 && (
              <span className="size-2 rounded-full bg-primary animate-pulse" />
            )}
            {mounted ? active.length : "—"}
          </div>
        </div>

        <div className="p-3.5 text-center sm:text-left sm:pl-4">
          <div className="text-xs text-muted-foreground">Correlated Findings</div>
          <div className="mt-1 font-mono text-lg font-semibold tabular-nums text-foreground">
            {mounted ? findings.length : "—"}
          </div>
        </div>

        <div className="p-3.5 text-center sm:text-left sm:pl-4">
          <div className="text-xs text-muted-foreground">Critical / High</div>
          <div className="mt-1 font-mono text-lg font-semibold tabular-nums">
            <span className={counts.critical > 0 ? "text-critical" : "text-foreground"}>
              {mounted ? counts.critical : "—"}
            </span>
            <span className="text-muted-foreground/50 font-normal"> / </span>
            <span className={counts.high > 0 ? "text-high" : "text-foreground"}>
              {mounted ? counts.high : "—"}
            </span>
          </div>
        </div>

        <div className="col-span-2 p-3.5 text-center sm:col-span-1 sm:text-left sm:pl-4">
          <div className="text-xs text-muted-foreground">Composite Risk</div>
          <div className="mt-1 font-mono text-lg font-semibold tabular-nums text-foreground">
            {mounted ? riskScore(findings) : "—"}
            <span className="text-xs font-normal text-muted-foreground"> / 100</span>
          </div>
        </div>
      </div>

      {/* Main Layout: Hero Scan Table + Threat Panel */}
      <div className="grid gap-6 xl:grid-cols-3">
        {/* Hero Scan Table (spans 2 columns on wide screens) */}
        <section className="xl:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-foreground">Target Operations</h2>
            <Link
              to="/history"
              className="text-xs text-muted-foreground transition-colors hover:text-foreground inline-flex items-center gap-1"
            >
              Full history <ArrowUpRight className="size-3" />
            </Link>
          </div>

          <div className="overflow-hidden rounded-xl border border-border/60 bg-card/40">
            {mounted && recent.length === 0 ? (
              <div className="py-16 text-center text-sm text-muted-foreground">
                No scans recorded. Launch a new scan to begin target reconnaissance.
              </div>
            ) : (
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-border/60 bg-muted/20 font-mono text-[11px] text-muted-foreground">
                    <th className="py-2.5 pl-4 pr-3 font-medium">Target</th>
                    <th className="px-3 py-2.5 font-medium">Status</th>
                    <th className="px-3 py-2.5 font-medium">Findings</th>
                    <th className="hidden px-3 py-2.5 font-medium md:table-cell">Lineup</th>
                    <th className="hidden px-3 py-2.5 text-right font-medium sm:table-cell">Updated</th>
                    <th className="py-2.5 pl-2 pr-4 text-right font-medium"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40 font-sans">
                  {(mounted ? recent : []).map((s) => {
                    const isRunning = s.status === "running";
                    const progress = aggregateProgress(s);
                    return (
                      <tr
                        key={s.id}
                        onClick={() => navigate({ to: "/scan/$id", params: { id: s.id } })}
                        className={`group cursor-pointer transition-colors hover:bg-accent/30 ${
                          isRunning ? "border-l-2 border-l-primary bg-primary/[0.02]" : ""
                        }`}
                      >
                        <td className="py-3 pl-4 pr-3">
                          <div className="font-medium text-foreground group-hover:text-primary transition-colors">
                            {s.name}
                          </div>
                          <div className="font-mono text-xs text-muted-foreground tabular-nums">
                            {s.target}
                          </div>
                        </td>

                        <td className="px-3 py-3 whitespace-nowrap">
                          <StatusDot status={s.status} paused={s.paused} />
                          {isRunning && (
                            <div className="mt-1.5 flex items-center gap-2">
                              <div className="h-1 w-20 overflow-hidden rounded-full bg-muted/60">
                                <div
                                  className="h-full rounded-full bg-primary transition-all duration-300"
                                  style={{ width: `${progress}%` }}
                                />
                              </div>
                              <span className="font-mono text-[10px] tabular-nums text-muted-foreground">
                                {progress}%
                              </span>
                            </div>
                          )}
                        </td>

                        <td className="px-3 py-3 whitespace-nowrap">
                          <FindingsSummary findings={s.findings} />
                        </td>

                        <td className="hidden px-3 py-3 whitespace-nowrap font-mono text-xs text-muted-foreground md:table-cell">
                          {s.config.intensity} · {s.config.ports}
                        </td>

                        <td className="hidden px-3 py-3 text-right font-mono text-xs tabular-nums text-muted-foreground sm:table-cell whitespace-nowrap">
                          {formatDistanceToNow(s.createdAt, { addSuffix: true })}
                        </td>

                        <td className="py-3 pl-2 pr-4 text-right">
                          <ArrowUpRight className="inline-block size-4 text-muted-foreground/60 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-primary" />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {/* Secondary Intelligence Panel */}
        <div className="space-y-6">
          {/* Severity Distribution */}
          <section className="rounded-xl border border-border/60 bg-card/40 p-4">
            <h2 className="text-sm font-semibold text-foreground">Severity Distribution</h2>
            <div className="mt-3.5 space-y-2.5">
              {SEVERITY_ORDER.map((sev) => (
                <div key={sev}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="capitalize text-muted-foreground">{sev}</span>
                    <span className="font-mono font-medium tabular-nums text-foreground">
                      {mounted ? counts[sev] : "—"}
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-muted/50">
                    <div
                      className={`h-full rounded-full transition-all duration-300 ${sevBar[sev]}`}
                      style={{ width: `${mounted ? (counts[sev] / maxSev) * 100 : 0}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Key Attack Vectors */}
          <section className="rounded-xl border border-border/60 bg-card/40 p-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-foreground">Key Attack Vectors</h2>
              <span className="font-mono text-xs tabular-nums text-muted-foreground">
                {vectors.length} prioritized
              </span>
            </div>

            <div className="mt-3.5 space-y-2.5">
              {(mounted ? vectors : []).length === 0 && (
                <p className="text-xs text-muted-foreground">No critical attack paths identified.</p>
              )}
              {(mounted ? vectors : []).map((v) => (
                <div
                  key={v.id}
                  className="rounded-lg border border-border/40 bg-background/50 p-3 transition-colors hover:border-border"
                >
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-xs font-medium text-foreground leading-snug">{v.title}</span>
                    <span
                      className={`font-mono text-[10px] font-semibold uppercase ${
                        v.severity === "critical"
                          ? "text-critical"
                          : v.severity === "high"
                            ? "text-high"
                            : "text-medium"
                      }`}
                    >
                      {v.severity}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{v.why}</p>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
