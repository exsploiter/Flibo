import { createFileRoute, Link } from "@tanstack/react-router";
import { formatDistanceToNow } from "date-fns";
import {
  Activity,
  ArrowUpRight,
  Bug,
  Crosshair,
  Flame,
  Radar,
  ShieldAlert,
} from "lucide-react";
import { useScans } from "@/lib/store";
import { aggregateProgress, countBySeverity, riskScore, synthesizeVectors } from "@/lib/synthesis";
import { SEVERITY_ORDER, type Scan, type Severity } from "@/lib/types";
import { SeverityBadge, ScanStatusPill, EmptyState } from "@/components/ui-bits";
import { Progress } from "@/components/ui/progress";
import { useMounted } from "@/lib/hooks";

export const Route = createFileRoute("/")({
  component: Dashboard,
  head: () => ({
    meta: [
      { title: "Flibo — Recon Dashboard" },
      {
        name: "description",
        content: "Live overview of recon scans, findings and ranked attack vectors.",
      },
      { property: "og:title", content: "Flibo — Recon Dashboard" },

      {
        property: "og:description",
        content: "Live overview of recon scans, findings and ranked attack vectors.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  accent,
}: {
  icon: typeof Radar;
  label: string;
  value: string | number;
  sub: string;
  accent?: boolean;
}) {
  return (
    <div className="group relative overflow-hidden rounded-2xl border border-border/60 bg-card/60 p-5 transition-all duration-200 hover:border-primary/40 hover:bg-card/80">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
        <div
          className={
            "flex size-8 items-center justify-center rounded-xl transition-transform duration-200 group-hover:scale-105 " +
            (accent ? "bg-primary/15 text-primary" : "bg-muted/60 text-muted-foreground")
          }
        >
          <Icon className="size-4" />
        </div>
      </div>
      <div className="mt-3 font-mono text-3xl font-bold tracking-tight text-foreground">{value}</div>
      <div className="mt-1 text-xs text-muted-foreground/90">{sub}</div>
    </div>
  );
}

function ActiveScanRow({ scan }: { scan: Scan }) {
  const agg = aggregateProgress(scan);
  return (
    <Link
      to="/scan/$id"
      params={{ id: scan.id }}
      className="group block rounded-2xl border border-border/60 bg-card/50 p-4 transition-all duration-200 hover:border-primary/50 hover:bg-card/75"
    >
      <div className="flex items-center gap-3">
        <ScanStatusPill status={scan.status} paused={scan.paused} />
        <span className="truncate text-sm font-semibold text-foreground group-hover:text-primary transition-colors">
          {scan.name}
        </span>
        <span className="ml-auto font-mono text-xs tabular-nums text-muted-foreground">{agg}%</span>
        <ArrowUpRight className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-primary" />
      </div>
      <Progress value={agg} className="mt-3 h-1.5" />
      <div className="mt-2.5 flex flex-wrap gap-1.5 font-mono text-[11px] text-muted-foreground">
        {scan.agents
          .filter((a) => a.status === "running" || a.status === "queued")
          .slice(0, 3)
          .map((a) => (
            <span key={a.id} className="rounded-md border border-border/40 bg-muted/40 px-2 py-0.5">
              {a.name}
            </span>
          ))}
      </div>
    </Link>
  );
}

function Dashboard() {
  const mounted = useMounted();
  const scans = useScans();

  const findings = scans.flatMap((s) => s.findings);
  const counts = countBySeverity(findings);
  const vectors = synthesizeVectors(findings).slice(0, 5);
  const active = scans.filter((s) => s.status === "running");
  const recent = [...scans]
    .sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || b.createdAt - a.createdAt)
    .slice(0, 6);
  const criticalHigh = counts.critical + counts.high;

  const maxSev = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s]));
  const sevBar: Record<Severity, string> = {
    critical: "bg-critical",
    high: "bg-high",
    medium: "bg-medium",
    low: "bg-low",
    info: "bg-info",
  };

  return (
    <div className="space-y-7">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground sm:text-3xl">Recon Dashboard</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Attack surface at a glance — {mounted ? scans.length : 0} targets monitored across internal and external perimeters.
          </p>
        </div>
        <Link
          to="/new-scan"
          className="glow-primary hidden sm:inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-transform hover:scale-[1.02] active:scale-[0.98]"
        >
          <Crosshair className="size-4" /> Launch Scan
        </Link>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Radar} label="Total Scans" value={mounted ? scans.length : "—"} sub="registered target scopes" />
        <StatCard icon={Activity} label="Active Operations" value={mounted ? active.length : "—"} sub="workers running live" accent />
        <StatCard icon={Bug} label="Total Findings" value={mounted ? findings.length : "—"} sub="correlated across all engines" />
        <StatCard icon={ShieldAlert} label="High & Critical" value={mounted ? criticalHigh : "—"} sub="immediate triage required" accent={criticalHigh > 0} />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <section>
            <div className="mb-3.5 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
                <Activity className="size-4 text-primary" /> Active Operations
              </h2>
              {active.length > 0 && (
                <span className="font-mono text-xs tabular-nums text-muted-foreground">
                  {active.length} running
                </span>
              )}
            </div>
            {mounted && active.length === 0 ? (
              <EmptyState
                icon={Crosshair}
                title="No active operations"
                body="Target perimeter is quiet. Launch a new scan to discover open services and vulnerabilities."
              />
            ) : (
              <div className="grid gap-3 sm:grid-cols-2">
                {(mounted ? active : []).map((s) => (
                  <ActiveScanRow key={s.id} scan={s} />
                ))}
              </div>
            )}
          </section>

          <section>
            <div className="mb-3.5 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
                <Radar className="size-4 text-primary" /> Recent Target Scans
              </h2>
              <Link to="/history" className="text-xs text-muted-foreground hover:text-primary transition-colors">
                View all ({scans.length})
              </Link>
            </div>
            {mounted && recent.length === 0 ? (
              <EmptyState icon={Radar} title="No scans yet" body="Your scan history will appear here once you initiate recon." />
            ) : (
              <div className="overflow-hidden rounded-2xl border border-border/60 bg-card/60 backdrop-blur-sm">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/40 bg-muted/20 text-left font-mono text-[11px] text-muted-foreground">
                      <th className="px-4 py-2.5 font-medium">Target</th>
                      <th className="px-3 py-2.5 font-medium">Status</th>
                      <th className="hidden px-3 py-2.5 font-medium md:table-cell">Findings</th>
                      <th className="px-4 py-2.5 text-right font-medium">Completed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/30">
                    {(mounted ? recent : []).map((s) => {
                      const c = countBySeverity(s.findings);
                      return (
                        <tr
                          key={s.id}
                          className="group transition-colors hover:bg-accent/40"
                        >
                          <td className="px-4 py-3">
                            <Link to="/scan/$id" params={{ id: s.id }} className="font-medium text-foreground group-hover:text-primary transition-colors">
                              {s.name}
                            </Link>
                            <div className="font-mono text-xs text-muted-foreground">{s.target}</div>
                          </td>
                          <td className="px-3 py-3">
                            <ScanStatusPill status={s.status} paused={s.paused} />
                          </td>
                          <td className="hidden px-3 py-3 md:table-cell">
                            <div className="flex items-center gap-1.5">
                              {(["critical", "high"] as Severity[]).map((sev) =>
                                c[sev] > 0 ? <SeverityBadge key={sev} severity={sev} /> : null,
                              )}
                              <span className="pl-1 font-mono text-xs tabular-nums text-muted-foreground">
                                {s.findings.length} findings
                              </span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-right font-mono text-xs tabular-nums text-muted-foreground">
                            {formatDistanceToNow(s.createdAt, { addSuffix: true })}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>

        <div className="space-y-6">
          <section className="rounded-2xl border border-border/60 bg-card/60 p-5 backdrop-blur-sm">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <ShieldAlert className="size-4 text-critical" /> Severity Distribution
            </h2>
            <div className="mt-4 space-y-3">
              {SEVERITY_ORDER.map((sev) => (
                <div key={sev}>
                  <div className="mb-1 flex items-center justify-between font-mono text-xs">
                    <span className="capitalize text-muted-foreground">{sev}</span>
                    <span className="tabular-nums font-semibold">{mounted ? counts[sev] : "—"}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-muted/50">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${sevBar[sev]}`}
                      style={{ width: `${mounted ? (counts[sev] / maxSev) * 100 : 0}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-5 flex items-center justify-between rounded-xl border border-border/40 bg-muted/30 px-3.5 py-3">
              <span className="text-xs text-muted-foreground">Composite Risk Index</span>
              <span className="font-mono text-lg font-bold tabular-nums text-primary">
                {mounted ? riskScore(findings) : "—"}<span className="text-xs text-muted-foreground font-normal"> / 100</span>
              </span>
            </div>
          </section>

          <section className="rounded-2xl border border-border/60 bg-card/60 p-5 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
                <Flame className="size-4 text-primary" /> Key Attack Vectors
              </h2>
              <span className="font-mono text-xs text-muted-foreground">{vectors.length} prioritized</span>
            </div>
            <div className="mt-4 space-y-3">
              {(mounted ? vectors : []).length === 0 && (
                <p className="text-sm text-muted-foreground">No attack paths synthesized yet.</p>
              )}
              {(mounted ? vectors : []).map((v) => (
                <div key={v.id} className="rounded-xl border border-border/50 bg-background/60 p-3.5 transition-colors hover:border-border">
                  <div className="flex items-start gap-2.5">
                    <SeverityBadge severity={v.severity} />
                    <span className="text-sm font-medium leading-snug text-foreground">{v.title}</span>
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{v.why}</p>
                </div>
              ))}
            </div>
            <Link
              to="/history"
              className="mt-4 inline-flex items-center gap-1.5 text-xs font-medium text-primary hover:underline"
            >
              Examine full threat inventory <ArrowUpRight className="size-3.5" />
            </Link>
          </section>
        </div>
      </div>
    </div>
  );
}
