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
    <div className="rounded-2xl border border-border/60 bg-card/70 p-5">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
          {label}
        </span>
        <div
          className={
            "flex size-8 items-center justify-center rounded-xl " +
            (accent ? "bg-primary/12 text-primary" : "bg-muted/50 text-muted-foreground")
          }
        >
          <Icon className="size-4" />
        </div>
      </div>
      <div className="mt-3 font-mono text-3xl font-bold tracking-tight">{value}</div>
      <div className="mt-1 text-xs text-muted-foreground">{sub}</div>
    </div>
  );
}

function ActiveScanRow({ scan }: { scan: Scan }) {
  const agg = aggregateProgress(scan);
  return (
    <Link
      to="/scan/$id"
      params={{ id: scan.id }}
      className="group block rounded-2xl border border-border/60 bg-card/50 p-4 transition-colors hover:border-primary/40"
    >
      <div className="flex items-center gap-3">
        <ScanStatusPill status={scan.status} paused={scan.paused} />
        <span className="truncate text-sm font-semibold">{scan.name}</span>
        <span className="ml-auto font-mono text-xs text-muted-foreground">{agg}%</span>
        <ArrowUpRight className="size-4 text-muted-foreground transition-colors group-hover:text-primary" />
      </div>
      <Progress value={agg} className="mt-3 h-1.5" />
      <div className="mt-2 flex gap-2 font-mono text-[11px] text-muted-foreground">
        {scan.agents
          .filter((a) => a.status === "running" || a.status === "queued")
          .slice(0, 3)
          .map((a) => (
            <span key={a.id} className="rounded-md bg-muted/60 px-2 py-0.5">
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
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Recon Dashboard</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Attack surface at a glance — {mounted ? scans.length : 0} scans tracked.
          </p>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Radar} label="Scans" value={mounted ? scans.length : "—"} sub="tracked targets" />
        <StatCard icon={Activity} label="Active" value={mounted ? active.length : "—"} sub="running right now" accent />
        <StatCard icon={Bug} label="Findings" value={mounted ? findings.length : "—"} sub="across all scans" />
        <StatCard icon={ShieldAlert} label="Crit + High" value={mounted ? criticalHigh : "—"} sub="needs attention first" accent />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <section>
            <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              <Activity className="size-4 text-primary" /> Active operations
            </h2>
            {mounted && active.length === 0 ? (
              <EmptyState
                icon={Crosshair}
                title="No scans running"
                body="Launch a new scan to map your target's attack surface."
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
            <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              <Radar className="size-4 text-primary" /> Recent scans
            </h2>
            {mounted && recent.length === 0 ? (
              <EmptyState icon={Radar} title="No scans yet" body="Your scan history will appear here." />
            ) : (
              <div className="overflow-hidden rounded-2xl border border-border/60 bg-card/60">
                <table className="w-full text-sm">
                  <tbody>
                    {(mounted ? recent : []).map((s) => {
                      const c = countBySeverity(s.findings);
                      return (
                        <tr key={s.id} className="border-b border-border/40 last:border-0">
                          <td className="px-4 py-3">
                            <Link to="/scan/$id" params={{ id: s.id }} className="font-medium hover:text-primary">
                              {s.name}
                            </Link>
                            <div className="font-mono text-[11px] text-muted-foreground">{s.target}</div>
                          </td>
                          <td className="px-2 py-3">
                            <ScanStatusPill status={s.status} paused={s.paused} />
                          </td>
                          <td className="hidden px-2 py-3 md:table-cell">
                            <div className="flex gap-1">
                              {(["critical", "high"] as Severity[]).map((sev) =>
                                c[sev] > 0 ? <SeverityBadge key={sev} severity={sev} /> : null,
                              )}
                              <span className="self-center pl-1 font-mono text-[11px] text-muted-foreground">
                                {s.findings.length} findings
                              </span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-right font-mono text-[11px] text-muted-foreground">
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
          <section className="rounded-2xl border border-border/60 bg-card/60 p-5">
            <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              <ShieldAlert className="size-4 text-critical" /> Severity distribution
            </h2>
            <div className="mt-4 space-y-3">
              {SEVERITY_ORDER.map((sev) => (
                <div key={sev}>
                  <div className="mb-1 flex items-center justify-between font-mono text-[11px]">
                    <span className="uppercase tracking-wider text-muted-foreground">{sev}</span>
                    <span>{mounted ? counts[sev] : "—"}</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-muted/60">
                    <div
                      className={`h-full rounded-full ${sevBar[sev]}`}
                      style={{ width: `${mounted ? (counts[sev] / maxSev) * 100 : 0}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-5 flex items-center justify-between rounded-xl bg-muted/40 px-3 py-2.5">
              <span className="text-xs text-muted-foreground">Composite risk score</span>
              <span className="font-mono text-lg font-bold text-primary">
                {mounted ? riskScore(findings) : "—"}/100
              </span>
            </div>
          </section>

          <section className="rounded-2xl border border-border/60 bg-card/60 p-5">
            <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              <Flame className="size-4 text-primary" /> Top attack vectors
            </h2>
            <div className="mt-4 space-y-3">
              {(mounted ? vectors : []).length === 0 && (
                <p className="text-sm text-muted-foreground">Nothing mapped yet.</p>
              )}
              {(mounted ? vectors : []).map((v) => (
                <div key={v.id} className="rounded-xl border border-border/50 bg-background/50 p-3">
                  <div className="flex items-start gap-2">
                    <SeverityBadge severity={v.severity} />
                    <span className="text-sm font-medium leading-snug">{v.title}</span>
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{v.why}</p>
                </div>
              ))}
            </div>
            <Link
              to="/history"
              className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
            >
              Open full history <ArrowUpRight className="size-3" />
            </Link>
          </section>
        </div>
      </div>
    </div>
  );
}
