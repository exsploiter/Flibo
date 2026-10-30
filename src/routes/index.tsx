import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { formatDistanceToNow } from "date-fns";
import { useState } from "react";
import {
  ArrowUpRight,
  Crosshair,
  ExternalLink,
  Shield,
  Layers,
  Terminal,
  Zap,
  Globe,
  Server,
  Bug,
  AlertTriangle,
  Radio,
  Lock,
  Cpu,
  Flame,
  Search,
} from "lucide-react";
import { useScans } from "@/lib/store";
import { aggregateProgress, countBySeverity, riskScore, synthesizeVectors } from "@/lib/synthesis";
import { SEVERITY_ORDER, type Scan, type Severity, type Finding } from "@/lib/types";
import { AGENTS } from "@/lib/mock";
import { useMounted } from "@/lib/hooks";

export const Route = createFileRoute("/")({
  component: Dashboard,
  head: () => ({
    meta: [
      { title: "Flibo — Recon Operations Dashboard" },
      {
        name: "description",
        content: "Live attack surface reconnaissance, perimeter telemetry, and vulnerability correlation.",
      },
      { property: "og:title", content: "Flibo — Recon Operations Dashboard" },
      {
        property: "og:description",
        content: "Live attack surface reconnaissance, perimeter telemetry, and vulnerability correlation.",
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
        <span className="size-1.5 rounded-full bg-low" />
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
  const [quickTarget, setQuickTarget] = useState("");

  const findings = scans.flatMap((s) => s.findings);
  const counts = countBySeverity(findings);
  const vectors = synthesizeVectors(findings).slice(0, 6);
  const active = scans.filter((s) => s.status === "running");
  const recent = [...scans].sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || b.createdAt - a.createdAt);

  // Surface category aggregations
  const portFindings = findings.filter((f) => f.kind === "port" && f.port);
  const webPorts = portFindings.filter((p) => [80, 443, 8080, 8443, 3000, 8000].includes(p.port!));
  const remotePorts = portFindings.filter((p) => [22, 3389, 21, 23].includes(p.port!));
  const dbPorts = portFindings.filter((p) => [3306, 5432, 6379, 27017, 1433, 9200].includes(p.port!));
  const subdomainCount = findings.filter((f) => f.kind === "subdomain").length;
  const kevCount = findings.filter((f) => f.cisaKev).length;

  const maxSev = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s]));
  const sevBar: Record<Severity, string> = {
    critical: "bg-critical",
    high: "bg-high",
    medium: "bg-medium",
    low: "bg-low",
    info: "bg-info",
  };

  const threatScore = mounted ? riskScore(findings) : 0;

  function handleQuickLaunch(e: React.FormEvent) {
    e.preventDefault();
    if (!quickTarget.trim()) {
      navigate({ to: "/new-scan" });
      return;
    }
    navigate({ to: "/new-scan" });
  }

  return (
    <div className="space-y-6">
      {/* Header with Quick Launch input */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-primary font-semibold">
            <Radio className="size-3.5 animate-pulse" />
            Tactical Reconnaissance Console
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground mt-0.5">
            Perimeter Security Operations
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Host attack surface inventory, live socket engine telemetry, and weaponizable CVE correlations.
          </p>
        </div>

        {/* Quick Launch Bar */}
        <form onSubmit={handleQuickLaunch} className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
            <input
              type="text"
              value={quickTarget}
              onChange={(e) => setQuickTarget(e.target.value)}
              placeholder="Quick target (domain / IP)..."
              className="w-64 rounded-xl border border-input bg-card/80 pl-9 pr-3 py-2 text-xs font-mono outline-none focus:ring-2 focus:ring-primary/40 shadow-xs"
            />
          </div>
          <button
            type="submit"
            className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2 text-xs font-medium text-primary-foreground shadow-xs transition-colors hover:bg-primary/90"
          >
            <Crosshair className="size-3.5" />
            New Sweep
          </button>
        </form>
      </div>

      {/* Expanded Tactical Metrics Grid */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <div className="rounded-2xl border border-border/60 bg-card p-3.5 shadow-panel">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Targets</span>
            <Globe className="size-3.5 text-muted-foreground" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold tabular-nums text-foreground">
            {mounted ? scans.length : "—"}
          </div>
          <div className="mt-1 font-mono text-[10px] text-muted-foreground">
            {subdomainCount} subdomains
          </div>
        </div>

        <div className="rounded-2xl border border-border/60 bg-card p-3.5 shadow-panel">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Active Probes</span>
            <Zap className="size-3.5 text-primary" />
          </div>
          <div className="mt-1 flex items-center gap-2 font-mono text-xl font-bold tabular-nums text-foreground">
            {mounted && active.length > 0 && <span className="size-2 rounded-full bg-primary animate-ping" />}
            {mounted ? active.length : "—"}
          </div>
          <div className="mt-1 font-mono text-[10px] text-muted-foreground">
            {active.length > 0 ? "live socket workers" : "engine idle"}
          </div>
        </div>

        <div className="rounded-2xl border border-border/60 bg-card p-3.5 shadow-panel">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Open Sockets</span>
            <Server className="size-3.5 text-muted-foreground" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold tabular-nums text-foreground">
            {mounted ? portFindings.length : "—"}
          </div>
          <div className="mt-1 font-mono text-[10px] text-muted-foreground">
            {webPorts.length} web · {remotePorts.length} shell
          </div>
        </div>

        <div className="rounded-2xl border border-border/60 bg-card p-3.5 shadow-panel">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Correlated Findings</span>
            <Bug className="size-3.5 text-muted-foreground" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold tabular-nums text-foreground">
            {mounted ? findings.length : "—"}
          </div>
          <div className="mt-1 font-mono text-[10px] text-muted-foreground">
            across {scans.length} assets
          </div>
        </div>

        <div className="rounded-2xl border border-border/60 bg-card p-3.5 shadow-panel">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Critical / High</span>
            <AlertTriangle className="size-3.5 text-critical" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold tabular-nums">
            <span className={counts.critical > 0 ? "text-critical" : "text-foreground"}>
              {mounted ? counts.critical : "—"}
            </span>
            <span className="text-muted-foreground/40 font-normal"> / </span>
            <span className={counts.high > 0 ? "text-high" : "text-foreground"}>
              {mounted ? counts.high : "—"}
            </span>
          </div>
          <div className="mt-1 font-mono text-[10px] text-muted-foreground">
            {kevCount > 0 ? <span className="text-critical font-semibold">{kevCount} CISA KEV</span> : "0 active KEVs"}
          </div>
        </div>

        <div className="rounded-2xl border border-border/60 bg-card p-3.5 shadow-panel">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Threat Index</span>
            <Shield className="size-3.5 text-primary" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold tabular-nums text-foreground">
            {threatScore}
            <span className="text-xs font-normal text-muted-foreground"> / 100</span>
          </div>
          <div className="mt-1 font-mono text-[10px]">
            <span
              className={
                threatScore > 50
                  ? "text-critical font-semibold"
                  : threatScore > 20
                    ? "text-high font-semibold"
                    : "text-low font-semibold"
              }
            >
              {threatScore > 50 ? "CRITICAL RISK" : threatScore > 20 ? "ELEVATED RISK" : "NOMINAL"}
            </span>
          </div>
        </div>
      </div>

      {/* Engine Status Grid */}
      <div className="rounded-2xl border border-border/50 bg-card/70 p-3.5 shadow-panel">
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-border/40">
          <div className="flex items-center gap-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            <Cpu className="size-3.5 text-primary" />
            15 V2 Reconnaissance Engines Active
          </div>
          <span className="font-mono text-[10px] text-low flex items-center gap-1.5">
            <span className="size-1.5 rounded-full bg-low" /> All engines online
          </span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {AGENTS.map((a) => (
            <span
              key={a.id}
              className="inline-flex items-center gap-1.5 rounded-lg border border-border/60 bg-background/60 px-2.5 py-1 font-mono text-[10px] font-medium text-muted-foreground"
            >
              <span className="size-1.5 rounded-full bg-primary/70" />
              {a.name}
            </span>
          ))}
        </div>
      </div>

      {/* Main Split: Scan Inventory + Threat Intelligence Sidebars */}
      <div className="grid gap-6 xl:grid-cols-3">
        {/* Scan Table (spans 2 columns) */}
        <section className="xl:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
              <Layers className="size-4 text-primary" /> Monitored Target Perimeters
            </h2>
            <Link
              to="/history"
              className="text-xs text-muted-foreground transition-colors hover:text-foreground inline-flex items-center gap-1"
            >
              Full history <ArrowUpRight className="size-3" />
            </Link>
          </div>

          <div className="overflow-hidden rounded-2xl border border-border/50 bg-card shadow-panel">
            {mounted && recent.length === 0 ? (
              <div className="py-16 text-center text-sm text-muted-foreground">
                No scans recorded. Launch a new scan to begin target reconnaissance.
              </div>
            ) : (
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-border/40 bg-muted/20 font-mono text-[11px] text-muted-foreground">
                    <th className="py-2.5 pl-4 pr-3 font-medium">Target Host</th>
                    <th className="px-3 py-2.5 font-medium">Engine Status</th>
                    <th className="px-3 py-2.5 font-medium">Findings</th>
                    <th className="hidden px-3 py-2.5 font-medium md:table-cell">Profile</th>
                    <th className="hidden px-3 py-2.5 text-right font-medium sm:table-cell">Audit Age</th>
                    <th className="py-2.5 pl-2 pr-4 text-right font-medium"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/30 font-sans">
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

          {/* Exposure Category Breakdown Strip */}
          <div className="grid gap-3 sm:grid-cols-3 pt-2">
            <div className="rounded-2xl border border-border/50 bg-card p-4 shadow-panel">
              <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                <Globe className="size-4 text-primary" /> Web Endpoints
              </div>
              <div className="mt-2 font-mono text-lg font-bold tabular-nums">
                {webPorts.length} <span className="text-xs font-normal text-muted-foreground">ports open</span>
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">
                HTTP/HTTPS services on 80, 443, 8080, 8443
              </p>
            </div>

            <div className="rounded-2xl border border-border/50 bg-card p-4 shadow-panel">
              <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                <Lock className="size-4 text-high" /> Shell & Access
              </div>
              <div className="mt-2 font-mono text-lg font-bold tabular-nums">
                {remotePorts.length} <span className="text-xs font-normal text-muted-foreground">ports open</span>
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">
                Remote daemons on SSH (22), RDP (3389)
              </p>
            </div>

            <div className="rounded-2xl border border-border/50 bg-card p-4 shadow-panel">
              <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                <Server className="size-4 text-critical" /> Databases & Caches
              </div>
              <div className="mt-2 font-mono text-lg font-bold tabular-nums">
                {dbPorts.length} <span className="text-xs font-normal text-muted-foreground">ports open</span>
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">
                Reachable datastores: MySQL, Redis, Postgres
              </p>
            </div>
          </div>
        </section>

        {/* Secondary Intelligence Panel */}
        <div className="space-y-6">
          {/* Key Attack Vectors (with MITRE tags) */}
          <section className="rounded-2xl border border-border/50 bg-card p-4 shadow-panel">
            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
                <Flame className="size-4 text-primary" /> Key Attack Vectors
              </h2>
              <span className="font-mono text-xs tabular-nums text-muted-foreground">
                {vectors.length} prioritized
              </span>
            </div>

            <div className="mt-3.5 space-y-2.5">
              {(mounted ? vectors : []).length === 0 && (
                <p className="text-xs text-muted-foreground py-4 text-center">No high-leverage attack paths identified.</p>
              )}
              {(mounted ? vectors : []).map((v) => (
                <div
                  key={v.id}
                  className="rounded-xl border border-border/50 bg-muted/20 p-3 transition-colors hover:border-border"
                >
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-xs font-semibold text-foreground leading-snug">{v.title}</span>
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
                  <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{v.why}</p>
                  {v.mitreTechnique && (
                    <div className="mt-2 font-mono text-[10px] text-muted-foreground/80 flex items-center gap-1.5">
                      <span className="font-semibold text-primary">MITRE:</span> {v.mitreTechnique}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>

          {/* Severity Distribution */}
          <section className="rounded-2xl border border-border/50 bg-card p-4 shadow-panel">
            <h2 className="text-sm font-semibold text-foreground">Fleet Severity Distribution</h2>
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
        </div>
      </div>
    </div>
  );
}
