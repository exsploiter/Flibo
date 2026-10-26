import { createFileRoute, Link, notFound, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { formatDistanceToNow } from "date-fns";
import {
  ArrowUpDown,
  Bookmark,
  Bug,
  ChevronDown,
  Copy,
  Download,
  ExternalLink,
  FileDown,
  FileJson,
  FileText,
  Globe,
  Loader2,
  Pause,
  Play,
  Printer,
  RotateCcw,
  Server,
  Square,
  Tag,
  Terminal,
  X,
} from "lucide-react";
import { useScan } from "@/lib/store";
import { AGENTS } from "@/lib/mock";
import { ensureRunner, cancelScan, retryAgent, togglePause, etaSeconds } from "@/lib/runner";
import { aggregateProgress, countBySeverity, riskScore, synthesizeVectors } from "@/lib/synthesis";
import { copyText, download, scanToCsv, scanToJson, scanToMarkdown, safeFileName } from "@/lib/export";
import { SEVERITY_ORDER, severityWeight, type Finding } from "@/lib/types";
import { AgentStatusDot, AGENT_STATUS_LABEL, EmptyState, ScanStatusPill, SeverityBadge } from "@/components/ui-bits";
import { LogConsole } from "@/components/LogConsole";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useMounted } from "@/lib/hooks";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/scan/$id")({
  component: ScanDetail,
  head: () => ({
    meta: [
      { title: "Scan Detail — VEKTOR" },
      { name: "description", content: "Live agent status, streamed output, findings and attack vectors." },
      { property: "og:title", content: "Scan Detail — VEKTOR" },
      { property: "og:description", content: "Live agent status, streamed output, findings and attack vectors." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

const TABS = [
  { id: "summary", label: "Summary" },
  { id: "ports", label: "Ports" },
  { id: "services", label: "Services" },
  { id: "subdomains", label: "Subdomains" },
  { id: "cves", label: "CVEs" },
  { id: "vectors", label: "Attack Vectors" },
  { id: "findings", label: "All Findings" },
  { id: "output", label: "Raw Output" },
] as const;

type TabId = (typeof TABS)[number]["id"];

function SeverityRing({ score }: { score: number }) {
  return (
    <div className="relative mx-auto size-36">
      <div
        className="absolute inset-0 rounded-full"
        style={{
          background: `conic-gradient(var(--color-primary) ${score}%, color-mix(in oklab, var(--color-border) 55%, transparent) 0)`,
        }}
      />
      <div className="absolute inset-[10px] flex flex-col items-center justify-center rounded-full bg-card">
        <span className="font-mono text-4xl font-bold">{score}</span>
        <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">risk</span>
      </div>
    </div>
  );
}

function CveCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="overflow-hidden rounded-2xl border border-border/60 bg-card/60">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-accent/40"
      >
        <SeverityBadge severity={f.severity} />
        <span className="font-mono text-xs text-primary">{f.cveId}</span>
        <span className="truncate text-sm">{f.title.replace(`${f.cveId} — `, "")}</span>
        <span className="ml-auto flex items-center gap-3">
          <span className="rounded-lg border border-border/60 px-2 py-0.5 font-mono text-[11px]">
            CVSS {f.cvss?.toFixed(1)}
          </span>
          <ChevronDown className={cn("size-4 text-muted-foreground transition-transform", open && "rotate-180")} />
        </span>
      </button>
      {open && (
        <div className="border-t border-border/40 px-4 py-3">
          <p className="text-sm leading-relaxed text-muted-foreground">{f.description}</p>
          <div className="mt-2 font-mono text-[11px] text-muted-foreground">
            affected: {f.service} {f.version}
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {f.references?.map((r) => (
              <a
                key={r.label}
                href={r.url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 rounded-lg border border-border/60 bg-background/60 px-2.5 py-1 font-mono text-[11px] transition-colors hover:border-primary/40 hover:text-primary"
              >
                <ExternalLink className="size-3" /> {r.label}
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ScanDetail() {
  const { id } = Route.useParams();
  const mounted = useMounted();
  const navigate = useNavigate();
  const scan = useScan(id);

  const [tab, setTab] = useState<TabId>("summary");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: "port" | "severity" | "service"; dir: 1 | -1 }>({ key: "port", dir: 1 });
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const running = scan?.status === "running";
  useEffect(() => {
    if (mounted && scan && running && !scan.paused) ensureRunner(id);
  }, [id, mounted, running, scan?.paused]);

  const vectors = useMemo(() => synthesizeVectors(scan?.findings ?? []), [scan?.findings]);
  const counts = useMemo(() => countBySeverity(scan?.findings ?? []), [scan?.findings]);

  if (!mounted) return <div className="py-24 text-center text-muted-foreground">Loading scan…</div>;
  if (!scan) throw notFound();

  const agg = aggregateProgress(scan);
  const eta = etaSeconds(scan);
  const etaLabel =
    eta === null
      ? "—"
      : eta >= 60
        ? `${Math.floor(eta / 60)}m ${eta % 60}s`
        : `${eta}s`;

  const filterFn = (f: Finding) =>
    !query ||
    `${f.title} ${f.service ?? ""} ${f.detail ?? ""} ${f.cveId ?? ""}`.toLowerCase().includes(query.toLowerCase());

  const portFindings = scan.findings.filter((f) => f.kind === "port").filter(filterFn);
  const techFindings = scan.findings.filter((f) => f.kind === "tech").filter(filterFn);
  const subFindings = scan.findings.filter((f) => f.kind === "subdomain").filter(filterFn);
  const cveFindings = scan.findings.filter((f) => f.kind === "cve").filter(filterFn);
  const allFindings = [...scan.findings]
    .filter(filterFn)
    .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity));

  const sortedPorts = [...portFindings].sort((a, b) =>
    sort.key === "severity"
      ? (severityWeight(a.severity) - severityWeight(b.severity)) * sort.dir
      : sort.key === "service"
        ? (a.service ?? "").localeCompare(b.service ?? "") * sort.dir
        : ((a.port ?? 0) - (b.port ?? 0)) * sort.dir,
  );

  function toggleSort(key: "port" | "severity" | "service") {
    setSort((s) => (s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: 1 }));
  }

  function toggleTag(f: Finding) {
    const has = f.tags.includes("investigate");
    updateFinding(f, (nf) => ({
      ...nf,
      tags: has ? nf.tags.filter((t) => t !== "investigate") : [...nf.tags, "investigate"],
    }));
  }

  function updateFinding(f: Finding, updater: (nf: Finding) => Finding) {
    // findings are updated in place through the scan object
    const { useScansStore } = { useScansStore: null as never };
    void useScansStore;
    import("@/lib/store").then(({ updateScan }) =>
      updateScan(scan.id, (s) => ({ ...s, findings: s.findings.map((x) => (x.id === f.id ? updater(x) : x)) })),
    );
  }

  function reRun() {
    const newId = `scan-${Date.now()}`;
    import("@/lib/store").then(({ addScan, addTargetHistory }) => {
      addScan({
        ...scan,
        id: newId,
        name: scan.name.replace(/^Re-run — /, "") + " (re-run)",
        status: "running",
        paused: false,
        createdAt: Date.now(),
        finishedAt: undefined,
        findings: [],
        agents: scan.agents.map((a, i) => ({ ...a, status: i === 0 ? "running" : "queued", progress: 0, logs: [], error: undefined })),
      });
      addTargetHistory(scan.targets);
      ensureRunner(newId);
      toast.success("Re-running with same config");
      void navigate({ to: "/scan/$id", params: { id: newId } });
    });
  }

  const activeTabEmpty = {
    ports: portFindings.length === 0,
    services: techFindings.length === 0,
    subdomains: subFindings.length === 0,
    cves: cveFindings.length === 0,
    vectors: vectors.length === 0,
    findings: allFindings.length === 0,
  }[tab as "ports" | "services" | "subdomains" | "cves" | "vectors" | "findings"];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-3xl border border-border/60 bg-card/60 p-5">
        <div className="flex flex-wrap items-start gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <ScanStatusPill status={scan.status} paused={scan.paused} />
              {scan.config.stealth && (
                <span className="rounded-lg border border-medium/30 bg-medium/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-medium">
                  stealth
                </span>
              )}
              <span className="rounded-lg border border-border/60 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                {scan.config.intensity} · {scan.config.ports}
              </span>
            </div>
            <h1 className="mt-2 truncate text-2xl font-bold tracking-tight">{scan.name}</h1>
            <div className="mt-1 flex flex-wrap items-center gap-2 font-mono text-xs text-muted-foreground">
              <span className="rounded-md bg-muted/60 px-2 py-0.5">{scan.target}</span>
              {scan.targets.slice(1).map((t) => (
                <span key={t} className="rounded-md bg-muted/40 px-2 py-0.5">{t}</span>
              ))}
              <span>· {formatDistanceToNow(scan.createdAt, { addSuffix: true })}</span>
              {scan.tags.map((t) => (
                <span key={t} className="rounded-md border border-border/50 px-1.5 py-0.5">#{t}</span>
              ))}
            </div>
          </div>

          <div className="no-print flex flex-wrap items-center gap-2">
            {running && (
              <Button variant="outline" size="sm" onClick={() => togglePause(scan.id)}>
                {scan.paused ? <Play className="size-3.5" /> : <Pause className="size-3.5" />}
                {scan.paused ? "Resume" : "Pause"}
              </Button>
            )}
            {running && (
              <Button
                variant="outline"
                size="sm"
                className="border-critical/40 text-critical hover:bg-critical/10"
                onClick={() => {
                  cancelScan(scan.id);
                  toast.info("Scan cancelled");
                }}
              >
                <Square className="size-3.5" /> Cancel
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={reRun}>
              <RotateCcw className="size-3.5" /> Re-run
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                import("@/lib/store").then(({ togglePin }) => togglePin(scan.id));
                toast.success(scan.pinned ? "Unpinned" : "Pinned to top of history");
              }}
            >
              <Bookmark className={cn("size-3.5", scan.pinned && "fill-primary text-primary")} />
              {scan.pinned ? "Pinned" : "Pin"}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <Download className="size-3.5" /> Export
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="rounded-xl border-border/60 bg-popover">
                <DropdownMenuItem
                  onClick={() => {
                    download(`${safeFileName(scan)}.json`, scanToJson(scan), "application/json");
                    toast.success("Exported JSON");
                  }}
                >
                  <FileJson className="size-4" /> JSON
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => {
                    download(`${safeFileName(scan)}.csv`, scanToCsv(scan), "text/csv");
                    toast.success("Exported CSV");
                  }}
                >
                  <FileDown className="size-4" /> CSV
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => {
                    download(`${safeFileName(scan)}.md`, scanToMarkdown(scan), "text/markdown");
                    toast.success("Exported Markdown");
                  }}
                >
                  <FileText className="size-4" /> Markdown
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => window.print()}>
                  <Printer className="size-4" /> PDF / print view
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={async () => {
                    await copyText(`${window.location.origin}/scan/${scan.id}`);
                    toast.success("Summary link copied");
                  }}
                >
                  <Copy className="size-4" /> Copy share link
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        {/* progress + eta */}
        {(running || scan.status === "complete" || scan.status === "partial") && (
          <div className="mt-4 flex items-center gap-4">
            <Progress value={agg} className="h-1.5 flex-1" />
            <span className="font-mono text-xs text-muted-foreground">
              aggregate {agg}%{running ? ` · ETA ≈ ${etaLabel}` : ""}
            </span>
          </div>
        )}

        {/* partial-failure warning */}
        {scan.agents.some((a) => a.status === "failed") && (
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-xl border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">
            <X className="size-3.5" />
            Partial failure —{" "}
            {scan.agents
              .filter((a) => a.status === "failed")
              .map((a) => a.name)
              .join(", ")}{" "}
              did not finish. Retry below.
          </div>
        )}
      </div>

      {/* Agents */}
      <div className="no-print grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {scan.agents.map((a) => (
          <div key={a.id} className="rounded-2xl border border-border/60 bg-card/60 p-4">
            <div className="flex items-center gap-2">
              <AgentStatusDot status={a.status} />
              <span className="truncate text-sm font-medium">{a.name}</span>
              <span className="ml-auto font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                {AGENT_STATUS_LABEL[a.status]}
              </span>
            </div>
            <Progress value={a.progress} className="mt-3 h-1" />
            {a.error && <p className="mt-2 text-[11px] leading-snug text-critical">{a.error}</p>}
            {a.status === "failed" && (
              <Button variant="outline" size="sm" className="mt-2 w-full rounded-xl" onClick={() => retryAgent(scan.id, a.id)}>
                <RotateCcw className="size-3" /> Retry
              </Button>
            )}
          </div>
        ))}
      </div>

      {/* Tabs */}
      <Tabs value={tab} onValueChange={(v) => setTab(v as TabId)}>
        <div className="no-print flex flex-wrap items-center justify-between gap-3">
          <TabsList className="h-auto flex-wrap justify-start gap-1 rounded-2xl bg-muted/40 p-1">
            {TABS.map((t) => (
              <TabsTrigger
                key={t.id}
                value={t.id}
                className="rounded-xl px-3 py-1.5 font-mono text-xs data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
              >
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
          {["ports", "services", "subdomains", "cves", "findings"].includes(tab) && (
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="filter findings…"
              className="w-48 rounded-xl border border-input bg-background/70 px-3 py-1.5 font-mono text-xs outline-none focus:ring-1 focus:ring-primary/50"
            />
          )}
        </div>

        <div className="mt-4">
          {tab === "summary" && (
            <div className="grid gap-6 lg:grid-cols-3">
              <div className="rounded-3xl border border-border/60 bg-card/60 p-6">
                <h3 className="mb-4 text-center font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
                  Risk score
                </h3>
                <SeverityRing score={riskScore(scan.findings)} />
                <p className="mt-4 text-center text-xs text-muted-foreground">
                  Weighted from {scan.findings.length} findings across {scan.agents.length} agents
                </p>
              </div>
              <div className="rounded-3xl border border-border/60 bg-card/60 p-6">
                <h3 className="mb-4 font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
                  Severity breakdown
                </h3>
                <div className="space-y-2.5">
                  {SEVERITY_ORDER.map((sev) => (
                    <div key={sev} className="flex items-center gap-3">
                      <SeverityBadge severity={sev} className="w-20 justify-center" />
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted/60">
                        <div
                          className={`h-full rounded-full ${
                            { critical: "bg-critical", high: "bg-high", medium: "bg-medium", low: "bg-low", info: "bg-info" }[sev]
                          }`}
                          style={{ width: `${Math.min(100, counts[sev] * 12)}%` }}
                        />
                      </div>
                      <span className="w-6 text-right font-mono text-xs">{counts[sev]}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="rounded-3xl border border-border/60 bg-card/60 p-6">
                <h3 className="mb-4 font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
                  Suggested entry points
                </h3>
                <div className="space-y-2">
                  {vectors.slice(0, 5).map((v) => (
                    <div key={v.id} className="rounded-xl border border-border/50 bg-background/40 p-3">
                      <div className="flex items-start gap-2">
                        <SeverityBadge severity={v.severity} />
                        <span className="text-sm font-medium leading-snug">{v.title}</span>
                      </div>
                      <div className="mt-1.5 flex items-center gap-2">
                        <div className="h-1 w-16 overflow-hidden rounded-full bg-muted/60">
                          <div className="h-full rounded-full bg-primary" style={{ width: `${v.confidence}%` }} />
                        </div>
                        <span className="font-mono text-[10px] text-muted-foreground">{v.confidence}% confidence</span>
                      </div>
                    </div>
                  ))}
                  {vectors.length === 0 && <p className="text-sm text-muted-foreground">No vectors mapped yet.</p>}
                </div>
              </div>
            </div>
          )}

          {tab === "ports" &&
            (portFindings.length === 0 ? (
              <EmptyState icon={Server} title="No open ports recorded" body="Port Scan hasn't reported results for this target yet." />
            ) : (
              <div className="overflow-hidden rounded-2xl border border-border/60 bg-card/60">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/40 bg-muted/30 font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                      {([["port", "Port"], ["service", "Service"], ["severity", "Severity"]] as const).map(([k, label]) => (
                        <th
                          key={k}
                          className="cursor-pointer select-none px-4 py-2.5 text-left hover:text-primary"
                          onClick={() => toggleSort(k)}
                        >
                          <span className="inline-flex items-center gap-1">
                            {label} <ArrowUpDown className="size-3" />
                          </span>
                        </th>
                      ))}
                      <th className="px-4 py-2.5 text-left">Banner</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedPorts.map((f) => (
                      <tr key={f.id} className="border-b border-border/30 last:border-0 hover:bg-accent/20">
                        <td className="px-4 py-2.5 font-mono text-primary">
                          {f.port}/<span className="text-muted-foreground">{f.protocol}</span>
                        </td>
                        <td className="px-4 py-2.5 font-medium">{f.service}</td>
                        <td className="px-4 py-2.5"><SeverityBadge severity={f.severity} /></td>
                        <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">{f.banner}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}

          {tab === "services" &&
            (techFindings.length === 0 ? (
              <EmptyState icon={Bug} title="No fingerprints yet" body="Tech Fingerprint hasn't reported software stacks for this target." />
            ) : (
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {techFindings.map((f) => (
                  <div key={f.id} className="rounded-2xl border border-border/60 bg-card/60 p-4">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-sm font-semibold">{f.service} <span className="text-muted-foreground">{f.version}</span></span>
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <p className="mt-2 text-xs text-muted-foreground">{f.detail}</p>
                  </div>
                ))}
              </div>
            ))}

          {tab === "subdomains" &&
            (subFindings.length === 0 ? (
              <EmptyState icon={Globe} title="No subdomains enumerated" body="Either the target is an IP, or DNS enumeration found nothing." />
            ) : (
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {subFindings.map((f) => (
                  <div key={f.id} className="flex items-center gap-3 rounded-2xl border border-border/60 bg-card/60 px-4 py-3">
                    <Globe className="size-4 shrink-0 text-info" />
                    <span className="truncate font-mono text-sm">{f.title}</span>
                    <SeverityBadge severity={f.severity} className="ml-auto shrink-0" />
                  </div>
                ))}
              </div>
            ))}

          {tab === "cves" &&
            (cveFindings.length === 0 ? (
              <EmptyState icon={Bug} title="No CVEs matched" body="No known vulnerabilities matched the detected fingerprints — good sign." />
            ) : (
              <div className="space-y-2.5">
                {cveFindings
                  .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
                  .map((f) => (
                    <CveCard key={f.id} f={f} />
                  ))}
              </div>
            ))}

          {tab === "vectors" &&
            (vectors.length === 0 ? (
              <EmptyState icon={Terminal} title="No attack vectors mapped" body="Vector synthesis needs findings to rank — wait for agents to finish." />
            ) : (
              <div className="space-y-3">
                {vectors.map((v, i) => (
                  <div key={v.id} className="flex items-start gap-4 rounded-2xl border border-border/60 bg-card/60 p-4">
                    <span className="font-mono text-2xl font-bold text-primary/50">#{i + 1}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={v.severity} />
                        <span className="text-sm font-semibold">{v.title}</span>
                        <span className="ml-auto font-mono text-[10px] text-muted-foreground">{v.confidence}% confidence</span>
                      </div>
                      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{v.why}</p>
                    </div>
                  </div>
                ))}
              </div>
            ))}

          {tab === "findings" &&
            (allFindings.length === 0 ? (
              <EmptyState icon={Bug} title="No findings yet" body="Agents haven't reported anything for this target." />
            ) : (
              <div className="overflow-hidden rounded-2xl border border-border/60 bg-card/60">
                {allFindings.map((f) => (
                  <div key={f.id} className="border-b border-border/30 last:border-0">
                    <button
                      onClick={() => setExpandedFinding((e) => (e === f.id ? null : f.id))}
                      className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-accent/20"
                    >
                      <SeverityBadge severity={f.severity} />
                      <span className="min-w-0 flex-1 truncate text-sm font-medium">{f.title}</span>
                      <span className="hidden font-mono text-[10px] uppercase tracking-wider text-muted-foreground sm:inline">
                        {f.kind}
                      </span>
                      {f.tags.includes("investigate") && <Tag className="size-3.5 text-primary" />}
                      <ChevronDown className={cn("size-4 text-muted-foreground transition-transform", expandedFinding === f.id && "rotate-180")} />
                    </button>
                    {expandedFinding === f.id && (
                      <div className="border-t border-border/30 px-4 py-3">
                        {f.detail && <p className="font-mono text-xs text-muted-foreground">{f.detail}</p>}
                        <div className="mt-2 flex flex-wrap items-center gap-2">
                          <Button
                            variant={f.tags.includes("investigate") ? "default" : "outline"}
                            size="sm"
                            className="rounded-xl"
                            onClick={() => toggleTag(f)}
                          >
                            <Tag className="size-3" />
                            {f.tags.includes("investigate") ? "Flagged: investigate" : "Flag: investigate further"}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="rounded-xl"
                            onClick={async () => {
                              await copyText(`${f.title}\n${f.detail ?? ""}`);
                              toast.success("Copied to clipboard");
                            }}
                          >
                            <Copy className="size-3" /> Copy
                          </Button>
                        </div>
                        <textarea
                          value={f.note}
                          onChange={(e) => updateFinding(f, (nf) => ({ ...nf, note: e.target.value }))}
                          placeholder="Add a note for this finding…"
                          className="mt-2 w-full rounded-xl border border-input bg-background/70 px-3 py-2 font-mono text-xs outline-none focus:ring-1 focus:ring-primary/50"
                          rows={2}
                        />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ))}

          {tab === "output" && (
            <div className="grid gap-4 lg:grid-cols-2">
              {scan.agents.map((a) => (
                <div key={a.id} className="rounded-2xl border border-border/60 bg-card/60 p-4">
                  <div className="mb-3 flex items-center gap-2">
                    <AgentStatusDot status={a.status} />
                    <span className="text-sm font-medium">{a.name}</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="ml-auto rounded-lg"
                      onClick={async () => {
                        await copyText(a.logs.join("\n"));
                        toast.success(`${a.name} output copied`);
                      }}
                    >
                      <Copy className="size-3" /> Copy
                    </Button>
                  </div>
                  <LogConsole logs={a.logs.slice(-200)} className="h-64" />
                </div>
              ))}
            </div>
          )}

          {activeTabEmpty && tab !== "summary" && tab !== "output" && tab !== "vectors" && (
            <Loader2 className="mx-auto mt-2 size-4 animate-spin text-muted-foreground" />
          )}
        </div>
      </Tabs>
    </div>
  );
}
