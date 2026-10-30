import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import {
  AlertTriangle,
  ClipboardPaste,
  Crosshair,
  EyeOff,
  FileUp,
  Play,
  RotateCcw,
  Tag,
} from "lucide-react";
import { parseTargets, TYPE_LABELS, type DetectedType } from "@/lib/detect";
import { AGENTS } from "@/lib/mock";
import { addScan, addTargetHistory, getTargetHistory } from "@/lib/store";
import { ensureRunner } from "@/lib/runner";
import type { Scan } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useMounted } from "@/lib/hooks";

export const Route = createFileRoute("/new-scan")({
  component: NewScan,
  head: () => ({
    meta: [
      { title: "New Scan — Flibo" },
      { name: "description", content: "Paste targets, pick agents, launch recon." },
      { property: "og:title", content: "New Scan — Flibo" },

      { property: "og:description", content: "Paste targets, pick agents, launch recon." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

const TYPE_CHIP: Record<DetectedType, string> = {
  url: "border-info/30 bg-info/10 text-info",
  ip: "border-primary/30 bg-primary/10 text-primary",
  cidr: "border-primary/30 bg-primary/10 text-primary",
  domain: "border-low/30 bg-low/10 text-low",
  subdomain: "border-low/30 bg-low/10 text-low",
  email: "border-info/30 bg-info/10 text-info",
  hash: "border-medium/30 bg-medium/10 text-medium",
  invalid: "border-critical/40 bg-critical/10 text-critical",
  empty: "border-border bg-muted/40 text-muted-foreground",
};

const INTENSITY = [
  { id: "quick", label: "Quick", hint: "top 100 ports · fastest" },
  { id: "standard", label: "Standard", hint: "top 1000 ports · balanced" },
  { id: "deep", label: "Deep", hint: "all 65k ports · slow, loud" },
] as const;

const PROFILES = [
  { id: "quick-sweep", label: "Quick Sweep", agents: ["port-scan", "os-detection"], intensity: "quick" as const, ports: "top-100", stealth: false },
  { id: "full-audit", label: "Full V2 Spectrum", agents: AGENTS.map((a) => a.id), intensity: "standard" as const, ports: "top-1000", stealth: false },
  { id: "cloud-takeover", label: "Cloud & Takeover", agents: ["subdomain-enum", "takeover-audit", "cloud-recon", "osint-recon"], intensity: "quick" as const, ports: "top-100", stealth: true },
  { id: "web-threat", label: "Web Threat Model", agents: ["port-scan", "waf-cdn", "ssl-deep", "webcontent", "api-discovery", "cms-fingerprint", "auth-surface", "cve-matcher"], intensity: "standard" as const, ports: "top-1000", stealth: false },
];

function NewScan() {
  const mounted = useMounted();
  const navigate = useNavigate();
  const fileRef = useRef<HTMLInputElement>(null);

  const [text, setText] = useState("");
  const [override, setOverride] = useState<"" | Exclude<DetectedType, "empty" | "invalid">>("");
  const [name, setName] = useState("");
  const [tags, setTags] = useState("");
  const [intensity, setIntensity] = useState<"quick" | "standard" | "deep">("standard");
  const [ports, setPorts] = useState("top-1000");
  const [customPorts, setCustomPorts] = useState("");
  const [stealth, setStealth] = useState(false);
  const [selectedAgents, setSelectedAgents] = useState<string[]>(AGENTS.map((a) => a.id));

  const parsed = useMemo(() => parseTargets(text), [text]);
  const invalid = parsed.filter((t) => !t.valid && !override);
  const validTargets = parsed
    .filter((t) => t.valid || override)
    .map((t) => ({ raw: t.raw, type: override || t.type }));
  const history = mounted ? getTargetHistory() : [];

  const canLaunch = validTargets.length > 0 && invalid.length === 0 && selectedAgents.length > 0;

  async function pasteFromClipboard() {
    try {
      const clip = await navigator.clipboard.readText();
      if (clip) setText((t) => (t ? t + "\n" + clip : clip));
      toast.success("Pasted from clipboard");
    } catch {
      toast.error("Clipboard unavailable — paste manually with Ctrl/Cmd+V");
    }
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    const content = await f.text();
    setText((t) => (t ? t + "\n" + content : content));
    toast.success(`Loaded ${f.name}`);
    e.target.value = "";
  }

  function applyProfile(id: string) {
    const p = PROFILES.find((x) => x.id === id);
    if (!p) return;
    setSelectedAgents(p.agents);
    setIntensity(p.intensity);
    setPorts(p.ports);
    setStealth(p.stealth);
    toast.success(`Profile applied — ${p.label}`);
  }

  function launch() {
    if (!canLaunch) return;
    const targets = validTargets.map((t) => t.raw);
    const id = `scan-${Date.now()}`;
    const scan: Scan = {
      id,
      name: name.trim() || `Recon — ${targets[0]}`,
      target: targets[0] ?? "",
      targets,
      tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
      config: {
        intensity,
        agents: selectedAgents,
        ports: ports === "custom" ? customPorts || "custom" : ports,
        stealth,
        scheduled: null,
      },
      status: "running",
      createdAt: Date.now(),
      agents: AGENTS.filter((a) => selectedAgents.includes(a.id)).map((a, i) => ({
        id: a.id,
        name: a.name,
        status: i === 0 ? "running" : "queued",
        progress: 0,
        logs: [],
      })),
      findings: [],
    };
    addScan(scan);
    addTargetHistory(targets);
    ensureRunner(id);
    toast.success("Scan launched", { description: scan.name });
    void navigate({ to: "/scan/$id", params: { id } });
  }

  const portOptions = [
    { id: "top-100", label: "Top 100" },
    { id: "top-1000", label: "Top 1000" },
    { id: "1-65535", label: "All 1–65535" },
    { id: "custom", label: "Custom" },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Launch new scan</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Paste targets, tune the agent lineup, and fire.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        {/* Targets column */}
        <div className="space-y-4 lg:col-span-3">
          <section className="rounded-3xl border border-border/50 bg-card p-6 shadow-panel">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-sm font-semibold text-foreground">
                Target Scope
              </h2>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={pasteFromClipboard}>
                  <ClipboardPaste className="size-3.5" /> Paste
                </Button>
                <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
                  <FileUp className="size-3.5" /> Bulk upload
                </Button>
                <input
                  ref={fileRef}
                  type="file"
                  accept=".txt,.csv,.md"
                  className="hidden"
                  onChange={onFile}
                />
              </div>
            </div>

            <Textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={"example.dev\n203.0.113.42\n10.0.4.0/24\nhttps://app.example.dev\nuser@example.dev\n5d41402abc4b2a76b9719d911017c592"}
              className="mt-3 min-h-40 rounded-2xl border-border/60 bg-background/70 font-mono text-[13px] focus-visible:ring-primary/50"
            />

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                Auto-detect
              </span>
              <select
                value={override}
                onChange={(e) => setOverride(e.target.value as typeof override)}
                className="rounded-lg border border-input bg-background px-2 py-1 font-mono text-xs text-foreground"
              >
                <option value="">on</option>
                {(["url", "ip", "cidr", "domain", "subdomain", "email", "hash"] as const).map((t) => (
                  <option key={t} value={t}>
                    force {TYPE_LABELS[t].toLowerCase()}
                  </option>
                ))}
              </select>
              <span className="font-mono text-[11px] text-muted-foreground">
                {parsed.length} token{parsed.length === 1 ? "" : "s"} · {validTargets.length} valid
              </span>
            </div>

            {parsed.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {parsed.map((t, i) => (
                  <span
                    key={i}
                    className={`inline-flex items-center gap-1.5 rounded-lg border px-2 py-0.5 font-mono text-[11px] ${
                      override && t.valid ? "border-info/30 bg-info/10 text-info" : TYPE_CHIP[t.type]
                    }`}
                  >
                    {!t.valid && !override && <AlertTriangle className="size-3" />}
                    <span className="max-w-52 truncate">{t.raw}</span>
                    <span className="opacity-70">{override || t.label}</span>
                  </span>
                ))}
              </div>
            )}

            {invalid.length > 0 && (
              <div className="mt-3 rounded-xl border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">
                <AlertTriangle className="mr-1.5 inline size-3.5" />
                {invalid.length} malformed token{invalid.length === 1 ? "" : "s"} — fix or remove before launch
                ({invalid.map((t) => t.raw).slice(0, 4).join(", ")}
                {invalid.length > 4 ? "…" : ""}).
              </div>
            )}

            {history.length > 0 && (
              <div className="mt-4 border-t border-border/40 pt-3">
                <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground/70">
                  Recent targets
                </span>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {history.slice(0, 8).map((h) => (
                    <button
                      key={h}
                      onClick={() => setText((t) => (t ? t + "\n" + h : h))}
                      className="rounded-lg border border-border/60 bg-background/60 px-2 py-1 font-mono text-[11px] text-muted-foreground transition-colors hover:border-primary/40 hover:text-primary"
                    >
                      {h}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </section>

          <section className="rounded-3xl border border-border/60 bg-card p-5">
            <h2 className="text-sm font-semibold text-foreground">
              Agent Pipeline Selection
            </h2>
            <div className="mt-3 space-y-2">
              {AGENTS.map((a) => {
                const on = selectedAgents.includes(a.id);
                return (
                  <label
                    key={a.id}
                    className="flex cursor-pointer items-center gap-3 rounded-2xl border border-border/50 bg-muted/40 px-4 py-3 transition-colors hover:border-primary/30"
                  >
                    <Switch checked={on} onCheckedChange={(v) =>
                      setSelectedAgents((prev) => (v ? [...prev, a.id] : prev.filter((x) => x !== a.id)))
                    } />
                    <div>
                      <div className="text-sm font-medium">{a.name}</div>
                      <div className="text-xs text-muted-foreground">{a.desc}</div>
                    </div>
                    <span
                      className={`ml-auto font-mono text-[10px] uppercase tracking-wider ${
                        on ? "text-primary font-semibold" : "text-muted-foreground/50"
                      }`}
                    >
                      {on ? "armed" : "off"}
                    </span>
                  </label>
                );
              })}
            </div>
          </section>
        </div>

        {/* Config column */}
        <div className="space-y-4 lg:col-span-2">
          <section className="rounded-3xl border border-border/50 bg-card p-5 shadow-panel">
            <h2 className="text-sm font-semibold text-foreground">
              Pre-configured Profiles
            </h2>
            <div className="mt-3 flex flex-wrap gap-2">
              {PROFILES.map((p) => (
                <button
                  key={p.id}
                  onClick={() => applyProfile(p.id)}
                  className="rounded-xl border border-border/60 bg-muted/30 px-3 py-1.5 text-xs font-semibold text-foreground transition-all hover:border-primary/40 hover:bg-secondary hover:text-primary"
                >
                  {p.label}
                </button>
              ))}
            </div>
          </section>

          <section className="rounded-3xl border border-border/50 bg-card p-5 shadow-panel">
            <h2 className="text-sm font-semibold text-foreground">
              Scan Intensity
            </h2>
            <div className="mt-3 grid grid-cols-3 gap-2">
              {INTENSITY.map((i) => (
                <button
                  key={i.id}
                  onClick={() => {
                    setIntensity(i.id);
                    setPorts(i.id === "quick" ? "top-100" : i.id === "standard" ? "top-1000" : "1-65535");
                  }}
                  className={`rounded-2xl border p-3 text-left transition-colors ${
                    intensity === i.id
                      ? "border-primary/50 bg-primary/10"
                      : "border-border/50 bg-muted/40 hover:border-border"
                  }`}
                >
                  <div className={`text-sm font-semibold ${intensity === i.id ? "text-primary" : ""}`}>
                    {i.label}
                  </div>
                  <div className="mt-0.5 text-[10px] leading-tight text-muted-foreground">{i.hint}</div>
                </button>
              ))}
            </div>

            <div className="mt-5">
              <Label className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                Port range
              </Label>
              <div className="mt-2 flex flex-wrap gap-2">
                {portOptions.map((p) => (
                  <button
                    key={p.id}
                    onClick={() => setPorts(p.id)}
                    className={`rounded-lg border px-2.5 py-1 font-mono text-xs transition-colors ${
                      ports === p.id
                        ? "border-primary/50 bg-primary/10 text-primary"
                        : "border-border/50 text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
              {ports === "custom" && (
                <Input
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  placeholder="e.g. 22,80,443,8000-9000"
                  className="mt-2 rounded-xl border-border/60 bg-background/70 font-mono text-xs"
                />
              )}
            </div>

            <div className="mt-5 flex items-center justify-between rounded-2xl border border-border/50 bg-muted/40 px-4 py-3">
              <div className="flex items-center gap-2">
                <EyeOff className="size-4 text-medium" />
                <div>
                  <div className="text-sm font-medium">Stealth mode</div>
                  <div className="text-xs text-muted-foreground">Throttle requests, randomize timing</div>
                </div>
              </div>
              <Switch checked={stealth} onCheckedChange={setStealth} />
            </div>

            <div className="mt-5 flex items-center justify-between rounded-2xl border border-dashed border-border/50 px-4 py-3 opacity-70">
              <div>
                <div className="text-sm font-medium">Schedule for later</div>
                <div className="text-xs text-muted-foreground">Coming soon — runs immediately for now</div>
              </div>
              <Input type="datetime-local" disabled className="w-44 rounded-xl border-border/60 bg-background/70 text-xs" />
            </div>
          </section>

          <section className="rounded-3xl border border-border/60 bg-card p-5">
            <div className="space-y-3">
              <div>
                <Label className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                  Scan name
                </Label>
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={validTargets[0] ? `Recon — ${validTargets[0].raw}` : "Recon — unnamed"}
                  className="mt-1.5 rounded-xl border-border/60 bg-background/70"
                />
              </div>
              <div>
                <Label className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                  Tags (comma-separated)
                </Label>
                <div className="relative mt-1.5">
                  <Tag className="absolute left-3 top-2.5 size-3.5 text-muted-foreground" />
                  <Input
                    value={tags}
                    onChange={(e) => setTags(e.target.value)}
                    placeholder="perimeter, web, opsec"
                    className="rounded-xl border-border/60 bg-background/70 pl-8"
                  />
                </div>
              </div>
            </div>

            <Button variant="hero" size="lg" className="mt-5 w-full rounded-2xl" disabled={!canLaunch} onClick={launch}>
              <Play className="size-4" /> Launch scan
            </Button>
            {!canLaunch && (
              <p className="mt-2 text-center font-mono text-[11px] text-muted-foreground">
                {invalid.length > 0
                  ? "resolve invalid tokens to continue"
                  : validTargets.length === 0
                    ? "add at least one valid target"
                    : "arm at least one agent"}
              </p>
            )}
          </section>

          <p className="flex items-center gap-1.5 px-1 font-mono text-[11px] text-muted-foreground/70">
            <RotateCcw className="size-3" /> configs you launch are reusable via History → re-run
          </p>
        </div>
      </div>
    </div>
  );
}
