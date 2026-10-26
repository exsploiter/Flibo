import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { KeyRound, Bell, SlidersHorizontal, Database, Save } from "lucide-react";
import { DEFAULT_SETTINGS, loadSettings, saveSettings, type AppSettings } from "@/lib/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";

export const Route = createFileRoute("/settings")({
  component: SettingsPage,
  head: () => ({
    meta: [
      { title: "Settings — Flibo" },
      { name: "description", content: "API keys, notification preferences and defaults." },
      { property: "og:title", content: "Settings — Flibo" },

      { property: "og:description", content: "API keys, notification preferences and defaults." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
});

function Card({
  icon: Icon,
  title,
  children,
}: {
  icon: typeof Bell;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-3xl border border-border/60 bg-card/60 p-6">
      <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
        <Icon className="size-4 text-primary" /> {title}
      </h2>
      <div className="mt-4 space-y-4">{children}</div>
    </section>
  );
}

function SettingsPage() {
  const [s, setS] = useState<AppSettings>(DEFAULT_SETTINGS);

  useEffect(() => setS(loadSettings()), []);

  function set<K extends keyof AppSettings>(k: K, v: AppSettings[K]) {
    setS((prev) => ({ ...prev, [k]: v }));
  }

  function save() {
    saveSettings(s);
    toast.success("Settings saved");
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Integrations and defaults — stored locally in this browser.
        </p>
      </div>

      <Card icon={KeyRound} title="API keys & integrations">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <Label className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              CVE database key (NVD)
            </Label>
            <Input
              type="password"
              value={s.cveApiKey}
              onChange={(e) => set("cveApiKey", e.target.value)}
              placeholder="nvdsig-…"
              className="mt-1.5 rounded-xl border-border/60 bg-background/70 font-mono text-xs"
            />
          </div>
          <div>
            <Label className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              nmap backend endpoint
            </Label>
            <Input
              value={s.nmapBackendUrl}
              onChange={(e) => set("nmapBackendUrl", e.target.value)}
              placeholder="https://scanner.internal/api"
              className="mt-1.5 rounded-xl border-border/60 bg-background/70 font-mono text-xs"
            />
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          Keys are kept in local browser storage only — nothing leaves this machine.
        </p>
      </Card>

      <Card icon={Bell} title="Notifications">
        <div className="flex items-center justify-between rounded-2xl border border-border/50 bg-background/40 px-4 py-3">
          <div>
            <div className="text-sm font-medium">In-app toast on completion</div>
            <div className="text-xs text-muted-foreground">Notify when a scan finishes or partially fails</div>
          </div>
          <Switch checked={s.notifyInApp} onCheckedChange={(v) => set("notifyInApp", v)} />
        </div>
        <div className="flex items-center justify-between rounded-2xl border border-border/50 bg-background/40 px-4 py-3">
          <div>
            <div className="text-sm font-medium">Email on completion</div>
            <div className="text-xs text-muted-foreground">Requires a configured mail relay</div>
          </div>
          <Switch checked={s.notifyEmail} onCheckedChange={(v) => set("notifyEmail", v)} />
        </div>
        {s.notifyEmail && (
          <div>
            <Label className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              Send to
            </Label>
            <Input
              value={s.notifyEmailTo}
              onChange={(e) => set("notifyEmailTo", e.target.value)}
              placeholder="operator@flibo.local"
              className="mt-1.5 rounded-xl border-border/60 bg-background/70 font-mono text-xs"
            />
          </div>
        )}
      </Card>

      <Card icon={SlidersHorizontal} title="Scan defaults">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <Label className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              Default profile
            </Label>
            <select
              value={s.defaultProfile}
              onChange={(e) => set("defaultProfile", e.target.value)}
              className="mt-1.5 w-full rounded-xl border border-input bg-background px-3 py-2 text-sm"
            >
              <option value="quick">Quick Sweep</option>
              <option value="standard">Full Audit</option>
              <option value="deep">Deep Recon</option>
            </select>
          </div>
        </div>
      </Card>

      <Card icon={Database} title="Data retention">
        <div>
          <Label className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
            Auto-delete scans older than
          </Label>
          <select
            value={s.retentionDays}
            onChange={(e) => set("retentionDays", e.target.value)}
            className="mt-1.5 w-full rounded-xl border border-input bg-background px-3 py-2 text-sm sm:w-64"
          >
            <option value="7">7 days</option>
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">1 year</option>
            <option value="never">Never</option>
          </select>
        </div>
        <p className="text-xs text-muted-foreground">
          Retention enforcement is a stub for now — nothing is auto-deleted yet.
        </p>
      </Card>

      <Button variant="hero" size="lg" className="rounded-2xl" onClick={save}>
        <Save className="size-4" /> Save settings
      </Button>
    </div>
  );
}
