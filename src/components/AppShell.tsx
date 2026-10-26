import { Link, useRouterState } from "@tanstack/react-router";
import { Crosshair, History, Radar, Settings2, TerminalSquare, Zap } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Dashboard", icon: Radar },
  { to: "/new-scan", label: "New Scan", icon: Crosshair },
  { to: "/history", label: "History", icon: History },
  { to: "/settings", label: "Settings", icon: Settings2 },
];

function NavItem({ to, label, icon: Icon, active }: { to: string; label: string; icon: typeof Radar; active: boolean }) {
  return (
    <Link
      to={to}
      className={cn(
        "group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors",
        active
          ? "bg-primary/12 text-primary"
          : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
      )}
    >
      <Icon className="size-4 shrink-0" strokeWidth={active ? 2.4 : 2} />
      {label}
      {active && <span className="ml-auto size-1.5 rounded-full bg-primary" />}
    </Link>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <div className="ambient-grid min-h-screen">
      {/* Sidebar */}
      <aside className="no-print fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-border/60 bg-card/50 backdrop-blur-xl md:flex">
        <div className="flex items-center gap-3 px-5 py-6">
          <div className="glow-primary flex size-10 items-center justify-center rounded-2xl bg-primary text-primary-foreground">
            <TerminalSquare className="size-5" strokeWidth={2.4} />
          </div>
          <div>
            <div className="font-mono text-lg font-bold tracking-tight leading-none">FLIBO</div>
            <div className="mt-1 font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
              recon · security ops
            </div>
          </div>

        </div>

        <nav className="flex flex-1 flex-col gap-1 px-3">
          <div className="px-3 pb-2 text-[11px] font-medium text-muted-foreground/75">
            Operations
          </div>
          {NAV.map((n) => (
            <NavItem
              key={n.to}
              to={n.to}
              label={n.label}
              icon={n.icon}
              active={n.to === "/" ? pathname === "/" : pathname.startsWith(n.to)}
            />
          ))}
        </nav>

        <div className="px-4 pb-5">
          <div className="rounded-2xl border border-border/60 bg-background/60 p-3">
            <div className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
              <span className="relative flex size-2">
                <span className="absolute inline-flex size-full animate-ping rounded-full bg-low opacity-60" />
                <span className="relative inline-flex size-2 rounded-full bg-low" />
              </span>
              engine: local · v0.9.1
            </div>
            <div className="mt-1.5 flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
              <Zap className="size-3 text-medium" />
              agents online · 5/5
            </div>
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className="flex min-h-screen flex-col md:pl-60">
        <header className="no-print sticky top-0 z-20 border-b border-border/60 bg-background/80 backdrop-blur-xl">
          <div className="mx-auto flex w-full max-w-[1440px] items-center gap-3 px-4 py-3 md:px-6">
            {/* Mobile brand */}
            <Link to="/" className="flex items-center gap-2 md:hidden">
              <div className="flex size-8 items-center justify-center rounded-xl bg-primary text-primary-foreground">
                <TerminalSquare className="size-4" />
              </div>
              <span className="font-mono text-sm font-bold">FLIBO</span>
            </Link>

            {/* Mobile nav pills */}
            <div className="flex items-center gap-1 overflow-x-auto md:hidden">
              {NAV.map((n) => (
                <Link
                  key={n.to}
                  to={n.to}
                  className={cn(
                    "rounded-lg px-2.5 py-1.5 font-mono text-xs",
                    (n.to === "/" ? pathname === "/" : pathname.startsWith(n.to))
                      ? "bg-primary/12 text-primary"
                      : "text-muted-foreground",
                  )}
                >
                  {n.label}
                </Link>
              ))}
            </div>

            <div className="ml-auto flex items-center gap-3">
              <div className="hidden items-center gap-2 rounded-full border border-border/60 bg-card/70 px-3 py-1.5 font-mono text-[11px] text-muted-foreground sm:flex">
                <span className="size-1.5 rounded-full bg-low" />
                opsec · passive mode
              </div>
              <Link
                to="/new-scan"
                className="glow-primary inline-flex items-center gap-2 rounded-xl bg-primary px-3.5 py-2 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
              >
                <Crosshair className="size-4" />
                New scan
              </Link>
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-6 md:px-6 md:py-8">{children}</main>

        <footer className="no-print border-t border-border/40 px-6 py-4 font-mono text-[11px] text-muted-foreground/70">
          Flibo — private recon automation console · personal use
        </footer>

      </div>
    </div>
  );
}
