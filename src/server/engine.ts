import { EventEmitter } from "node:events";
import { getScanById, updateScanById, getSettings } from "./db";
import type { Finding, Scan, ScanAgent } from "./types";
import { runPortScan } from "./scanner/ports";
import { runDnsScan } from "./scanner/dns";
import { runHttpScan } from "./scanner/http";
import { runCveScan } from "./scanner/cve";
import { runOsScan } from "./scanner/os";

interface ActiveScanTask {
  scanId: string;
  cancelled: boolean;
  paused: boolean;
  activeAgentId: string | null;
}

class ScanEngineManager extends EventEmitter {
  private activeTasks = new Map<string, ActiveScanTask>();

  public getTask(scanId: string): ActiveScanTask | undefined {
    return this.activeTasks.get(scanId);
  }

  public isRunning(scanId: string): boolean {
    const task = this.activeTasks.get(scanId);
    return !!task && !task.cancelled;
  }

  public pauseScan(scanId: string): void {
    const task = this.activeTasks.get(scanId);
    if (task) {
      task.paused = true;
    }
    updateScanById(scanId, (s) => ({ ...s, paused: true }));
    this.emitEvent(scanId, "status", { paused: true, status: "running" });
  }

  public resumeScan(scanId: string): void {
    const task = this.activeTasks.get(scanId);
    if (task) {
      task.paused = false;
    }
    updateScanById(scanId, (s) => ({ ...s, paused: false }));
    this.emitEvent(scanId, "status", { paused: false, status: "running" });
  }

  public cancelScan(scanId: string): void {
    const task = this.activeTasks.get(scanId);
    if (task) {
      task.cancelled = true;
    }
    updateScanById(scanId, (s) => ({
      ...s,
      status: "cancelled",
      paused: false,
      finishedAt: Date.now(),
      agents: s.agents.map((a) =>
        a.status === "running" || a.status === "queued"
          ? { ...a, status: "failed", error: "Cancelled by operator" }
          : a
      ),
    }));
    this.emitEvent(scanId, "status", { status: "cancelled" });
  }

  public retryAgent(scanId: string, agentId: string): void {
    const scan = getScanById(scanId);
    if (!scan) return;

    updateScanById(scanId, (s) => ({
      ...s,
      status: "running",
      paused: false,
      agents: s.agents.map((a) =>
        a.id === agentId
          ? {
              ...a,
              status: "queued",
              progress: 0,
              error: undefined,
              logs: [...a.logs, `[${new Date().toTimeString().slice(0, 8)}] Operator requested retry — agent queued`],
            }
          : a
      ),
    }));

    void this.startOrResumeScan(scanId);
  }

  public emitEvent(scanId: string, eventType: string, data: unknown): void {
    this.emit(`scan:${scanId}`, { type: eventType, data });
  }

  public async startOrResumeScan(scanId: string): Promise<void> {
    if (this.activeTasks.has(scanId)) {
      const existing = this.activeTasks.get(scanId);
      if (existing && !existing.cancelled) {
        return; // already active
      }
    }

    const task: ActiveScanTask = {
      scanId,
      cancelled: false,
      paused: false,
      activeAgentId: null,
    };
    this.activeTasks.set(scanId, task);

    try {
      await this.runScanLoop(task);
    } catch (err) {
      console.error(`[ScanEngine] Unhandled scan failure for ${scanId}:`, err);
    } finally {
      this.activeTasks.delete(scanId);
    }
  }

  private async runScanLoop(task: ActiveScanTask): Promise<void> {
    let scan = getScanById(task.scanId);
    if (!scan) return;

    // Run agents in order
    for (let i = 0; i < scan.agents.length; i++) {
      if (task.cancelled) break;

      // Handle pause loop
      while (task.paused) {
        if (task.cancelled) break;
        await new Promise((r) => setTimeout(r, 500));
      }

      // Re-fetch scan state
      scan = getScanById(task.scanId);
      if (!scan) break;

      const agent = scan.agents[i];
      if (!agent) continue;

      if (agent.status === "complete") {
        continue;
      }

      task.activeAgentId = agent.id;

      // Mark agent running
      updateScanById(task.scanId, (s) => ({
        ...s,
        status: "running",
        agents: s.agents.map((a) => (a.id === agent.id ? { ...a, status: "running", progress: 0 } : a)),
      }));
      this.emitEvent(task.scanId, "agent_start", { agentId: agent.id });

      const logHandler = (line: string) => {
        const ts = new Date().toTimeString().slice(0, 8);
        const formatted = line.startsWith("[") ? line : `[${ts}] ${line}`;
        updateScanById(task.scanId, (s) => ({
          ...s,
          agents: s.agents.map((a) => (a.id === agent.id ? { ...a, logs: [...a.logs, formatted].slice(-500) } : a)),
        }));
        this.emitEvent(task.scanId, "log", { agentId: agent.id, line: formatted });
      };

      const progressHandler = (pct: number) => {
        updateScanById(task.scanId, (s) => ({
          ...s,
          agents: s.agents.map((a) => (a.id === agent.id ? { ...a, progress: pct } : a)),
        }));
        this.emitEvent(task.scanId, "progress", { agentId: agent.id, progress: pct });
      };

      const shouldStop = () => task.cancelled;

      const settings = getSettings();
      let newFindings: Finding[] = [];
      let agentFailed = false;
      let failureError: string | undefined = undefined;

      try {
        logHandler(`[${agent.name}] Initializing probe against target: ${scan.target}`);

        if (agent.id === "port-scan") {
          newFindings = await runPortScan({
            target: scan.target,
            portsConfig: scan.config.ports,
            intensity: scan.config.intensity,
            stealth: scan.config.stealth,
            onProgress: progressHandler,
            onLog: logHandler,
            shouldStop,
          });
        } else if (agent.id === "subdomain-enum") {
          newFindings = await runDnsScan({
            target: scan.target,
            intensity: scan.config.intensity,
            onProgress: progressHandler,
            onLog: logHandler,
            shouldStop,
          });
        } else if (agent.id === "tech-fingerprint") {
          newFindings = await runHttpScan({
            target: scan.target,
            intensity: scan.config.intensity,
            onProgress: progressHandler,
            onLog: logHandler,
            shouldStop,
          });
        } else if (agent.id === "cve-matcher") {
          const currentScan = getScanById(task.scanId);
          newFindings = await runCveScan({
            target: scan.target,
            previousFindings: currentScan?.findings || [],
            cveApiKey: settings.cveApiKey,
            onProgress: progressHandler,
            onLog: logHandler,
            shouldStop,
          });
        } else if (agent.id === "os-detection") {
          const currentScan = getScanById(task.scanId);
          newFindings = await runOsScan({
            target: scan.target,
            previousFindings: currentScan?.findings || [],
            onProgress: progressHandler,
            onLog: logHandler,
            shouldStop,
          });
        } else {
          // Unknown custom agent fallback
          logHandler(`[${agent.name}] Completed standard agent execution`);
          progressHandler(100);
        }
      } catch (err) {
        agentFailed = true;
        failureError = err instanceof Error ? err.message : String(err);
        logHandler(`[${agent.name}] ERROR: Agent encountered error: ${failureError}`);
      }

      if (task.cancelled) {
        break;
      }

      // Update scan with new findings and complete agent
      updateScanById(task.scanId, (s) => ({
        ...s,
        findings: [...s.findings, ...newFindings],
        agents: s.agents.map((a) =>
          a.id === agent.id
            ? {
                ...a,
                status: agentFailed ? "failed" : "complete",
                progress: agentFailed ? a.progress : 100,
                error: failureError,
              }
            : a
        ),
      }));

      this.emitEvent(task.scanId, "agent_complete", {
        agentId: agent.id,
        status: agentFailed ? "failed" : "complete",
        findingsCount: newFindings.length,
      });

      // Brief pacing between agents
      await new Promise((r) => setTimeout(r, 300));
    }

    // Wrap up overall scan
    if (!task.cancelled) {
      const finalScan = getScanById(task.scanId);
      if (finalScan) {
        const hasFailed = finalScan.agents.some((a) => a.status === "failed");
        const finalStatus = hasFailed ? "partial" : "complete";

        updateScanById(task.scanId, (s) => ({
          ...s,
          status: finalStatus,
          finishedAt: Date.now(),
        }));

        this.emitEvent(task.scanId, "scan_complete", { status: finalStatus });
      }
    }
  }
}

export const scanEngine = new ScanEngineManager();
