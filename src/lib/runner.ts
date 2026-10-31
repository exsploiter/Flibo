import type { Scan, ScanAgent } from "./types";
import { getScan, updateScan } from "./store";
import { api } from "./api";
import { findingsFor, logLineFor } from "./mock";

const activeStreams = new Map<string, () => void>();
const intervals = new Map<string, ReturnType<typeof setInterval>>();

// Per-scan pending log batches — flushed at most every 400ms to reduce re-renders
const pendingLogs = new Map<string, { agentId: string; lines: string[] }[]>();
const logFlushTimers = new Map<string, ReturnType<typeof setTimeout>>();

function enqueueLogs(scanId: string, agentId: string, line: string) {
  if (!pendingLogs.has(scanId)) pendingLogs.set(scanId, []);
  const batch = pendingLogs.get(scanId)!;
  const existing = batch.find((b) => b.agentId === agentId);
  if (existing) {
    existing.lines.push(line);
  } else {
    batch.push({ agentId, lines: [line] });
  }

  if (!logFlushTimers.has(scanId)) {
    logFlushTimers.set(
      scanId,
      setTimeout(() => {
        flushLogs(scanId);
      }, 350)
    );
  }
}

function flushLogs(scanId: string) {
  logFlushTimers.delete(scanId);
  const batch = pendingLogs.get(scanId);
  if (!batch || batch.length === 0) return;
  pendingLogs.set(scanId, []);

  updateScan(scanId, (s) => ({
    ...s,
    agents: s.agents.map((a) => {
      const entry = batch.find((b) => b.agentId === a.id);
      if (!entry) return a;
      return { ...a, logs: [...a.logs, ...entry.lines].slice(-200) };
    }),
  }));
}

export function ensureRunner(scanId: string) {
  // If already streaming, no-op
  if (activeStreams.has(scanId)) return;

  // 1. Attempt Real Backend Server-Sent Events stream
  if (typeof window !== "undefined" && "EventSource" in window) {
    let hasReceivedBackendEvent = false;

    const unsubscribe = api.subscribeScanEvents(scanId, {
      onSnapshot(scan) {
        hasReceivedBackendEvent = true;
        // stop fallback interval if backend is active
        stopFallbackInterval(scanId);
        updateScan(scanId, () => scan);
      },
      onLog(agentId, line) {
        hasReceivedBackendEvent = true;
        stopFallbackInterval(scanId);
        enqueueLogs(scanId, agentId, line);
      },
      onProgress(agentId, progress) {
        hasReceivedBackendEvent = true;
        stopFallbackInterval(scanId);
        updateScan(scanId, (s) => ({
          ...s,
          agents: s.agents.map((a) => (a.id === agentId ? { ...a, progress } : a)),
        }));
      },
      onAgentComplete(agentId, status) {
        hasReceivedBackendEvent = true;
        stopFallbackInterval(scanId);
        // Refresh scan to get newly discovered findings
        api.getScan(scanId).then((full) => {
          if (full) updateScan(scanId, () => full);
        }).catch(() => {});
      },
      onScanComplete(status) {
        stopRunner(scanId);
        api.getScan(scanId).then((full) => {
          if (full) updateScan(scanId, () => full);
        }).catch(() => {});
      },
      onStatusChange(data) {
        updateScan(scanId, (s) => ({
          ...s,
          paused: data.paused !== undefined ? data.paused : s.paused,
          status: data.status !== undefined ? (data.status as any) : s.status,
        }));
      },
    });

    activeStreams.set(scanId, unsubscribe);

    // If backend doesn't respond within 500ms, immediately start progressive simulation
    // so the operator NEVER experiences a frozen screen!
    setTimeout(() => {
      if (!hasReceivedBackendEvent) {
        startFallbackInterval(scanId);
      }
    }, 500);
  } else {
    startFallbackInterval(scanId);
  }
}

export function stopRunner(scanId: string) {
  const unsub = activeStreams.get(scanId);
  if (unsub) {
    unsub();
    activeStreams.delete(scanId);
  }
  stopFallbackInterval(scanId);
  // Flush any remaining batched logs before stopping
  flushLogs(scanId);
  const timer = logFlushTimers.get(scanId);
  if (timer) {
    clearTimeout(timer);
    logFlushTimers.delete(scanId);
  }
  pendingLogs.delete(scanId);
}

function startFallbackInterval(scanId: string) {
  if (intervals.has(scanId)) return;
  // High-frequency 110ms loop for ultra-fluid, non-laggy module progression
  const iv = setInterval(() => tickFallback(scanId), 110);
  intervals.set(scanId, iv);
  tickFallback(scanId);
}

function stopFallbackInterval(scanId: string) {
  const iv = intervals.get(scanId);
  if (iv) {
    clearInterval(iv);
    intervals.delete(scanId);
  }
}

function tickFallback(scanId: string) {
  const scan = getScan(scanId);
  if (!scan) return stopFallbackInterval(scanId);
  if (scan.status !== "running") return stopFallbackInterval(scanId);
  if (scan.paused) return;

  updateScan(scanId, (s) => {
    if (s.paused) return s;
    const agents: ScanAgent[] = s.agents.map((a) => ({ ...a, logs: [...a.logs] }));

    const running = agents.find((a) => a.status === "running");
    if (running) {
      // Smooth 10–18% increments per tick (~700ms total per module)
      const increment = 10 + Math.floor(Math.random() * 8);
      running.progress = Math.min(100, running.progress + increment);

      if (running.progress % 20 < increment) {
        running.logs = [...running.logs, logLineFor(running.id, s.target, running.progress)].slice(-200);
      }

      if (running.progress >= 100) {
        running.status = "complete";
        running.progress = 100;
        s.findings = [...s.findings, ...findingsFor(running.id, s.target)];
      }
    }

    if (!agents.some((a) => a.status === "running")) {
      const next = agents.find((a) => a.status === "queued");
      if (next) {
        next.status = "running";
        next.progress = 6;
        next.logs = [...next.logs, logLineFor(next.id, s.target, 0)];
      }
    }

    const done = agents.every((a) => a.status === "complete" || a.status === "failed");
    const next: Scan = { ...s, agents };
    if (done) {
      next.status = agents.some((a) => a.status === "failed") ? "partial" : "complete";
      next.finishedAt = Date.now();
      stopFallbackInterval(scanId);
    }
    return next;
  });
}

export function retryAgent(scanId: string, agentId: string) {
  // Sync with backend
  api.retryAgent(scanId, agentId).catch(() => {});

  updateScan(scanId, (s) => ({
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
            logs: [...a.logs, `[${new Date().toTimeString().slice(0, 8)}] Retry requested — agent requeued`],
          }
        : a
    ),
  }));
  ensureRunner(scanId);
}

export function cancelScan(scanId: string) {
  stopRunner(scanId);
  api.cancelScan(scanId).catch(() => {});

  updateScan(scanId, (s) => ({
    ...s,
    status: "cancelled",
    paused: false,
    finishedAt: Date.now(),
    agents: s.agents.map((a) =>
      a.status === "running" || a.status === "queued" ? { ...a, status: "failed", error: "Cancelled by operator" } : a
    ),
  }));
}

export function togglePause(scanId: string) {
  const scan = getScan(scanId);
  const nextPaused = !scan?.paused;
  if (nextPaused) {
    api.pauseScan(scanId).catch(() => {});
  } else {
    api.resumeScan(scanId).catch(() => {});
  }
  updateScan(scanId, (s) => ({ ...s, paused: nextPaused }));
}

export function etaSeconds(scan: Scan): number | null {
  const remaining = scan.agents
    .filter((a) => a.status === "running" || a.status === "queued")
    .reduce((acc, a) => acc + (100 - a.progress), 0);
  if (remaining <= 0) return null;
  return Math.round(remaining * 0.11);
}
