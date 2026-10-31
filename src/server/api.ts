import type { IncomingMessage, ServerResponse } from "node:http";
import {
  createScan,
  deleteScanById,
  enforceRetention,
  getScanById,
  getSettings,
  getTargetHistory,
  listScans,
  updateScanById,
  updateSettings,
} from "./db";
import { scanEngine } from "./engine";
import { computeRiskScore, countFindingsBySeverity, synthesizeAttackVectors } from "./scanner/synthesis";
import type { AppSettings, Scan, ScanAgent } from "./types";
import { parseTargets } from "../lib/detect";
import { scanToCsv, scanToJson, scanToMarkdown } from "../lib/export";
import { AGENTS } from "../lib/mock";

const startTime = Date.now();

function jsonResponse(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      ...headers,
    },
  });
}

function textResponse(text: string, contentType = "text/plain", status = 200, headers: Record<string, string> = {}): Response {
  return new Response(text, {
    status,
    headers: {
      "Content-Type": contentType,
      "Access-Control-Allow-Origin": "*",
      ...headers,
    },
  });
}

export async function handleApiRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  // 1. Health check
  if (pathname === "/api/health" && method === "GET") {
    const memory = process.memoryUsage();
    const scans = listScans();
    const active = scans.filter((s) => s.status === "running").length;
    return jsonResponse({
      status: "ok",
      uptime: Math.round((Date.now() - startTime) / 1000),
      activeScans: active,
      totalScans: scans.length,
      memoryUsageMb: Math.round(memory.heapUsed / 1024 / 1024),
      nodeVersion: process.version,
      dbType: "json-store",
    });
  }

  // 2. Settings
  if (pathname === "/api/settings") {
    if (method === "GET") {
      return jsonResponse(getSettings());
    }
    if (method === "PUT" || method === "PATCH") {
      try {
        const body = (await request.json()) as Partial<AppSettings>;
        const updated = updateSettings(body);
        return jsonResponse(updated);
      } catch (err) {
        return jsonResponse({ error: "Invalid JSON payload" }, 400);
      }
    }
  }

  // 3. Targets Parse & History
  if (pathname === "/api/targets/parse" && method === "POST") {
    try {
      const body = (await request.json()) as { text?: string };
      const parsed = parseTargets(body.text || "");
      return jsonResponse({ targets: parsed });
    } catch {
      return jsonResponse({ error: "Invalid target parse payload" }, 400);
    }
  }

  if (pathname === "/api/targets/history" && method === "GET") {
    return jsonResponse(getTargetHistory());
  }

  // 4. Data retention cleanup
  if (pathname === "/api/retention/cleanup" && method === "POST") {
    const pruned = enforceRetention();
    return jsonResponse({ prunedCount: pruned });
  }

  // 5. Scans Collection: GET /api/scans & POST /api/scans
  if (pathname === "/api/scans") {
    if (method === "GET") {
      const search = url.searchParams.get("search") || undefined;
      const status = url.searchParams.get("status") || undefined;
      const limitStr = url.searchParams.get("limit");
      const offsetStr = url.searchParams.get("offset");

      const limit = limitStr ? parseInt(limitStr, 10) : undefined;
      const offset = offsetStr ? parseInt(offsetStr, 10) : undefined;

      const scans = listScans({ search, status, limit, offset });
      return jsonResponse(scans);
    }

    if (method === "POST") {
      try {
        const body = (await request.json()) as Partial<Scan>;
        const targets = body.targets && body.targets.length > 0 ? body.targets : [body.target || "localhost"];
        const primaryTarget = targets[0] ?? "localhost";

        const id = body.id || `scan-${Date.now()}`;
        const selectedAgentIds = body.config?.agents || AGENTS.map((a) => a.id);

        const scanAgents: ScanAgent[] = AGENTS.filter((a) => selectedAgentIds.includes(a.id)).map((a, i) => ({
          id: a.id,
          name: a.name,
          status: i === 0 ? "running" : "queued",
          progress: 0,
          logs: [`[${new Date().toTimeString().slice(0, 8)}] Agent ${a.name} registered`],
        }));

        const newScan: Scan = {
          id,
          name: body.name?.trim() || `Recon — ${primaryTarget}`,
          target: primaryTarget,
          targets,
          tags: body.tags || [],
          config: {
            intensity: body.config?.intensity || "standard",
            agents: selectedAgentIds,
            ports: body.config?.ports || "top-1000",
            stealth: body.config?.stealth ?? false,
            scheduled: null,
          },
          status: "running",
          paused: false,
          createdAt: Date.now(),
          agents: scanAgents,
          findings: [],
          pinned: body.pinned || false,
        };

        const created = createScan(newScan);
        // Start background scan execution asynchronously
        void scanEngine.startOrResumeScan(created.id);

        return jsonResponse(created, 201);
      } catch (err) {
        return jsonResponse({ error: "Failed to create scan", detail: String(err) }, 400);
      }
    }
  }

  // 6. Scan Specific Actions: /api/scans/:id/*
  const scanMatch = pathname.match(/^\/api\/scans\/([^/]+)(.*)$/);
  if (scanMatch) {
    const scanId = scanMatch[1] ?? "";
    const subPath = scanMatch[2] ?? "";
    const scan = getScanById(scanId);

    if (!scan) {
      return jsonResponse({ error: "Scan not found" }, 404);
    }

    // SSE Real-time events stream
    if (subPath === "/events" && method === "GET") {
      const stream = new ReadableStream({
        start(controller) {
          const encoder = new TextEncoder();

          const send = (eventType: string, data: unknown) => {
            controller.enqueue(encoder.encode(`event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`));
          };

          // Initial snapshot
          send("snapshot", getScanById(scanId));

          const onEngineEvent = (evt: { type: string; data: unknown }) => {
            send(evt.type, evt.data);
          };

          const eventName = `scan:${scanId}`;
          scanEngine.on(eventName, onEngineEvent);

          // Ping every 15s to keep connection alive
          const pingIv = setInterval(() => {
            try {
              controller.enqueue(encoder.encode(`: ping\n\n`));
            } catch {
              clearInterval(pingIv);
            }
          }, 15000);

          request.signal.addEventListener("abort", () => {
            clearInterval(pingIv);
            scanEngine.off(eventName, onEngineEvent);
            try {
              controller.close();
            } catch {
              // ignore
            }
          });
        },
      });

      return new Response(stream, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    // Cancel scan
    if (subPath === "/cancel" && method === "POST") {
      scanEngine.cancelScan(scanId);
      const updated = getScanById(scanId);
      return jsonResponse(updated);
    }

    // Pause / Resume
    if (subPath === "/pause" && method === "POST") {
      scanEngine.pauseScan(scanId);
      return jsonResponse({ paused: true });
    }

    if (subPath === "/resume" && method === "POST") {
      scanEngine.resumeScan(scanId);
      return jsonResponse({ paused: false });
    }

    // Retry agent
    const retryMatch = subPath.match(/^\/agents\/([^/]+)\/retry$/);
    if (retryMatch && method === "POST") {
      const agentId = retryMatch[1] ?? "";
      scanEngine.retryAgent(scanId, agentId);
      const updated = getScanById(scanId);
      return jsonResponse(updated);
    }

    // Export formats
    if (subPath === "/export" && method === "GET") {
      const format = url.searchParams.get("format") || "json";
      if (format === "csv") {
        return textResponse(scanToCsv(scan), "text/csv; charset=utf-8", 200, {
          "Content-Disposition": `attachment; filename="${scan.id}.csv"`,
        });
      }
      if (format === "markdown" || format === "md") {
        return textResponse(scanToMarkdown(scan), "text/markdown; charset=utf-8", 200, {
          "Content-Disposition": `attachment; filename="${scan.id}.md"`,
        });
      }
      return textResponse(scanToJson(scan), "application/json; charset=utf-8", 200, {
        "Content-Disposition": `attachment; filename="${scan.id}.json"`,
      });
    }

    // GET /api/scans/:id
    if (subPath === "" && method === "GET") {
      const counts = countFindingsBySeverity(scan.findings);
      const risk = computeRiskScore(scan.findings);
      const vectors = synthesizeAttackVectors(scan.findings);

      return jsonResponse({
        ...scan,
        synthesis: {
          counts,
          riskScore: risk,
          vectors,
        },
      });
    }

    // PATCH /api/scans/:id
    if (subPath === "" && method === "PATCH") {
      try {
        const body = (await request.json()) as Partial<Scan>;
        const updated = updateScanById(scanId, (curr) => ({
          ...curr,
          name: body.name !== undefined ? body.name : curr.name,
          pinned: body.pinned !== undefined ? body.pinned : curr.pinned,
          tags: body.tags !== undefined ? body.tags : curr.tags,
          paused: body.paused !== undefined ? body.paused : curr.paused,
        }));
        if (body.paused !== undefined) {
          if (body.paused) scanEngine.pauseScan(scanId);
          else scanEngine.resumeScan(scanId);
        }
        return jsonResponse(updated);
      } catch (err) {
        return jsonResponse({ error: "Failed to update scan" }, 400);
      }
    }

    // DELETE /api/scans/:id
    if (subPath === "" && method === "DELETE") {
      scanEngine.cancelScan(scanId);
      const deleted = deleteScanById(scanId);
      return jsonResponse({ success: deleted });
    }
  }

  return jsonResponse({ error: "Not Found", pathname }, 404);
}

/**
 * Node HTTP Request/Response adapter for Vite dev server middleware
 */
export function handleNodeApi(req: IncomingMessage, res: ServerResponse): void {
  const protocol = "http";
  const host = req.headers.host || "localhost:3000";
  const url = `${protocol}://${host}${req.url}`;

  // Read body if method has payload
  const hasBody = ["POST", "PUT", "PATCH"].includes((req.method || "").toUpperCase());

  const execute = async (body?: string) => {
    try {
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (v !== undefined) {
          if (Array.isArray(v)) {
            v.forEach((val) => headers.append(k, val));
          } else {
            headers.set(k, v);
          }
        }
      }

      const reqInit: RequestInit = {
        method: req.method || "GET",
        headers,
      };
      if (hasBody && body) {
        reqInit.body = body;
      }
      const webRequest = new Request(url, reqInit);

      const webResponse = await handleApiRequest(webRequest);

      res.statusCode = webResponse.status;
      webResponse.headers.forEach((val, key) => {
        res.setHeader(key, val);
      });

      if (webResponse.body) {
        const reader = webResponse.body.getReader();
        const pump = async () => {
          while (true) {
            const { done, value } = await reader.read();
            if (done) {
              res.end();
              break;
            }
            res.write(value);
          }
        };
        await pump();
      } else {
        res.end();
      }
    } catch (err) {
      console.error("[API Adapter Error]", err);
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ error: "Internal Server Error", detail: String(err) }));
      }
    }
  };

  if (hasBody) {
    let bodyData = "";
    req.on("data", (chunk) => {
      bodyData += chunk;
    });
    req.on("end", () => {
      void execute(bodyData);
    });
  } else {
    void execute();
  }
}
