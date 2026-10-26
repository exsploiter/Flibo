import type { AppSettings, Scan } from "./types";

const BASE_URL = typeof window !== "undefined" ? "" : "http://localhost:3000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!res.ok) {
    const errBody = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}: ${errBody || res.statusText}`);
  }

  return (await res.json()) as T;
}

export const api = {
  async getHealth() {
    return request<{ status: string; uptime: number; activeScans: number; totalScans: number }>("/api/health");
  },

  async listScans(query?: { search?: string; status?: string; limit?: number; offset?: number }): Promise<Scan[]> {
    const params = new URLSearchParams();
    if (query?.search) params.set("search", query.search);
    if (query?.status && query.status !== "all") params.set("status", query.status);
    if (query?.limit) params.set("limit", String(query.limit));
    if (query?.offset) params.set("offset", String(query.offset));

    const qs = params.toString();
    return request<Scan[]>(`/api/scans${qs ? `?${qs}` : ""}`);
  },

  async getScan(id: string): Promise<Scan> {
    return request<Scan>(`/api/scans/${id}`);
  },

  async createScan(scan: Partial<Scan>): Promise<Scan> {
    return request<Scan>("/api/scans", {
      method: "POST",
      body: JSON.stringify(scan),
    });
  },

  async updateScan(id: string, patch: Partial<Scan>): Promise<Scan> {
    return request<Scan>(`/api/scans/${id}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    });
  },

  async deleteScan(id: string): Promise<{ success: boolean }> {
    return request<{ success: boolean }>(`/api/scans/${id}`, {
      method: "DELETE",
    });
  },

  async cancelScan(id: string): Promise<Scan> {
    return request<Scan>(`/api/scans/${id}/cancel`, {
      method: "POST",
    });
  },

  async pauseScan(id: string): Promise<{ paused: boolean }> {
    return request<{ paused: boolean }>(`/api/scans/${id}/pause`, {
      method: "POST",
    });
  },

  async resumeScan(id: string): Promise<{ paused: boolean }> {
    return request<{ paused: boolean }>(`/api/scans/${id}/resume`, {
      method: "POST",
    });
  },

  async retryAgent(scanId: string, agentId: string): Promise<Scan> {
    return request<Scan>(`/api/scans/${scanId}/agents/${agentId}/retry`, {
      method: "POST",
    });
  },

  async getSettings(): Promise<AppSettings> {
    return request<AppSettings>("/api/settings");
  },

  async saveSettings(settings: Partial<AppSettings>): Promise<AppSettings> {
    return request<AppSettings>("/api/settings", {
      method: "PUT",
      body: JSON.stringify(settings),
    });
  },

  async getTargetHistory(): Promise<string[]> {
    return request<string[]>("/api/targets/history");
  },

  subscribeScanEvents(
    scanId: string,
    callbacks: {
      onLog?: (agentId: string, line: string) => void;
      onProgress?: (agentId: string, progress: number) => void;
      onAgentComplete?: (agentId: string, status: string) => void;
      onScanComplete?: (status: string) => void;
      onSnapshot?: (scan: Scan) => void;
      onStatusChange?: (data: { paused?: boolean; status?: string }) => void;
    }
  ): () => void {
    if (typeof window === "undefined" || !("EventSource" in window)) {
      return () => {};
    }

    const es = new EventSource(`/api/scans/${scanId}/events`);

    es.addEventListener("snapshot", (e) => {
      try {
        const data = JSON.parse(e.data) as Scan;
        callbacks.onSnapshot?.(data);
      } catch {
        // ignore
      }
    });

    es.addEventListener("log", (e) => {
      try {
        const data = JSON.parse(e.data) as { agentId: string; line: string };
        callbacks.onLog?.(data.agentId, data.line);
      } catch {
        // ignore
      }
    });

    es.addEventListener("progress", (e) => {
      try {
        const data = JSON.parse(e.data) as { agentId: string; progress: number };
        callbacks.onProgress?.(data.agentId, data.progress);
      } catch {
        // ignore
      }
    });

    es.addEventListener("agent_complete", (e) => {
      try {
        const data = JSON.parse(e.data) as { agentId: string; status: string };
        callbacks.onAgentComplete?.(data.agentId, data.status);
      } catch {
        // ignore
      }
    });

    es.addEventListener("scan_complete", (e) => {
      try {
        const data = JSON.parse(e.data) as { status: string };
        callbacks.onScanComplete?.(data.status);
      } catch {
        // ignore
      }
    });

    es.addEventListener("status", (e) => {
      try {
        const data = JSON.parse(e.data) as { paused?: boolean; status?: string };
        callbacks.onStatusChange?.(data);
      } catch {
        // ignore
      }
    });

    return () => {
      es.close();
    };
  },
};
