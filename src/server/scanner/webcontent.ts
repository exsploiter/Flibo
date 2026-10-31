import type { Finding } from "../types";

export interface ContentDiscoveryResult {
  findings: Finding[];
  logs: string[];
}

const COMMON_PROBES = [
  { path: "/.env", severity: "critical" as const, title: "Exposed Environment File (.env)", note: "Sensitive secrets, database credentials or API keys exposed publicly." },
  { path: "/.git/HEAD", severity: "high" as const, title: "Exposed Git Repository Root (.git/HEAD)", note: "Source code history, commits, and internal credentials can be dumped." },
  { path: "/wp-config.php.bak", severity: "critical" as const, title: "Exposed Backup Configuration File", note: "Contains raw plaintext database credentials." },
  { path: "/backup.sql", severity: "high" as const, title: "Publicly Accessible Database Dump (.sql)", note: "Full database schema and user records potentially exposed." },
  { path: "/phpinfo.php", severity: "medium" as const, title: "PHP Configuration Diagnostic Exposed (phpinfo)", note: "Exposes environment variables, server architecture, and PHP module versions." },
  { path: "/admin", severity: "low" as const, title: "Exposed Administrative Portal (/admin)", note: "Review access control, MFA enforcement, and rate limiting." },
  { path: "/actuator/health", severity: "low" as const, title: "Spring Boot Actuator Endpoint Exposed", note: "Monitor if actuators leak heap dumps, env vars, or metrics." },
  { path: "/swagger-ui.html", severity: "low" as const, title: "Interactive Swagger UI Documentation Exposed", note: "Enables public enumeration of internal API routes and schemas." },
];

export async function runContentDiscovery(
  target: string,
  onLog?: (line: string) => void
): Promise<ContentDiscoveryResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  function emit(msg: string) {
    logs.push(msg);
    if (onLog) onLog(msg);
  }

  const host = target.replace(/^https?:\/\//i, "").split(/[/:]/)[0];
  const baseUrl = `https://${host}`;

  emit(`[webcontent] Starting directory & sensitive path discovery on ${baseUrl}`);

      // Run all probes in parallel for speed (each has its own 2s timeout)
      const results = await Promise.allSettled(
        COMMON_PROBES.map(async (probe) => {
          const url = `${baseUrl}${probe.path}`;
          const res = await fetch(url, {
            method: "GET",
            headers: { "User-Agent": "Flibo-SecOps/2.0" },
            signal: AbortSignal.timeout(2000),
          });
          if (res.status !== 200) return null;
          const text = await res.text();
          const isSoft404 = text.includes("404 Not Found") || text.includes("Page Not Found") || text.length < 20;
          if (isSoft404) return null;
          return { probe, url, text };
        })
      );

      for (const r of results) {
        if (r.status === "fulfilled" && r.value) {
          const { probe, url: probeUrl, text } = r.value;
          emit(`[webcontent] Found accessible path: ${probe.path} [HTTP 200, ${text.length} bytes]`);
          findings.push({
            id: `content-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
            agent: "webcontent",
            kind: "content",
            severity: probe.severity,
            title: probe.title,
            detail: `Path ${probe.path} responded with HTTP 200 OK (${text.length} bytes).`,
            evidence: text.slice(0, 300),
            mitreTechnique: probe.path.includes(".env") ? "T1552.001 - Credentials In Files" : "T1596 - Search Open Technical Databases",
            compliance: { owasp: "A01:2021-Broken Access Control", cis: "5.1" },
            confidence: 90,
            tags: ["content", "path", "exposure"],
            note: probe.note,
          });
          void probeUrl; // suppress unused warning
        }
      }

      emit(`[webcontent] Completed path sweeps. Total exposure findings: ${findings.length}`);
      return { findings, logs };
    }
