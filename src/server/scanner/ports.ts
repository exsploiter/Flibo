import net from "node:net";
import type { Finding, Severity } from "../types";

export interface PortScanOptions {
  target: string;
  portsConfig: string;
  intensity: "quick" | "standard" | "deep";
  stealth: boolean;
  onProgress: (pct: number) => void;
  onLog: (line: string) => void;
  shouldStop: () => boolean;
}

export interface DiscoveredPort {
  port: number;
  protocol: "tcp";
  service: string;
  banner?: string;
  latencyMs: number;
  severity: Severity;
}

const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
  1433, 1521, 2049, 2082, 2083, 2086, 2087, 3000, 3128, 3306, 3389,
  5000, 5432, 5900, 5901, 6379, 8000, 8008, 8080, 8081, 8443, 8888,
  9000, 9090, 9200, 9300, 11211, 27017, 28017
];

const KNOWN_SERVICES: Record<number, { service: string; severity: Severity; note?: string }> = {
  21: { service: "ftp", severity: "medium", note: "Cleartext file transfer protocol" },
  22: { service: "ssh", severity: "low", note: "Encrypted remote terminal" },
  23: { service: "telnet", severity: "critical", note: "Unencrypted legacy management protocol" },
  25: { service: "smtp", severity: "medium", note: "Mail transfer agent" },
  53: { service: "domain", severity: "info", note: "DNS resolver / server" },
  80: { service: "http", severity: "info", note: "Standard plaintext web server" },
  110: { service: "pop3", severity: "medium", note: "Cleartext mail retrieval" },
  111: { service: "rpcbind", severity: "medium", note: "Sun RPC portmapper" },
  135: { service: "msrpc", severity: "medium", note: "Microsoft RPC endpoint mapper" },
  139: { service: "netbios-ssn", severity: "medium", note: "NetBIOS Session Service" },
  143: { service: "imap", severity: "medium", note: "Cleartext IMAP mail service" },
  443: { service: "https", severity: "info", note: "Encrypted web server (TLS)" },
  445: { service: "microsoft-ds", severity: "high", note: "SMB file and printer sharing" },
  993: { service: "imaps", severity: "low", note: "Secure IMAP over TLS" },
  995: { service: "pop3s", severity: "low", note: "Secure POP3 over TLS" },
  1433: { service: "ms-sql-s", severity: "high", note: "Microsoft SQL Server database" },
  1521: { service: "oracle", severity: "high", note: "Oracle database listener" },
  2049: { service: "nfs", severity: "high", note: "Network File System export" },
  3000: { service: "dev-web", severity: "low", note: "Development web application" },
  3306: { service: "mysql", severity: "high", note: "MySQL/MariaDB database port" },
  3389: { service: "ms-wbt-server", severity: "high", note: "Microsoft Remote Desktop (RDP)" },
  5000: { service: "upnp/dev", severity: "low", note: "Docker Registry or Dev server" },
  5432: { service: "postgresql", severity: "high", note: "PostgreSQL relational database" },
  5900: { service: "vnc", severity: "high", note: "VNC remote framebuffer session" },
  6379: { service: "redis", severity: "critical", note: "Redis in-memory store (potential unauthenticated RCE)" },
  8000: { service: "http-alt", severity: "info", note: "Alternative HTTP server" },
  8080: { service: "http-proxy", severity: "low", note: "HTTP proxy or alternative web port" },
  8443: { service: "https-alt", severity: "low", note: "Alternative HTTPS web service" },
  8888: { service: "jupyter/http", severity: "medium", note: "Jupyter notebook or HTTP admin" },
  9000: { service: "php-fpm/minio", severity: "medium", note: "PHP-FPM FastCGI or MinIO S3" },
  9200: { service: "elasticsearch", severity: "high", note: "Elasticsearch REST API (unauthenticated data exposure)" },
  11211: { service: "memcached", severity: "high", note: "Memcached distributed cache" },
  27017: { service: "mongodb", severity: "critical", note: "MongoDB NoSQL database port" },
};

export function parsePortList(config: string, intensity: "quick" | "standard" | "deep"): number[] {
  // If custom ports specified (not a preset), parse custom first
  if (config && config !== "top-100" && config !== "top-1000" && config !== "all-65k" && config !== "custom") {
    const list: number[] = [];
    const parts = config.split(/[,;\s]+/);
    for (const part of parts) {
      if (part.includes("-")) {
        const [startStr, endStr] = part.split("-");
        const start = parseInt(startStr || "0", 10);
        const end = parseInt(endStr || "0", 10);
        if (!isNaN(start) && !isNaN(end) && start > 0 && end <= 65535) {
          for (let p = Math.min(start, end); p <= Math.max(start, end); p++) {
            if (list.length < 500) list.push(p);
          }
        }
      } else {
        const p = parseInt(part, 10);
        if (!isNaN(p) && p > 0 && p <= 65535) {
          list.push(p);
        }
      }
    }
    if (list.length > 0) return Array.from(new Set(list));
  }

  if (config === "top-100" || intensity === "quick") {
    return COMMON_PORTS.slice(0, 25);
  }
  if (config === "top-1000" || intensity === "standard") {
    return COMMON_PORTS;
  }
  if (intensity === "deep" || config === "all-65k") {
    return Array.from(new Set([...COMMON_PORTS, ...Array.from({ length: 60 }, (_, i) => 8000 + i)]));
  }

  return COMMON_PORTS;
}


function cleanHost(target: string): string {
  let host = target.trim();
  if (host.startsWith("http://") || host.startsWith("https://")) {
    try {
      const parsed = new URL(host);
      host = parsed.hostname;
    } catch {
      // fallback
    }
  }
  if (host.includes("/")) {
    host = host.split("/")[0] || host;
  }
  return host;
}

function probePort(
  host: string,
  port: number,
  timeoutMs: number
): Promise<{ open: boolean; latencyMs: number; banner?: string }> {
  return new Promise((resolve) => {
    const start = Date.now();
    let banner = "";
    let resolved = false;

    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);

    const finish = (open: boolean) => {
      if (resolved) return;
      resolved = true;
      socket.removeAllListeners();
      socket.destroy();
      if (banner.trim()) {
        resolve({ open, latencyMs: Date.now() - start, banner: banner.trim() });
      } else {
        resolve({ open, latencyMs: Date.now() - start });
      }
    };

    socket.connect(port, host, () => {
      // Connected! Now attempt banner grabbing
      if (port === 80 || port === 8080 || port === 8000) {
        try {
          socket.write("HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n");
        } catch {
          // ignore write error
        }
      } else {
        try {
          socket.write("\r\n");
        } catch {
          // ignore
        }
      }

      // Wait briefly for banner data
      const bannerTimer = setTimeout(() => {
        finish(true);
      }, 400);

      socket.on("data", (data) => {
        clearTimeout(bannerTimer);
        const chunk = data.toString("utf-8", 0, Math.min(data.length, 512));
        banner += chunk;
        finish(true);
      });
    });

    socket.on("timeout", () => finish(false));
    socket.on("error", () => finish(false));
  });
}

export async function runPortScan(options: PortScanOptions): Promise<Finding[]> {
  const host = cleanHost(options.target);
  const ports = parsePortList(options.portsConfig, options.intensity);
  const findings: Finding[] = [];

  options.onLog(`[PortScan] Initiating TCP port probe against ${host} (${ports.length} target ports)`);
  options.onLog(`[PortScan] Intensity: ${options.intensity} · Stealth: ${options.stealth ? "ENABLED" : "DISABLED"}`);

  const concurrency = options.stealth ? 6 : 20;
  const timeoutMs = options.intensity === "quick" ? 700 : 1100;
  let completed = 0;

  options.onProgress(6);

  for (let i = 0; i < ports.length; i += concurrency) {
    if (options.shouldStop()) {
      options.onLog(`[PortScan] Scan cancelled by operator`);
      break;
    }

    const batch = ports.slice(i, i + concurrency);
    const results = await Promise.all(
      batch.map(async (port) => {
        const res = await probePort(host, port, timeoutMs);
        completed++;
        const pct = Math.min(96, Math.max(8, Math.round((completed / ports.length) * 100)));
        options.onProgress(pct);
        return { port, ...res };
      })
    );

    for (const r of results) {
      if (r.open) {
        const meta = KNOWN_SERVICES[r.port] ?? {
          service: `port-${r.port}`,
          severity: "info",
        };

        const cleanBanner = r.banner
          ? r.banner.replace(/[\r\n]+/g, " ").slice(0, 100)
          : undefined;

        options.onLog(
          `[PortScan] DISCOVERED OPEN: ${r.port}/tcp (${meta.service}) - ${r.latencyMs}ms${
            cleanBanner ? ` - [${cleanBanner}]` : ""
          }`
        );

        findings.push({
          id: `find-port-${r.port}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          agent: "port-scan",
          kind: "port",
          severity: meta.severity,
          title: `Open Port ${r.port}/TCP (${meta.service.toUpperCase()})`,
          port: r.port,
          protocol: "tcp",
          service: meta.service,
          banner: cleanBanner || `${meta.service} on port ${r.port}`,
          detail: `Port ${r.port}/tcp is publicly accessible. Response latency: ${r.latencyMs}ms. ${meta.note || ""}`,
          tags: ["network", "tcp", meta.service],
          note: `Auto-discovered via TCP SYN probe. RTT ${r.latencyMs}ms.`,
        });
      }
    }

    const pct = Math.round((completed / ports.length) * 100);
    options.onProgress(pct);

    if (options.stealth) {
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  options.onProgress(100);
  options.onLog(
    `[PortScan] Completed sweep: ${ports.length} ports probed, ${findings.length} open ports detected`
  );
  return findings;
}
