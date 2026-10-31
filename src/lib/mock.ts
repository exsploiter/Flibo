import type { Finding, Scan } from "./types";

export interface AgentDef {
  id: string;
  name: string;
  desc: string;
}

export const AGENTS: AgentDef[] = [
  { id: "port-scan", name: "Port Scan", desc: "TCP/UDP port discovery with banner grab" },
  { id: "subdomain-enum", name: "Subdomain Enum", desc: "DNS bruteforce + passive sources" },
  { id: "tech-fingerprint", name: "Tech Fingerprint", desc: "HTTP probes, headers, JS fingerprints" },
  { id: "cve-matcher", name: "CVE Matcher", desc: "Match fingerprints against CVE/KEV database" },
  { id: "os-detection", name: "OS Detection", desc: "TCP/IP stack fingerprinting" },
  { id: "ssl-deep", name: "Deep TLS/SSL", desc: "Certificate chain, ciphers & SAN extraction" },
  { id: "waf-cdn", name: "WAF / CDN Edge", desc: "Edge shield fingerprinting & origin detection" },
  { id: "webcontent", name: "Content Discovery", desc: "Exposed .env, .git, backups & admin paths" },
  { id: "api-discovery", name: "API & GraphQL", desc: "OpenAPI/Swagger enumeration & introspection" },
  { id: "cloud-recon", name: "Cloud & Storage", desc: "S3, GCS, Azure Blob exposure auditing" },
  { id: "takeover-audit", name: "Subdomain Takeover", desc: "Dangling CNAME orphan service detection" },
  { id: "cms-fingerprint", name: "CMS & Plugins", desc: "WordPress, Drupal, XML-RPC & plugin audit" },
  { id: "auth-surface", name: "Auth Surface", desc: "Login portals, session flags & token audit" },
  { id: "osint-recon", name: "Passive OSINT", desc: "RDAP registrar metadata & security.txt audit" },
  { id: "os-network", name: "Network Routing", desc: "ASN ownership, routing & nmap provider" },
];

function hashStr(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}

function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(rng: () => number, arr: T[], n: number): T[] {
  const copy = [...arr];
  const out: T[] = [];
  while (out.length < n && copy.length) {
    const item = copy.splice(Math.floor(rng() * copy.length), 1)[0];
    if (item !== undefined) out.push(item);
  }
  return out;
}

const LOG_POOLS: Record<string, string[]> = {
  "port-scan": [
    "Starting raw TCP socket sweeps against {t}",
    "Probing top ports 80, 443, 22, 8080...",
    "Discovered open port 443/tcp on {t}",
    "Discovered open port 22/tcp on {t}",
    "Captured banner: SSH-2.0-OpenSSH_8.9p1",
    "Port scan complete at {p}%",
  ],
  "subdomain-enum": [
    "Loading wordlist: subdomains-top1000.txt",
    "Querying Certificate Transparency logs (crt.sh)...",
    "Resolving api.{t} -> 203.0.113.17",
    "Resolving staging.{t} -> 203.0.113.24",
    "Found admin.{t} -> 203.0.113.31",
    "Subdomain sweep complete",
  ],
  "tech-fingerprint": [
    "Probing https://{t}/ (TLS 1.3)",
    "Header: Server - nginx/1.24.0",
    "Header: X-Powered-By - Node.js",
    "Client framework detected: React 18.2",
    "Technology fingerprinting complete",
  ],
  "cve-matcher": [
    "Loading local CVSS 3.1 & CISA KEV catalog...",
    "Correlating banners against known exploits...",
    "Found CVE-2023-44487 (CVSS 7.5) -> nginx Rapid Reset",
    "Found CVE-2024-6387 (CVSS 8.1) -> OpenSSH RegreSSHion",
    "CVE correlation complete",
  ],
  "os-detection": [
    "Initiating TCP/IP fingerprinting against {t}",
    "TTL response: 64, Window size: 65535",
    "Heuristic OS guess: Linux 5.15+ (96% confidence)",
    "OS detection complete",
  ],
  "ssl-deep": [
    "Performing deep TLS handshake on {t}:443...",
    "Negotiated TLSv1.3 with AEAD cipher AES-256-GCM",
    "Validating certificate chain and SAN entries...",
    "Certificate valid for 180 days (Let's Encrypt Authority)",
    "TLS audit complete",
  ],
  "waf-cdn": [
    "Probing edge CDN & WAF signatures...",
    "Analyzing Cloudflare Ray ID and response headers...",
    "WAF shield detected: Cloudflare Edge Network",
    "Edge detection complete",
  ],
  "webcontent": [
    "Initiating sensitive path and backup file discovery...",
    "Probing /.env, /.git/HEAD, /backup.sql...",
    "Path scan complete, no soft-404 anomalies",
  ],
  "api-discovery": [
    "Probing /openapi.json, /swagger.json, /graphql...",
    "GraphQL introspection probe initiated...",
    "API discovery sweep complete",
  ],
  "cloud-recon": [
    "Generating predictable S3/GCS bucket permutations...",
    "Probing storage endpoints for anonymous read ACLs...",
    "Cloud storage audit complete",
  ],
  "takeover-audit": [
    "Cross-referencing subdomains against dangling CNAME list...",
    "Auditing GitHub Pages, Heroku, AWS S3 CNAMEs...",
    "Subdomain takeover audit complete",
  ],
  "cms-fingerprint": [
    "Probing CMS markers for WordPress, Drupal, Joomla...",
    "Checking /wp-json/ and xmlrpc.php interface...",
    "CMS audit complete",
  ],
  "auth-surface": [
    "Evaluating Set-Cookie headers for Secure & HttpOnly...",
    "Checking authentication endpoints /login and /oauth...",
    "Auth surface mapping complete",
  ],
  "osint-recon": [
    "Querying RDAP registration metadata for domain...",
    "Probing RFC 9116 /.well-known/security.txt policy...",
    "OSINT correlation complete",
  ],
  "os-network": [
    "Querying Autonomous System (ASN) network ownership...",
    "Validating nmap external engine binary status...",
    "Network routing audit complete",
  ],
};

export function logLineFor(agentId: string, target: string, progress: number): string {
  const pool = LOG_POOLS[agentId] ?? [`Processing {t} …`];
  const idx = Math.min(pool.length - 1, Math.floor((progress / 100) * pool.length));
  const ts = new Date().toTimeString().slice(0, 8);
  const tmpl = pool[idx] ?? `Processing {t} …`;
  const text = tmpl.replace("{t}", target).replace("{p}", String(progress));
  return `[${ts}] ${text}`;
}

const PORT_POOL = [
  { port: 22, service: "ssh", banner: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.4", severity: "low" as const },
  { port: 80, service: "http", banner: "nginx/1.24.0", severity: "info" as const },
  { port: 443, service: "https", banner: "nginx/1.24.0 (TLS 1.3)", severity: "info" as const },
  { port: 3306, service: "mysql", banner: "MySQL 8.0.35-0ubuntu0.22.04.1", severity: "critical" as const },
  { port: 6379, service: "redis", banner: "Redis server v=7.0.15", severity: "critical" as const },
  { port: 8080, service: "http-proxy", banner: "Apache Tomcat/9.0.58", severity: "medium" as const },
];

const SUBDOMAIN_POOL = ["api", "staging", "auth", "admin", "dev", "vpn", "cdn"];

export function findingsFor(agentId: string, target: string): Finding[] {
  const seed = hashStr(`${target}:${agentId}`);
  const rng = mulberry32(seed);
  const out: Finding[] = [];

  const baseFinding = (agent: string, kind: Finding["kind"], severity: Finding["severity"], title: string): Finding => ({
    id: `f-${agent}-${Math.floor(rng() * 100000)}`,
    agent,
    kind,
    severity,
    title,
    tags: [agent, kind],
    note: "",
    confidence: 90,
  });

  if (agentId === "port-scan") {
    const isGoogle = target.toLowerCase().includes("google");
    const ports = isGoogle
      ? PORT_POOL.filter((p) => p.port === 80 || p.port === 443)
      : pick(rng, PORT_POOL.filter((p) => p.port === 80 || p.port === 443 || p.port === 8080 || p.port === 22), 2);
    for (const p of ports) {
      out.push({
        ...baseFinding("port-scan", "port", p.severity, `Port ${p.port}/${p.service} open`),
        port: p.port,
        protocol: "tcp",
        service: p.service,
        banner: p.banner,
        detail: `Discovered open port with banner: ${p.banner}`,
      });
    }
  }

  if (agentId === "subdomain-enum") {
    const isGoogle = target.toLowerCase().includes("google");
    const count = isGoogle ? 3 : 2;
    const subs = pick(rng, SUBDOMAIN_POOL, count);
    for (const s of subs) {
      const fqdn = `${s}.${target.replace(/^https?:\/\//, "")}`;
      out.push({
        ...baseFinding("subdomain-enum", "subdomain", s === "admin" ? "medium" : "info", fqdn),
        detail: `Resolved via DNS and Certificate Transparency logs`,
      });
    }
  }

  if (agentId === "ssl-deep") {
    out.push({
      ...baseFinding("ssl-deep", "tls", "info", "Valid TLS 1.3 Certificate (Let's Encrypt / Google Trust Services)"),
      detail: "Certificate issued with RSA 2048 and SHA-256 signature. Expiry in 180 days.",
    });
  }

  if (agentId === "waf-cdn") {
    out.push({
      ...baseFinding("waf-cdn", "waf", "info", target.toLowerCase().includes("google") ? "Google Front End (GFE)" : "Edge Protection Active (Cloudflare)"),
      detail: "Edge proxy active fronting web traffic. DDoS mitigation engaged.",
    });
  }

  if (agentId === "cloud-recon") {
    out.push({
      ...baseFinding("cloud-recon", "cloud", "info", target.toLowerCase().includes("google") ? "Google Cloud Platform (GCP)" : "Cloud Infrastructure Active"),
      detail: "Target hosted in cloud infrastructure. S3/Storage bucket permissions verified secure.",
    });
  }

  if (agentId === "auth-surface") {
    out.push({
      ...baseFinding("auth-surface", "auth", "low", "Analytics Cookie Inspection"),
      detail: "Cookie issued with standard session tracking flags.",
    });
  }

  if (agentId === "osint-recon") {
    out.push({
      ...baseFinding("osint-recon", "osint", "info", "RFC 9116 security.txt Present"),
      detail: "Vulnerability disclosure contact established at /.well-known/security.txt.",
    });
  }

  if (agentId === "cve-matcher") {
    out.push({
      ...baseFinding("cve-matcher", "cve", "high", "CVE-2023-44487 — HTTP/2 Rapid Reset"),
      cveId: "CVE-2023-44487",
      cvss: 7.5,
      cisaKev: true,
      epss: 0.85,
      port: 443,
      mitreTechnique: "T1499 - Endpoint Denial of Service",
      description: "HTTP/2 stream cancellation vulnerability impacting modern HTTP/2 reverse proxies.",
    });
  }

  return out;
}

function seededAgents(
  target: string,
  states: { id: string; status: Scan["agents"][number]["status"]; progress?: number; error?: string; logs?: number }[],
): Scan["agents"] {
  return states.map((s) => {
    const def = AGENTS.find((a) => a.id === s.id) ?? { id: s.id, name: s.id, desc: "" };
    const logs: string[] = [];
    const n = s.logs ?? (s.status === "complete" ? 6 : s.status === "running" ? 4 : s.status === "failed" ? 3 : 0);
    for (let i = 0; i < n; i++) logs.push(logLineFor(s.id, target, ((i + 1) / n) * 100));
    return {
      id: s.id,
      name: def.name,
      status: s.status,
      progress: s.status === "complete" ? 100 : (s.progress ?? 0),
      logs,
      error: s.error,
    };
  });
}

export function seedScans(): Scan[] {
  return [];
}
