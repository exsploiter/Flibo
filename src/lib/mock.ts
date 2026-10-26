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
  { id: "cve-matcher", name: "CVE Matcher", desc: "Match fingerprints against CVE database" },
  { id: "os-detection", name: "OS Detection", desc: "TCP/IP stack fingerprinting" },
];

// ---------- deterministic RNG per target ----------

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

function isIpLike(target: string): boolean {
  return /^\d/.test(target) || target.includes("/");
}

// ---------- live log generation ----------

const LOG_POOLS: Record<string, string[]> = {
  "port-scan": [
    "Starting Nmap 7.96 ( https://nmap.org )",
    "Initiating Ping Scan against {t} (2 hosts)",
    "Completed Ping Scan — 2.11s elapsed",
    "Initiating SYN Stealth Scan against {t}",
    "Discovered open port 443/tcp on {t}",
    "Discovered open port 22/tcp on {t}",
    "SYN Stealth Scan Timing: about {p}% done",
    "Initiating Service scan against 6 services on {t}",
    "Completed SYN Stealth Scan at — 38.42s elapsed",
    "Final report written: 6 hosts responded",
  ],
  "subdomain-enum": [
    "Loading wordlist: subdomains-top1-5000.txt",
    "Wildcard detection: disabled (no wildcard on {t})",
    "Resolving api.{t} … [203.0.113.17]",
    "Resolving staging.{t} … [203.0.113.24]",
    "Resolving vpn.{t} … NXDOMAIN",
    "Found: admin.{t} [203.0.113.31]",
    "Querying passive sources: crt.sh, hackertarget …",
    "Merged results: 5 unique subdomains for {t}",
  ],
  "tech-fingerprint": [
    "Probing https://{t}/ (TLS 1.3, HTTP/2)",
    "Header: server — nginx/1.24.0",
    "Header: x-powered-by — Node.js",
    "Match: nginx 1.24.0 (confidence 99%)",
    "Fingerprinting client-side JS frameworks …",
    "Match: React 18.2.0 (bundled vendor chunk)",
    "Probing :8080 … service detected",
    "Fingerprint set complete for {t}",
  ],
  "cve-matcher": [
    "Loading CVE database (snapshot 2026-06)",
    "Matching fingerprints against CVE index …",
    "Found CVE-2023-44487 (CVSS 7.5) → nginx/1.24.0",
    "Found CVE-2024-22019 (CVSS 7.5) → Node.js 18.19.0",
    "Found CVE-2023-38408 (CVSS 9.8) → OpenSSH 8.9p1",
    "Cross-checking exploit availability (Exploit-DB) …",
    "Correlation complete: 6 CVEs mapped for {t}",
  ],
  "os-detection": [
    "Initiating TCP/IP fingerprinting against {t}",
    "Sending 10 probes (16 total ports)",
    "OS guesses: Linux 5.x (98%), Linux 4.x (92%)",
    "Distance: 11 hops (TTL 51 → guessed Linux)",
    "Fingerprint locked: Linux 5.15 kernel series",
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

// ---------- finding generators (deterministic per target) ----------

const PORT_POOL = [
  { port: 22, service: "ssh", banner: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.4", severity: "low" as const },
  { port: 80, service: "http", banner: "nginx 1.24.0", severity: "info" as const },
  { port: 443, service: "https", banner: "nginx 1.24.0 (TLS 1.3)", severity: "info" as const },
  { port: 3306, service: "mysql", banner: "MySQL 5.7.41-log", severity: "high" as const },
  { port: 8080, service: "http-proxy", banner: "Node.js http server", severity: "medium" as const },
  { port: 6379, service: "redis", banner: "Redis 6.0.16 (no auth)", severity: "high" as const },
  { port: 5432, service: "postgresql", banner: "PostgreSQL 14.9", severity: "high" as const },
  { port: 25, service: "smtp", banner: "Postfix smtpd", severity: "medium" as const },
];

const SUBDOMAIN_POOL = ["api", "dev", "staging", "vpn", "mail", "cdn", "admin", "git", "status", "s3"];

const TECH_POOL = [
  { name: "nginx", version: "1.24.0", severity: "info" as const },
  { name: "Node.js", version: "18.19.0", severity: "low" as const },
  { name: "React", version: "18.2.0", severity: "info" as const },
  { name: "MySQL", version: "5.7.41", severity: "medium" as const },
  { name: "OpenSSH", version: "8.9p1", severity: "low" as const },
  { name: "Redis", version: "6.0.16", severity: "medium" as const },
  { name: "jQuery", version: "3.6.0", severity: "low" as const },
  { name: "Ubuntu", version: "22.04 LTS", severity: "info" as const },
];

interface CveSeed {
  id: string;
  service: string;
  version: string;
  cvss: number;
  severity: "critical" | "high" | "medium";
  title: string;
  description: string;
}

const CVE_POOL: CveSeed[] = [
  {
    id: "CVE-2023-38408",
    service: "OpenSSH",
    version: "8.9p1",
    cvss: 9.8,
    severity: "critical",
    title: "OpenSSH agent forwarding remote code execution",
    description:
      "The OpenSSH agent (ssh-agent) permits loading a PKCS#11 library from an arbitrary path. Code execution in the agent is possible via forwarded agent sockets when signed libraries are loaded on the forwarding host.",
  },
  {
    id: "CVE-2023-44487",
    service: "nginx",
    version: "1.24.0",
    cvss: 7.5,
    severity: "high",
    title: "HTTP/2 Rapid Reset — denial of service",
    description:
      "HTTP/2 protocol-level flood where an attacker opens and immediately cancels a large number of streams, causing high CPU and memory amplification on the server.",
  },
  {
    id: "CVE-2024-22019",
    service: "Node.js",
    version: "18.19.0",
    cvss: 7.5,
    severity: "high",
    title: "Node.js HTTP chunk extension DoS",
    description:
      "A maliciously crafted HTTP request with an unbounded chunk extension can disable the Node.js HTTP server via resource exhaustion.",
  },
  {
    id: "CVE-2023-21980",
    service: "MySQL",
    version: "5.7.41",
    cvss: 7.1,
    severity: "high",
    title: "MySQL Server privilege escalation",
    description:
      "Vulnerability in the MySQL Server component allows a high-privileged attacker to escalate privileges via SQL and connection-level vectors.",
  },
  {
    id: "CVE-2022-32213",
    service: "Node.js",
    version: "18.19.0",
    cvss: 5.3,
    severity: "medium",
    title: "HTTP request smuggling — malformed chunked transfer encoding",
    description:
      "llhttp parser in Node.js accepts transfer-encoding headers with obfuscated framing, enabling HTTP request smuggling against downstream proxies.",
  },
  {
    id: "CVE-2022-05402",
    service: "Redis",
    version: "6.0.16",
    cvss: 10,
    severity: "critical",
    title: "Redis Lua sandbox escape (Debian packaging)",
    description:
      "Packaging issue allows a local or remote attacker with Lua eval access to escape the sandbox and execute arbitrary code on the host.",
  },
];

let fidCounter = 100;

function baseFinding(agent: string, kind: Finding["kind"], severity: Finding["severity"], title: string): Finding {
  return {
    id: `f${++fidCounter}`,
    agent,
    kind,
    severity,
    title,
    tags: [],
    note: "",
  };
}

export function findingsFor(agentId: string, target: string): Finding[] {
  const rng = mulberry32(hashStr(target + "::" + agentId));
  const out: Finding[] = [];

  if (agentId === "port-scan") {
    const ports = pick(rng, PORT_POOL, 4 + Math.floor(rng() * 3));
    for (const p of ports) {
      out.push({
        ...baseFinding("port-scan", "port", p.severity, `${p.service.toUpperCase()} on :${p.port}`),
        port: p.port,
        protocol: "tcp",
        service: p.service,
        banner: p.banner,
        detail: `${target} — tcp/${p.port} open, banner: "${p.banner}"`,
      });
    }
  }

  if (agentId === "subdomain-enum") {
    if (isIpLike(target)) return [];
    const subs = pick(rng, SUBDOMAIN_POOL, 3 + Math.floor(rng() * 3));
    for (const s of subs) {
      const admin = s === "admin";
      out.push({
        ...baseFinding(
          "subdomain-enum",
          "subdomain",
          admin ? "medium" : "info",
          `${s}.${target.replace(/^https?:\/\//, "")}`,
        ),
        detail: admin
          ? "Admin panel reachable without additional ACL — review authentication surface."
          : `Resolved to 203.0.113.${17 + Math.floor(rng() * 200)}`,
      });
    }
  }

  if (agentId === "tech-fingerprint") {
    const techs = pick(rng, TECH_POOL, 3 + Math.floor(rng() * 3));
    for (const t of techs) {
      out.push({
        ...baseFinding("tech-fingerprint", "tech", t.severity, `${t.name} ${t.version}`),
        service: t.name,
        version: t.version,
        detail: `Detected via HTTP header / payload fingerprint (confidence ${90 + Math.floor(rng() * 10)}%)`,
      });
    }
  }

  if (agentId === "cve-matcher") {
    const cves = pick(rng, CVE_POOL, 3 + Math.floor(rng() * 3));
    for (const c of cves) {
      out.push({
        ...baseFinding("cve-matcher", "cve", c.severity, `${c.id} — ${c.title}`),
        cveId: c.id,
        cvss: c.cvss,
        severity: c.severity,
        service: c.service,
        version: c.version,
        title: `${c.id} — ${c.title}`,
        description: c.description,
        references: [
          { label: "NVD", url: `https://nvd.nist.gov/vuln/detail/${c.id}` },
          { label: "MITRE", url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${c.id}` },
          { label: "Exploit-DB", url: `https://www.exploit-db.com/search?q=${c.id}` },
        ],
      });
    }
  }

  if (agentId === "os-detection") {
    const linux = rng() > 0.35;
    out.push({
      ...baseFinding(
        "os-detection",
        "os",
        "info",
        linux ? "Linux 5.15 (kernel series)" : "Windows Server 2019",
      ),
      detail: linux
        ? "TCP/IP fingerprint: TTL 51, window 64240 — Linux 5.x (98% confidence)"
        : "TCP/IP fingerprint: TTL 128, window 65535 — Windows Server 2019 (95% confidence)",
    });
  }

  return out;
}

// ---------- seeded scans ----------

function seededAgents(
  target: string,
  states: { id: string; status: Scan["agents"][number]["status"]; progress?: number; error?: string; logs?: number }[],
): Scan["agents"] {
  return states.map((s) => {
    const def = AGENTS.find((a) => a.id === s.id)!;
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
  const now = Date.now();

  const t1 = "acme-labs.dev";
  const scan1: Scan = {
    id: "scan-seed-1",
    name: "Perimeter sweep — acme-labs.dev",
    target: t1,
    targets: [t1, "203.0.113.17"],
    tags: ["perimeter", "web"],
    config: { intensity: "standard", agents: AGENTS.map((a) => a.id), ports: "top-1000", stealth: false, scheduled: null },
    status: "complete",
    createdAt: now - 1000 * 60 * 60 * 26,
    finishedAt: now - 1000 * 60 * 60 * 26 + 1000 * 60 * 8,
    agents: seededAgents(t1, [
      { id: "port-scan", status: "complete" },
      { id: "subdomain-enum", status: "complete" },
      { id: "tech-fingerprint", status: "complete" },
      { id: "cve-matcher", status: "complete" },
      { id: "os-detection", status: "complete" },
    ]),
    findings: [
      ...findingsFor("port-scan", t1),
      ...findingsFor("subdomain-enum", t1),
      ...findingsFor("tech-fingerprint", t1),
      ...findingsFor("cve-matcher", t1),
      ...findingsFor("os-detection", t1),
    ],
  };

  const t2 = "10.0.4.0/24";
  const scan2: Scan = {
    id: "scan-seed-2",
    name: "Internal segment sweep — 10.0.4.0/24",
    target: t2,
    targets: [t2],
    tags: ["internal", "network"],
    config: { intensity: "quick", agents: ["port-scan", "os-detection"], ports: "top-100", stealth: true, scheduled: null },
    status: "complete",
    createdAt: now - 1000 * 60 * 60 * 4,
    finishedAt: now - 1000 * 60 * 60 * 4 + 1000 * 60 * 3,
    agents: seededAgents(t2, [
      { id: "port-scan", status: "complete" },
      { id: "os-detection", status: "complete" },
    ]),
    findings: [...findingsFor("port-scan", t2), ...findingsFor("os-detection", t2)],
  };

  const t3 = "203.0.113.42";
  const scan3: Scan = {
    id: "scan-seed-3",
    name: "Edge recon — 203.0.113.42",
    target: t3,
    targets: [t3],
    tags: ["edge", "opsec"],
    config: { intensity: "deep", agents: AGENTS.map((a) => a.id), ports: "1-65535", stealth: true, scheduled: null },
    status: "running",
    createdAt: now - 1000 * 60 * 6,
    agents: seededAgents(t3, [
      { id: "subdomain-enum", status: "complete" },
      { id: "port-scan", status: "complete" },
      { id: "cve-matcher", status: "running", progress: 42 },
      { id: "tech-fingerprint", status: "queued" },
      { id: "os-detection", status: "failed", error: "Timed out after 300s — host filtered TCP probes" },
    ]),
    findings: [...findingsFor("port-scan", t3), ...findingsFor("subdomain-enum", t3)],
  };

  const scan4: Scan = {
    id: "scan-seed-4",
    name: "Legacy host check — oldcorp.internal",
    target: "legacy.oldcorp.internal",
    targets: ["legacy.oldcorp.internal"],
    tags: ["legacy"],
    config: { intensity: "standard", agents: ["port-scan", "cve-matcher"], ports: "top-100", stealth: false, scheduled: null },
    status: "cancelled",
    createdAt: now - 1000 * 60 * 60 * 72,
    agents: seededAgents("legacy.oldcorp.internal", [
      { id: "port-scan", status: "complete", logs: 3 },
      { id: "cve-matcher", status: "queued" },
    ]),
    findings: [...findingsFor("port-scan", "legacy.oldcorp.internal")],
  };

  return [scan3, scan1, scan2, scan4];
}
