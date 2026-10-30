import type { AttackChainGraph, Finding, Scan, Severity } from "./types";
import { severityWeight } from "./types";

export interface AttackVector {
  id: string;
  severity: Severity;
  title: string;
  why: string;
  confidence: number;
  findingId: string;
  mitreTechnique?: string;
  cisaKev?: boolean;
}

export function synthesizeVectors(findings: Finding[]): AttackVector[] {
  const vectors: AttackVector[] = [];

  for (const f of findings) {
    if (f.kind === "takeover") {
      vectors.push({
        id: `v-${f.id}`,
        severity: "critical",
        title: `Dangling CNAME Takeover: ${f.title}`,
        why: "Subdomain points to unclaimed third-party cloud hosting — trivial full hijack.",
        confidence: f.confidence || 98,
        findingId: f.id,
        mitreTechnique: f.mitreTechnique || "T1584.004",
      });
    }
    if (f.kind === "cloud") {
      vectors.push({
        id: `v-${f.id}`,
        severity: "critical",
        title: `Cloud Exfiltration: ${f.title}`,
        why: "Unprotected cloud object storage permits public directory listing and data dumping.",
        confidence: f.confidence || 99,
        findingId: f.id,
        mitreTechnique: f.mitreTechnique || "T1530",
      });
    }
    if (f.kind === "content" && (f.title.includes(".env") || f.title.includes("Backup"))) {
      vectors.push({
        id: `v-${f.id}`,
        severity: "critical",
        title: `Secret Leak: ${f.title}`,
        why: "Exposed environment or database backup files leak production secrets and API keys.",
        confidence: f.confidence || 95,
        findingId: f.id,
        mitreTechnique: f.mitreTechnique || "T1552.001",
      });
    }
    if (f.kind === "cve") {
      const sName = (f.service ?? "").trim();
      const vName = (f.version ?? "").trim();
      const label =
        sName && vName
          ? vName.toLowerCase().startsWith(sName.toLowerCase())
            ? vName
            : `${sName} ${vName}`
          : sName || vName || "service";

      vectors.push({
        id: `v-${f.id}`,
        severity: f.severity,
        title: `${f.cveId} → ${label}`,
        why: `${f.cisaKev ? "CISA KEV Actively Exploited. " : ""}Exploitable service fingerprint matched. ${f.description?.slice(0, 90) ?? ""}`,
        confidence: f.cisaKev ? 99 : Math.min(95, 60 + Math.round((f.cvss ?? 5) * 4)),
        findingId: f.id,
        mitreTechnique: f.mitreTechnique || "T1190",
        cisaKev: f.cisaKev,
      });
    }
    if (f.kind === "port" && f.service && ["redis", "mysql", "postgresql", "mongodb"].includes(f.service)) {
      vectors.push({
        id: `v-${f.id}`,
        severity: "high",
        title: `Unauthenticated ${f.service} exposed on :${f.port}`,
        why: `Datastore reachable from scan position with banner "${f.banner}". Lateral-movement pivot candidate.`,
        confidence: 82,
        findingId: f.id,
        mitreTechnique: "T1595.001",
      });
    }
    if (f.kind === "auth" && f.severity === "medium") {
      vectors.push({
        id: `v-${f.id}`,
        severity: "medium",
        title: `Insecure Session Cookie: ${f.title}`,
        why: "Missing Secure or HttpOnly flags enables session hijacking via XSS.",
        confidence: 90,
        findingId: f.id,
        mitreTechnique: f.mitreTechnique || "T1539",
      });
    }
    if (f.kind === "port" && f.port === 8080) {
      vectors.push({
        id: `v-${f.id}`,
        severity: "medium",
        title: `Cleartext admin-adjacent service on :8080`,
        why: "Unencrypted HTTP service often hosts management consoles — interceptable traffic.",
        confidence: 64,
        findingId: f.id,
      });
    }
  }

  return vectors.sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity) || b.confidence - a.confidence);
}

export function generateAttackChainGraph(target: string, findings: Finding[]): AttackChainGraph {
  const nodes: AttackChainGraph["nodes"] = [
    { id: "target-root", label: target, kind: "target", severity: "info" },
  ];
  const edges: AttackChainGraph["edges"] = [];

  const ports = findings.filter((f) => f.kind === "port");
  const cves = findings.filter((f) => f.kind === "cve");
  const takeovers = findings.filter((f) => f.kind === "takeover");
  const clouds = findings.filter((f) => f.kind === "cloud");
  const content = findings.filter((f) => f.kind === "content");

  for (const p of ports.slice(0, 5)) {
    const pId = `node-port-${p.port}`;
    nodes.push({ id: pId, label: `Port ${p.port} (${p.service || "tcp"})`, kind: "service", severity: p.severity });
    edges.push({ source: "target-root", target: pId, label: "exposes" });

    for (const c of cves.filter((cv) => cv.port === p.port)) {
      const cId = `node-cve-${c.id}`;
      nodes.push({ id: cId, label: c.cveId || c.title, kind: "cve", severity: c.severity });
      edges.push({ source: pId, target: cId, label: "vulnerable" });
    }
  }

  for (const cl of clouds.slice(0, 2)) {
    const clId = `node-cloud-${cl.id}`;
    nodes.push({ id: clId, label: cl.title, kind: "cloud", severity: cl.severity });
    edges.push({ source: "target-root", target: clId, label: "bucket leak" });
  }

  for (const tk of takeovers.slice(0, 2)) {
    const tkId = `node-tk-${tk.id}`;
    nodes.push({ id: tkId, label: tk.title, kind: "takeover", severity: tk.severity });
    edges.push({ source: "target-root", target: tkId, label: "dangling CNAME" });
  }

  for (const ct of content.slice(0, 2)) {
    const ctId = `node-ct-${ct.id}`;
    nodes.push({ id: ctId, label: ct.title, kind: "content", severity: ct.severity });
    edges.push({ source: "target-root", target: ctId, label: "exposed file" });
  }

  return { nodes, edges };
}

export function computeHistoricalDelta(
  currentFindings: Finding[],
  previousFindings: Finding[]
): { newFindings: Finding[]; resolvedFindings: Finding[]; persistingFindings: Finding[] } {
  const prevTitles = new Set(previousFindings.map((f) => f.title));
  const currTitles = new Set(currentFindings.map((f) => f.title));

  const newFindings = currentFindings.filter((f) => !prevTitles.has(f.title)).map((f) => ({ ...f, delta: "new" as const }));
  const persistingFindings = currentFindings.filter((f) => prevTitles.has(f.title)).map((f) => ({ ...f, delta: "persisting" as const }));
  const resolvedFindings = previousFindings.filter((f) => !currTitles.has(f.title)).map((f) => ({ ...f, delta: "resolved" as const }));

  return { newFindings, resolvedFindings, persistingFindings };
}

export function riskScore(findings: Finding[]): number {
  const counts = countBySeverity(findings);
  let boost = 0;
  for (const f of findings) {
    if (f.cisaKev) boost += 10;
    if (f.epss && f.epss > 0.5) boost += 8;
  }
  const raw = counts.critical * 20 + counts.high * 10 + counts.medium * 4 + counts.low * 1.5 + boost;
  return Math.min(100, Math.round(raw));
}

export function countBySeverity(findings: Finding[]): Record<Finding["severity"], number> {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity]++;
  return out;
}

export function aggregateProgress(scan: Scan): number {
  if (!scan.agents.length) return 0;
  return Math.round(scan.agents.reduce((a, x) => a + x.progress, 0) / scan.agents.length);
}
