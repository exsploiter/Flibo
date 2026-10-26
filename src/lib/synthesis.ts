import type { Finding, Scan } from "./types";
import { severityWeight } from "./types";

export interface AttackVector {
  id: string;
  severity: Finding["severity"];
  title: string;
  why: string;
  confidence: number;
  findingId: string;
}

export function synthesizeVectors(findings: Finding[]): AttackVector[] {
  const vectors: AttackVector[] = [];

  for (const f of findings) {
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
        why: `Exploitable service fingerprint matched. ${f.description?.slice(0, 90) ?? ""}`,
        confidence: Math.min(95, 60 + Math.round((f.cvss ?? 5) * 4)),
        findingId: f.id,
      });
    }
    if (f.kind === "port" && f.service && ["redis", "mysql", "postgresql"].includes(f.service)) {
      vectors.push({
        id: `v-${f.id}`,
        severity: "high",
        title: `Unauthenticated ${f.service} exposed on :${f.port}`,
        why: `Datastore reachable from scan position with banner "${f.banner}". Lateral-movement pivot candidate.`,
        confidence: 82,
        findingId: f.id,
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
    if (f.kind === "subdomain" && f.title.startsWith("admin.")) {
      vectors.push({
        id: `v-${f.id}`,
        severity: "medium",
        title: `Admin panel reachable at ${f.title}`,
        why: "Exposed management surface — credential attacks and known-CVE chaining apply.",
        confidence: 70,
        findingId: f.id,
      });
    }
    if (f.kind === "tech" && f.service === "jQuery" && (f.version ?? "").startsWith("3.6")) {
      vectors.push({
        id: `v-${f.id}`,
        severity: "low",
        title: `Aging client library ${f.service} ${f.version}`,
        why: "Known XSS patterns in this line — useful for phishing-adjacent delivery.",
        confidence: 40,
        findingId: f.id,
      });
    }
  }

  return vectors.sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity) || b.confidence - a.confidence);
}

export function riskScore(findings: Finding[]): number {
  const counts = countBySeverity(findings);
  const raw = counts.critical * 14 + counts.high * 8 + counts.medium * 4 + counts.low * 1.5;
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
