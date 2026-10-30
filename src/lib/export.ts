import type { Finding, Scan } from "./types";
import { synthesizeVectors, countBySeverity } from "./synthesis";

export function download(filename: string, text: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function scanToJson(scan: Scan): string {
  return JSON.stringify(
    {
      scan: {
        id: scan.id,
        name: scan.name,
        target: scan.target,
        targets: scan.targets,
        tags: scan.tags,
        config: scan.config,
        status: scan.status,
        createdAt: new Date(scan.createdAt).toISOString(),
        finishedAt: scan.finishedAt ? new Date(scan.finishedAt).toISOString() : null,
      },
      severityCounts: countBySeverity(scan.findings),
      attackVectors: synthesizeVectors(scan.findings),
      findings: scan.findings,
      graph: scan.graph,
      agents: scan.agents.map((a) => ({ id: a.id, name: a.name, status: a.status, progress: a.progress })),
    },
    null,
    2,
  );
}

export function scanToCsv(scan: Scan): string {
  const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const head = "severity,kind,agent,title,service,version,port,cve,cvss,epss,cisa_kev,mitre,tags,note";
  const rows = scan.findings.map((f: Finding) =>
    [
      f.severity,
      f.kind,
      f.agent,
      f.title,
      f.service ?? "",
      f.version ?? "",
      f.port ?? "",
      f.cveId ?? "",
      f.cvss ?? "",
      f.epss ?? "",
      f.cisaKev ? "YES" : "NO",
      f.mitreTechnique ?? "",
      f.tags.join("|"),
      f.note,
    ]
      .map(esc)
      .join(","),
  );
  return [head, ...rows].join("\n");
}

export function scanToMarkdown(scan: Scan): string {
  const counts = countBySeverity(scan.findings);
  const vectors = synthesizeVectors(scan.findings);
  const lines: string[] = [
    `# ${scan.name}`,
    "",
    `**Target:** ${scan.targets.join(", ")}  `,
    `**Status:** ${scan.status}  `,
    `**Launched:** ${new Date(scan.createdAt).toLocaleString()}  `,
    `**Tags:** ${scan.tags.join(", ") || "—"}`,
    "",
    "## Severity summary",
    "",
    `Critical: ${counts.critical} · High: ${counts.high} · Medium: ${counts.medium} · Low: ${counts.low} · Info: ${counts.info}`,
    "",
    "## Attack vectors (ranked)",
    "",
    ...vectors.map((v, i) => `${i + 1}. **[${v.severity.toUpperCase()}]** ${v.title} — ${v.why}`),
    "",
    "## Findings",
    "",
    ...scan.findings.map(
      (f) =>
        `- **[${f.severity.toUpperCase()}]** ${f.title}${f.port ? ` (${f.service} :${f.port})` : ""}${f.cveId ? ` (CVSS ${f.cvss})` : ""}${f.cisaKev ? " [CISA KEV]" : ""}${f.mitreTechnique ? ` [${f.mitreTechnique}]` : ""}`,
    ),
    "",
    "## Agent output",
    "",
    ...scan.agents.flatMap((a) => ["```", `# ${a.name} (${a.status})`, ...a.logs.slice(-12), "```", ""]),
  ];
  return lines.join("\n");
}

export function scanToExecutiveSummary(scan: Scan): string {
  const counts = countBySeverity(scan.findings);
  const vectors = synthesizeVectors(scan.findings);
  const topRisks = vectors.slice(0, 3);

  return [
    `# EXECUTIVE SECURITY POSTURE BRIEFING`,
    `Target: ${scan.target}`,
    `Date: ${new Date().toLocaleDateString()}`,
    `Classification: CONFIDENTIAL`,
    ``,
    `## Posture Overview`,
    `Flibo completed an automated perimeter and attack surface assessment across ${scan.targets.length} target asset(s).`,
    `Overall Risk Index: ${counts.critical > 0 ? "CRITICAL RISK" : counts.high > 0 ? "ELEVATED RISK" : "NOMINAL RISK"}`,
    ``,
    `## Findings Distribution`,
    `- Critical Impact Issues: ${counts.critical}`,
    `- High Impact Issues: ${counts.high}`,
    `- Medium Severity Issues: ${counts.medium}`,
    `- Low / Informational: ${counts.low + counts.info}`,
    ``,
    `## Top 3 Priority Remediations`,
    ...topRisks.map((r, i) => `${i + 1}. **${r.title}** (${r.severity.toUpperCase()}): ${r.why}`),
    ``,
    `## Next Steps`,
    `Remediate identified critical exposures immediately. Conduct re-scan upon hotfix deployment.`,
  ].join("\n");
}

export function scanToTicketing(scan: Scan): string {
  const actionable = scan.findings.filter((f) => f.severity === "critical" || f.severity === "high");
  return actionable
    .map(
      (f) =>
        `ISSUE: [${f.severity.toUpperCase()}] ${f.title}\n` +
        `Target: ${scan.target}\n` +
        `Severity: ${f.severity}\n` +
        `Category: ${f.kind}\n` +
        `CVE: ${f.cveId || "N/A"} (CVSS: ${f.cvss || "N/A"})\n` +
        `MITRE: ${f.mitreTechnique || "N/A"}\n` +
        `Description: ${f.detail || f.title}\n` +
        `Recommended Fix: ${f.note || "Remediate according to vendor advisory."}\n` +
        `----------------------------------------`,
    )
    .join("\n\n");
}

export function safeFileName(s: string) {
  return s.replace(/[^a-z0-9_.-]/gi, "_").toLowerCase();
}
