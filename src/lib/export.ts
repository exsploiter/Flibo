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
      agents: scan.agents.map((a) => ({ id: a.id, name: a.name, status: a.status, progress: a.progress })),
    },
    null,
    2,
  );
}

export function scanToCsv(scan: Scan): string {
  const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const head = "severity,kind,agent,title,service,version,port,cve,cvss,tags,note";
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
        `- **[${f.severity.toUpperCase()}]** ${f.title}${f.port ? ` (${f.service} :${f.port})` : ""}${f.cveId ? ` (CVSS ${f.cvss})` : ""}${f.note ? ` — note: ${f.note}` : ""}`,
    ),
    "",
    "## Agent output",
    "",
    ...scan.agents.flatMap((a) => ["```", `# ${a.name} (${a.status})`, ...a.logs.slice(-12), "```", ""]),
  ];
  return lines.join("\n");
}

export function safeFileName(scan: Scan): string {
  return `${scan.name.replace(/[^a-z0-9-]+/gi, "-").toLowerCase()}-${scan.id}`;
}
