import type { AttackChainGraph, AttackVector, Finding, Severity } from "../types";

export function countFindingsBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) {
      counts[f.severity]++;
    }
  }
  return counts;
}

export function computeRiskScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;
  const counts = countFindingsBySeverity(findings);
  
  // EPSS and KEV boost
  let boost = 0;
  for (const f of findings) {
    if (f.cisaKev) boost += 10;
    if (f.epss && f.epss > 0.5) boost += 8;
  }

  const raw =
    counts.critical * 28 +
    counts.high * 16 +
    counts.medium * 7 +
    counts.low * 2 +
    counts.info * 0.5 +
    boost;

  return Math.min(100, Math.round(raw));
}

export function synthesizeAttackVectors(findings: Finding[]): AttackVector[] {
  const vectors: AttackVector[] = [];
  const cves = findings.filter((f) => f.kind === "cve");
  const ports = findings.filter((f) => f.kind === "port");
  const subdomains = findings.filter((f) => f.kind === "subdomain");
  const content = findings.filter((f) => f.kind === "content");
  const takeover = findings.filter((f) => f.kind === "takeover");
  const cloud = findings.filter((f) => f.kind === "cloud");
  const auth = findings.filter((f) => f.kind === "auth");
  const tech = findings.filter((f) => f.kind === "tech");

  // 1. Critical Subdomain Takeover & Brand Hijacking
  if (takeover.length > 0) {
    vectors.push({
      id: "vec-takeover",
      title: "Active Subdomain Takeover & Cross-Domain Impersonation",
      severity: "critical",
      mitreTechnique: "T1584.004 - Serverless / Cloud Hosting",
      description: `Identified ${takeover.length} dangling CNAME pointing to de-provisioned cloud services. Attackers can claim the external name to bypass CORS, steal session cookies, or conduct high-credibility spear-phishing.`,
      findings: takeover,
      remediation: "Immediately delete dangling DNS records or provision the corresponding hosting resources.",
    });
  }

  // 2. Critical Cloud Storage Bucket Leak
  if (cloud.length > 0) {
    vectors.push({
      id: "vec-cloud-leak",
      title: "Public Cloud Bucket Data Exfiltration",
      severity: "critical",
      mitreTechnique: "T1530 - Data from Cloud Storage Object",
      description: `Publicly accessible cloud storage containers allow unauthenticated listing and dumping of sensitive assets or database backups.`,
      findings: cloud,
      remediation: "Apply strict cloud access policies (e.g. S3 Block Public Access) and audit object ACLs.",
    });
  }

  // 3. Exposed Credentials & Source Secrets
  const envFindings = content.filter((c) => c.title.includes(".env") || c.title.includes("Backup") || c.title.includes(".git"));
  if (envFindings.length > 0) {
    vectors.push({
      id: "vec-secrets-leak",
      title: "Public Secrets & Source Code Exposure",
      severity: "critical",
      mitreTechnique: "T1552.001 - Credentials In Files",
      description: `Exposed environment variables, configuration backups, or .git repositories allow direct harvesting of database passwords, API keys, and internal source code.`,
      findings: envFindings,
      remediation: "Purge public files from webroot, rotate all leaked credentials immediately, and reconfigure server access rules.",
    });
  }

  // 4. Critical RCE / Exploit Surface (with CISA KEV / EPSS awareness)
  const criticalCves = cves.filter((c) => c.severity === "critical" || (c.cvss && c.cvss >= 9.0) || c.cisaKev);
  if (criticalCves.length > 0) {
    const hasKev = criticalCves.some((c) => c.cisaKev);
    vectors.push({
      id: "vec-rce",
      title: hasKev ? "CISA KEV Actively Exploited Remote Code Execution" : "Remote Code Execution via High-Severity CVEs",
      severity: "critical",
      mitreTechnique: "T1190 - Exploit Public-Facing Application",
      cisaKev: hasKev,
      description: `Identified ${criticalCves.length} critical vulnerability (including ${criticalCves[0]?.cveId || "known CVE"}). ${hasKev ? "Cataloged in CISA KEV with active in-the-wild exploitation." : "High weaponization probability."}`,
      findings: criticalCves,
      remediation: "Immediately patch affected packages or apply emergency vendor hotfixes. Restrict perimeter access using firewall or VPN.",
    });
  }

  // 5. Unauthenticated Database or In-Memory Cache Exposure
  const dbPorts = ports.filter((p) => [3306, 5432, 6379, 27017, 1433, 9200, 11211].includes(p.port || 0));
  if (dbPorts.length > 0) {
    vectors.push({
      id: "vec-db-exposure",
      title: "Public Database / Cache Service Exposure",
      severity: "critical",
      mitreTechnique: "T1595.001 - Port Scanning",
      description: `Database and caching ports (${dbPorts.map((p) => `${p.port}/${p.service}`).join(", ")}) are directly accessible from the public internet.`,
      findings: dbPorts,
      remediation: "Bind database listeners to localhost/private VPC only (127.0.0.1). Enforce strict security group firewall rules.",
    });
  }

  // 6. Sensitive Subdomain Proliferation
  const sensitiveSubs = subdomains.filter((s) => /staging|admin|internal|vpn|dev|corp|portal/.test(s.title.toLowerCase()));
  if (sensitiveSubs.length > 0) {
    vectors.push({
      id: "vec-subdomains",
      title: "Non-Production & Administrative Subdomains Publicly Resolvable",
      severity: "high",
      mitreTechnique: "T1596 - Search Open Technical Databases",
      description: `Discovered active subdomains indicative of development, staging, or internal management environments: ${sensitiveSubs.map((s) => s.title.replace("Discovered Subdomain: ", "")).slice(0, 4).join(", ")}.`,
      findings: sensitiveSubs,
      remediation: "Migrate non-production endpoints behind zero-trust access proxies or an internal corporate VPN.",
    });
  }

  // 7. Session & Cookie Security Vulnerabilities
  if (auth.length > 0) {
    vectors.push({
      id: "vec-auth-flaws",
      title: "Authentication Weakness & Session Hijack Risk",
      severity: "medium",
      mitreTechnique: "T1539 - Steal Web Session Cookie",
      description: `Identified session cookies lacking Secure or HttpOnly flags alongside exposed login entry points.`,
      findings: auth,
      remediation: "Enforce strict cookie attributes and rate-limiting on all authentication endpoints.",
    });
  }

  // 8. General Attack Surface if ports open
  if (ports.length > 0 && vectors.length === 0) {
    vectors.push({
      id: "vec-general-exposure",
      title: "Public Network Perimeter Services Exposed",
      severity: "medium",
      mitreTechnique: "T1046 - Network Service Discovery",
      description: `Target maintains ${ports.length} open network ports accessible to external scanners.`,
      findings: ports,
      remediation: "Review open ports against business requirements and close all unnecessary services.",
    });
  }

  return vectors;
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

  // Add ports
  for (const p of ports.slice(0, 6)) {
    const pId = `node-port-${p.port}`;
    nodes.push({ id: pId, label: `Port ${p.port} (${p.service || "tcp"})`, kind: "service", severity: p.severity });
    edges.push({ source: "target-root", target: pId, label: "exposes" });

    // Link CVEs to relevant port
    for (const c of cves.filter((cv) => cv.port === p.port)) {
      const cId = `node-cve-${c.id}`;
      nodes.push({ id: cId, label: c.cveId || c.title, kind: "cve", severity: c.severity });
      edges.push({ source: pId, target: cId, label: "vulnerable to" });
    }
  }

  // Add Cloud leaks
  for (const cl of clouds.slice(0, 2)) {
    const clId = `node-cloud-${cl.id}`;
    nodes.push({ id: clId, label: cl.title, kind: "cloud", severity: cl.severity });
    edges.push({ source: "target-root", target: clId, label: "unprotected bucket" });
  }

  // Add Takeovers
  for (const tk of takeovers.slice(0, 2)) {
    const tkId = `node-tk-${tk.id}`;
    nodes.push({ id: tkId, label: tk.title, kind: "takeover", severity: tk.severity });
    edges.push({ source: "target-root", target: tkId, label: "dangling CNAME" });
  }

  // Add Content leaks
  for (const ct of content.slice(0, 3)) {
    const ctId = `node-ct-${ct.id}`;
    nodes.push({ id: ctId, label: ct.title, kind: "content", severity: ct.severity });
    edges.push({ source: "target-root", target: ctId, label: "exposed path" });
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
