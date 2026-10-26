import type { AttackVector, Finding, Severity } from "../types";

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
  const raw =
    counts.critical * 28 +
    counts.high * 16 +
    counts.medium * 7 +
    counts.low * 2 +
    counts.info * 0.5;
  return Math.min(100, Math.round(raw));
}

export function synthesizeAttackVectors(findings: Finding[]): AttackVector[] {
  const vectors: AttackVector[] = [];
  const cves = findings.filter((f) => f.kind === "cve");
  const ports = findings.filter((f) => f.kind === "port");
  const subdomains = findings.filter((f) => f.kind === "subdomain");
  const tech = findings.filter((f) => f.kind === "tech");

  // 1. Critical RCE / Exploit Surface
  const criticalCves = cves.filter((c) => c.severity === "critical" || (c.cvss && c.cvss >= 9.0));
  if (criticalCves.length > 0) {
    vectors.push({
      id: "vec-rce",
      title: "Remote Code Execution via High-Severity CVEs",
      severity: "critical",
      description: `Identified ${criticalCves.length} critical vulnerability with CVSS >= 9.0 (including ${criticalCves[0]?.cveId || "known CVE"}). Exploitation could allow arbitrary command execution on target infrastructure.`,
      findings: criticalCves,
      remediation: "Immediately patch affected packages or apply emergency vendor hotfixes. Restrict perimeter access using firewall or VPN.",
    });
  }

  // 2. Unauthenticated Database or In-Memory Cache Exposure
  const dbPorts = ports.filter((p) => [3306, 5432, 6379, 27017, 1433, 9200, 11211].includes(p.port || 0));
  if (dbPorts.length > 0) {
    vectors.push({
      id: "vec-db-exposure",
      title: "Public Database / Cache Service Exposure",
      severity: "critical",
      description: `Database and caching ports (${dbPorts.map((p) => `${p.port}/${p.service}`).join(", ")}) are directly accessible from the public internet. This creates severe risk of unauthorized data dumping, database manipulation, or unauthenticated RCE (e.g. Redis Lua sandbox escape).`,
      findings: dbPorts,
      remediation: "Bind database listeners to localhost/private VPC only (127.0.0.1). Enforce strict security group firewall rules preventing direct public internet inbound.",
    });
  }

  // 3. Attack Surface Expansion via Subdomain Proliferation
  const sensitiveSubs = subdomains.filter((s) => /staging|admin|internal|vpn|dev|corp|portal/.test(s.title.toLowerCase()));
  if (sensitiveSubs.length > 0) {
    vectors.push({
      id: "vec-subdomains",
      title: "Non-Production & Administrative Subdomains Publicly Resolvable",
      severity: "high",
      description: `Discovered active subdomains indicative of development, staging, or internal management environments: ${sensitiveSubs.map((s) => s.title.replace("Discovered Subdomain: ", "")).slice(0, 4).join(", ")}. These environments frequently exhibit weaker credentials or unpatched debug code.`,
      findings: sensitiveSubs,
      remediation: "Migrate non-production endpoints behind authenticated zero-trust access proxies or an internal corporate VPN. Remove unnecessary external DNS records.",
    });
  }

  // 4. Missing Web Anti-Clickjacking & XSS Defenses
  const missingHeaders = tech.filter((t) => t.title.includes("Missing"));
  if (missingHeaders.length >= 2) {
    vectors.push({
      id: "vec-web-headers",
      title: "Client-Side Exploit Surface (Weak Security Headers)",
      severity: "medium",
      description: `The application fails to declare critical browser security headers (${missingHeaders.map((m) => m.title.replace("Missing ", "")).join(", ")}). Users are vulnerable to iframe clickjacking, SSL stripping, and cross-site scripting propagation.`,
      findings: missingHeaders,
      remediation: "Deploy a strict Content-Security-Policy, enforce X-Frame-Options: SAMEORIGIN, and configure Strict-Transport-Security on the reverse proxy.",
    });
  }

  // 5. General Attack Surface if ports open
  if (ports.length > 0 && vectors.length === 0) {
    vectors.push({
      id: "vec-general-exposure",
      title: "Public Network Perimeter Services Exposed",
      severity: "medium",
      description: `Target maintains ${ports.length} open network ports accessible to external scanners. Each service represents an entry point for automated credential bruteforcing or service-specific exploits.`,
      findings: ports,
      remediation: "Review open ports against business requirements and close all unnecessary services at the edge firewall.",
    });
  }

  return vectors;
}
