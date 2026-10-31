import dns from "node:dns/promises";
import type { Finding } from "../types";

export interface DnsScanOptions {
  target: string;
  intensity: "quick" | "standard" | "deep";
  onProgress: (pct: number) => void;
  onLog: (line: string) => void;
  shouldStop: () => boolean;
}

const COMMON_SUBDOMAINS = [
  "www", "api", "admin", "staging", "dev", "vpn", "mail", "app",
  "auth", "portal", "test", "cdn", "beta", "status", "git",
  "internal", "db", "docs", "remote", "corp", "k8s", "monitor"
];

function extractDomain(raw: string): string {
  let host = raw.trim();
  if (host.startsWith("http://") || host.startsWith("https://")) {
    try {
      const parsed = new URL(host);
      host = parsed.hostname;
    } catch {
      // fallback
    }
  }
  if (host.includes(":")) host = host.split(":")[0] || host;
  if (host.includes("/")) host = host.split("/")[0] || host;
  return host;
}

function isIpAddress(host: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":");
}

export async function runDnsScan(options: DnsScanOptions): Promise<Finding[]> {
  const host = extractDomain(options.target);
  const findings: Finding[] = [];

  options.onLog(`[DnsEnum] Starting DNS and Subdomain Reconnaissance for ${host}`);

  if (isIpAddress(host)) {
    options.onLog(`[DnsEnum] Target is an IP address — performing reverse PTR lookup`);
    try {
      const hostnames = await dns.reverse(host);
      if (hostnames && hostnames.length > 0) {
        options.onLog(`[DnsEnum] Reverse PTR resolved: ${hostnames.join(", ")}`);
        findings.push({
          id: `find-ptr-${Date.now()}`,
          agent: "subdomain-enum",
          kind: "subdomain",
          severity: "info",
          title: `Reverse DNS: ${hostnames[0]}`,
          detail: `IP ${host} reverses to ${hostnames.join(", ")}`,
          tags: ["dns", "ptr", "reverse-lookup"],
          note: `Reverse DNS lookup succeeded. Hostnames: ${hostnames.join(", ")}`,
        });
      }
    } catch (err) {
      options.onLog(`[DnsEnum] No PTR records found for ${host}`);
    }
    options.onProgress(100);
    return findings;
  }

  // 1. Resolve Root DNS Records (A, AAAA, MX, TXT)
  options.onLog(`[DnsEnum] Querying authoritative records (A, AAAA, MX, TXT)...`);
  options.onProgress(15);

  try {
    const aRecords = await dns.resolve4(host).catch(() => []);
    if (aRecords.length > 0) {
      options.onLog(`[DnsEnum] A records: ${aRecords.join(", ")}`);
    }

    const aaaaRecords = await dns.resolve6(host).catch(() => []);
    if (aaaaRecords.length > 0) {
      options.onLog(`[DnsEnum] AAAA records: ${aaaaRecords.join(", ")}`);
    }

    const mxRecords = await dns.resolveMx(host).catch(() => []);
    if (mxRecords.length > 0) {
      options.onLog(`[DnsEnum] MX mail exchangers: ${mxRecords.map((m) => `${m.exchange} (pri: ${m.priority})`).join(", ")}`);
    }

    // Check TXT for SPF and DMARC
    const txtRecords = await dns.resolveTxt(host).catch(() => []);
    const flatTxt = txtRecords.map((t) => t.join(""));
    const hasSpf = flatTxt.some((t) => t.includes("v=spf1"));
    if (!hasSpf) {
      options.onLog(`[DnsEnum] WARNING: Missing SPF record on ${host} (email spoofing risk)`);
      findings.push({
        id: `find-spf-${Date.now()}`,
        agent: "subdomain-enum",
        kind: "tech",
        severity: "medium",
        title: "Missing Email SPF Record",
        detail: `The domain ${host} lacks an SPF (Sender Policy Framework) record, allowing unauthorized senders to spoof emails from this domain.`,
        tags: ["dns", "spf", "email-security"],
        note: "Add a TXT record with 'v=spf1 mx -all' or appropriate mail relays.",
      });
    } else {
      options.onLog(`[DnsEnum] SPF record verified`);
    }

    // Check DMARC
    try {
      const dmarcTxt = await dns.resolveTxt(`_dmarc.${host}`).catch(() => []);
      const hasDmarc = dmarcTxt.some((t) => t.join("").includes("v=DMARC1"));
      if (!hasDmarc) {
        options.onLog(`[DnsEnum] WARNING: Missing DMARC record on _dmarc.${host}`);
        findings.push({
          id: `find-dmarc-${Date.now()}`,
          agent: "subdomain-enum",
          kind: "tech",
          severity: "low",
          title: "Missing DMARC Policy",
          detail: `Domain does not enforce DMARC (Domain-based Message Authentication, Reporting, and Conformance).`,
          tags: ["dns", "dmarc", "email-security"],
          note: "Configure '_dmarc' TXT record to enforce reject or quarantine policies.",
        });
      } else {
        options.onLog(`[DnsEnum] DMARC record found on _dmarc.${host}`);
      }
    } catch {
      // ignore
    }
  } catch (err) {
    options.onLog(`[DnsEnum] DNS query error: ${String(err)}`);
  }

  options.onProgress(35);

  // 2. Passive Certificate Transparency Enumeration (crt.sh)
  options.onLog(`[DnsEnum] Checking Certificate Transparency logs for historical subdomains...`);
  const discoveredSubdomains = new Set<string>();

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2800);
    const crtRes = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(host)}&output=json`, {
      signal: controller.signal,
      headers: { "User-Agent": "FliboReconBot/2.0" },
    }).catch(() => null);

    clearTimeout(timeout);

    if (crtRes && crtRes.ok) {
      const data = (await crtRes.json()) as Array<{ name_value?: string }>;
      if (Array.isArray(data)) {
        for (const item of data) {
          if (item.name_value) {
            const subs = item.name_value.split("\n");
            for (const sub of subs) {
              const clean = sub.trim().toLowerCase().replace(/^\*\./, "");
              if (clean.endsWith(host) && clean !== host) {
                discoveredSubdomains.add(clean);
              }
            }
          }
        }
        options.onLog(`[DnsEnum] Certificate Transparency logs yielded ${discoveredSubdomains.size} certificates`);
      }
    }
  } catch {
    options.onLog(`[DnsEnum] crt.sh CT lookup timed out or unavailable — falling back to active bruteforce`);
  }

  options.onProgress(55);

  // 3. Active DNS Bruteforce of Common Subdomains — run in parallel batches for speed
  const candidates = options.intensity === "deep" ? COMMON_SUBDOMAINS : COMMON_SUBDOMAINS.slice(0, 14);
  for (const prefix of candidates) {
    discoveredSubdomains.add(`${prefix}.${host}`);
  }

  const subList = Array.from(discoveredSubdomains);
  options.onLog(`[DnsEnum] Validating ${subList.length} candidate subdomains in parallel...`);

  let resolvedCount = 0;
  const BATCH = 8; // parallel DNS lookups per batch

    for (let i = 0; i < subList.length; i += BATCH) {
      if (options.shouldStop()) break;
          const batch = subList.slice(i, i + BATCH);
          const results = await Promise.allSettled(
            batch.map(async (sub) => {
              const ips = await dns.resolve4(sub);
              return { sub, ips };
            })
          );

          for (const r of results) {
            if (r.status === "fulfilled" && r.value.ips.length > 0) {
              const { sub, ips } = r.value;
              resolvedCount++;
              const isSensitive = /staging|admin|internal|vpn|dev|db|corp|auth/.test(sub);
              const severity = isSensitive ? "medium" : "info";
              options.onLog(`[DnsEnum] [+] RESOLVED: ${sub} -> [${ips.join(", ")}]`);
              findings.push({
                id: `find-sub-${sub}-${Date.now()}`,
                agent: "subdomain-enum",
                kind: "subdomain",
                severity,
                title: `Discovered Subdomain: ${sub}`,
                detail: `Active DNS resolution for ${sub} points to: ${ips.join(", ")}. ${isSensitive ? "High value target (administrative/internal/staging environment)." : ""
                  }`,
                tags: ["subdomain", "dns", isSensitive ? "sensitive-asset" : "public-asset"],
                note: `Resolved IPv4: ${ips.join(", ")}`,
              });
            }
          }

          options.onProgress(55 + Math.round(((i + BATCH) / subList.length) * 40));
        }

        options.onProgress(100);
        options.onLog(
          `[DnsEnum] Subdomain enumeration completed: ${resolvedCount} live subdomains confirmed active`
        );

        return findings;
      }
