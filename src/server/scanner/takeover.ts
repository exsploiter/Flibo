import * as dns from "node:dns/promises";
import type { Finding } from "../types";

export interface TakeoverResult {
  findings: Finding[];
  logs: string[];
}

const TAKEOVER_FINGERPRINTS = [
  { cnamePattern: "github.io", errorSignature: "There isn't a GitHub Pages site here", service: "GitHub Pages" },
  { cnamePattern: "herokuapp.com", errorSignature: "No such app", service: "Heroku" },
  { cnamePattern: "myshopify.com", errorSignature: "Sorry, this shop is currently unavailable", service: "Shopify" },
  { cnamePattern: "s3.amazonaws.com", errorSignature: "NoSuchBucket", service: "AWS S3" },
  { cnamePattern: "azurewebsites.net", errorSignature: "404 Web Site not found", service: "Microsoft Azure" },
  { cnamePattern: "netlify.app", errorSignature: "Not Found - Request ID", service: "Netlify" },
];

export async function runSubdomainTakeover(
  subdomains: string[],
  onLog?: (line: string) => void
): Promise<TakeoverResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  function emit(msg: string) {
    logs.push(msg);
    if (onLog) onLog(msg);
  }

  emit(`[takeover] Evaluating ${subdomains.length} hostnames for dangling CNAME takeovers`);

  for (const host of subdomains.slice(0, 20)) {
    try {
      const cnames = await dns.resolveCname(host).catch(() => []);
      for (const cname of cnames) {
        for (const fp of TAKEOVER_FINGERPRINTS) {
          if (cname.toLowerCase().includes(fp.cnamePattern)) {
            emit(`[takeover] Dangling CNAME candidate: ${host} -> ${cname} (${fp.service})`);

            // Probe HTTP to verify orphaned service
            try {
              const res = await fetch(`http://${host}`, { signal: AbortSignal.timeout(3000) });
              const body = await res.text();
              if (body.includes(fp.errorSignature)) {
                emit(`[takeover] CRITICAL: Subdomain takeover confirmed on ${host}!`);
                findings.push({
                  id: `takeover-${Date.now()}`,
                  agent: "takeover-audit",
                  kind: "takeover",
                  severity: "critical",
                  title: `Subdomain Takeover Vulnerability (${fp.service})`,
                  detail: `Host ${host} points to unclaimed ${fp.service} resource (${cname}). An attacker can claim this name.`,
                  tags: ["takeover", "dns", "cname", fp.service.toLowerCase()],
                  mitreTechnique: "T1584.004 - Serverless / Cloud Hosting",
                  confidence: 96,
                  compliance: { owasp: "A05:2021-Security Misconfiguration" },
                  note: `Immediately remove CNAME record for ${host} or claim the corresponding ${fp.service} asset.`,
                });
              }
            } catch {
              // Ignore probe failure
            }
          }
        }
      }
    } catch {
      // Continue
    }
  }

  return { findings, logs };
}
