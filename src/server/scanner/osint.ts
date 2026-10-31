import type { Finding } from "../types";

export interface OsintResult {
  findings: Finding[];
  logs: string[];
}

export async function runOsintAudit(
  target: string,
  onLog?: (line: string) => void
): Promise<OsintResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  function emit(msg: string) {
    logs.push(msg);
    if (onLog) onLog(msg);
  }

  const host = target.replace(/^https?:\/\//i, "").split(/[/:]/)[0] || target;
  const domain = host.split(".").slice(-2).join(".") || host;

  emit(`[osint] Initiating passive OSINT exposure correlation for domain '${domain}'`);

  try {
    // 1. RDAP Domain Registration query
    const rdapUrl = `https://rdap.org/domain/${domain}`;
    const res = await fetch(rdapUrl, { signal: AbortSignal.timeout(3500) }).catch(() => null);

    if (res && res.status === 200) {
      const rdap = await res.json().catch(() => null);
      if (rdap && rdap.ldhName) {
        const events = rdap.events || [];
        const regEvent = events.find((e: { eventAction: string }) => e.eventAction === "registration");
        const expEvent = events.find((e: { eventAction: string }) => e.eventAction === "expiration");

        emit(`[osint] RDAP resolved: ${rdap.ldhName} (Reg: ${regEvent?.eventDate || "N/A"}, Exp: ${expEvent?.eventDate || "N/A"})`);
        findings.push({
          id: `osint-rdap-${Date.now()}`,
          agent: "osint-recon",
          kind: "osint",
          severity: "info",
          title: `Domain Registration Metadata (${domain})`,
          detail: `Registrar metadata registered on ${regEvent?.eventDate || "unknown"}. Expiration: ${expEvent?.eventDate || "unknown"}.`,
          tags: ["osint", "whois", "rdap", "domain"],
          confidence: 100,
          note: "Track domain renewal dates to prevent hostile expiry acquisition.",
        });
      }
    }

    // 2. Security.txt vulnerability contact check
    const secUrl = `https://${host}/.well-known/security.txt`;
    const secRes = await fetch(secUrl, { signal: AbortSignal.timeout(2500) }).catch(() => null);
    if (secRes && secRes.status === 200) {
      const secText = await secRes.text().catch(() => "");
      if (secText.includes("Contact:")) {
        emit(`[osint] Valid security.txt vulnerability disclosure file located at /.well-known/security.txt`);
        findings.push({
          id: `osint-sectxt-${Date.now()}`,
          agent: "osint-recon",
          kind: "osint",
          severity: "info",
          title: "RFC 9116 security.txt Policy Present",
          detail: `Responsible disclosure contacts published at /.well-known/security.txt.`,
          tags: ["osint", "security.txt", "compliance"],
          confidence: 100,
          note: "Positive defense signal: operator maintains formal security contact policy.",
        });
      }
    } else {
      findings.push({
        id: `osint-nosectxt-${Date.now()}`,
        agent: "osint-recon",
        kind: "osint",
        severity: "low",
        title: "Missing RFC 9116 security.txt Vulnerability Policy",
        detail: "No security.txt found at /.well-known/security.txt to direct security researchers.",
        tags: ["osint", "security.txt", "best-practice"],
        confidence: 90,
        note: "Publish /.well-known/security.txt to standardise security disclosure channels.",
      });
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    emit(`[osint] OSINT correlation completed: ${msg}`);
  }

  return { findings, logs };
}
