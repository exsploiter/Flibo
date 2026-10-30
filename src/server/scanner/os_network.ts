import { exec } from "node:child_process";
import { promisify } from "node:util";
import type { Finding } from "../types";

const execAsync = promisify(exec);

export interface NetworkOsResult {
  findings: Finding[];
  logs: string[];
}

export async function runNetworkOsScan(
  target: string,
  onLog?: (line: string) => void
): Promise<NetworkOsResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  function emit(msg: string) {
    logs.push(msg);
    if (onLog) onLog(msg);
  }

  const host = target.replace(/^https?:\/\//i, "").split(/[/:]/)[0];
  emit(`[os_network] Gathering network routing, hop distance, and nmap provider capabilities for ${host}`);

  // 1. Check if nmap binary is available
  let nmapAvailable = false;
  try {
    const { stdout } = await execAsync("nmap --version");
    if (stdout.includes("Nmap version")) {
      nmapAvailable = true;
      const version = stdout.split("\n")[0].trim();
      emit(`[os_network] Native host nmap provider detected: ${version}`);
      findings.push({
        id: `net-nmap-${Date.now()}`,
        agent: "os-network",
        kind: "os",
        severity: "info",
        title: "Host Nmap Binary Available",
        detail: `External scanner provider active: ${version}. Advanced NSE script profiles enabled.`,
        tags: ["nmap", "provider", "scanner"],
        confidence: 100,
        note: "Flibo can leverage host nmap for enhanced -sV and -O fingerprint passes.",
      });
    }
  } catch {
    emit(`[os_network] Native nmap binary not in PATH — utilizing built-in raw TCP socket engine`);
  }

  // 2. ASN / IP info lookup
  try {
    const ipRes = await fetch(`https://ipapi.co/${host}/json/`, { signal: AbortSignal.timeout(3000) }).catch(() => null);
    if (ipRes && ipRes.status === 200) {
      const geo = await ipRes.json().catch(() => null);
      if (geo && geo.org) {
        emit(`[os_network] Network Autonomous System: ${geo.asn || "N/A"} (${geo.org}), Country: ${geo.country_name || "N/A"}`);
        findings.push({
          id: `net-asn-${Date.now()}`,
          agent: "os-network",
          kind: "os",
          severity: "info",
          title: `Network Infrastructure (${geo.org})`,
          detail: `Target routed through ASN ${geo.asn || "N/A"} (${geo.org}). Location: ${geo.city || "Unknown"}, ${geo.country_name || ""}.`,
          tags: ["network", "asn", "routing"],
          confidence: 95,
          note: "Confirm scope boundary against ASN ownership before broad port sweep.",
        });
      }
    }
  } catch {
    // Continue
  }

  return { findings, logs };
}
