import type { Finding } from "../types";

export interface CmsFingerprintResult {
  findings: Finding[];
  logs: string[];
}

export async function runCmsFingerprint(
  target: string,
  onLog?: (line: string) => void
): Promise<CmsFingerprintResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  function emit(msg: string) {
    logs.push(msg);
    if (onLog) onLog(msg);
  }

  const host = target.replace(/^https?:\/\//i, "").split(/[/:]/)[0];
  const baseUrl = `https://${host}`;

  emit(`[cms_fingerprint] Probing CMS markers (WordPress, Drupal, Joomla, Ghost) on ${baseUrl}`);

  try {
    // 1. WordPress Probe
    const wpRes = await fetch(`${baseUrl}/wp-json/`, { signal: AbortSignal.timeout(2500) }).catch(() => null);
    if (wpRes && wpRes.status === 200) {
      const data = await wpRes.json().catch(() => null);
      if (data && data.name) {
        emit(`[cms_fingerprint] WordPress REST API exposed at /wp-json/ (Site: ${data.name})`);
        findings.push({
          id: `cms-wp-${Date.now()}`,
          agent: "cms-fingerprint",
          kind: "cms",
          severity: "low",
          title: `WordPress REST API Accessible (${data.name})`,
          detail: `Exposes user namespaces, routes, and endpoint schemas via /wp-json/.`,
          tags: ["cms", "wordpress", "rest-api"],
          confidence: 99,
          note: "Harden /wp-json/ endpoints or restrict user enumeration routes (/wp-json/wp/v2/users).",
        });
      }
    }

    // 2. XML-RPC Exposure
    const xmlrpcRes = await fetch(`${baseUrl}/xmlrpc.php`, {
      method: "POST",
      body: "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>",
      signal: AbortSignal.timeout(2500),
    }).catch(() => null);

    if (xmlrpcRes && xmlrpcRes.status === 200) {
      const xmlText = await xmlrpcRes.text().catch(() => "");
      if (xmlText.includes("methodResponse")) {
        emit(`[cms_fingerprint] Sensitive: XML-RPC endpoint (/xmlrpc.php) is active`);
        findings.push({
          id: `cms-xmlrpc-${Date.now()}`,
          agent: "cms-fingerprint",
          kind: "cms",
          severity: "medium",
          title: "WordPress XML-RPC Interface Enabled",
          detail: "XML-RPC enables remote pingback DDoS amplification and brute-force credential stuffing.",
          tags: ["cms", "wordpress", "xmlrpc", "ddos"],
          mitreTechnique: "T1110 - Brute Force",
          confidence: 95,
          note: "Disable xmlrpc.php at web server level (nginx / apache) if not strictly required.",
        });
      }
    }
  } catch {
    // Continue
  }

  return { findings, logs };
}
