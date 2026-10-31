import type { Finding } from "../types";

export interface WafCdnResult {
  detected: boolean;
  provider?: string | undefined;
  findings: Finding[];
  logs: string[];
}

export async function runWafCdnAudit(
  target: string,
  onLog?: (line: string) => void
): Promise<WafCdnResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  function emit(msg: string) {
    logs.push(msg);
    if (onLog) onLog(msg);
  }

  const host = target.replace(/^https?:\/\//i, "").split(/[/:]/)[0];
  const url = `https://${host}`;

  emit(`[waf_cdn] Probing edge perimeter signatures on ${url}`);

  let detected = false;
  let provider: string | undefined;

  try {
    const res = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Flibo/2.0",
      },
      signal: AbortSignal.timeout(4000),
    });

    const headers = res.headers;
    const server = headers.get("server")?.toLowerCase() || "";
    const cfRay = headers.get("cf-ray");
    const akamai = headers.get("x-akamai-transformed") || headers.get("akamai-origin-hop");
    const fastly = headers.get("fastly-restarts") || headers.get("x-fastly-request-id");
    const cloudfront = headers.get("x-amz-cf-id") || headers.get("x-amz-cf-pop");
    const sucuri = headers.get("x-sucuri-id");

    if (cfRay || server.includes("cloudflare")) {
      detected = true;
      provider = "Cloudflare";
    } else if (akamai || server.includes("akamai")) {
      detected = true;
      provider = "Akamai";
    } else if (cloudfront || server.includes("cloudfront")) {
      detected = true;
      provider = "AWS CloudFront / AWS WAF";
    } else if (fastly || server.includes("fastly")) {
      detected = true;
      provider = "Fastly";
    } else if (sucuri || server.includes("sucuri")) {
      detected = true;
      provider = "Sucuri WAF";
    }

    if (detected && provider) {
      emit(`[waf_cdn] Positive edge detection: ${provider} active fronting target`);
      findings.push({
        id: `waf-${Date.now()}`,
        agent: "waf-cdn",
        kind: "waf",
        severity: "info",
        title: `Edge WAF / CDN Identified (${provider})`,
        detail: `Target is fronted by ${provider}. Probes will operate with WAF-adaptive timing.`,
        tags: ["waf", "cdn", "edge", provider.toLowerCase()],
        confidence: 99,
        note: "Origin IP may be masked behind CDN. Check historical DNS for real IP exposure.",
      });
    } else {
      emit(`[waf_cdn] No dominant commercial WAF signatures detected in response headers`);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    emit(`[waf_cdn] Edge probe encounter: ${msg}`);
  }

  return { detected, provider, findings, logs };
}
