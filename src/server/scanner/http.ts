import type { Finding } from "../types";

export interface HttpScanOptions {
  target: string;
  intensity: "quick" | "standard" | "deep";
  onProgress: (pct: number) => void;
  onLog: (line: string) => void;
  shouldStop: () => boolean;
}

function cleanUrl(raw: string): { httpsUrl: string; httpUrl: string; host: string } {
  let host = raw.trim();
  if (host.startsWith("http://") || host.startsWith("https://")) {
    try {
      const u = new URL(host);
      host = u.host;
    } catch {
      // fallback
    }
  }
  return {
    httpsUrl: `https://${host}`,
    httpUrl: `http://${host}`,
    host,
  };
}

export async function runHttpScan(options: HttpScanOptions): Promise<Finding[]> {
  const { httpsUrl, httpUrl, host } = cleanUrl(options.target);
  const findings: Finding[] = [];

  options.onLog(`[TechFingerprint] Probing web targets for ${host}`);
  options.onProgress(10);

  let activeUrl = httpsUrl;
  let res: Response | null = null;

  // 1. Try HTTPS first, then HTTP fallback
  try {
    options.onLog(`[TechFingerprint] Sending HTTPS request to ${httpsUrl}`);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    res = await fetch(httpsUrl, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 FliboRecon/2.0",
      },
    });
    clearTimeout(timeout);
  } catch (httpsErr) {
    options.onLog(`[TechFingerprint] HTTPS connection failed (${String(httpsErr)}), falling back to plaintext HTTP`);
    try {
      activeUrl = httpUrl;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      res = await fetch(httpUrl, {
        signal: controller.signal,
        redirect: "follow",
        headers: { "User-Agent": "FliboRecon/2.0" },
      });

      clearTimeout(timeout);

      findings.push({
        id: `find-plaintext-http-${Date.now()}`,
        agent: "tech-fingerprint",
        kind: "tech",
        severity: "medium",
        title: "Plaintext HTTP In Use (No HTTPS)",
        detail: `The service only responds over unencrypted HTTP (${httpUrl}). Traffic is vulnerable to interception and MITM attacks.`,
        tags: ["http", "cleartext", "encryption"],
        note: "Deploy TLS certificate and enforce automatic HTTPS redirection.",
      });
    } catch (httpErr) {
      options.onLog(`[TechFingerprint] Host did not respond to standard HTTP/HTTPS probes: ${String(httpErr)}`);
    }
  }

  options.onProgress(40);

  if (!res) {
    options.onLog(`[TechFingerprint] No HTTP response received from ${host}`);
    options.onProgress(100);
    return findings;
  }

  options.onLog(`[TechFingerprint] HTTP probe responded: status ${res.status} (${res.statusText})`);

  // 2. Analyze Server and Tech Headers
  const serverHeader = res.headers.get("server");
  if (serverHeader) {
    options.onLog(`[TechFingerprint] [+] Web Server Detected: ${serverHeader}`);
    findings.push({
      id: `find-server-hdr-${Date.now()}`,
      agent: "tech-fingerprint",
      kind: "tech",
      severity: "info",
      title: `Web Server: ${serverHeader}`,
      service: "http",
      banner: serverHeader,
      detail: `Server banner exposed in HTTP headers: '${serverHeader}'. Version disclosure assists attackers in fingerprinting target vulnerabilities.`,
      tags: ["server", "tech", "fingerprint"],
      note: "Consider masking or stripping the Server header token in production.",
    });
  }

  const poweredBy = res.headers.get("x-powered-by");
  if (poweredBy) {
    options.onLog(`[TechFingerprint] [+] Technology Disclosed: X-Powered-By: ${poweredBy}`);
    findings.push({
      id: `find-powered-by-${Date.now()}`,
      agent: "tech-fingerprint",
      kind: "tech",
      severity: "low",
      title: `Technology Disclosed: ${poweredBy}`,
      service: poweredBy,
      banner: poweredBy,
      detail: `Backend technology framework exposed via X-Powered-By header: '${poweredBy}'.`,
      tags: ["tech", "framework", "information-disclosure"],
      note: "Disable X-Powered-By header in application server configuration.",
    });
  }

  // 3. Security Headers Audit
  options.onLog(`[TechFingerprint] Evaluating security headers configuration...`);

  // HSTS
  if (activeUrl.startsWith("https://")) {
    const hsts = res.headers.get("strict-transport-security");
    if (!hsts) {
      options.onLog(`[TechFingerprint] [-] Missing HSTS (Strict-Transport-Security)`);
      findings.push({
        id: `find-hsts-${Date.now()}`,
        agent: "tech-fingerprint",
        kind: "tech",
        severity: "medium",
        title: "Missing Strict-Transport-Security (HSTS)",
        detail: "The web application does not implement HSTS, leaving users vulnerable to SSL stripping and man-in-the-middle attacks.",
        tags: ["security-headers", "hsts", "ssl-tls"],
        note: "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      });
    } else {
      options.onLog(`[TechFingerprint] [+] HSTS enabled: ${hsts}`);
    }
  }

  // Content-Security-Policy
  const csp = res.headers.get("content-security-policy");
  if (!csp) {
    options.onLog(`[TechFingerprint] [-] Missing Content-Security-Policy (CSP)`);
    findings.push({
      id: `find-csp-${Date.now()}`,
      agent: "tech-fingerprint",
      kind: "tech",
      severity: "low",
      title: "Missing Content-Security-Policy (CSP)",
      detail: "No Content-Security-Policy header detected. CSP mitigates Cross-Site Scripting (XSS) and data injection attacks.",
      tags: ["security-headers", "csp", "xss-mitigation"],
      note: "Implement a restrictive Content-Security-Policy restricting script-src, object-src, and default-src.",
    });
  }

  // X-Frame-Options (Clickjacking)
  const xfo = res.headers.get("x-frame-options");
  if (!xfo && (!csp || !csp.includes("frame-ancestors"))) {
    options.onLog(`[TechFingerprint] [-] Missing Anti-Clickjacking (X-Frame-Options)`);
    findings.push({
      id: `find-xfo-${Date.now()}`,
      agent: "tech-fingerprint",
      kind: "tech",
      severity: "medium",
      title: "Missing Anti-Clickjacking Protection",
      detail: "The application lacks an X-Frame-Options or CSP frame-ancestors directive, allowing attackers to embed the page in malicious iframes.",
      tags: ["security-headers", "clickjacking", "ui-redressing"],
      note: "Configure header: X-Frame-Options: SAMEORIGIN or DENY.",
    });
  }

  // X-Content-Type-Options
  const xcto = res.headers.get("x-content-type-options");
  if (!xcto || !xcto.includes("nosniff")) {
    findings.push({
      id: `find-xcto-${Date.now()}`,
      agent: "tech-fingerprint",
      kind: "tech",
      severity: "low",
      title: "Missing X-Content-Type-Options Header",
      detail: "Missing 'X-Content-Type-Options: nosniff' header allows browsers to perform MIME-type sniffing, which can lead to script execution.",
      tags: ["security-headers", "mime-sniffing"],
      note: "Add header: X-Content-Type-Options: nosniff.",
    });
  }

  options.onProgress(70);

  // 4. HTML Body Fingerprinting & Framework Detection
  try {
    const text = await res.text();
    const detectedFrameworks: string[] = [];

    if (text.includes("react") || text.includes("_react") || text.includes("__NEXT_DATA__") || text.includes("next/router")) {
      detectedFrameworks.push("React / Next.js");
    }
    if (text.includes("vue") || text.includes("__VUE__") || text.includes("nuxt")) {
      detectedFrameworks.push("Vue / Nuxt.js");
    }
    if (text.includes("wp-content") || text.includes("wordpress") || text.includes("wp-includes")) {
      detectedFrameworks.push("WordPress CMS");
    }
    if (text.includes("tailwind") || text.includes("tw-")) {
      detectedFrameworks.push("Tailwind CSS");
    }
    if (text.includes("bootstrap") || text.includes("navbar-collapse")) {
      detectedFrameworks.push("Bootstrap");
    }
    if (text.includes("jquery")) {
      detectedFrameworks.push("jQuery");
    }

    // Title tag
    const titleMatch = text.match(/<title[^>]*>([^<]+)<\/title>/i);
    const pageTitle = titleMatch ? titleMatch[1]?.trim() : undefined;

    for (const fw of detectedFrameworks) {
      options.onLog(`[TechFingerprint] [+] Client Stack: ${fw} identified`);
      findings.push({
        id: `find-fw-${fw.toLowerCase().replace(/[^a-z0-9]/g, "")}-${Date.now()}`,
        agent: "tech-fingerprint",
        kind: "tech",
        severity: "info",
        title: `Client Stack: ${fw}`,
        detail: `Client-side application utilizes ${fw}.${pageTitle ? ` Page title: "${pageTitle}".` : ""}`,
        tags: ["tech", "frontend", "framework"],
        note: `Fingerprinted from HTML structure and script bundles.`,
      });
    }
  } catch {
    // text reading error
  }

  options.onProgress(85);

  // 5. Probe Recon Endpoints (/robots.txt)
  try {
    options.onLog(`[TechFingerprint] Probing ${activeUrl}/robots.txt...`);
    const robotsRes = await fetch(`${activeUrl}/robots.txt`, {
      headers: { "User-Agent": "FliboRecon/2.0" },
    }).catch(() => null);


    if (robotsRes && robotsRes.ok) {
      const robotsTxt = await robotsRes.text();
      const disallows = robotsTxt
        .split("\n")
        .filter((l) => l.toLowerCase().startsWith("disallow:"))
        .map((l) => l.split(":")[1]?.trim())
        .filter(Boolean);

      if (disallows.length > 0) {
        options.onLog(`[TechFingerprint] [+] robots.txt found with ${disallows.length} Disallow directives: ${disallows.slice(0, 3).join(", ")}...`);
        findings.push({
          id: `find-robots-${Date.now()}`,
          agent: "tech-fingerprint",
          kind: "tech",
          severity: "info",
          title: "Robots.txt Disclosed Endpoints",
          detail: `Found ${disallows.length} restricted paths listed in robots.txt: ${disallows.slice(0, 8).join(", ")}. These paths frequently highlight administrative or internal endpoints.`,
          tags: ["recon", "robots.txt", "endpoints"],
          note: `Disallow sample: ${disallows.slice(0, 5).join(", ")}`,
        });
      }
    }
  } catch {
    // ignore
  }

  options.onProgress(100);
  options.onLog(`[TechFingerprint] Completed tech stack analysis (${findings.length} findings generated)`);
  return findings;
}
