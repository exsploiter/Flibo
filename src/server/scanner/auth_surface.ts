import type { Finding } from "../types";

export interface AuthSurfaceResult {
  findings: Finding[];
  logs: string[];
}

export async function runAuthSurfaceScan(
  target: string,
  onLog?: (line: string) => void
): Promise<AuthSurfaceResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  function emit(msg: string) {
    logs.push(msg);
    if (onLog) onLog(msg);
  }

  const host = target.replace(/^https?:\/\//i, "").split(/[/:]/)[0];
  const baseUrl = `https://${host}`;

  emit(`[auth_surface] Mapping authentication endpoints & session cookie security on ${baseUrl}`);

  try {
    const res = await fetch(baseUrl, {
      method: "GET",
      signal: AbortSignal.timeout(3500),
    });

    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie") || ""];

    for (const cookie of setCookies.filter(Boolean)) {
      const lower = cookie.toLowerCase();
      const name = cookie.split("=")[0].trim();

      const isSecure = lower.includes("secure");
      const isHttpOnly = lower.includes("httponly");
      const isSameSite = lower.includes("samesite");

      if (!isSecure || !isHttpOnly) {
        emit(`[auth_surface] Cookie '${name}' missing critical protection flags (Secure: ${isSecure}, HttpOnly: ${isHttpOnly})`);
        findings.push({
          id: `auth-cookie-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          agent: "auth-surface",
          kind: "auth",
          severity: "medium",
          title: `Insecure Session Cookie Flags (${name})`,
          detail: `Cookie '${name}' is issued without ${!isSecure ? "Secure" : ""} ${!isHttpOnly ? "HttpOnly" : ""} attributes.`,
          tags: ["auth", "cookie", "xss", "session"],
          mitreTechnique: "T1539 - Steal Web Session Cookie",
          compliance: { owasp: "A07:2021-Identification and Authentication Failures", cis: "3.2" },
          confidence: 100,
          note: "Set 'Secure', 'HttpOnly', and 'SameSite=Lax/Strict' flags on all session cookies.",
        });
      }
    }

    // Auth portals
    const authPaths = ["/login", "/signin", "/auth/login", "/oauth/authorize"];
    for (const path of authPaths) {
      try {
        const authRes = await fetch(`${baseUrl}${path}`, { signal: AbortSignal.timeout(2000) });
        if (authRes.status === 200) {
          emit(`[auth_surface] Identified active authentication entry point: ${path}`);
          findings.push({
            id: `auth-portal-${Date.now()}`,
            agent: "auth-surface",
            kind: "auth",
            severity: "info",
            title: `Active Authentication Endpoint (${path})`,
            detail: `Accessible login portal identified at ${path}.`,
            tags: ["auth", "portal", "login"],
            confidence: 90,
            note: "Ensure MFA enforcement, brute-force rate-limiting, and account lockout protections.",
          });
          break;
        }
      } catch {
        // Continue
      }
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    emit(`[auth_surface] Auth audit completed: ${msg}`);
  }

  return { findings, logs };
}
