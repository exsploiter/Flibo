import type { Finding } from "../types";

export interface ApiDiscoveryResult {
  findings: Finding[];
  logs: string[];
}

export async function runApiDiscovery(
  target: string,
  onLog?: (line: string) => void
): Promise<ApiDiscoveryResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  function emit(msg: string) {
    logs.push(msg);
    if (onLog) onLog(msg);
  }

  const host = target.replace(/^https?:\/\//i, "").split(/[/:]/)[0];
  const baseUrl = `https://${host}`;

  emit(`[api_discovery] Mapping API & GraphQL attack surface on ${baseUrl}`);

  // 1. OpenAPI / Swagger check
  const apiPaths = ["/openapi.json", "/swagger.json", "/api-docs", "/v1/api-docs"];
  for (const path of apiPaths) {
    try {
      const res = await fetch(`${baseUrl}${path}`, {
        headers: { "User-Agent": "Flibo-SecOps/2.0" },
        signal: AbortSignal.timeout(2500),
      });
      if (res.status === 200) {
        const json = await res.json().catch(() => null);
        if (json && (json.openapi || json.swagger || json.paths)) {
          const endpointCount = Object.keys(json.paths || {}).length;
          emit(`[api_discovery] OpenAPI schema discovered at ${path} with ${endpointCount} endpoints`);
          findings.push({
            id: `api-spec-${Date.now()}`,
            agent: "api-discovery",
            kind: "api",
            severity: "medium",
            title: `Exposed OpenAPI / Swagger Specification (${endpointCount} routes)`,
            detail: `Public API documentation available at ${path}. Contains schemas and parameters.`,
            tags: ["api", "openapi", "documentation"],
            mitreTechnique: "T1592 - Gather Victim Host Information",
            confidence: 95,
            note: "Restrict API documentation to authenticated developers or internal gateways.",
          });
          break;
        }
      }
    } catch {
      // Continue
    }
  }

  // 2. GraphQL Introspection Probe
  try {
    const gqlUrl = `${baseUrl}/graphql`;
    const res = await fetch(gqlUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Flibo-SecOps/2.0",
      },
      body: JSON.stringify({
        query: "{ __schema { types { name } } }",
      }),
      signal: AbortSignal.timeout(3000),
    });

    if (res.status === 200) {
      const data = await res.json().catch(() => null);
      if (data?.data?.__schema?.types) {
        const typesCount = data.data.__schema.types.length;
        emit(`[api_discovery] GraphQL introspection enabled: ${typesCount} schema types enumerated`);
        findings.push({
          id: `gql-intro-${Date.now()}`,
          agent: "api-discovery",
          kind: "api",
          severity: "high",
          title: "GraphQL Introspection Enabled in Production",
          detail: `GraphQL endpoint at /graphql responded to introspection with ${typesCount} data types.`,
          tags: ["api", "graphql", "introspection", "misconfig"],
          mitreTechnique: "T1592.004 - Client Configurations",
          confidence: 98,
          compliance: { owasp: "A05:2021-Security Misconfiguration" },
          note: "Disable GraphQL introspection in production builds to prevent schema leakage.",
        });
      }
    }
  } catch {
    // Continue
  }

  return { findings, logs };
}
