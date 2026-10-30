import * as tls from "node:tls";
import type { Finding } from "../types";

export interface SslAuditResult {
  findings: Finding[];
  logs: string[];
}

export async function runSslAudit(
  target: string,
  onLog?: (line: string) => void
): Promise<SslAuditResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  function emit(msg: string) {
    logs.push(msg);
    if (onLog) onLog(msg);
  }

  const hostname = target.replace(/^https?:\/\//i, "").split(/[/:]/)[0];
  const port = 443;

  emit(`[ssl_deep] Initiating deep TLS handshake on ${hostname}:${port}`);

  try {
    const socket = await new Promise<tls.TLSSocket>((resolve, reject) => {
      const sock = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          rejectUnauthorized: false,
          timeout: 4000,
        },
        () => resolve(sock)
      );
      sock.on("error", reject);
      sock.on("timeout", () => {
        sock.destroy();
        reject(new Error("TLS connection timed out"));
      });
    });

    const cert = socket.getPeerCertificate(true);
    const cipher = socket.getCipher();
    const protocol = socket.getProtocol();

    socket.end();

    emit(`[ssl_deep] Negotiated ${protocol} with cipher ${cipher.name} (${cipher.standardName || "N/A"})`);

    if (protocol === "TLSv1" || protocol === "TLSv1.1") {
      findings.push({
        id: `ssl-legacy-${Date.now()}`,
        agent: "ssl-deep",
        kind: "tls",
        severity: "high",
        title: `Obsolete Protocol Enabled (${protocol})`,
        detail: `The host permits negotiation of deprecated protocol ${protocol}, vulnerable to downgrade attacks.`,
        port: 443,
        service: "https",
        tags: ["tls", "deprecated", "compliance"],
        compliance: { owasp: "A02:2021-Cryptographic Failures", cis: "3.1" },
        mitreTechnique: "T1040 - Network Sniffing",
        confidence: 98,
        note: "Disable TLS 1.0 and 1.1; enforce TLS 1.2 and TLS 1.3 only.",
      });
    }

    if (cert && cert.valid_to) {
      const expiry = new Date(cert.valid_to).getTime();
      const daysRemaining = Math.round((expiry - Date.now()) / (1000 * 60 * 60 * 24));
      emit(`[ssl_deep] Certificate CN: ${cert.subject?.CN || "Unknown"}, expires in ${daysRemaining} days`);

      if (daysRemaining < 15) {
        findings.push({
          id: `ssl-expiry-${Date.now()}`,
          agent: "ssl-deep",
          kind: "tls",
          severity: daysRemaining <= 0 ? "critical" : "medium",
          title: daysRemaining <= 0 ? "TLS Certificate Expired" : `TLS Certificate Expiring Soon (${daysRemaining}d)`,
          detail: `Certificate for ${cert.subject?.CN} expires on ${cert.valid_to}.`,
          port: 443,
          tags: ["tls", "certificate", "expiration"],
          confidence: 100,
          note: "Renew certificate immediately to prevent client connection failures.",
        });
      }

      // Extract SANs
      if (cert.subjectaltname) {
        const sans = cert.subjectaltname
          .split(",")
          .map((s) => s.trim().replace(/^DNS:/, ""))
          .filter(Boolean);
        emit(`[ssl_deep] Extracted ${sans.length} Subject Alternative Names (SANs)`);

        findings.push({
          id: `ssl-san-${Date.now()}`,
          agent: "ssl-deep",
          kind: "tls",
          severity: "info",
          title: `TLS SAN Perimeter (${sans.length} hostnames)`,
          detail: `Hostnames declared: ${sans.slice(0, 10).join(", ")}${sans.length > 10 ? "..." : ""}`,
          port: 443,
          tags: ["tls", "san", "recon"],
          confidence: 95,
          note: "Cross-reference SAN names for secondary perimeter targets.",
        });
      }
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    emit(`[ssl_deep] Port 443 TLS audit non-conclusive: ${msg}`);
  }

  return { findings, logs };
}
