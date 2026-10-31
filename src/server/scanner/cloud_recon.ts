import type { Finding } from "../types";

export interface CloudReconResult {
  findings: Finding[];
  logs: string[];
}

export async function runCloudRecon(
  target: string,
  onLog?: (line: string) => void
): Promise<CloudReconResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  function emit(msg: string) {
    logs.push(msg);
    if (onLog) onLog(msg);
  }

  const host = target.replace(/^https?:\/\//i, "").split(/[/:]/)[0] || target;
  const nameBase = host.split(".")[0] || host;

  emit(`[cloud_recon] Auditing cloud storage permutations for '${nameBase}'`);

  const s3Buckets = [
    `http://${nameBase}.s3.amazonaws.com`,
    `http://${nameBase}-assets.s3.amazonaws.com`,
    `http://${nameBase}-backup.s3.amazonaws.com`,
  ];

  for (const bUrl of s3Buckets) {
    try {
      const res = await fetch(bUrl, {
        method: "GET",
        signal: AbortSignal.timeout(2500),
      });

      if (res.status === 200) {
        const text = await res.text();
        if (text.includes("<ListBucketResult>")) {
          emit(`[cloud_recon] Critical: S3 Bucket ${bUrl} is publicly listable!`);
          findings.push({
            id: `cloud-s3-${Date.now()}`,
            agent: "cloud-recon",
            kind: "cloud",
            severity: "critical",
            title: `Publicly Listable AWS S3 Bucket (${bUrl})`,
            detail: `The S3 bucket permits anonymous read and directory listing of uploaded assets.`,
            tags: ["cloud", "aws", "s3", "storage", "leak"],
            mitreTechnique: "T1530 - Data from Cloud Storage Object",
            confidence: 100,
            compliance: { cis: "2.1.5", owasp: "A01:2021-Broken Access Control" },
            note: "Enforce S3 Block Public Access (BPA) and lock bucket ACLs.",
          });
        }
      } else if (res.status === 403) {
        emit(`[cloud_recon] S3 Bucket exists but access is forbidden (Protected)`);
      }
    } catch {
      // Timeout or DNS failure
    }
  }

  return { findings, logs };
}
