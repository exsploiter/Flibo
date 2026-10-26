export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type AgentStatus = "queued" | "running" | "complete" | "failed";

export type ScanStatus =
  | "running"
  | "complete"
  | "partial"
  | "failed"
  | "cancelled";

export type FindingKind = "port" | "cve" | "subdomain" | "tech" | "os";

export interface LogLine {
  id: number;
  text: string;
}

export interface ScanAgent {
  id: string;
  name: string;
  status: AgentStatus;
  progress: number;
  logs: string[];
  error?: string | undefined;
}

export interface Finding {
  id: string;
  agent: string;
  kind: FindingKind;
  severity: Severity;
  title: string;
  detail?: string;
  port?: number;
  protocol?: "tcp" | "udp";
  service?: string;
  version?: string;
  banner?: string;
  cveId?: string;
  cvss?: number;
  description?: string;
  references?: { label: string; url: string }[];
  tags: string[];
  note: string;
}

export interface ScanConfig {
  intensity: "quick" | "standard" | "deep";
  agents: string[];
  ports: string;
  stealth: boolean;
  scheduled: string | null;
}

export interface Scan {
  id: string;
  name: string;
  target: string;
  targets: string[];
  tags: string[];
  config: ScanConfig;
  status: ScanStatus;
  paused?: boolean | undefined;
  createdAt: number;
  finishedAt?: number | undefined;
  agents: ScanAgent[];
  findings: Finding[];
  pinned?: boolean | undefined;
}

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function severityWeight(s: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}
