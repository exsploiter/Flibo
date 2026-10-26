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

export interface AttackVector {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  findings: Finding[];
  remediation: string;
}

export interface AppSettings {
  cveApiKey: string;
  nmapBackendUrl: string;
  notifyInApp: boolean;
  notifyEmail: boolean;
  notifyEmailTo: string;
  defaultProfile: string;
  retentionDays: string;
}

export interface SystemHealth {
  status: "ok" | "degraded" | "error";
  uptime: number;
  activeScans: number;
  totalScans: number;
  memoryUsageMb: number;
  nodeVersion: string;
  dbType: string;
}
