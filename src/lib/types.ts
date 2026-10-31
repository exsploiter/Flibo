export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type AgentStatus = "queued" | "running" | "complete" | "failed";

export type ScanStatus =
  | "running"
  | "complete"
  | "partial"
  | "failed"
  | "cancelled";

export type FindingKind =
  | "port"
  | "cve"
  | "subdomain"
  | "tech"
  | "os"
  | "content"
  | "api"
  | "waf"
  | "cloud"
  | "takeover"
  | "tls"
  | "cms"
  | "auth"
  | "osint";

export type TriageStatus = "new" | "confirmed" | "false_positive" | "remediated";

export interface LogLine {
  id: number;
  text: string;
}

export interface AppSettings {
  cveApiKey?: string;
  nmapBackendUrl?: string;
  notifyInApp: boolean;
  notifyEmail: boolean;
  notifyEmailTo: string;
  webhookUrl?: string;
  defaultProfile: string;
  retentionDays: string;
  operatorName?: string;
  clientName?: string;
  engagementName?: string;
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
  epss?: number;
  cisaKev?: boolean;
  mitreTechnique?: string;
  exploitAvailable?: boolean;
  confidence?: number;
  triageStatus?: TriageStatus;
  evidence?: string;
  compliance?: {
    owasp?: string;
    cis?: string;
  };
  delta?: "new" | "resolved" | "persisting";
  description?: string;
  references?: { label: string; url: string }[];
  tags: string[];
  note: string;
}

export interface AttackChainNode {
  id: string;
  label: string;
  kind: string;
  severity?: Severity;
}

export interface AttackChainEdge {
  source: string;
  target: string;
  label?: string;
}

export interface AttackChainGraph {
  nodes: AttackChainNode[];
  edges: AttackChainEdge[];
}

export interface AttackVector {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  findings: Finding[];
  remediation: string;
  mitreTechnique?: string;
  cisaKev?: boolean;
  epss?: number;
}

export interface ScanConfig {
  intensity: "quick" | "standard" | "deep";
  timing?: "passive" | "stealth" | "normal" | "aggressive";
  agents: string[];
  ports: string;
  stealth: boolean;
  scheduled: string | null;
  workspace?: string;
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
  graph?: AttackChainGraph | undefined;
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
