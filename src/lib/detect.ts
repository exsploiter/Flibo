export type DetectedType =
  | "url"
  | "ip"
  | "cidr"
  | "domain"
  | "subdomain"
  | "email"
  | "hash"
  | "invalid"
  | "empty";

export interface ParsedTarget {
  raw: string;
  type: DetectedType;
  valid: boolean;
  label: string;
}

export const TYPE_LABELS: Record<Exclude<DetectedType, "empty">, string> = {
  url: "URL",
  ip: "IP address",
  cidr: "CIDR range",
  domain: "Domain",
  subdomain: "Subdomain",
  email: "Email",
  hash: "File hash",
  invalid: "Unrecognized",
};

function validIpOctets(s: string): boolean {
  return s.split(".").every((o) => /^\d{1,3}$/.test(o) && +o <= 255);
}

export function detectInput(raw: string): DetectedType {
  const s = raw.trim();
  if (!s) return "empty";
  if (/^https?:\/\/[^\s]+$/i.test(s)) return "url";
  if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(s)) {
    const [ip, mask] = s.split("/");
    if (ip && mask && validIpOctets(ip) && +mask <= 32) return "cidr";
    return "invalid";
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return validIpOctets(s) ? "ip" : "invalid";
  if (/^[a-f0-9]{32}$/i.test(s) || /^[a-f0-9]{40}$/i.test(s) || /^[a-f0-9]{64}$/i.test(s))
    return "hash";
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(s)) return "email";
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$/i.test(s)) {
    const parts = s.replace(/\.$/, "").split(".");
    return parts.length > 2 ? "subdomain" : "domain";
  }
  return "invalid";
}

export function parseTargets(text: string): ParsedTarget[] {
  return text
    .split(/[\n,;]+/)
    .map((t) => t.trim())
    .filter(Boolean)
    .map((raw) => {
      const type = detectInput(raw);
      const valid = type !== "invalid";
      return {
        raw,
        type,
        valid,
        label: TYPE_LABELS[type as Exclude<DetectedType, "empty">] ?? "Unrecognized",
      };
    });
}
