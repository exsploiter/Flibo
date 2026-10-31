import { describe, it, expect, beforeEach } from "vitest";
import { parsePortList } from "../server/scanner/ports";
import { runCveScan } from "../server/scanner/cve";
import { runOsScan } from "../server/scanner/os";
import { computeRiskScore, countFindingsBySeverity, synthesizeAttackVectors } from "../server/scanner/synthesis";
import {
  createScan,
  deleteScanById,
  enforceRetention,
  getScanById,
  getSettings,
  getTargetHistory,
  listScans,
  updateScanById,
  updateSettings,
} from "../server/db";
import { handleApiRequest } from "../server/api";
import type { Finding, Scan } from "../server/types";

describe("Backend Reconnaissance & Scanner Core", () => {
  it("should parse port specifications accurately", () => {
    const quick = parsePortList("top-100", "quick");
    expect(quick.length).toBeGreaterThan(10);
    expect(quick).toContain(80);
    expect(quick).toContain(443);

    const custom = parsePortList("80,443,8080-8085", "standard");
    expect(custom).toContain(80);
    expect(custom).toContain(443);
    expect(custom).toContain(8080);
    expect(custom).toContain(8085);
    expect(custom).not.toContain(8086);
  });

  it("should match CVEs based on service fingerprints and calculate CVSS", async () => {
    const mockFindings: Finding[] = [
      {
        id: "f1",
        agent: "port-scan",
        kind: "port",
        severity: "low",
        title: "Open Port 22/TCP",
        port: 22,
        service: "ssh",
        banner: "OpenSSH 8.9p1 Ubuntu",
        tags: ["ssh", "openssh"],
        note: "test",
      },
      {
        id: "f2",
        agent: "port-scan",
        kind: "port",
        severity: "critical",
        title: "Open Port 6379/TCP",
        port: 6379,
        service: "redis",
        banner: "Redis 6.0.16",
        tags: ["redis", "database"],
        note: "test",
      },
    ];

    const logs: string[] = [];
    const cves = await runCveScan({
      target: "scanme.internal",
      previousFindings: mockFindings,
      onProgress: () => {},
      onLog: (l) => logs.push(l),
      shouldStop: () => false,
    });

    expect(cves.length).toBeGreaterThan(0);
    const redisCve = cves.find((c) => c.cveId === "CVE-2022-0543");
    expect(redisCve).toBeDefined();
    expect(redisCve?.cvss).toBe(10.0);
    expect(redisCve?.severity).toBe("critical");

    const sshCve = cves.find((c) => c.cveId === "CVE-2024-6387" || c.cveId === "CVE-2023-38408");
    expect(sshCve).toBeDefined();
  });

  it("should heuristically detect operating systems from banners and open ports", async () => {
    const findings: Finding[] = [
      {
        id: "f-port",
        agent: "port-scan",
        kind: "port",
        severity: "low",
        title: "Open Port 22",
        port: 22,
        service: "ssh",
        banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
        tags: ["ssh"],
        note: "banner test",
      },
    ];

    const osFindings = await runOsScan({
      target: "10.0.0.1",
      previousFindings: findings,
      onProgress: () => {},
      onLog: () => {},
      shouldStop: () => false,
    });

    expect(osFindings.length).toBe(1);
    expect(osFindings[0]?.title).toContain("Ubuntu");
  });

  it("should synthesize attack vectors and compute composite risk scores", () => {
    const sampleFindings: Finding[] = [
      {
        id: "f-crit",
        agent: "cve-matcher",
        kind: "cve",
        severity: "critical",
        cveId: "CVE-2023-38408",
        cvss: 9.8,
        title: "OpenSSH RCE",
        tags: ["cve", "rce"],
        note: "",
      },
      {
        id: "f-redis",
        agent: "port-scan",
        kind: "port",
        port: 6379,
        service: "redis",
        severity: "critical",
        title: "Redis exposed",
        tags: ["redis"],
        note: "",
      },
      {
        id: "f-sub",
        agent: "subdomain-enum",
        kind: "subdomain",
        severity: "medium",
        title: "Discovered Subdomain: staging.target.com",
        tags: ["subdomain"],
        note: "",
      },
    ];

    const counts = countFindingsBySeverity(sampleFindings);
    expect(counts.critical).toBe(2);
    expect(counts.medium).toBe(1);

    const score = computeRiskScore(sampleFindings);
    // With calibrated scoring: 2 criticals + 1 medium → ~26. Should be meaningfully > 15, not inflated to 100.
    expect(score).toBeGreaterThan(15);
    expect(score).toBeLessThan(100);

    const vectors = synthesizeAttackVectors(sampleFindings);
    expect(vectors.some((v) => v.id === "vec-rce")).toBe(true);
    expect(vectors.some((v) => v.id === "vec-db-exposure")).toBe(true);
    expect(vectors.some((v) => v.id === "vec-subdomains")).toBe(true);
  });
});

describe("Backend Database & Retention Layer", () => {
  it("should perform scan CRUD operations accurately", () => {
    const testScanId = `test-scan-${Date.now()}`;
    const testScan: Scan = {
      id: testScanId,
      name: "Unit Test Scan",
      target: "127.0.0.1",
      targets: ["127.0.0.1"],
      tags: ["test", "internal"],
      config: {
        intensity: "quick",
        agents: ["port-scan"],
        ports: "80,443",
        stealth: false,
        scheduled: null,
      },
      status: "complete",
      createdAt: Date.now(),
      agents: [],
      findings: [],
      pinned: true,
    };

    createScan(testScan);
    const fetched = getScanById(testScanId);
    expect(fetched).toBeDefined();
    expect(fetched?.name).toBe("Unit Test Scan");

    updateScanById(testScanId, (s) => ({ ...s, name: "Updated Scan Name" }));
    expect(getScanById(testScanId)?.name).toBe("Updated Scan Name");

    const history = getTargetHistory();
    expect(history).toContain("127.0.0.1");

    deleteScanById(testScanId);
    expect(getScanById(testScanId)).toBeUndefined();
  });

  it("should manage settings and retention policies", () => {
    updateSettings({ retentionDays: "30", notifyInApp: false });
    const s = getSettings();
    expect(s.retentionDays).toBe("30");
    expect(s.notifyInApp).toBe(false);

    const pruned = enforceRetention();
    expect(typeof pruned).toBe("number");
  });
});

describe("Backend REST API Suite", () => {
  it("GET /api/health should return system status, memory, and uptime", async () => {
    const req = new Request("http://localhost:3000/api/health", { method: "GET" });
    const res = await handleApiRequest(req);
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.status).toBe("ok");
    expect(data.totalScans).toBeGreaterThanOrEqual(0);
    expect(data.memoryUsageMb).toBeGreaterThan(0);
  });

  it("GET & POST /api/scans should create and list scans", async () => {
    const createReq = new Request("http://localhost:3000/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "API Test Target",
        target: "scanme.nmap.org",
        targets: ["scanme.nmap.org"],
        tags: ["api-test"],
        config: {
          intensity: "quick",
          agents: ["port-scan"],
          ports: "80",
          stealth: false,
        },
      }),
    });

    const createRes = await handleApiRequest(createReq);
    expect(createRes.status).toBe(201);
    const createdScan = await createRes.json();
    expect(createdScan.id).toBeDefined();
    expect(createdScan.target).toBe("scanme.nmap.org");

    // List scans
    const listReq = new Request("http://localhost:3000/api/scans?search=scanme", { method: "GET" });
    const listRes = await handleApiRequest(listReq);
    expect(listRes.status).toBe(200);
    const list = await listRes.json();
    expect(Array.isArray(list)).toBe(true);
    expect(list.some((s: Scan) => s.id === createdScan.id)).toBe(true);

    // Get scan with synthesis
    const detailReq = new Request(`http://localhost:3000/api/scans/${createdScan.id}`, { method: "GET" });
    const detailRes = await handleApiRequest(detailReq);
    expect(detailRes.status).toBe(200);
    const detail = await detailRes.json();
    expect(detail.synthesis).toBeDefined();
    expect(detail.synthesis.riskScore).toBeDefined();

    // Export scan
    const exportReq = new Request(`http://localhost:3000/api/scans/${createdScan.id}/export?format=json`, {
      method: "GET",
    });
    const exportRes = await handleApiRequest(exportReq);
    expect(exportRes.status).toBe(200);
    const exportedJson = await exportRes.text();
    expect(exportedJson).toContain(createdScan.id);

    // Clean up
    deleteScanById(createdScan.id);
  });

  it("POST /api/targets/parse should detect target types correctly", async () => {
    const req = new Request("http://localhost:3000/api/targets/parse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: "192.168.1.1\napi.example.com\nhttps://portal.site.org" }),
    });

    const res = await handleApiRequest(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.targets.length).toBe(3);
    expect(data.targets[0].type).toBe("ip");
    expect(data.targets[1].type).toBe("subdomain");
    expect(data.targets[2].type).toBe("url");
  });
});
