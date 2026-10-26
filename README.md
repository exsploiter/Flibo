<div align="center">

# ⚡ Flibo
### Autonomous Attack Surface Reconnaissance & Threat Intelligence Engine

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)](https://github.com/exsploiter/Flibo)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19.2-61dafb?style=flat-square&logo=react)](https://react.dev/)
[![TanStack Start](https://img.shields.io/badge/TanStack%20Start-1.168-ff4154?style=flat-square)](https://tanstack.com/start)
[![Node.js](https://img.shields.io/badge/Node.js-24%2B-green?style=flat-square&logo=node.js)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-MIT-purple?style=flat-square)](LICENSE)

*A full-stack, autonomous cyber reconnaissance and vulnerability management platform designed for security engineers, red teams, and DevSecOps operators.*

[Features](#-key-features) • [Architecture](#-architecture) • [Scanner Agents](#-autonomous-recon-agents) • [API Reference](#-rest--sse-api-reference) • [Getting Started](#-getting-started) • [Testing](#-testing)

---

</div>

## 🌐 Overview

**Flibo** transforms raw domain names, IP addresses, and CIDR blocks into actionable threat intelligence. Built from the ground up with a reactive frontend and a multi-agent backend engine, Flibo autonomously maps perimeters, audits network ports, identifies misconfigurations, correlates Common Vulnerabilities and Exposures (CVEs), and synthesizes exploit attack vectors in real-time.


---

## ✨ Key Features

- **Multi-Agent Asynchronous Recon Engine**: Runs concurrent or sequential reconnaissance agents powered by native Node.js TCP sockets, DNS resolvers, and TLS inspectors.
- **Real-Time Live Terminal Streaming (SSE)**: Streams probe activities, banner grabs, and agent progress directly to client browsers using Server-Sent Events with sub-second latency.
- **Automated CVE Correlation & CVSS 3.1 Scoring**: Matches detected software banners against a curated CVE intelligence catalog and official NVD advisories.
- **Attack Vector Synthesis**: Evaluates discovered vulnerabilities and exposed services to model chained, multi-stage attack paths with remediation guidance.
- **Persistent Storage & Retention Engine**: Atomic, file-backed database layer with configurable data retention policies ($7$, $30$, $90$, $365$ days).
- **Multi-Format Reporting**: One-click exports of findings to **JSON**, **CSV**, and formatted **Markdown** security reports.
- **Dark Mode UI & Glassmorphism Aesthetics**: Built with Tailwind CSS, Radix UI primitives, Lucide icons, and responsive layouts.

---

## 🏛 Architecture

Flibo separates concerns cleanly between a responsive client interface, an API gateway, an asynchronous task engine, and modular scanner agents.


```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLIENT UI (React 19)                          │
│  Dashboard (/)  •  New Scan (/new-scan)  •  Details (/scan/:id)        │
│  History (/history)  •  Settings (/settings)                           │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTP Fetch / SSE EventSource
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    API GATEWAY & SSR (src/server/api.ts)                │
│  • REST Endpoints (/api/scans, /api/settings, /api/health)              │
│  • Server-Sent Events Stream (/api/scans/:id/events)                    │
│  • Dev Server Vite Plugin + Nitro Production SSR Handlers               │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Dispatches Scan Jobs
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│               SCAN COORDINATOR ENGINE (src/server/engine.ts)            │
│  • Task state tracking (Queued -> Running -> Paused -> Complete)        │
│  • Pause / Resume / Cancel controllers                                  │
│  • Live EventEmitter event bus for real-time telemetry                  │
└───────┬─────────────────┬─────────────────┬─────────────────┬───────────┘
        │                 │                 │                 │
        ▼                 ▼                 ▼                 ▼
 ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
 │  Port Scan   │  │   DNS & CT   │  │   Web Tech   │  │ CVE Matcher  │
 │ (node:net)   │  │(node:dns/crt)│  │ (HTTP/TLS)   │  │(CVSS Engine) │
 └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
        │                 │                 │                 │
        └─────────────────┴────────┬────────┴─────────────────┘
                                   │ Aggregates Findings
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                ATTACK VECTOR SYNTHESIS & RISK ENGINE                    │
│  • Correlates multi-agent discoveries into ranked threat chains         │
│  • Computes composite Risk Score (0 - 100) and severity breakdowns      │
│  • Persists to atomic database layer (.data/flibo_db.json)              │

└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔍 Autonomous Recon Agents

| Agent | Module | Description & Capabilities |
| :--- | :--- | :--- |
| **Port Scan** | `ports.ts` | TCP port discovery using raw sockets (`node:net`). Supports presets (`top-100`, `top-1000`, `all-65k`) or custom port ranges (e.g. `80,443,8000-8080`). Performs service identification, latency measurement, and banner grabbing across SSH, FTP, SMTP, HTTP, MySQL, and Redis. |
| **Subdomain Enum** | `dns.ts` | Resolves authoritative `A`, `AAAA`, `MX`, and `TXT` records using `node:dns/promises`. Audits email security policies (**SPF** and **DMARC**). Enumerate subdomains passively via public Certificate Transparency (CT) logs (`crt.sh`) and actively validates common high-value infrastructure subdomains (`admin`, `staging`, `vpn`, `api`, `internal`). |
| **Tech Fingerprint** | `http.ts` | Probes HTTP and HTTPS endpoints. Audits critical browser security headers (**HSTS**, **Content-Security-Policy**, **X-Frame-Options Anti-Clickjacking**, **X-Content-Type-Options**). Identifies frontend and backend frameworks (React, Next.js, Vue, Nuxt, WordPress, Tailwind, Express) and inspects `/robots.txt` for disallowed administrative paths. |
| **CVE Matcher** | `cve.ts` | Correlates discovered service banners against vulnerability intelligence databases. Computes CVSS 3.1 severity scores, identifies Remote Code Execution (RCE) surfaces, and attaches official NVD and Exploit-DB references. |
| **OS Detection** | `os.ts` | Heuristic TCP/IP stack and banner analyzer identifying Linux (Ubuntu, Debian, RHEL/CentOS, Alpine), Windows Server, FreeBSD, and Cloud Native/Edge environments. |

---

## 📡 REST & SSE API Reference

All backend endpoints are served under `/api`:

### System & Health
- `GET /api/health` — System status, uptime, active scan workers, total scans, and memory consumption.

### Scans Management
- `GET /api/scans` — Retrieve scan list. Supports `?search=`, `?status=`, `?limit=`, and `?offset=`.
- `POST /api/scans` — Create and immediately dispatch an asynchronous scan.
  ```json
  {
    "name": "Audit example.com",
    "target": "example.com",
    "targets": ["example.com"],
    "tags": ["production", "external"],
    "config": {
      "intensity": "standard",
      "agents": ["port-scan", "subdomain-enum", "tech-fingerprint", "cve-matcher", "os-detection"],
      "ports": "top-1000",
      "stealth": false
    }
  }
  ```
- `GET /api/scans/:id` — Full scan details including agents, findings, logs, and synthesized attack vectors.
- `PATCH /api/scans/:id` — Update scan metadata (name, tags, pinned status).
- `DELETE /api/scans/:id` — Remove scan record and abort active background workers.

### Scan Operations & Real-Time Streaming
- `GET /api/scans/:id/events` — **Server-Sent Events (SSE)** stream. Pushes live `log`, `progress`, `agent_start`, `agent_complete`, and `scan_complete` events.
- `POST /api/scans/:id/pause` — Pause an ongoing scan.
- `POST /api/scans/:id/resume` — Resume a paused scan.
- `POST /api/scans/:id/cancel` — Abort a running scan immediately.
- `POST /api/scans/:id/agents/:agentId/retry` — Retry a failed or cancelled agent.
- `GET /api/scans/:id/export?format=json|csv|markdown` — Download scan findings in JSON, CSV, or Markdown.

### Targets & Configuration
- `POST /api/targets/parse` — Validate and categorize target strings (URL, Domain, Subdomain, IP, CIDR, Email, Hash).
- `GET /api/targets/history` — Autocomplete history of previous targets.
- `GET /api/settings` — Read application preferences and API keys.
- `PUT /api/settings` — Update preferences (CVE API keys, notifications, default profiles, data retention).
- `POST /api/retention/cleanup` — Manually trigger retention policy pruning.

---

## 🚀 Getting Started

### Prerequisites
- **Node.js**: `v20.0.0` or higher (Recommended: `v22` / `v24`)
- **Package Manager**: `npm`, `yarn`, or `pnpm`

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/exsploiter/Flibo.git
   cd Flibo
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start the development server**:
   ```bash
   npm run dev
   ```
   Open your browser and navigate to `http://localhost:3000`.

4. **Build for production**:
   ```bash
   npm run build
   ```

---

## 🧪 Testing

Flibo includes an automated test suite powered by [Vitest](https://vitest.dev/) covering scanner logic, CVSS calculations, attack vector synthesis, database transactions, and REST API routes:


```bash
npm run test
```

---

## 📂 Project Structure

```
Flibo/
├── src/
│   ├── components/            # UI components (LogConsole, AppShell, UI primitives)
│   ├── lib/
│   │   ├── api.ts             # Strongly typed frontend client & SSE subscriber
│   │   ├── store.ts           # Hybrid reactive client store
│   │   ├── runner.ts          # Real-time scan runner & fallback simulation
│   │   ├── detect.ts          # Target parser and regex auto-detection
│   │   └── types.ts           # Shared data interfaces
│   ├── routes/                # TanStack Start file-based routing
│   │   ├── index.tsx          # Threat intelligence dashboard
│   │   ├── new-scan.tsx       # Scan creation & target configuration
│   │   ├── scan.$id.tsx       # Live scan details, logs, findings & tabs
│   │   ├── history.tsx        # Searchable scan history & re-runs
│   │   └── settings.tsx       # Integrations, API keys & retention setup
│   ├── server/                # Functional backend architecture
│   │   ├── api.ts             # REST & SSE API router and node adapter
│   │   ├── engine.ts          # Asynchronous scan coordinator & event bus
│   │   ├── db.ts              # Atomic file-backed persistence layer
│   │   ├── vite-plugin.ts     # Vite dev server middleware bridge
│   │   ├── types.ts           # Backend type definitions
│   │   └── scanner/           # Autonomous reconnaissance agents
│   │       ├── ports.ts       # TCP socket scanner & banner grabber
│   │       ├── dns.ts         # DNS resolution, SPF/DMARC & CT logs
│   │       ├── http.ts        # HTTP probing, security headers & tech stack
│   │       ├── cve.ts         # Vulnerability matcher & CVSS scoring
│   │       ├── os.ts          # OS & TCP/IP stack fingerprinting
│   │       └── synthesis.ts   # Attack vector synthesis & risk scoring
│   ├── server.ts              # Nitro / SSR production server entry
│   └── test/                  # Automated unit and integration tests
├── package.json
├── vite.config.ts
└── README.md
```

---

## 🛡 Security & Responsible Disclosure

This tool is designed strictly for authorized security assessments, defensive reconnaissance, and educational purposes. Ensure you have explicit authorization from target owners before initiating scans. Unauthorized scanning of third-party networks may violate applicable laws.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
