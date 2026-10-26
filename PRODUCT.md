# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Security engineers, red teamers, bug bounty hunters, and DevSecOps practitioners conducting target reconnaissance, perimeter audits, and vulnerability correlation.

## Product Purpose
Flibo is a private, high-fidelity reconnaissance automation and attack surface console. It bridges raw network-level intelligence gathering with weaponizable CVE threat modeling into a unified tactical operations interface.

## Positioning
Unlike simulated mockup dashboards or cloud-dependent SaaS scanners, Flibo executes real, local socket-level engine probes (raw TCP port scans, DNS CT log audits, live HTTP probes, CVSS 3.1 CVE correlations, and attack vector synthesis) directly on the host with zero external SaaS dependencies and real-time SSE streaming.

## Operating Context
Used during engagement setup, active target scoping, internal network sweeps, and defensive posture reviews. Operates both connected and in air-gapped/offline-capable modes, persisting state atomically to local disk and streaming terminal logs via SSE.

## Capabilities and Constraints
- Real TCP port scanner (`node:net`) with adaptive timeouts and batch concurrency.
- DNS reconnaissance (`node:dns/promises`) with certificate transparency logs and SPF/DMARC auditing.
- HTTP service prober with security header inspection, server fingerprinting, and technology detection.
- Local CVSS 3.1 CVE database matcher correlating banner versions with known critical exploits.
- Attack vector synthesis algorithm that models exploit chains from discovered services.
- Real-time Server-Sent Events (SSE) telemetry pipeline with offline fallback.
- Multi-format export: JSON, CSV, Markdown, and formatted PDF print views.
- Strict constraint: Name is Flibo (VEKTOR is permanently deprecated).

## Brand Commitments
- Name: Flibo (strictly Flibo, never VEKTOR).
- Aesthetic: Professional tactical dark palette: deep obsidian slate canvas (`oklch(0.12 0.006 250)`), surgical amber primary (`oklch(0.72 0.185 48)`), high-contrast foreground, calibrated CVSS severity scale.
- Typography: Sora for geometric display clarity, JetBrains Mono for telemetry, data, and terminal logs.
- Tone: Utilitarian, precise, tactical, mission-oriented.

## Evidence on Hand
- Full end-to-end codebase: `src/server/` (engine, scanner, database, API), `src/lib/` (client API, runner, store, synthesis), `src/routes/` (dashboard, scan detail, history, new scan, settings).
- 10/10 passing Vitest unit & integration test suite (`src/test/backend.test.ts`, `src/test/app-routing.test.tsx`).
- Production build passing on Nitro + Cloudflare module target.
- Public repository: `https://github.com/exsploiter/Flibo.git`.

## Product Principles
1. Ground Truth Over Simulation: Every displayed port, banner, and vulnerability originates from real network socket probes and verified CVE datasets.
2. Zero Cognitive Friction: Multi-target inputs, instant auto-detection of IP/CIDR/Domain/URL/Hash types, and one-click profile launches.
3. Air-Gapped Privacy & Ownership: Local persistence (`.data/flibo_db.json`), zero mandatory telemetry phone-homes, and fully private scan archives.
4. Actionable Threat Prioritization: Composite risk indexing and attack chain synthesis that highlights high-leverage entry points rather than overwhelming operators with raw data.

## Accessibility & Inclusion
High-contrast text compliance (≥4.5:1 ratio), visible focus rings, tabular numbers (`tabular-nums`) for numeric data readability, and semantic ARIA labeling for screen readers.
