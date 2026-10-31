import React, { useEffect, useRef, useState, useMemo } from "react";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import {
  ShieldAlert,
  Server,
  Layers,
  Network,
  Maximize2,
  Minimize2,
  RotateCw,
  Eye,
  SlidersHorizontal,
  ExternalLink,
  ChevronRight,
  Info,
  Bug,
  Globe,
  Sparkles,
} from "lucide-react";
import type { Finding, Scan, Severity } from "@/lib/types";
import { SeverityBadge } from "@/components/ui-bits";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type NodeCategory = "root" | "port" | "host" | "tech" | "endpoint" | "security" | "flaw";

export interface Graph3DNode {
  id: string;
  label: string;
  category: NodeCategory;
  severity: Severity | "normal";
  detail?: string | undefined;
  sublabel?: string | undefined;
  cvss?: number | undefined;
  cveId?: string | undefined;
  service?: string | undefined;
  port?: number | undefined;
  references?: { label: string; url: string }[] | undefined;
  findingRef?: Finding | undefined;
  x: number;
  y: number;
  z: number;
  radius: number;
  color: number;
  glowColor: number;
  connectedEdgeIds: string[];
}

export interface Graph3DEdge {
  id: string;
  source: string;
  target: string;
  label?: string | undefined;
  severity: Severity | "normal";
  color: number;
}

const SEVERITY_COLORS: Record<string, { hex: number; css: string }> = {
  critical: { hex: 0xef4444, css: "#ef4444" },
  high: { hex: 0xf97316, css: "#f97316" },
  medium: { hex: 0xeab308, css: "#eab308" },
  low: { hex: 0x22c55e, css: "#22c55e" },
  info: { hex: 0x38bdf8, css: "#38bdf8" },
  normal: { hex: 0x06b6d4, css: "#06b6d4" },
};

const CATEGORY_COLORS: Record<NodeCategory, number> = {
  root: 0xff5500,     // Orange / Primary target
  port: 0x6366f1,     // Indigo / Ports
  host: 0x8b5cf6,     // Purple / Host & OS
  tech: 0x10b981,     // Emerald / Tech Stack
  endpoint: 0xa855f7, // Violet / Endpoints & paths
  security: 0x0ea5e9, // Sky blue / Security config
  flaw: 0xf43f5e,     // Rose red / Flaws
};

export function build3DWebGraph(scan: Scan): { nodes: Graph3DNode[]; edges: Graph3DEdge[] } {
  const nodes: Graph3DNode[] = [];
  const edges: Graph3DEdge[] = [];
  const nodeMap = new Map<string, Graph3DNode>();

  function addNode(node: Omit<Graph3DNode, "connectedEdgeIds">): Graph3DNode {
    if (nodeMap.has(node.id)) return nodeMap.get(node.id)!;
    const fullNode: Graph3DNode = { ...node, connectedEdgeIds: [] };
    nodes.push(fullNode);
    nodeMap.set(node.id, fullNode);
    return fullNode;
  }

  function addEdge(sourceId: string, targetId: string, label?: string, severity: Severity | "normal" = "normal") {
    if (!nodeMap.has(sourceId) || !nodeMap.has(targetId)) return;
    const edgeId = `edge-${sourceId}-${targetId}`;
    if (edges.some((e) => e.id === edgeId)) return;

    const color = severity !== "normal" ? SEVERITY_COLORS[severity]?.hex ?? 0x38bdf8 : 0x475569;
    const edge: Graph3DEdge = { id: edgeId, source: sourceId, target: targetId, label, severity, color };
    edges.push(edge);
    nodeMap.get(sourceId)!.connectedEdgeIds.push(edgeId);
    nodeMap.get(targetId)!.connectedEdgeIds.push(edgeId);
  }

  // 1. Center Root Node: Target Website
  const rootNode = addNode({
    id: "node-root",
    label: scan.target.replace(/^https?:\/\//i, "").replace(/\/$/, "") || scan.target,
    category: "root",
    severity: "normal",
    sublabel: "Target Origin Perimeter",
    detail: `Primary scanned web asset: ${scan.target}. Root of network exposure graph.`,
    x: 0,
    y: 0,
    z: 0,
    radius: 9,
    color: CATEGORY_COLORS.root,
    glowColor: 0xff7722,
  });

  const ports = scan.findings.filter((f) => f.kind === "port" && f.port);
  const techFindings = scan.findings.filter((f) => f.kind === "tech");
  const osFindings = scan.findings.filter((f) => f.kind === "os" || f.agent === "os-detection");
  const wafFindings = scan.findings.filter((f) => f.kind === "waf" || f.agent === "waf-cdn");
  const subFindings = scan.findings.filter((f) => f.kind === "subdomain");
  const tlsFindings = scan.findings.filter((f) => f.kind === "tls" || f.agent === "ssl-deep");
  const authFindings = scan.findings.filter((f) => f.kind === "auth" || f.agent === "auth-surface");
  const osintFindings = scan.findings.filter((f) => f.kind === "osint" || f.agent === "osint-recon");
  const cveFindings = scan.findings.filter((f) => f.kind === "cve");

  // 2. Perimeter Layer (Radius ~45)
  // Ports
  const portRadius = 45;
  const totalPerimeter = Math.max(1, ports.length + (osFindings.length ? 1 : 0) + (wafFindings.length ? 1 : 0) + subFindings.length);
  let perimIndex = 0;

  for (const p of ports) {
    const angle = (perimIndex / totalPerimeter) * Math.PI * 2;
    const x = Math.cos(angle) * portRadius;
    const z = Math.sin(angle) * portRadius;
    const y = ((perimIndex % 2 === 0 ? 1 : -1) * 8) + (Math.sin(angle * 2) * 6);
    perimIndex++;

    const portNode = addNode({
      id: `node-port-${p.port}`,
      label: `Port ${p.port}/${p.protocol || "tcp"}`,
      category: "port",
      severity: p.severity,
      port: p.port,
      service: p.service,
      sublabel: p.banner ? p.banner.slice(0, 45) : `${p.service || "unknown"} daemon`,
      detail: p.detail || `Open network listening socket on TCP port ${p.port}.`,
      findingRef: p,
      x,
      y,
      z,
      radius: 6,
      color: CATEGORY_COLORS.port,
      glowColor: 0x818cf8,
    });
    addEdge(rootNode.id, portNode.id, "listens", p.severity);
  }

  // OS & Host Infrastructure
  if (osFindings.length > 0) {
    const osF = osFindings[0]!;
    const angle = (perimIndex / totalPerimeter) * Math.PI * 2;
    perimIndex++;
    const hostNode = addNode({
      id: "node-host-os",
      label: osF.title.replace(/^Operating System:\s*/i, ""),
      category: "host",
      severity: osF.severity,
      sublabel: "Host Kernel & OS",
      detail: osF.detail || "Operating system architecture identified via TCP/IP heuristics.",
      findingRef: osF,
      x: Math.cos(angle) * portRadius,
      y: 12,
      z: Math.sin(angle) * portRadius,
      radius: 6.5,
      color: CATEGORY_COLORS.host,
      glowColor: 0xa78bfa,
    });
    addEdge(rootNode.id, hostNode.id, "runs_on", "normal");
  }

  // WAF / CDN Edge
  if (wafFindings.length > 0) {
    const wafF = wafFindings[0]!;
    const angle = (perimIndex / totalPerimeter) * Math.PI * 2;
    perimIndex++;
    const wafNode = addNode({
      id: "node-edge-waf",
      label: wafF.title.replace(/^Edge WAF \/ CDN Identified \(/i, "").replace(/\)$/, "") || "Edge Shield",
      category: "host",
      severity: wafF.severity,
      sublabel: "Cloud Edge Proxy / WAF",
      detail: wafF.detail || "Front-line security gateway filtering external traffic.",
      findingRef: wafF,
      x: Math.cos(angle) * portRadius,
      y: -14,
      z: Math.sin(angle) * portRadius,
      radius: 6,
      color: 0x38bdf8,
      glowColor: 0x38bdf8,
    });
    addEdge(rootNode.id, wafNode.id, "shielded_by", "normal");
  }

  // Subdomains
  for (const s of subFindings.slice(0, 6)) {
    const angle = (perimIndex / totalPerimeter) * Math.PI * 2;
    perimIndex++;
    const subNode = addNode({
      id: `node-sub-${s.id}`,
      label: s.title,
      category: "host",
      severity: s.severity,
      sublabel: "Resolved Subdomain",
      detail: s.detail || "Active subdomain discovered via DNS and Certificate Transparency logs.",
      findingRef: s,
      x: Math.cos(angle) * (portRadius + 10),
      y: (perimIndex % 2 === 0 ? 10 : -10),
      z: Math.sin(angle) * (portRadius + 10),
      radius: 5,
      color: CATEGORY_COLORS.host,
      glowColor: 0x9333ea,
    });
    addEdge(rootNode.id, subNode.id, "subdomain", s.severity);
  }

  // 3. Technical Composition Layer (Radius ~90)
  const techRadius = 90;
  const webServerFinding = techFindings.find((f) => f.title.toLowerCase().includes("web server:"));
  let webServerNodeId = "node-port-443";
  if (!nodeMap.has(webServerNodeId) && nodeMap.has("node-port-80")) {
    webServerNodeId = "node-port-80";
  }
  if (!nodeMap.has(webServerNodeId)) {
    webServerNodeId = rootNode.id;
  }

  if (webServerFinding) {
    const wsNode = addNode({
      id: "node-tech-webserver",
      label: webServerFinding.title.replace(/^Web Server:\s*/i, ""),
      category: "tech",
      severity: webServerFinding.severity,
      sublabel: "Web Server Runtime",
      detail: webServerFinding.detail || "Server daemon handling inbound HTTP/HTTPS socket transactions.",
      findingRef: webServerFinding,
      x: -techRadius * 0.7,
      y: 18,
      z: techRadius * 0.4,
      radius: 7,
      color: CATEGORY_COLORS.tech,
      glowColor: 0x34d399,
    });
    addEdge(webServerNodeId, wsNode.id, "powered_by", "normal");
    webServerNodeId = wsNode.id;
  }

  // Client stacks (React, Next.js, Bootstrap)
  const clientStacks = techFindings.filter((f) => f.title.toLowerCase().includes("client stack:"));
  clientStacks.forEach((cs, i) => {
    const name = cs.title.replace(/^Client Stack:\s*/i, "");
    const csNode = addNode({
      id: `node-client-stack-${i}`,
      label: name,
      category: "tech",
      severity: cs.severity,
      sublabel: "Client Frontend Stack",
      detail: cs.detail || `Application client-side framework: ${name}`,
      findingRef: cs,
      x: -techRadius * 0.4 + i * 22,
      y: 28,
      z: techRadius * 0.6 + i * 15,
      radius: 5.5,
      color: CATEGORY_COLORS.tech,
      glowColor: 0x10b981,
    });
    addEdge(webServerNodeId, csNode.id, "renders", "normal");
  });

  // Endpoints / Robots.txt
  const robotsFinding = techFindings.find((f) => f.title.toLowerCase().includes("robots.txt"));
  if (robotsFinding) {
    const epNode = addNode({
      id: "node-endpoints-robots",
      label: "Disclosed Endpoints (/robots.txt)",
      category: "endpoint",
      severity: robotsFinding.severity,
      sublabel: "Directives & Internal Paths",
      detail: robotsFinding.detail || "Exposed internal URLs listed in crawler policy.",
      findingRef: robotsFinding,
      x: techRadius * 0.75,
      y: -15,
      z: techRadius * 0.35,
      radius: 5.5,
      color: CATEGORY_COLORS.endpoint,
      glowColor: 0xc084fc,
    });
    addEdge(webServerNodeId, epNode.id, "exposes_route", "normal");
  }

  // TLS SAN / Certificate
  if (tlsFindings.length > 0) {
    const tlsF = tlsFindings[0]!;
    const tlsNode = addNode({
      id: "node-security-tls",
      label: tlsF.title,
      category: "security",
      severity: tlsF.severity,
      sublabel: "TLS / Cryptographic Transport",
      detail: tlsF.detail || "Certificate authority, cipher suites and SAN coverage.",
      findingRef: tlsF,
      x: techRadius * 0.5,
      y: -28,
      z: -techRadius * 0.5,
      radius: 5.5,
      color: CATEGORY_COLORS.security,
      glowColor: 0x38bdf8,
    });
    addEdge(nodeMap.has("node-port-443") ? "node-port-443" : rootNode.id, tlsNode.id, "secures_with", "normal");
  }

  // Auth & Session Architecture
  if (authFindings.length > 0) {
    const authF = authFindings[0]!;
    const authNode = addNode({
      id: "node-auth-session",
      label: authF.title,
      category: "security",
      severity: authF.severity,
      sublabel: "Session & Auth Surface",
      detail: authF.detail || "Session cookie flags, HttpOnly, and SameSite enforcement.",
      findingRef: authF,
      x: -techRadius * 0.65,
      y: -22,
      z: -techRadius * 0.45,
      radius: 5.8,
      color: SEVERITY_COLORS[authF.severity]?.hex ?? CATEGORY_COLORS.security,
      glowColor: SEVERITY_COLORS[authF.severity]?.hex ?? 0xeab308,
    });
    addEdge(webServerNodeId, authNode.id, "authenticates", authF.severity);
  }

  // 4. Flaws & Vulnerabilities Layer (Radius ~140 - 165)
  // Correlated CVEs
  const flawRadius = 145;
  const allFlaws: Finding[] = [
    ...cveFindings,
    ...techFindings.filter((f) => f.title.toLowerCase().includes("missing")),
    ...scan.findings.filter((f) => f.kind === "takeover" || f.kind === "cloud" || f.kind === "content"),
    ...osintFindings.filter((f) => f.severity !== "info"),
  ];

  const totalFlaws = Math.max(1, allFlaws.length);
  allFlaws.forEach((flaw, idx) => {
    const angle = (idx / totalFlaws) * Math.PI * 2;
    const x = Math.cos(angle) * flawRadius;
    const z = Math.sin(angle) * flawRadius;
    const y = ((idx % 2 === 0 ? 1 : -1) * 32) + (Math.sin(angle * 3) * 15);

    const isCve = flaw.kind === "cve";
    const sevColor = SEVERITY_COLORS[flaw.severity]?.hex ?? 0xf97316;

    const flawNode = addNode({
      id: `node-flaw-${flaw.id}`,
      label: flaw.title,
      category: "flaw",
      severity: flaw.severity,
      cvss: flaw.cvss,
      cveId: flaw.cveId,
      sublabel: isCve ? `CVSS ${flaw.cvss?.toFixed(1) || "N/A"} Vulnerability` : "Configuration Defect",
      detail: flaw.description || flaw.detail || "Identified security exposure requiring remediation.",
      references: flaw.references,
      findingRef: flaw,
      x,
      y,
      z,
      radius: isCve ? 6.5 : 5,
      color: sevColor,
      glowColor: sevColor,
    });

    // Smart parent connection: connect flaw to the exact component it affects
    if (flaw.title.includes("SPF") || flaw.title.includes("DMARC")) {
      addEdge(rootNode.id, flawNode.id, "dns_misconfig", flaw.severity);
    } else if (flaw.title.includes("HSTS") || flaw.title.includes("CSP")) {
      addEdge(nodeMap.has("node-tech-webserver") ? "node-tech-webserver" : webServerNodeId, flawNode.id, "missing_header", flaw.severity);
    } else if (flaw.title.includes("Node.js") || flaw.title.includes("Next.js")) {
      const clientNode = nodes.find((n) => n.id.startsWith("node-client-stack"));
      addEdge(clientNode ? clientNode.id : webServerNodeId, flawNode.id, "vulnerable_runtime", flaw.severity);
    } else if (flaw.title.includes("nginx") || flaw.title.includes("HTTP/2")) {
      addEdge(nodeMap.has("node-tech-webserver") ? "node-tech-webserver" : webServerNodeId, flawNode.id, "exploitable_module", flaw.severity);
    } else if (flaw.kind === "auth") {
      addEdge(nodeMap.has("node-auth-session") ? "node-auth-session" : webServerNodeId, flawNode.id, "cookie_vulnerability", flaw.severity);
    } else if (flaw.port && nodeMap.has(`node-port-${flaw.port}`)) {
      addEdge(`node-port-${flaw.port}`, flawNode.id, "port_flaw", flaw.severity);
    } else {
      addEdge(webServerNodeId, flawNode.id, "correlated_flaw", flaw.severity);
    }
  });

  return { nodes, edges };
}

export function AttackGraph3D({ scan }: { scan: Scan }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<Graph3DNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<Graph3DNode | null>(null);
  const [isRotating, setIsRotating] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [filterCategory, setFilterCategory] = useState<string>("all");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");

  const graphData = useMemo(() => build3DWebGraph(scan), [scan]);

  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  const nodesGroupRef = useRef<THREE.Group | null>(null);
  const edgesGroupRef = useRef<THREE.Group | null>(null);
  const particlesRef = useRef<THREE.Points | null>(null);
  const nodeMeshesRef = useRef<Map<string, THREE.Mesh>>(new Map());

  // Setup Three.js scene
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const width = container.clientWidth;
    const height = container.clientHeight || 580;

    // 1. Scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0b0f17); // Dark cybernetic deep space
    scene.fog = new THREE.FogExp2(0x0b0f17, 0.0018);
    sceneRef.current = scene;

    // 2. Camera
    const camera = new THREE.PerspectiveCamera(52, width / height, 1, 2000);
    camera.position.set(0, 95, 230);
    cameraRef.current = camera;

    // 3. Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.25;
    container.innerHTML = "";
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // 4. Orbit Controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.06;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.8;
    controls.minDistance = 40;
    controls.maxDistance = 650;
    controls.maxPolarAngle = Math.PI * 0.88;
    controlsRef.current = controls;

    // 5. Ambient & Directional Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.9);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0xff7733, 2.8, 450);
    pointLight.position.set(0, 0, 0);
    scene.add(pointLight);

    const cyanLight = new THREE.DirectionalLight(0x38bdf8, 1.2);
    cyanLight.position.set(150, 200, 150);
    scene.add(cyanLight);

    const purpleLight = new THREE.DirectionalLight(0xa855f7, 0.9);
    purpleLight.position.set(-150, -100, -150);
    scene.add(purpleLight);

    // 6. Background Grid & Cosmic Starfield
    const gridHelper = new THREE.GridHelper(500, 40, 0x1e293b, 0x0f172a);
    gridHelper.position.y = -65;
    scene.add(gridHelper);

    // Starfield particles
    const starCount = 650;
    const starGeo = new THREE.BufferGeometry();
    const starCoords = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount * 3; i += 3) {
      starCoords[i] = (Math.random() - 0.5) * 1000;
      starCoords[i + 1] = (Math.random() - 0.5) * 800;
      starCoords[i + 2] = (Math.random() - 0.5) * 1000;
    }
    starGeo.setAttribute("position", new THREE.BufferAttribute(starCoords, 3));
    const starMat = new THREE.PointsMaterial({ color: 0x64748b, size: 1.8, transparent: true, opacity: 0.6 });
    const starField = new THREE.Points(starGeo, starMat);
    scene.add(starField);

    // 7. Graph Groups
    const edgesGroup = new THREE.Group();
    const nodesGroup = new THREE.Group();
    scene.add(edgesGroup);
    scene.add(nodesGroup);
    edgesGroupRef.current = edgesGroup;
    nodesGroupRef.current = nodesGroup;

    // Raycaster for interaction
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handlePointerMove = (e: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const meshes = Array.from(nodeMeshesRef.current.values());
      const intersects = raycaster.intersectObjects(meshes, false);

      if (intersects.length > 0 && intersects[0]?.object) {
        const hit = intersects[0].object as THREE.Mesh;
        const nodeId = hit.userData["nodeId"] as string | undefined;
        const n = graphData.nodes.find((item) => item.id === nodeId);
        setHoveredNode(n || null);
        renderer.domElement.style.cursor = "pointer";
      } else {
        setHoveredNode(null);
        renderer.domElement.style.cursor = "default";
      }
    };

    const handleClick = (e: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const meshes = Array.from(nodeMeshesRef.current.values());
      const intersects = raycaster.intersectObjects(meshes, false);

      if (intersects.length > 0 && intersects[0]?.object) {
        const hit = intersects[0].object as THREE.Mesh;
        const nodeId = hit.userData["nodeId"] as string | undefined;
        const n = graphData.nodes.find((item) => item.id === nodeId);
        if (n) {
          setSelectedNode(n);
          // Pivot controls towards clicked node
          controls.target.set(n.x * 0.5, n.y * 0.5, n.z * 0.5);
        }
      }
    };

    renderer.domElement.addEventListener("mousemove", handlePointerMove);
    renderer.domElement.addEventListener("click", handleClick);

    // Animation Loop
    let animFrame: number;
    const clock = new THREE.Clock();

    const animate = () => {
      animFrame = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      controls.update();

      // Pulse Central Root halo
      const rootMesh = nodeMeshesRef.current.get("node-root");
      if (rootMesh) {
        const scale = 1 + Math.sin(elapsedTime * 2.5) * 0.06;
        rootMesh.scale.set(scale, scale, scale);
      }

      // Gently rotate starfield
      starField.rotation.y = elapsedTime * 0.015;

      renderer.render(scene, camera);
    };

    animate();

    // Resize Handler
    const handleResize = () => {
      if (!container || !renderer || !camera) return;
      const w = container.clientWidth;
      const h = container.clientHeight || 580;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener("resize", handleResize);

    return () => {
      cancelAnimationFrame(animFrame);
      window.removeEventListener("resize", handleResize);
      renderer.domElement.removeEventListener("mousemove", handlePointerMove);
      renderer.domElement.removeEventListener("click", handleClick);
      renderer.dispose();
      controls.dispose();
    };
  }, []);

  // Update controls auto-rotation state
  useEffect(() => {
    if (controlsRef.current) {
      controlsRef.current.autoRotate = isRotating;
    }
  }, [isRotating]);

  // Re-build 3D Meshes & Edges when data or filter changes
  useEffect(() => {
    if (!sceneRef.current || !nodesGroupRef.current || !edgesGroupRef.current) return;

    const nodesGroup = nodesGroupRef.current;
    const edgesGroup = edgesGroupRef.current;

    // Clear old meshes
    while (nodesGroup.children.length > 0) {
      const child = nodesGroup.children[0]!;
      nodesGroup.remove(child);
      if (child instanceof THREE.Mesh) {
        child.geometry.dispose();
        if (Array.isArray(child.material)) child.material.forEach((m) => m.dispose());
        else child.material.dispose();
      }
    }

    while (edgesGroup.children.length > 0) {
      const child = edgesGroup.children[0]!;
      edgesGroup.remove(child);
      if (child instanceof THREE.Line || child instanceof THREE.Mesh) {
        child.geometry.dispose();
      }
    }

    nodeMeshesRef.current.clear();

    // Filter nodes
    const visibleNodes = graphData.nodes.filter((n) => {
      if (filterCategory !== "all") {
        if (filterCategory === "flaws" && n.category !== "flaw") return false;
        if (filterCategory === "tech" && n.category !== "tech" && n.category !== "endpoint") return false;
        if (filterCategory === "ports" && n.category !== "port") return false;
      }
      if (filterSeverity !== "all") {
        if (n.category === "flaw" && n.severity !== filterSeverity) return false;
      }
      return true;
    });

    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));
    visibleNodeIds.add("node-root"); // Always show origin target

    // Build Node Meshes
    visibleNodes.forEach((node) => {
      const isSelected = selectedNode?.id === node.id;
      const isHovered = hoveredNode?.id === node.id;

      // Base sphere geometry
      const geometry = new THREE.SphereGeometry(node.radius, 24, 24);
      const material = new THREE.MeshStandardMaterial({
        color: isSelected ? 0xffffff : node.color,
        emissive: node.glowColor,
        emissiveIntensity: isSelected ? 1.6 : isHovered ? 1.2 : 0.65,
        roughness: 0.25,
        metalness: 0.35,
      });

      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.set(node.x, node.y, node.z);
      mesh.userData = { nodeId: node.id };

      // Outer wireframe halo ring
      const ringGeo = new THREE.RingGeometry(node.radius * 1.3, node.radius * 1.45, 20);
      const ringMat = new THREE.MeshBasicMaterial({
        color: node.glowColor,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: isSelected ? 0.9 : 0.45,
      });
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      ringMesh.rotation.x = Math.PI / 2;
      mesh.add(ringMesh);

      nodesGroup.add(mesh);
      nodeMeshesRef.current.set(node.id, mesh);
    });

    // Build Web Filament Edges
    const nodeMap = new Map(graphData.nodes.map((n) => [n.id, n]));

    graphData.edges.forEach((edge) => {
      if (!visibleNodeIds.has(edge.source) || !visibleNodeIds.has(edge.target)) return;

      const src = nodeMap.get(edge.source);
      const tgt = nodeMap.get(edge.target);
      if (!src || !tgt) return;

      const p1 = new THREE.Vector3(src.x, src.y, src.z);
      const p2 = new THREE.Vector3(tgt.x, tgt.y, tgt.z);

      // Curve edge slightly for organic web effect
      const mid = p1.clone().lerp(p2, 0.5);
      const dist = p1.distanceTo(p2);
      mid.y += Math.sin(dist * 0.05) * 8;

      const curve = new THREE.QuadraticBezierCurve3(p1, mid, p2);
      const points = curve.getPoints(24);
      const edgeGeo = new THREE.BufferGeometry().setFromPoints(points);

      const isConnectedToSelected =
        selectedNode && (selectedNode.id === edge.source || selectedNode.id === edge.target);

      const edgeMat = new THREE.LineBasicMaterial({
        color: isConnectedToSelected ? 0xffffff : edge.color,
        transparent: true,
        opacity: isConnectedToSelected ? 0.95 : selectedNode ? 0.18 : 0.45,
      });

      const line = new THREE.Line(edgeGeo, edgeMat);
      edgesGroup.add(line);
    });
  }, [graphData, filterCategory, filterSeverity, selectedNode, hoveredNode]);

  function resetView() {
    if (cameraRef.current && controlsRef.current) {
      cameraRef.current.position.set(0, 95, 230);
      controlsRef.current.target.set(0, 0, 0);
      controlsRef.current.update();
      setSelectedNode(null);
    }
  }

  const flawCount = graphData.nodes.filter((n) => n.category === "flaw").length;
  const techCount = graphData.nodes.filter((n) => n.category === "tech" || n.category === "endpoint").length;

  return (
    <div
      className={cn(
        "relative rounded-3xl border border-border/60 bg-card overflow-hidden shadow-2xl transition-all duration-300",
        isFullscreen ? "fixed inset-0 z-50 rounded-none h-screen w-screen" : "w-full"
      )}
    >
      {/* Header Bar */}
      <div className="absolute top-0 inset-x-0 z-20 flex flex-wrap items-center justify-between gap-3 p-4 bg-gradient-to-b from-background/90 via-background/60 to-transparent backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="size-9 rounded-xl border border-primary/40 bg-primary/10 flex items-center justify-center text-primary shadow-sm shadow-primary/20">
            <Sparkles className="size-4" />
          </div>
          <div>
            <h3 className="font-semibold text-sm flex items-center gap-2">
              <span>3D Attack Path & Tech Composition Web</span>
              <span className="rounded-md border border-primary/30 bg-primary/10 px-2 py-0.2 font-mono text-[10px] text-primary uppercase font-bold">
                Live Interactive WebGL
              </span>
            </h3>
            <p className="text-[11px] text-muted-foreground">
              Dynamic multi-hop neural mesh mapping perimeters, web architecture & validated flaws
            </p>
          </div>
        </div>

        {/* Toolbar Controls */}
        <div className="flex items-center gap-2">
          {/* Category Filter */}
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="rounded-xl border border-border/60 bg-background/80 px-2.5 py-1.5 font-mono text-xs outline-none hover:border-primary/50 text-foreground"
          >
            <option value="all">All Web Layers ({graphData.nodes.length})</option>
            <option value="flaws">Flaws Only ({flawCount})</option>
            <option value="tech">Tech Stacks ({techCount})</option>
            <option value="ports">Perimeter Ports</option>
          </select>

          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="rounded-xl border border-border/60 bg-background/80 px-2.5 py-1.5 font-mono text-xs outline-none hover:border-primary/50 text-foreground"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="medium">Medium Only</option>
            <option value="low">Low Only</option>
          </select>

          {/* Auto rotate */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsRotating((r) => !r)}
            className={cn("h-8 rounded-xl font-mono text-xs", isRotating && "border-primary/50 text-primary")}
            title="Toggle 3D Orbit Rotation"
          >
            <RotateCw className={cn("size-3.5 mr-1.5", isRotating && "animate-spin")} />
            {isRotating ? "Orbiting" : "Paused"}
          </Button>

          {/* Reset View */}
          <Button
            variant="outline"
            size="sm"
            onClick={resetView}
            className="h-8 rounded-xl font-mono text-xs"
            title="Reset 3D Camera"
          >
            Reset
          </Button>

          {/* Fullscreen */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsFullscreen((f) => !f)}
            className="h-8 w-8 p-0 rounded-xl"
            title={isFullscreen ? "Exit Fullscreen" : "Fullscreen View"}
          >
            {isFullscreen ? <Minimize2 className="size-3.5" /> : <Maximize2 className="size-3.5" />}
          </Button>
        </div>
      </div>

      {/* 3D Canvas Mount Point */}
      <div
        ref={containerRef}
        className={cn(
          "w-full bg-[#0b0f17] select-none cursor-grab active:cursor-grabbing",
          isFullscreen ? "h-screen" : "h-[590px]"
        )}
      />

      {/* Hover Tooltip Overlay */}
      {hoveredNode && !selectedNode && (
        <div className="pointer-events-none absolute bottom-5 left-5 z-20 rounded-2xl border border-border/60 bg-card/95 p-3.5 backdrop-blur-md shadow-xl max-w-sm transition-all animate-in fade-in zoom-in-95">
          <div className="flex items-center gap-2">
            <span
              className="size-2.5 rounded-full"
              style={{ backgroundColor: SEVERITY_COLORS[hoveredNode.severity]?.css ?? "#38bdf8" }}
            />
            <span className="font-mono text-xs font-bold text-foreground truncate">{hoveredNode.label}</span>
            {hoveredNode.severity !== "normal" && (
              <SeverityBadge severity={hoveredNode.severity as Severity} className="scale-90 ml-auto" />
            )}
          </div>
          {hoveredNode.sublabel && (
            <p className="mt-1 text-[11px] font-mono text-muted-foreground">{hoveredNode.sublabel}</p>
          )}
          <p className="mt-1.5 text-xs text-foreground/80 line-clamp-2 leading-snug">{hoveredNode.detail}</p>
          <div className="mt-2 text-[10px] font-mono text-primary flex items-center gap-1">
            <span>Click node to inspect intelligence</span> <ChevronRight className="size-3" />
          </div>
        </div>
      )}

      {/* Selected Node Intelligence Drawer */}
      {selectedNode && (
        <div className="absolute top-16 right-5 z-20 w-96 rounded-2xl border border-border/80 bg-card/95 p-5 backdrop-blur-md shadow-2xl animate-in slide-in-from-right-5 max-h-[calc(100%-80px)] overflow-y-auto">
          <div className="flex items-start justify-between gap-3 pb-3 border-b border-border/50">
            <div>
              <span className="font-mono text-[10px] uppercase tracking-wider text-primary font-bold">
                {selectedNode.category.toUpperCase()} NODE
              </span>
              <h4 className="font-bold text-sm text-foreground mt-0.5 leading-snug break-words">
                {selectedNode.label}
              </h4>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="rounded-lg p-1 text-muted-foreground hover:bg-muted hover:text-foreground text-xs font-mono"
            >
              ✕
            </button>
          </div>

          <div className="mt-3 space-y-3">
            {selectedNode.severity !== "normal" && (
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-muted-foreground">Flaw Severity:</span>
                <SeverityBadge severity={selectedNode.severity as Severity} />
              </div>
            )}

            {selectedNode.cvss !== undefined && (
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-muted-foreground">CVSS 3.1 Base:</span>
                <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-critical/10 text-critical border border-critical/30">
                  {selectedNode.cvss.toFixed(1)} / 10.0
                </span>
              </div>
            )}

            {selectedNode.port && (
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-muted-foreground">Target Port:</span>
                <span className="font-mono text-xs font-bold text-foreground">:{selectedNode.port}</span>
              </div>
            )}

            {selectedNode.sublabel && (
              <div>
                <span className="text-[11px] font-mono text-muted-foreground uppercase">Classification:</span>
                <p className="font-mono text-xs text-foreground mt-0.5">{selectedNode.sublabel}</p>
              </div>
            )}

            <div>
              <span className="text-[11px] font-mono text-muted-foreground uppercase">Analysis Detail:</span>
              <p className="text-xs text-muted-foreground mt-1 leading-relaxed bg-muted/30 p-2.5 rounded-xl border border-border/40">
                {selectedNode.detail}
              </p>
            </div>

            {selectedNode.references && selectedNode.references.length > 0 && (
              <div>
                <span className="text-[11px] font-mono text-muted-foreground uppercase">Intelligence References:</span>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {selectedNode.references.map((r, i) => (
                    <a
                      key={i}
                      href={r.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 rounded-lg border border-border/60 bg-muted/40 px-2 py-1 font-mono text-[10px] text-foreground hover:border-primary/50 hover:text-primary transition-colors"
                    >
                      <ExternalLink className="size-2.5" /> {r.label}
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Legend & Stats Footer Overlay */}
      <div className="absolute bottom-4 inset-x-4 z-10 flex flex-wrap items-center justify-between gap-3 pointer-events-none">
        {/* Left: Interactive Legend */}
        <div className="flex flex-wrap items-center gap-4 px-3.5 py-1.5 rounded-xl bg-background/80 border border-border/60 backdrop-blur-md pointer-events-auto shadow-lg text-[11px] font-mono">
          <div className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-[#ff5500]" />
            <span className="text-muted-foreground">Origin</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-[#6366f1]" />
            <span className="text-muted-foreground">Port</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-[#10b981]" />
            <span className="text-muted-foreground">Tech Stack</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-[#ef4444]" />
            <span className="text-muted-foreground">Critical/High Flaw</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-[#eab308]" />
            <span className="text-muted-foreground">Medium Flaw</span>
          </div>
        </div>

        {/* Right: Metrics pill */}
        <div className="px-3.5 py-1.5 rounded-xl bg-background/80 border border-border/60 backdrop-blur-md pointer-events-auto shadow-lg font-mono text-[11px] text-muted-foreground flex items-center gap-3">
          <span>{graphData.nodes.length} nodes</span>
          <span>·</span>
          <span>{graphData.edges.length} web links</span>
          <span>·</span>
          <span className="text-primary">{flawCount} flaws correlated</span>
        </div>
      </div>
    </div>
  );
}
