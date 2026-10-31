import fs from "node:fs";
import path from "node:path";
import type { AppSettings, Scan } from "./types";
import { seedScans } from "../lib/mock";

const DATA_DIR = path.resolve(process.cwd(), ".data");
const DB_FILE = path.join(DATA_DIR, "flibo_db.json");


interface DatabaseSchema {
  version: number;
  scans: Scan[];
  settings: AppSettings;
  targetHistory: string[];
  updatedAt: number;
}

const DEFAULT_SETTINGS: AppSettings = {
  cveApiKey: "",
  nmapBackendUrl: "",
  notifyInApp: true,
  notifyEmail: false,
  notifyEmailTo: "",
  defaultProfile: "standard",
  retentionDays: "90",
};

let memoryDb: DatabaseSchema | null = null;
let writeTimeout: NodeJS.Timeout | null = null;

function ensureDataDir(): void {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  } catch (err) {
    console.warn("[DB] Failed to ensure data dir:", err);
  }
}

function loadDb(): DatabaseSchema {
  if (memoryDb) return memoryDb;
  ensureDataDir();

  if (fs.existsSync(DB_FILE)) {
    try {
      const raw = fs.readFileSync(DB_FILE, "utf-8");
      const parsed = JSON.parse(raw) as DatabaseSchema;
      if (parsed && Array.isArray(parsed.scans)) {
        memoryDb = {
          version: parsed.version || 1,
          scans: parsed.scans,
          settings: { ...DEFAULT_SETTINGS, ...parsed.settings },
          targetHistory: Array.isArray(parsed.targetHistory) ? parsed.targetHistory : [],
          updatedAt: parsed.updatedAt || Date.now(),
        };
        return memoryDb;
      }
    } catch (err) {
      console.error("[DB] Corrupt db file, seeding fresh database:", err);
    }
  }

  // Default empty database
  memoryDb = {
    version: 1,
    scans: [],
    settings: { ...DEFAULT_SETTINGS },
    targetHistory: [],
    updatedAt: Date.now(),
  };
  saveDbSync();
  return memoryDb;
}

export function saveDbSync(): void {
  if (!memoryDb) return;
  ensureDataDir();
  try {
    memoryDb.updatedAt = Date.now();
    const tmpFile = `${DB_FILE}.tmp.${Date.now()}`;
    fs.writeFileSync(tmpFile, JSON.stringify(memoryDb, null, 2), "utf-8");
    fs.renameSync(tmpFile, DB_FILE);
  } catch (err) {
    console.error("[DB] Failed to persist database:", err);
  }
}

export function scheduleSave(): void {
  if (writeTimeout) return;
  writeTimeout = setTimeout(() => {
    writeTimeout = null;
    saveDbSync();
  }, 250);
}

// Scans CRUD
export function listScans(query?: { search?: string | undefined; status?: string | undefined; limit?: number | undefined; offset?: number | undefined }): Scan[] {
  const db = loadDb();
  let list = [...db.scans];

  if (query?.status && query.status !== "all") {
    list = list.filter((s) => s.status === query.status);
  }

  if (query?.search) {
    const q = query.search.toLowerCase();
    list = list.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.target.toLowerCase().includes(q) ||
        s.tags.some((t) => t.toLowerCase().includes(q)),
    );
  }

  list.sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || b.createdAt - a.createdAt);

  const offset = query?.offset ?? 0;
  const limit = query?.limit ?? 100;
  return list.slice(offset, offset + limit);
}

export function getScanById(id: string): Scan | undefined {
  const db = loadDb();
  return db.scans.find((s) => s.id === id);
}

export function createScan(scan: Scan): Scan {
  const db = loadDb();
  // prepend scan
  db.scans = [scan, ...db.scans.filter((s) => s.id !== scan.id)];
  // also add target to history
  if (scan.targets?.length) {
    addTargetHistory(scan.targets);
  } else if (scan.target) {
    addTargetHistory([scan.target]);
  }
  scheduleSave();
  return scan;
}

export function updateScanById(id: string, updater: (scan: Scan) => Scan): Scan | undefined {
  const db = loadDb();
  const idx = db.scans.findIndex((s) => s.id === id);
  if (idx === -1) return undefined;
  const current = db.scans[idx];
  if (!current) return undefined;
  const updated = updater({ ...current });
  db.scans[idx] = updated;
  scheduleSave();
  return updated;
}

export function deleteScanById(id: string): boolean {
  const db = loadDb();
  const prevLen = db.scans.length;
  db.scans = db.scans.filter((s) => s.id !== id);
  if (db.scans.length !== prevLen) {
    scheduleSave();
    return true;
  }
  return false;
}

// Settings
export function getSettings(): AppSettings {
  const db = loadDb();
  return { ...db.settings };
}

export function updateSettings(partial: Partial<AppSettings>): AppSettings {
  const db = loadDb();
  db.settings = { ...db.settings, ...partial };
  scheduleSave();
  return db.settings;
}

// Target History
export function getTargetHistory(): string[] {
  const db = loadDb();
  return [...db.targetHistory];
}

export function addTargetHistory(targets: string[]): string[] {
  const db = loadDb();
  const set = new Set([...targets.filter(Boolean), ...db.targetHistory]);
  db.targetHistory = Array.from(set).slice(0, 50);
  scheduleSave();
  return db.targetHistory;
}

// Data Retention Enforcement
export function enforceRetention(): number {
  const db = loadDb();
  const daysStr = db.settings.retentionDays;
  if (!daysStr || daysStr === "never") return 0;
  const days = parseInt(daysStr, 10);
  if (isNaN(days) || days <= 0) return 0;

  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  const originalCount = db.scans.length;
  // keep pinned scans even if old
  db.scans = db.scans.filter((s) => s.pinned || s.createdAt >= cutoff);
  const deleted = originalCount - db.scans.length;
  if (deleted > 0) {
    scheduleSave();
  }
  return deleted;
}
