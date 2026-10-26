import { useSyncExternalStore } from "react";
import type { Scan } from "./types";
import { seedScans } from "./mock";
import { api } from "./api";

const KEY = "vektor.scans.v1";

type Listener = () => void;

let state: Scan[] | null = null;
const listeners = new Set<Listener>();
let hasSyncedWithBackend = false;

function emit() {
  for (const l of listeners) l();
}

function persist() {
  try {
    localStorage.setItem(KEY, JSON.stringify(state));
  } catch {
    // storage full/unavailable — in-memory only
  }
}

function syncWithBackend() {
  if (hasSyncedWithBackend || typeof window === "undefined") return;
  hasSyncedWithBackend = true;

  api
    .listScans()
    .then((remoteScans) => {
      if (Array.isArray(remoteScans) && remoteScans.length > 0) {
        state = remoteScans;
        persist();
        emit();
      }
    })
    .catch((err) => {
      console.warn("[Store] Backend scan sync failed (offline or starting up):", err);
    });
}

function ensure(): Scan[] {
  if (state) return state;
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Scan[];
      if (Array.isArray(parsed) && parsed.length) {
        state = parsed;
        syncWithBackend();
        return state;
      }
    }
  } catch {
    // corrupted store — reseed
  }
  state = seedScans();
  persist();
  syncWithBackend();
  return state;
}

const subscribe = (l: Listener) => {
  listeners.add(l);
  return () => listeners.delete(l);
};

const getSnapshot = () => ensure();
const getServerSnapshot = (): Scan[] => [];

export function useScans(): Scan[] {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}

export function useScan(id: string): Scan | undefined {
  const scans = useScans();
  return scans.find((s) => s.id === id);
}

export function getScan(id: string): Scan | undefined {
  return ensure().find((s) => s.id === id);
}

function setAll(next: Scan[]) {
  state = next;
  persist();
  emit();
}

export function addScan(scan: Scan) {
  setAll([scan, ...ensure().filter((s) => s.id !== scan.id)]);
  // sync to backend
  api
    .createScan(scan)
    .then((created) => {
      setAll([created, ...ensure().filter((s) => s.id !== created.id)]);
    })
    .catch((err) => {
      console.warn("[Store] Failed to save scan to backend:", err);
    });
}

export function updateScan(id: string, updater: (s: Scan) => Scan) {
  const current = ensure();
  const next = current.map((s) => (s.id === id ? updater(s) : s));
  setAll(next);

  const updatedItem = next.find((s) => s.id === id);
  if (updatedItem) {
    api.updateScan(id, updatedItem).catch(() => {
      // ignore
    });
  }
}

export function deleteScan(id: string) {
  setAll(ensure().filter((s) => s.id !== id));
  api.deleteScan(id).catch(() => {
    // ignore
  });
}

export function togglePin(id: string) {
  updateScan(id, (s) => ({ ...s, pinned: !s.pinned }));
}

// ---------- target history (for autocomplete) ----------

const TARGETS_KEY = "vektor.targets.v1";

export function addTargetHistory(targets: string[]) {
  try {
    const prev: string[] = JSON.parse(localStorage.getItem(TARGETS_KEY) || "[]");
    const merged = Array.from(new Set([...targets, ...prev])).slice(0, 30);
    localStorage.setItem(TARGETS_KEY, JSON.stringify(merged));
  } catch {
    // ignore
  }
}

export function getTargetHistory(): string[] {
  try {
    return JSON.parse(localStorage.getItem(TARGETS_KEY) || "[]") as string[];
  } catch {
    return [];
  }
}

// ---------- generic persisted settings ----------

const SETTINGS_KEY = "vektor.settings.v1";

export interface AppSettings {
  cveApiKey: string;
  nmapBackendUrl: string;
  notifyInApp: boolean;
  notifyEmail: boolean;
  notifyEmailTo: string;
  defaultProfile: string;
  retentionDays: string;
}

export const DEFAULT_SETTINGS: AppSettings = {
  cveApiKey: "",
  nmapBackendUrl: "",
  notifyInApp: true,
  notifyEmail: false,
  notifyEmailTo: "",
  defaultProfile: "standard",
  retentionDays: "90",
};

export function loadSettings(): AppSettings {
  try {
    const local = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}") as Partial<AppSettings>;
    // async sync from backend
    if (typeof window !== "undefined") {
      api
        .getSettings()
        .then((remote) => {
          if (remote) {
            localStorage.setItem(SETTINGS_KEY, JSON.stringify(remote));
          }
        })
        .catch(() => {});
    }
    return { ...DEFAULT_SETTINGS, ...local };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export function saveSettings(s: AppSettings) {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
    api.saveSettings(s).catch(() => {});
  } catch {
    // ignore
  }
}
