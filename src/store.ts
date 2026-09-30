import { create } from "zustand";
import { createJSONStorage, persist, type StateStorage } from "zustand/middleware";
import { useMemo } from "react";
import type { DeviceRecord, FrameworkId, Mapping, Rule, VendorId } from "./engine/types";
import { detectVendor } from "./engine/detect";
import { parseConfig } from "./engine/parsers";
import { RULES } from "./engine/rules/library";
import { DEFAULT_REMEDIATION_SETTINGS, type RemediationSettings } from "./engine/rules/remediation";
import { buildFleet, type FleetView } from "./engine/fleet";
import { SAMPLES } from "./engine/samples";
import { DEFAULT_LLM_MODEL } from "./engine/llm";
import type { RiskException, Triage, TriageState } from "./engine/exceptions";
import { findingKey } from "./engine/exceptions";
import { sha256Sync } from "./lib/hash";
import { safeLocalStorage, uid } from "./lib/util";

export interface ActivityEntry {
  id: string;
  at: string;
  actor: "admin" | "engine" | "classifier" | "llm";
  action: string;
  target: string;
  detail?: string;
}

export interface ScanPoint {
  at: string;
  score: number;
  devices: number;
  fail: number;
  label?: string;
}

export interface ConfigVersion {
  raw: string;
  sha256: string;
  ingestedAt: string;
  fileName: string;
}

export interface Settings {
  remediation: RemediationSettings;
  llm: { apiKey: string; model: string };
  theme: "dark" | "light";
  operator: string;
  organisation: string;
}

export interface IngestOutcome {
  added: DeviceRecord[];
  replaced: { record: DeviceRecord; previousSha: string }[];
  skipped: { fileName: string; reason: string }[];
}

interface State {
  devices: DeviceRecord[];
  /** previous configuration versions per device id (newest first, capped) */
  history: Record<string, ConfigVersion[]>;
  mappings: Mapping[];
  customRules: Rule[];
  disabledRules: string[];
  frameworks: FrameworkId[];
  exceptions: Record<string, RiskException>;
  triage: Record<string, Triage>;
  settings: Settings;
  activity: ActivityEntry[];
  scans: ScanPoint[];
  seededAt: string | null;
  persistError: string | null;
  version: number;

  addDevices: (files: { fileName: string; raw: string; sha256: string; sample?: boolean }[], opts?: { replaceExisting?: boolean }) => IngestOutcome;
  removeDevice: (id: string) => DeviceRecord | undefined;
  restoreDevice: (record: DeviceRecord, versions?: ConfigVersion[]) => void;
  setVendorOverride: (id: string, vendor: VendorId | undefined) => void;
  updateDevice: (id: string, patch: Partial<Pick<DeviceRecord, "site" | "tags" | "owner">>) => void;
  addMapping: (m: Omit<Mapping, "id" | "createdAt" | "hits"> & { id?: string }) => Mapping;
  updateMapping: (id: string, patch: Partial<Mapping>) => void;
  removeMapping: (id: string) => Mapping | undefined;
  importMappings: (list: Mapping[]) => { imported: number; skipped: number };
  addCustomRule: (r: Rule) => boolean;
  removeCustomRule: (id: string) => void;
  toggleRule: (id: string, enabled: boolean) => void;
  setFrameworks: (f: FrameworkId[]) => void;
  acceptRisk: (deviceKey: string, ruleId: string, input: { reason: string; expires?: string; ticket?: string }) => void;
  revokeException: (key: string) => void;
  setTriage: (deviceKey: string, ruleId: string, patch: { state?: TriageState; owner?: string; due?: string; note?: string }) => void;
  updateSettings: (patch: Partial<Settings>) => void;
  log: (e: Omit<ActivityEntry, "id" | "at">) => void;
  recordScan: (p: Omit<ScanPoint, "at">) => void;
  setPersistError: (msg: string | null) => void;
  resetToSamples: () => void;
  clearAll: () => void;
}

const SESSION_KEY_NAME = "netsentinel-llm-key";
function readSessionKey(): string {
  try {
    return sessionStorage.getItem(SESSION_KEY_NAME) ?? "";
  } catch {
    return "";
  }
}
function writeSessionKey(key: string): void {
  try {
    if (key) sessionStorage.setItem(SESSION_KEY_NAME, key);
    else sessionStorage.removeItem(SESSION_KEY_NAME);
  } catch {
    /* unavailable */
  }
}

/** Storage wrapper that survives a full quota instead of throwing inside React. */
function quotaSafeStorage(): StateStorage {
  const ls = safeLocalStorage();
  return {
    getItem: (name) => (ls ? ls.getItem(name) : null),
    setItem: (name, value) => {
      if (!ls) return;
      try {
        ls.setItem(name, value);
        const s = useStore.getState();
        if (s.persistError) s.setPersistError(null);
      } catch (e) {
        const msg = /quota|exceeded|NS_ERROR_DOM_QUOTA/i.test(String(e)) ? "Browser storage is full. Changes stay in memory but are not saved — remove devices or export your work." : `Could not save: ${String(e)}`;
        useStore.getState().setPersistError(msg);
      }
    },
    removeItem: (name) => {
      if (ls) ls.removeItem(name);
    },
  };
}

function seedDevices(): DeviceRecord[] {
  const base = Date.now() - 1000 * 60 * 60 * 4;
  return SAMPLES.filter((s) => s.seed).map((s, i) => ({
    id: `dev-${s.id}`,
    fileName: s.fileName,
    ingestedAt: new Date(base + i * 1000 * 60 * 7).toISOString(),
    raw: s.raw,
    sha256: sha256Sync(s.raw),
    detection: detectVendor(s.raw),
    sample: true,
    site: s.site,
  }));
}

function seedActivity(): ActivityEntry[] {
  const now = Date.now();
  const at = (minAgo: number) => new Date(now - minAgo * 60000).toISOString();
  const n = SAMPLES.filter((s) => s.seed).length;
  return [
    { id: uid("act"), at: at(240), actor: "admin", action: "Sample fleet loaded", target: `${n} configuration files`, detail: "Cisco IOS-XE, NX-OS, Arista EOS, Junos, FortiOS, PAN-OS, RouterOS, Huawei VRP and one unknown vendor (Extreme EXOS)." },
    { id: uid("act"), at: at(239), actor: "engine", action: "Vendor detection", target: `${n - 1} of ${n} files matched a signature`, detail: "access-ex-12.xsf routed to the generic parser — waiting for training." },
    { id: uid("act"), at: at(238), actor: "engine", action: "Compliance evaluation", target: "CIS · NIST · STIG · ISO", detail: "Findings recomputed for the fleet." },
  ];
}

function hostnameOf(raw: string, vendor: VendorId): string | undefined {
  try {
    return parseConfig(raw, vendor).result.identity.hostname;
  } catch {
    return undefined;
  }
}

export const useStore = create<State>()(
  persist(
    (set, get) => ({
      devices: [],
      history: {},
      mappings: [],
      customRules: [],
      disabledRules: [],
      frameworks: ["cis", "nist", "stig", "iso"],
      exceptions: {},
      triage: {},
      settings: {
        remediation: DEFAULT_REMEDIATION_SETTINGS,
        llm: { apiKey: "", model: DEFAULT_LLM_MODEL },
        theme: "light",
        operator: "netops@example.in",
        organisation: "Example Corp — Network Security Operations",
      },
      activity: [],
      scans: [],
      seededAt: null,
      persistError: null,
      version: 2,

      addDevices: (files, opts) => {
        const outcome: IngestOutcome = { added: [], replaced: [], skipped: [] };
        const state = get();
        const bySha = new Map(state.devices.map((d) => [d.sha256, d]));
        const next = [...state.devices];
        const history = { ...state.history };
        for (const f of files) {
          if (bySha.has(f.sha256)) {
            outcome.skipped.push({ fileName: f.fileName, reason: `identical to ${bySha.get(f.sha256)!.fileName}` });
            continue;
          }
          const detection = detectVendor(f.raw);
          const hostname = hostnameOf(f.raw, detection.vendor);
          const existing = hostname ? next.find((d) => (d.vendorOverride ?? d.detection.vendor) === detection.vendor && hostnameOf(d.raw, d.vendorOverride ?? d.detection.vendor) === hostname) : undefined;
          if (existing && opts?.replaceExisting !== false) {
            // New version of a known device: keep the id, archive the previous configuration.
            const prev: ConfigVersion = { raw: existing.raw, sha256: existing.sha256, ingestedAt: existing.ingestedAt, fileName: existing.fileName };
            history[existing.id] = [prev, ...(history[existing.id] ?? [])].slice(0, 5);
            const updated: DeviceRecord = { ...existing, fileName: f.fileName, raw: f.raw, sha256: f.sha256, ingestedAt: new Date().toISOString(), detection, sample: f.sample };
            next[next.indexOf(existing)] = updated;
            bySha.set(f.sha256, updated);
            outcome.replaced.push({ record: updated, previousSha: prev.sha256 });
            continue;
          }
          const record: DeviceRecord = { id: uid("dev"), fileName: f.fileName, ingestedAt: new Date().toISOString(), raw: f.raw, sha256: f.sha256, detection, sample: f.sample };
          next.push(record);
          bySha.set(f.sha256, record);
          outcome.added.push(record);
        }
        set({ devices: next, history });
        const parts: string[] = [];
        if (outcome.added.length) parts.push(`${outcome.added.length} added`);
        if (outcome.replaced.length) parts.push(`${outcome.replaced.length} new version${outcome.replaced.length > 1 ? "s" : ""}`);
        if (outcome.skipped.length) parts.push(`${outcome.skipped.length} duplicate${outcome.skipped.length > 1 ? "s" : ""} skipped`);
        if (outcome.added.length || outcome.replaced.length) {
          get().log({
            actor: "admin",
            action: "Configuration ingested",
            target: parts.join(" · "),
            detail: [...outcome.added, ...outcome.replaced.map((r) => r.record)].map((r) => `${r.fileName} → ${r.detection.vendor}${r.detection.vendor === "generic" ? "" : ` (${Math.round(r.detection.confidence * 100)}%)`}`).join("; "),
          });
        }
        return outcome;
      },
      removeDevice: (id) => {
        const d = get().devices.find((x) => x.id === id);
        set((s) => {
          const history = { ...s.history };
          delete history[id];
          return { devices: s.devices.filter((x) => x.id !== id), history };
        });
        if (d) get().log({ actor: "admin", action: "Device removed", target: d.fileName });
        return d;
      },
      restoreDevice: (record, versions) => {
        set((s) => ({ devices: [...s.devices.filter((d) => d.id !== record.id), record], history: versions ? { ...s.history, [record.id]: versions } : s.history }));
        get().log({ actor: "admin", action: "Device restored", target: record.fileName });
      },
      setVendorOverride: (id, vendor) => {
        set((s) => ({ devices: s.devices.map((d) => (d.id === id ? { ...d, vendorOverride: vendor } : d)) }));
        const d = get().devices.find((x) => x.id === id);
        if (d) get().log({ actor: "admin", action: "Vendor override", target: d.fileName, detail: vendor ? `Parsed as ${vendor}` : "Back to auto-detection" });
      },
      updateDevice: (id, patch) => set((s) => ({ devices: s.devices.map((d) => (d.id === id ? { ...d, ...patch } : d)) })),
      addMapping: (m) => {
        const mapping: Mapping = { ...m, id: m.id ?? uid("map"), createdAt: new Date().toISOString(), hits: 0 };
        set((s) => ({ mappings: [...s.mappings, mapping] }));
        get().log({ actor: m.createdBy === "llm" ? "llm" : m.createdBy === "classifier" ? "classifier" : "admin", action: "Mapping learned", target: `${mapping.name} → ${mapping.param}`, detail: `/${mapping.pattern}/ (${mapping.valueMode})` });
        return mapping;
      },
      updateMapping: (id, patch) => {
        set((s) => ({ mappings: s.mappings.map((m) => (m.id === id ? { ...m, ...patch } : m)) }));
        const m = get().mappings.find((x) => x.id === id);
        if (m) get().log({ actor: "admin", action: "Mapping updated", target: `${m.name} → ${m.param}`, detail: `/${m.pattern}/ (${m.valueMode})` });
      },
      removeMapping: (id) => {
        const m = get().mappings.find((x) => x.id === id);
        set((s) => ({ mappings: s.mappings.filter((x) => x.id !== id) }));
        if (m) get().log({ actor: "admin", action: "Mapping removed", target: m.name });
        return m;
      },
      importMappings: (list) => {
        const existing = new Set(get().mappings.map((m) => m.id));
        let skipped = 0;
        const fresh: Mapping[] = [];
        for (const m of list) {
          if (!m || typeof m.pattern !== "string" || typeof m.param !== "string" || existing.has(m.id)) { skipped++; continue; }
          try { new RegExp(m.pattern, m.flags ?? "i"); } catch { skipped++; continue; }
          fresh.push({ ...m, id: m.id ?? uid("map"), hits: m.hits ?? 0, createdAt: m.createdAt ?? new Date().toISOString(), createdBy: m.createdBy ?? "admin" });
        }
        set((s) => ({ mappings: [...s.mappings, ...fresh] }));
        if (fresh.length) get().log({ actor: "admin", action: "Mapping pack imported", target: `${fresh.length} mappings${skipped ? ` (${skipped} skipped)` : ""}` });
        return { imported: fresh.length, skipped };
      },
      addCustomRule: (r) => {
        if ([...RULES, ...get().customRules].some((x) => x.id === r.id)) return false;
        set((s) => ({ customRules: [...s.customRules, r] }));
        get().log({ actor: "admin", action: "Custom control added", target: `${r.id} — ${r.title}` });
        return true;
      },
      removeCustomRule: (id) => {
        set((s) => ({ customRules: s.customRules.filter((x) => x.id !== id), disabledRules: s.disabledRules.filter((x) => x !== id) }));
        get().log({ actor: "admin", action: "Custom control removed", target: id });
      },
      toggleRule: (id, enabled) => {
        set((s) => ({ disabledRules: enabled ? s.disabledRules.filter((x) => x !== id) : Array.from(new Set([...s.disabledRules, id])) }));
        get().log({ actor: "admin", action: enabled ? "Control enabled" : "Control disabled", target: id });
      },
      setFrameworks: (f) => {
        set({ frameworks: f });
        get().log({ actor: "admin", action: "Frameworks selected", target: f.map((x) => x.toUpperCase()).join(" · ") || "none" });
      },
      acceptRisk: (deviceKey, ruleId, input) => {
        const key = findingKey(deviceKey, ruleId);
        const ex: RiskException = { key, ruleId, deviceKey, reason: input.reason, by: get().settings.operator, at: new Date().toISOString(), expires: input.expires, ticket: input.ticket };
        set((s) => ({ exceptions: { ...s.exceptions, [key]: ex }, triage: { ...s.triage, [key]: { ...(s.triage[key] ?? { key }), key, state: "accepted", updatedAt: ex.at } } }));
        get().log({ actor: "admin", action: "Risk accepted", target: `${deviceKey} · ${ruleId}`, detail: `${input.reason}${input.expires ? ` (until ${input.expires})` : ""}${input.ticket ? ` · ${input.ticket}` : ""}` });
      },
      revokeException: (key) => {
        set((s) => {
          const exceptions = { ...s.exceptions };
          delete exceptions[key];
          const triage = { ...s.triage };
          if (triage[key]?.state === "accepted") triage[key] = { ...triage[key], state: "open", updatedAt: new Date().toISOString() };
          return { exceptions, triage };
        });
        get().log({ actor: "admin", action: "Risk acceptance revoked", target: key });
      },
      setTriage: (deviceKey, ruleId, patch) => {
        const key = findingKey(deviceKey, ruleId);
        set((s) => ({ triage: { ...s.triage, [key]: { ...(s.triage[key] ?? { key, state: "open" as TriageState }), ...patch, key, updatedAt: new Date().toISOString() } } }));
        get().log({ actor: "admin", action: "Finding triaged", target: `${deviceKey} · ${ruleId}`, detail: [patch.state && `state: ${patch.state}`, patch.owner && `owner: ${patch.owner}`, patch.due && `due: ${patch.due}`].filter(Boolean).join(" · ") });
      },
      updateSettings: (patch) => {
        if (patch.llm) writeSessionKey(patch.llm.apiKey);
        set((s) => ({ settings: { ...s.settings, ...patch } }));
        const fields = Object.keys(patch).filter((k) => k !== "theme");
        if (fields.length) get().log({ actor: "admin", action: "Settings updated", target: fields.map((f) => (f === "llm" ? `llm (${patch.llm?.apiKey ? "key set" : "key cleared"}, ${patch.llm?.model})` : f)).join(", ") });
      },
      log: (e) => set((s) => ({ activity: [{ ...e, id: uid("act"), at: new Date().toISOString() }, ...s.activity].slice(0, 500) })),
      recordScan: (p) => set((s) => ({ scans: [...s.scans, { ...p, at: new Date().toISOString() }].slice(-120) })),
      setPersistError: (msg) => set({ persistError: msg }),
      resetToSamples: () => {
        set({ devices: seedDevices(), history: {}, mappings: [], customRules: [], disabledRules: [], exceptions: {}, triage: {}, activity: seedActivity(), scans: [], seededAt: new Date().toISOString() });
        get().log({ actor: "admin", action: "Workspace reset", target: "sample fleet restored", detail: "Uploaded devices, learned mappings, custom controls, exceptions and history were discarded." });
      },
      clearAll: () => {
        set({ devices: [], history: {}, mappings: [], customRules: [], disabledRules: [], exceptions: {}, triage: {}, activity: [], scans: [], seededAt: new Date().toISOString() });
        get().log({ actor: "admin", action: "Workspace cleared", target: "all devices, mappings and custom controls" });
      },
    }),
    {
      name: "netsentinel-v2",
      version: 2,
      storage: createJSONStorage(quotaSafeStorage),
      partialize: (s) => ({
        devices: s.devices,
        history: s.history,
        mappings: s.mappings,
        customRules: s.customRules,
        disabledRules: s.disabledRules,
        frameworks: s.frameworks,
        exceptions: s.exceptions,
        triage: s.triage,
        settings: { ...s.settings, llm: { ...s.settings.llm, apiKey: "" } },
        activity: s.activity,
        scans: s.scans,
        seededAt: s.seededAt,
        version: s.version,
      }),
      merge: (persisted, current) => {
        const p = (persisted ?? {}) as Partial<State>;
        return {
          ...current,
          ...p,
          history: p.history ?? {},
          exceptions: p.exceptions ?? {},
          triage: p.triage ?? {},
          settings: {
            ...current.settings,
            ...(p.settings ?? {}),
            remediation: { ...DEFAULT_REMEDIATION_SETTINGS, ...(p.settings?.remediation ?? {}) },
            llm: { model: p.settings?.llm?.model ?? DEFAULT_LLM_MODEL, apiKey: readSessionKey() },
          },
        };
      },
      onRehydrateStorage: () => (state) => {
        if (state && !state.seededAt) state.resetToSamples();
      },
    },
  ),
);

// If persistence is unavailable the rehydrate callback still fires; guard the first paint.
if (!useStore.getState().seededAt) useStore.getState().resetToSamples();

export function useActiveRules(): Rule[] {
  const disabled = useStore((s) => s.disabledRules);
  const custom = useStore((s) => s.customRules);
  return useMemo(() => [...RULES, ...custom].filter((r) => !disabled.includes(r.id)), [disabled, custom]);
}

export function useFleet(): FleetView {
  const devices = useStore((s) => s.devices);
  const mappings = useStore((s) => s.mappings);
  const frameworks = useStore((s) => s.frameworks);
  const settings = useStore((s) => s.settings.remediation);
  const exceptions = useStore((s) => s.exceptions);
  const triage = useStore((s) => s.triage);
  const rules = useActiveRules();
  return useMemo(() => buildFleet(devices, mappings, rules, frameworks, settings, { exceptions, triage }), [devices, mappings, rules, frameworks, settings, exceptions, triage]);
}

export function applyTheme(theme: "dark" | "light"): void {
  try {
    document.documentElement.setAttribute("data-theme", theme);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", theme === "dark" ? "#0f1216" : "#f3f4f1");
  } catch {
    /* no DOM */
  }
}
