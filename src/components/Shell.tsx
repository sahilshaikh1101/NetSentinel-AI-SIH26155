import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useLocation } from "wouter";
import { BookOpenCheck, CircleHelp, FileText, Gauge, GraduationCap, Moon, Search, Server, Settings2, ShieldAlert, Sun, UploadCloud } from "lucide-react";
import { create } from "zustand";
import { applyTheme, useActiveRules, useFleet, useStore } from "../store";
import type { FrameworkId } from "../engine/types";
import { FRAMEWORKS } from "../engine/rules/library";
import { VENDOR_META } from "../engine/sbm";
import { useDialog } from "./ui";
import { cn } from "../lib/util";

interface UiState {
  query: string;
  setQuery: (q: string) => void;
  palette: boolean;
  setPalette: (open: boolean) => void;
  /** device pre-selected when navigating to the Training Studio */
  trainingDevice: string | null;
  setTrainingDevice: (id: string | null) => void;
}
export const useUi = create<UiState>((set) => ({
  query: "",
  setQuery: (query) => set({ query }),
  palette: false,
  setPalette: (palette) => set({ palette }),
  trainingDevice: null,
  setTrainingDevice: (trainingDevice) => set({ trainingDevice }),
}));

/** Monogram in a gauge ring: the N of NetSentinel, with the accent arc marking the measured quadrant. */
export function BrandMark({ size = 28 }: { size?: number }) {
  return (
    <svg className="brand__mark" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <circle cx="16" cy="16" r="13.5" fill="none" stroke="currentColor" strokeWidth="1.8" />
      <path d="M16 2.5a13.5 13.5 0 0 1 13.5 13.5" fill="none" stroke="var(--accent)" strokeWidth="3" strokeLinecap="round" />
      <path d="M10.5 22V10l11 12V10" fill="none" stroke="currentColor" strokeWidth="2.3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export const NAV: { href: string; label: string; icon: ReactNode; hint: string; rule?: boolean }[] = [
  { href: "/", label: "Overview", icon: <Gauge />, hint: "Fleet posture, pipeline and heatmap" },
  { href: "/ingest", label: "Ingest", icon: <UploadCloud />, hint: "Upload configurations, samples, vendor detection", rule: true },
  { href: "/devices", label: "Devices", icon: <Server />, hint: "Identity, baseline model, drift, evidence" },
  { href: "/findings", label: "Findings", icon: <ShieldAlert />, hint: "Every control evaluation, triage, risk acceptance" },
  { href: "/frameworks", label: "Frameworks", icon: <BookOpenCheck />, hint: "CIS, NIST, STIG, ISO control library" },
  { href: "/training", label: "Training Studio", icon: <GraduationCap />, hint: "Teach the parser new syntax", rule: true },
  { href: "/reports", label: "Reports", icon: <FileText />, hint: "PDF, CSV, JSON, evidence bundle", rule: true },
  { href: "/help", label: "Methodology", icon: <CircleHelp />, hint: "How scoring, coverage and training work" },
  { href: "/settings", label: "Settings", icon: <Settings2 />, hint: "Identity, remediation defaults, LLM assist, workspace" },
];

export function Shell({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  const frameworks = useStore((s) => s.frameworks);
  const setFrameworks = useStore((s) => s.setFrameworks);
  const theme = useStore((s) => s.settings.theme);
  const updateSettings = useStore((s) => s.updateSettings);
  const persistError = useStore((s) => s.persistError);
  const fleet = useFleet();
  const palette = useUi((s) => s.palette);
  const setPalette = useUi((s) => s.setPalette);
  const firstRender = useRef(true);
  useEffect(() => applyTheme(theme), [theme]);

  // Route change: back to the top and hand focus to the page heading (skip the very first paint).
  useEffect(() => {
    if (firstRender.current) { firstRender.current = false; return; }
    window.scrollTo({ top: 0 });
    const h = document.getElementById("page-title");
    h?.focus({ preventScroll: true });
  }, [location]);

  // Global shortcuts: Ctrl/⌘+K or "/" opens the command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName;
      const typing = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (e.target as HTMLElement | null)?.isContentEditable;
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette(true); }
      else if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) { e.preventDefault(); setPalette(true); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setPalette]);

  const toggleFw = (f: FrameworkId) => setFrameworks(frameworks.includes(f) ? frameworks.filter((x) => x !== f) : [...frameworks, f]);
  const isActive = (href: string) => (href === "/" ? location === "/" : location.startsWith(href));
  const current = NAV.find((n) => isActive(n.href))?.label ?? "Not found";
  const failed = fleet.summary.fail;
  const unknown = fleet.unrecognized;
  const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

  return (
    <div className="shell">
      <a href="#main" className="skip">Skip to content</a>
      <aside className="rail">
        <Link href="/" className="brand" aria-label="NetSentinel AI home">
          <BrandMark />
          <div>
            <div className="brand__name">NetSentinel</div>
            <div className="brand__tag">COMPLIANCE AUDITOR</div>
          </div>
        </Link>
        <nav className="nav" aria-label="Primary">
          {NAV.map((n) => (
            <div key={n.href} style={{ display: "contents" }}>
              {n.rule && <div className="nav__rule" aria-hidden="true" />}
              <Link href={n.href} className={cn(isActive(n.href) && "active")} aria-current={isActive(n.href) ? "page" : undefined} title={n.label}>
                {n.icon}
                <span className="label">{n.label}</span>
                {n.href === "/findings" && failed > 0 && <span className="badge badge--fail" aria-label={`${failed} failed controls`}>{failed}</span>}
                {n.href === "/training" && unknown > 0 && <span className="badge badge--accent" aria-label={`${unknown} lines awaiting training`}>{unknown}</span>}
              </Link>
            </div>
          ))}
        </nav>
        <div className="rail__foot">
          SIH 2026 · PS SIH26155<br />NTRO · Blockchain &amp; Cybersecurity<br />v2.0 · runs entirely in the browser
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="topbar__crumb"><span>NetSentinel</span><span aria-hidden="true">/</span><strong>{current}</strong></div>
          <div className="topbar__spacer" />
          <div className="scope" role="group" aria-label="Frameworks in scope">
            <span className="scope__label">Scope</span>
            {(Object.keys(FRAMEWORKS) as FrameworkId[]).map((f) => (
              <button key={f} type="button" className={cn(frameworks.includes(f) && "on")} aria-pressed={frameworks.includes(f)} onClick={() => toggleFw(f)} title={`${FRAMEWORKS[f].name} — ${frameworks.includes(f) ? "in scope, click to exclude" : "excluded, click to include"}`}>
                {FRAMEWORKS[f].short}
              </button>
            ))}
          </div>
          <button type="button" className="btn btn--ghost" onClick={() => setPalette(true)} aria-label="Search devices, controls and pages" title="Search (Ctrl+K)">
            <Search size={15} /> <span className="label">Search</span> <kbd>{isMac ? "⌘" : "Ctrl"} K</kbd>
          </button>
          <button type="button" className="btn btn--ghost btn--icon" onClick={() => updateSettings({ theme: theme === "dark" ? "light" : "dark" })} aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"} title="Toggle theme">
            {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
          </button>
        </header>
        {persistError && (
          <div className="banner banner--fail" role="alert">
            <ShieldAlert size={16} aria-hidden="true" />
            <span className="grow">{persistError}</span>
            <Link href="/settings" className="btn btn--sm">Manage workspace</Link>
          </div>
        )}
        <main id="main">{children}</main>
      </div>
      {palette && <Palette onClose={() => setPalette(false)} />}
    </div>
  );
}

interface PaletteItem { kind: string; label: string; hint: string; go: () => void }

function Palette({ onClose }: { onClose: () => void }) {
  const [, navigate] = useLocation();
  const fleet = useFleet();
  const rules = useActiveRules();
  const setQuery = useUi((s) => s.setQuery);
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  useDialog(true, onClose, ref);

  const items = useMemo<PaletteItem[]>(() => {
    const needle = q.trim().toLowerCase();
    const pages: PaletteItem[] = NAV.map((n) => ({ kind: "Page", label: n.label, hint: n.hint, go: () => navigate(n.href) }));
    const devices: PaletteItem[] = fleet.devices.map((d) => ({ kind: "Device", label: d.name, hint: `${VENDOR_META[d.vendor].short} · ${d.record.fileName} · ${d.summary.fail} failed`, go: () => navigate(`/devices/${d.record.id}`) }));
    const controls: PaletteItem[] = rules.map((r) => ({ kind: "Control", label: `${r.id} — ${r.title}`, hint: `${r.category} · ${r.severity}`, go: () => { setQuery(r.id); navigate("/findings"); } }));
    const all = [...pages, ...devices, ...controls];
    const hits = needle ? all.filter((i) => `${i.label} ${i.hint}`.toLowerCase().includes(needle)) : [...pages, ...devices.slice(0, 5)];
    const list = hits.slice(0, 14);
    if (needle) list.push({ kind: "Findings", label: `Search findings for “${q.trim()}”`, hint: "opens Findings filtered by this text", go: () => { setQuery(q.trim()); navigate("/findings"); } });
    return list;
  }, [q, fleet.devices, rules, navigate, setQuery]);

  useEffect(() => setIdx(0), [q]);
  const run = (it: PaletteItem | undefined) => { if (!it) return; it.go(); onClose(); };

  return (
    <>
      <div className="scrim" onClick={onClose} aria-hidden="true" />
      <div ref={ref} className="palette" role="dialog" aria-modal="true" aria-label="Search">
        <input
          data-autofocus
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Jump to a page, device or control…"
          aria-label="Search"
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-list"
          aria-activedescendant={items[idx] ? `palette-${idx}` : undefined}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(items.length - 1, i + 1)); }
            else if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
            else if (e.key === "Enter") { e.preventDefault(); run(items[idx]); }
          }}
        />
        <div className="palette__list" id="palette-list" role="listbox">
          {items.map((it, i) => (
            <div key={`${it.kind}-${it.label}`} id={`palette-${i}`} role="option" aria-selected={i === idx} className={cn("palette__item", i === idx && "on")} onMouseEnter={() => setIdx(i)} onClick={() => run(it)}>
              <span className="palette__kind">{it.kind}</span>
              <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{it.label}</span>
              <span className="small muted nowrap" style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis" }}>{it.hint}</span>
            </div>
          ))}
          {!items.length && <div className="empty">Nothing matches.</div>}
        </div>
      </div>
    </>
  );
}
