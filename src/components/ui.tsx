import { Component, useEffect, useMemo, useRef, useState, type CSSProperties, type ErrorInfo, type KeyboardEvent as ReactKeyboardEvent, type ReactNode, type RefObject } from "react";
import { create } from "zustand";
import { AlertCircle, ArrowDown, ArrowUp, ArrowUpDown, Check, CheckCircle2, Copy, Info, X } from "lucide-react";
import type { Evidence, FrameworkId, Severity, Status, VendorId } from "../engine/types";
import { VENDOR_META } from "../engine/sbm";
import { FRAMEWORKS } from "../engine/rules/library";
import { scoreLabel } from "../engine/rules/evaluate";
import { cn } from "../lib/util";

/* ───────────────────────── toasts ───────────────────────── */
export interface ToastAction { label: string; onClick: () => void }
interface Toast { id: string; kind: "ok" | "err" | "info"; title: string; desc?: string; action?: ToastAction }
interface ToastState { toasts: Toast[]; push: (t: Omit<Toast, "id">) => string; dismiss: (id: string) => void }
const timers = new Map<string, ReturnType<typeof setTimeout>>();
function clearTimer(id: string) { const t = timers.get(id); if (t) clearTimeout(t); timers.delete(id); }
function scheduleDismiss(id: string, ms: number) { clearTimer(id); timers.set(id, setTimeout(() => { timers.delete(id); useToasts.getState().dismiss(id); }, ms)); }
export const useToasts = create<ToastState>((set) => ({
  toasts: [],
  push: (t) => {
    const id = Math.random().toString(36).slice(2);
    set((s) => ({ toasts: [...s.toasts, { ...t, id }].slice(-4) }));
    scheduleDismiss(id, t.kind === "err" ? 9000 : t.action ? 8000 : 4500);
    return id;
  },
  dismiss: (id) => { clearTimer(id); set((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })); },
}));
export const toast = {
  ok: (title: string, desc?: string, action?: ToastAction) => useToasts.getState().push({ kind: "ok", title, desc, action }),
  err: (title: string, desc?: string, action?: ToastAction) => useToasts.getState().push({ kind: "err", title, desc, action }),
  info: (title: string, desc?: string, action?: ToastAction) => useToasts.getState().push({ kind: "info", title, desc, action }),
};
export function Toasts() {
  const toasts = useToasts((s) => s.toasts);
  const dismiss = useToasts((s) => s.dismiss);
  return (
    <div className="toasts" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={cn("toast", `toast--${t.kind}`)} onMouseEnter={() => clearTimer(t.id)} onMouseLeave={() => scheduleDismiss(t.id, 2500)} onFocus={() => clearTimer(t.id)} onBlur={() => scheduleDismiss(t.id, 2500)}>
          {t.kind === "ok" ? <CheckCircle2 size={18} color="var(--pass)" aria-hidden="true" /> : t.kind === "err" ? <AlertCircle size={18} color="var(--fail)" aria-hidden="true" /> : <Info size={18} color="var(--accent)" aria-hidden="true" />}
          <div className="grow">
            <strong>{t.title}</strong>
            {t.desc && <div className="muted">{t.desc}</div>}
            {t.action && <button type="button" className="btn btn--sm" style={{ marginTop: 8 }} onClick={() => { t.action?.onClick(); dismiss(t.id); }}>{t.action.label}</button>}
          </div>
          <button type="button" className="btn btn--ghost btn--sm btn--icon" onClick={() => dismiss(t.id)} aria-label="Dismiss notification"><X size={14} /></button>
        </div>
      ))}
    </div>
  );
}

/* ───────────────────────── page structure ───────────────────────── */
export function Page({ title, eyebrow, status, actions, children }: { title: ReactNode; eyebrow?: ReactNode; status?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <div className="page">
      <header className="page__head">
        <div className="grow">
          {eyebrow && <div className="eyebrow" style={{ marginBottom: 6 }}>{eyebrow}</div>}
          <h1 id="page-title" tabIndex={-1} style={{ outline: "none" }}>{title}</h1>
          {status && <div className="page__status">{status}</div>}
        </div>
        {actions && <div className="page__actions">{actions}</div>}
      </header>
      {children}
    </div>
  );
}

/** Items of a status line, separated by middle dots. */
export function StatusLine({ items }: { items: ReactNode[] }) {
  const list = items.filter((i) => i !== null && i !== undefined && i !== false);
  return <>{list.map((it, i) => <span key={i} className="row" style={{ gap: 14 }}>{i > 0 && <span className="sep" aria-hidden="true">·</span>}<span>{it}</span></span>)}</>;
}

export function Section({ id, num, title, sub, actions, children, box, flush, className, style }: { id?: string; num?: string; title?: ReactNode; sub?: ReactNode; actions?: ReactNode; children: ReactNode; box?: boolean; flush?: boolean; className?: string; style?: CSSProperties }) {
  return (
    <section className={cn("section", className)} style={style} aria-labelledby={id}>
      {(title || actions) && (
        <div className="section__head">
          <div>
            {title && <h2 id={id}>{num && <span className="section__num">{num}</span>}{title}</h2>}
            {sub && <div className="section__sub">{sub}</div>}
          </div>
          {actions && <div className="section__actions">{actions}</div>}
        </div>
      )}
      {box ? <div className={cn("box", flush ? "box--flush" : "box--pad")}>{children}</div> : children}
    </section>
  );
}

export function Kpis({ cols = 4, children }: { cols?: number; children: ReactNode }) {
  return <div className={`kpis kpis--${cols}`}>{children}</div>;
}
export function Kpi({ label, value, unit, hint, tone, onClick, active }: { label: ReactNode; value: ReactNode; unit?: string; hint?: ReactNode; tone?: "pass" | "fail" | "warn" | "info" | "muted"; onClick?: () => void; active?: boolean }) {
  const color = tone === "pass" ? "var(--pass)" : tone === "fail" ? "var(--fail)" : tone === "warn" ? "var(--warn)" : tone === "info" ? "var(--info)" : tone === "muted" ? "var(--muted)" : undefined;
  const body = (
    <>
      <span className="kpi__label">{label}</span>
      <span className="kpi__value" style={{ color }}>{value}{unit && <small>{unit}</small>}</span>
      {hint && <span className="kpi__hint">{hint}</span>}
    </>
  );
  if (onClick) {
    return (
      <button type="button" className={cn("kpi", "kpi--clickable")} aria-pressed={active} onClick={onClick} style={{ borderTop: 0, borderBottom: 0, borderLeft: 0, borderRadius: 0, background: active ? "var(--accent-soft)" : "none", textAlign: "left", font: "inherit", color: "inherit", cursor: "pointer", appearance: "none" }}>
        {body}
      </button>
    );
  }
  return <div className="kpi">{body}</div>;
}

export function Empty({ icon, title, hint, action }: { icon?: ReactNode; title: string; hint?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      {icon}
      <strong>{title}</strong>
      {hint && <span className="small">{hint}</span>}
      {action}
    </div>
  );
}

export function Callout({ tone, children, icon }: { tone?: "warn" | "fail" | "ai"; children: ReactNode; icon?: ReactNode }) {
  return <div className={cn("callout", tone && `callout--${tone}`)} role={tone === "fail" ? "alert" : undefined}>{icon && <span style={{ verticalAlign: -2, marginRight: 6, display: "inline-flex" }}>{icon}</span>}{children}</div>;
}

/* ───────────────────────── tabs, segments, switches ───────────────────────── */
export function Tabs({ tabs, value, onChange, label }: { tabs: { id: string; label: string; badge?: number }[]; value: string; onChange: (id: string) => void; label: string }) {
  const onKey = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft" && e.key !== "Home" && e.key !== "End") return;
    e.preventDefault();
    const i = tabs.findIndex((t) => t.id === value);
    const n = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    onChange(tabs[n].id);
    e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]')[n]?.focus();
  };
  return (
    <div className="tabs" role="tablist" aria-label={label} onKeyDown={onKey}>
      {tabs.map((t) => (
        <button key={t.id} type="button" role="tab" id={`tab-${t.id}`} aria-selected={value === t.id} aria-controls={`panel-${t.id}`} tabIndex={value === t.id ? 0 : -1} className={cn(value === t.id && "on")} onClick={() => onChange(t.id)}>
          {t.label}
          {t.badge !== undefined && <span className={cn("badge", value === t.id && "badge--accent")}>{t.badge}</span>}
        </button>
      ))}
    </div>
  );
}
export function TabPanel({ id, active, children, pad }: { id: string; active: boolean; children: ReactNode; pad?: boolean }) {
  if (!active) return null;
  return <div role="tabpanel" id={`panel-${id}`} aria-labelledby={`tab-${id}`} className={pad ? "stack" : undefined} style={pad ? { padding: 16, gap: 14 } : undefined}>{children}</div>;
}

export function Segmented<T extends string>({ options, value, onChange, label }: { options: { id: T; label: string; count?: number }[]; value: T; onChange: (v: T) => void; label: string }) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.id} type="button" className={cn(value === o.id && "on")} aria-pressed={value === o.id} onClick={() => onChange(o.id)}>
          {o.label}
          {o.count !== undefined && <span className="badge">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Switch({ checked, onChange, label, ariaLabel, id }: { checked: boolean; onChange: (v: boolean) => void; label?: ReactNode; ariaLabel?: string; id?: string }) {
  return (
    <label className="switch">
      <input id={id} type="checkbox" role="switch" aria-checked={checked} aria-label={ariaLabel} checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label && <span>{label}</span>}
    </label>
  );
}

/* ───────────────────────── semantic marks ───────────────────────── */
export const STATUS_LABEL: Record<Status, string> = { pass: "Pass", fail: "Fail", warning: "Not assessed", na: "N/A" };
export function Stamp({ status, accepted }: { status: Status; accepted?: boolean }) {
  if (accepted) return <span className="stamp stamp--accepted" title="Failed control with an active risk acceptance">Accepted</span>;
  return <span className={cn("stamp", `stamp--${status}`)}>{STATUS_LABEL[status]}</span>;
}
export function Sev({ severity }: { severity: Severity }) {
  return <span className={cn("sev", `sev--${severity}`)}><i aria-hidden="true" />{severity[0].toUpperCase() + severity.slice(1)}</span>;
}
export function Vendor({ vendor, label }: { vendor: VendorId; label?: ReactNode }) {
  const m = VENDOR_META[vendor];
  return <span className="vendor"><i className="vendor__dot" style={{ background: m.color }} aria-hidden="true" />{label ?? m.short}</span>;
}
export function FwTag({ framework, id, title }: { framework: FrameworkId; id?: string; title?: string }) {
  return <span className={cn("tag", `tag--${framework}`)} title={title ?? FRAMEWORKS[framework].name}>{FRAMEWORKS[framework].short}{id ? ` ${id}` : ""}</span>;
}

/* ───────────────────────── instruments ───────────────────────── */
export function scoreTone(score: number, assessable = true): string {
  if (!assessable) return "var(--muted)";
  return score >= 85 ? "var(--pass)" : score >= 65 ? "var(--warn)" : "var(--fail)";
}
export function Gauge({ score, assessable, label, sub, coverage, bySeverity }: { score: number; assessable: boolean; label: string; sub?: ReactNode; coverage?: number; bySeverity?: Record<Severity, number> }) {
  const tone = scoreTone(score, assessable);
  const l = scoreLabel(score, assessable, { coverage, bySeverity });
  const pill = l.tone === "good" ? "pill--pass" : l.tone === "warn" ? "pill--warning" : l.tone === "bad" ? "pill--fail" : "pill--na";
  return (
    <div className="gauge" role="img" aria-label={`${label}: ${assessable ? `${score} of 100, ${l.label}` : "not assessed"}`}>
      <div className="gauge__value">
        <span className="gauge__num" style={{ color: tone }}>{assessable ? score : "—"}<small> /100</small></span>
        <span className={cn("pill", pill)}>{l.label}</span>
      </div>
      <div className="gauge__bar"><i style={{ width: `${assessable ? score : 0}%`, background: tone }} /></div>
      <div className="gauge__bands" aria-hidden="true"><span style={{ flex: 65, background: "var(--fail-soft)" }} /><span style={{ flex: 20, background: "var(--warn-soft)" }} /><span style={{ flex: 15, background: "var(--pass-soft)" }} /></div>
      <div className="gauge__ticks" aria-hidden="true" style={{ position: "relative", height: 14 }}>
        <span style={{ position: "absolute", left: 0 }}>0</span>
        <span style={{ position: "absolute", left: "65%", transform: "translateX(-50%)" }}>65</span>
        <span style={{ position: "absolute", left: "85%", transform: "translateX(-50%)" }}>85</span>
        <span style={{ position: "absolute", right: 0 }}>100</span>
      </div>
      {sub && <div className="small muted">{sub}</div>}
    </div>
  );
}
export function ScoreCell({ score, assessable }: { score: number; assessable: boolean }) {
  if (!assessable) return <span className="pill pill--na" title="Too little of this configuration was understood for a score to mean anything">Not assessed</span>;
  return (
    <span className="scorebar" role="img" aria-label={`score ${score} of 100`}>
      <span className="scorebar__track"><span className="scorebar__fill" style={{ width: `${score}%`, background: scoreTone(score) }} /></span>
      <span className="scorebar__n">{score}</span>
    </span>
  );
}
export function Bars({ rows }: { rows: { label: ReactNode; value: number; max: number; color: string; suffix?: string; title?: string }[] }) {
  return (
    <div className="bars">
      {rows.map((r, i) => (
        <div key={i} className="bars__row" title={r.title}>
          <span className="nowrap" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{r.label}</span>
          <div className="bars__track"><div className="bars__fill" style={{ width: `${r.max ? Math.round((r.value / r.max) * 100) : 0}%`, background: r.color }} /></div>
          <span className="num right small">{r.value}{r.suffix ?? ""}</span>
        </div>
      ))}
    </div>
  );
}
export function StackBar({ parts, label }: { parts: { value: number; color: string; label: string }[]; label: string }) {
  const total = parts.reduce((s, p) => s + p.value, 0);
  return (
    <div className="stackbar" role="img" aria-label={`${label}: ${parts.map((p) => `${p.value} ${p.label}`).join(", ")}`}>
      {parts.filter((p) => p.value > 0).map((p, i) => <span key={i} style={{ width: `${total ? (p.value / total) * 100 : 0}%`, background: p.color }} title={`${p.value} ${p.label}`} />)}
    </div>
  );
}
export function Sparkline({ points, height = 64 }: { points: number[]; height?: number }) {
  if (points.length < 2) return <div className="small muted">The trend line appears after the next audit run.</div>;
  const w = 320;
  const min = Math.min(...points, 0);
  const max = Math.max(...points, 100);
  const x = (i: number) => (i / (points.length - 1)) * (w - 8) + 4;
  const y = (v: number) => height - 6 - ((v - min) / (max - min || 1)) * (height - 14);
  const d = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)} ${y(p).toFixed(1)}`).join(" ");
  const last = points[points.length - 1];
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" role="img" aria-label={`score trend over ${points.length} audit runs, now ${last}`}>
      <line x1="4" x2={w - 4} y1={y(85)} y2={y(85)} stroke="var(--line-strong)" strokeDasharray="3 4" />
      <path d={`${d} L${x(points.length - 1)} ${height} L4 ${height} Z`} fill="var(--accent-soft)" />
      <path d={d} fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
      <circle cx={x(points.length - 1)} cy={y(last)} r="3.5" fill="var(--accent-strong)" />
    </svg>
  );
}
/** Heat colour for a pass rate (0..100) or null when nothing was assessed. The legend uses the same function. */
export function heatColor(passRate: number | null): string {
  if (passRate === null) return "var(--hover)";
  const p = Math.max(0, Math.min(100, passRate));
  return `color-mix(in srgb, var(--pass-soft) ${Math.round(p)}%, var(--fail-soft))`;
}
export function HeatLegend() {
  return (
    <div className="legend" aria-label="Heatmap legend">
      <span><i style={{ background: heatColor(100) }} /> all controls pass</span>
      <span><i style={{ background: heatColor(50) }} /> half fail</span>
      <span><i style={{ background: heatColor(0) }} /> all fail</span>
      <span><i style={{ background: heatColor(null) }} /> no evidence</span>
    </div>
  );
}

/* ───────────────────────── tables ───────────────────────── */
export type SortDir = "asc" | "desc";
export interface SortState { key: string; dir: SortDir }
export type Getters<T> = Record<string, (row: T) => string | number | boolean | null | undefined>;
export function useSort<T>(rows: T[], getters: Getters<T>, initial: SortState) {
  const [sort, setSort] = useState<SortState>(initial);
  const sorted = useMemo(() => {
    const g = getters[sort.key];
    if (!g) return rows;
    const dir = sort.dir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = g(a), vb = g(b);
      if (va === vb) return 0;
      if (va === undefined || va === null || va === "") return 1;
      if (vb === undefined || vb === null || vb === "") return -1;
      if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir;
      if (typeof va === "boolean" && typeof vb === "boolean") return ((va ? 1 : 0) - (vb ? 1 : 0)) * dir;
      return String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: "base" }) * dir;
    });
  }, [rows, getters, sort]);
  const toggle = (key: string) =>
    setSort((s) => {
      if (s.key === key) return { key, dir: s.dir === "asc" ? "desc" : "asc" };
      const sample = rows[0];
      const numeric = sample !== undefined && typeof getters[key]?.(sample) === "number";
      return { key, dir: numeric ? "desc" : "asc" };
    });
  return { sorted, sort, toggle };
}
export function SortTh({ label, k, sort, onSort, align, style }: { label: ReactNode; k: string; sort: SortState; onSort: (k: string) => void; align?: "right"; style?: CSSProperties }) {
  const active = sort.key === k;
  return (
    <th className={align === "right" ? "right" : undefined} style={style} aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" onClick={() => onSort(k)} title={`Sort by ${typeof label === "string" ? label : k}`}>
        {label}
        {active ? (sort.dir === "asc" ? <ArrowUp className="sort" aria-hidden="true" /> : <ArrowDown className="sort" aria-hidden="true" />) : <ArrowUpDown className="sort" style={{ opacity: 0.35 }} aria-hidden="true" />}
      </button>
    </th>
  );
}
export function Pager({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (pages <= 1) return null;
  const from = page * pageSize + 1;
  const to = Math.min(total, (page + 1) * pageSize);
  return (
    <nav className="pager" aria-label="Pagination">
      <span className="num">{from}–{to} of {total}</span>
      <span className="grow" />
      <button type="button" className="btn btn--sm" disabled={page === 0} onClick={() => onPage(page - 1)}>Previous</button>
      <span className="num">{page + 1} / {pages}</span>
      <button type="button" className="btn btn--sm" disabled={page >= pages - 1} onClick={() => onPage(page + 1)}>Next</button>
    </nav>
  );
}

/* ───────────────────────── code & evidence ───────────────────────── */
export type LineMark = "hit" | "fail" | "unknown" | "add" | "del";
export function CodeViewer({ raw, marks, focusLine, maxHeight }: { raw: string; marks?: Map<number, LineMark>; focusLine?: number; maxHeight?: number }) {
  const lines = useMemo(() => raw.replace(/\r\n?/g, "\n").split("\n"), [raw]);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!focusLine || !ref.current) return;
    const el = ref.current.querySelector<HTMLElement>(`[data-line="${focusLine}"]`);
    el?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [focusLine]);
  return (
    <div className="code" ref={ref} style={maxHeight ? { maxHeight } : undefined} tabIndex={0} aria-label="Configuration text">
      {lines.map((t, i) => {
        const n = i + 1;
        const mark = marks?.get(n);
        return (
          <div key={n} className={cn("code__line", mark, focusLine === n && "hit")} data-line={n}>
            <span className="code__n" aria-hidden="true">{n}</span>
            <span className="code__t">{t || " "}</span>
          </div>
        );
      })}
    </div>
  );
}
export function EvidenceList({ evidence, onJump, limit }: { evidence: Evidence[]; onJump?: (line: number) => void; limit?: number }) {
  if (!evidence.length) return <div className="small muted">No configuration line carried evidence for this control.</div>;
  const list = limit ? evidence.slice(0, limit) : evidence;
  return (
    <div className="evidence">
      {list.map((e, i) =>
        onJump && e.line ? (
          <button key={i} type="button" className="evidence__line" onClick={() => onJump(e.line)} title="Show this line in the configuration">
            <span className="n">L{e.line}</span>
            <span className="t">{e.text}</span>
            <span className="j">open ↗</span>
          </button>
        ) : (
          <div key={i} className="evidence__line" title={e.line ? `Line ${e.line}` : "Platform default"}>
            <span className="n">{e.line ? `L${e.line}` : "def"}</span>
            <span className="t">{e.text}</span>
            <span className="j" />
          </div>
        ),
      )}
      {limit && evidence.length > limit && <div className="small muted">+{evidence.length - limit} more lines</div>}
    </div>
  );
}
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn--sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          toast.err("Clipboard unavailable", "Select the text and copy it manually.");
        }
      }}
    >
      {done ? <Check /> : <Copy />} {done ? "Copied" : label}
    </button>
  );
}

/* ───────────────────────── overlays ───────────────────────── */
const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
/** Escape closes, Tab is trapped inside, focus returns to the opener, background scroll is locked. */
export function useDialog(open: boolean, onClose: () => void, ref: RefObject<HTMLElement | null>) {
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const node = ref.current;
    const focusables = () => Array.from(node?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []);
    const t = window.setTimeout(() => {
      const list = focusables();
      (list.find((el) => el.dataset.autofocus !== undefined) ?? list[0] ?? node)?.focus();
    }, 10);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); closeRef.current(); return; }
      if (e.key !== "Tab" || !node) return;
      const list = focusables();
      if (!list.length) { e.preventDefault(); return; }
      const first = list[0], last = list[list.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (e.shiftKey && (active === first || !node.contains(active))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && (active === last || !node.contains(active))) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.clearTimeout(t);
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
      previous?.focus?.();
    };
  }, [open, ref]);
}
export function Drawer({ open, onClose, title, sub, children, foot, width }: { open: boolean; onClose: () => void; title: ReactNode; sub?: ReactNode; children: ReactNode; foot?: ReactNode; width?: number }) {
  const ref = useRef<HTMLElement>(null);
  useDialog(open, onClose, ref);
  if (!open) return null;
  return (
    <>
      <div className="scrim" onClick={onClose} aria-hidden="true" />
      <aside ref={ref} className="drawer" style={width ? { width: `min(${width}px, 100%)` } : undefined} role="dialog" aria-modal="true" aria-labelledby="drawer-title">
        <div className="drawer__head">
          <div className="grow">
            <h2 id="drawer-title">{title}</h2>
            {sub && <div className="small muted" style={{ marginTop: 6 }}>{sub}</div>}
          </div>
          <button type="button" className="btn btn--ghost btn--icon" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </div>
        <div className="drawer__body">{children}</div>
        {foot && <div className="drawer__foot">{foot}</div>}
      </aside>
    </>
  );
}
export function Modal({ open, onClose, title, children, wide, foot }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; wide?: boolean; foot?: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useDialog(open, onClose, ref);
  if (!open) return null;
  return (
    <>
      <div className="scrim" aria-hidden="true" />
      <div className="modal" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
        <div ref={ref} className={cn("modal__card", wide && "modal__card--wide")} role="dialog" aria-modal="true" aria-labelledby="modal-title">
          <div className="modal__head">
            <h2 id="modal-title">{title}</h2>
            <button type="button" className="btn btn--ghost btn--icon" onClick={onClose} aria-label="Close"><X size={18} /></button>
          </div>
          <div className="modal__body">{children}</div>
          {foot && <div className="drawer__foot">{foot}</div>}
        </div>
      </div>
    </>
  );
}
/** Two-click confirmation for destructive actions: the first click arms the button for three seconds. */
export function Confirm({ label, armedLabel = "Click again to confirm", onConfirm, danger, icon, small = true, className }: { label: string; armedLabel?: string; onConfirm: () => void; danger?: boolean; icon?: ReactNode; small?: boolean; className?: string }) {
  const [arm, setArm] = useState(false);
  useEffect(() => {
    if (!arm) return;
    const t = setTimeout(() => setArm(false), 3000);
    return () => clearTimeout(t);
  }, [arm]);
  return (
    <button type="button" className={cn("btn", small && "btn--sm", danger && "btn--danger", arm && "armed", className)} aria-live="polite" onClick={() => (arm ? (onConfirm(), setArm(false)) : setArm(true))}>
      {icon}
      {arm ? armedLabel : label}
    </button>
  );
}

/* ───────────────────────── error boundary ───────────────────────── */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error("NetSentinel UI error", error, info); }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="error-fallback" role="alert">
        <h1 style={{ fontSize: 24 }}>The page hit an unexpected error</h1>
        <p className="muted">Your devices, mappings and settings are still stored in this browser. Reload to continue. If the error returns, reset the workspace to the sample fleet.</p>
        <pre className="cli" style={{ maxHeight: 160 }}>{this.state.error.message || String(this.state.error)}</pre>
        <div className="row">
          <button type="button" className="btn btn--primary" onClick={() => window.location.reload()}>Reload</button>
          <Confirm label="Reset workspace and reload" danger small={false} onConfirm={() => { try { window.localStorage.removeItem("netsentinel-v2"); } catch { /* ignore */ } window.location.hash = "#/"; window.location.reload(); }} />
        </div>
      </div>
    );
  }
}
