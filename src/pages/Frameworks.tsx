import { useMemo, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { useActiveRules, useFleet, useStore } from "../store";
import { Confirm, FwTag, Modal, Page, Section, Sev, StatusLine, Switch, toast } from "../components/ui";
import { FRAMEWORKS, RULES } from "../engine/rules/library";
import { SBM_CATEGORIES, SBM_INDEX, SBM_PARAMS, VENDOR_IDS, VENDOR_META, paramType } from "../engine/sbm";
import { cn, pct } from "../lib/util";
import type { ControlCategory, FrameworkId, Operator, Rule, RuleCheckNode, Severity } from "../engine/types";

const paramsOf = (c: RuleCheckNode): string[] => ("param" in c ? [c.param] : "all" in c ? c.all.flatMap(paramsOf) : c.any.flatMap(paramsOf));

const OPS: { id: Operator; label: string; needsValue: boolean }[] = [
  { id: "eq", label: "equals", needsValue: true },
  { id: "neq", label: "does not equal", needsValue: true },
  { id: "gte", label: "is at least", needsValue: true },
  { id: "lte", label: "is at most", needsValue: true },
  { id: "includes", label: "list includes", needsValue: true },
  { id: "excludes", label: "list excludes", needsValue: true },
  { id: "empty", label: "is empty / false", needsValue: false },
  { id: "notEmpty", label: "is not empty", needsValue: false },
  { id: "exists", label: "is observed", needsValue: false },
  { id: "notExists", label: "is not observed", needsValue: false },
  { id: "regex", label: "matches regex", needsValue: true },
];
const FW_IDS = Object.keys(FRAMEWORKS) as FrameworkId[];

/** Which conditions make sense for a parameter's type — a list cannot be "at least 12". */
const OPS_BY_TYPE: Record<string, Operator[]> = {
  boolean: ["eq", "neq", "exists", "notExists", "empty", "notEmpty"],
  number: ["eq", "neq", "gte", "lte", "exists", "notExists"],
  string: ["eq", "neq", "regex", "in", "notIn", "exists", "notExists", "empty", "notEmpty"],
  list: ["includes", "excludes", "in", "notIn", "countGte", "countLte", "empty", "notEmpty", "exists", "notExists"],
};

export default function Frameworks() {
  const fleet = useFleet();
  const frameworks = useStore((s) => s.frameworks);
  const setFrameworks = useStore((s) => s.setFrameworks);
  const disabled = useStore((s) => s.disabledRules);
  const toggleRule = useStore((s) => s.toggleRule);
  const customRules = useStore((s) => s.customRules);
  const addCustomRule = useStore((s) => s.addCustomRule);
  const removeCustomRule = useStore((s) => s.removeCustomRule);
  const active = useActiveRules();
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("all");
  const [fw, setFw] = useState<FrameworkId | "all">("all");
  const [open, setOpen] = useState(false);

  const all = useMemo(() => [...RULES, ...customRules], [customRules]);
  const rows = all.filter((r) => (cat === "all" || r.category === cat) && (fw === "all" || r.refs.some((x) => x.framework === fw)) && (!q || `${r.id} ${r.title} ${r.refs.map((x) => x.id).join(" ")}`.toLowerCase().includes(q.toLowerCase())));
  const perFramework = (f: FrameworkId) => all.filter((r) => r.refs.some((x) => x.framework === f)).length;
  const fleetRate = useMemo(() => {
    const out: Record<FrameworkId, { pass: number; fail: number }> = { cis: { pass: 0, fail: 0 }, nist: { pass: 0, fail: 0 }, stig: { pass: 0, fail: 0 }, iso: { pass: 0, fail: 0 } };
    for (const f of fleet.findings) {
      if (f.status !== "pass" && f.status !== "fail") continue;
      for (const r of f.refs) out[r.framework][f.status]++;
    }
    return out;
  }, [fleet.findings]);

  const nextId = (n: number) => `NS-CUSTOM-${String(n).padStart(3, "0")}`;
  const [form, setForm] = useState({ id: nextId(customRules.length + 1), title: "", category: "Management Plane" as ControlCategory, severity: "medium" as Severity, param: SBM_PARAMS[0].key, op: "eq" as Operator, value: "true", expected: "", description: "", cis: "", nist: "", stig: "", iso: "", remediation: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const set = (k: keyof typeof form, v: string) => setForm((f) => ({ ...f, [k]: v }));
  const op = OPS.find((o) => o.id === form.op)!;
  const allowedOps = OPS.filter((o) => OPS_BY_TYPE[paramType(form.param)]?.includes(o.id) ?? true);

  const save = () => {
    const e: Record<string, string> = {};
    const idv = form.id.trim().toUpperCase();
    if (!/^[A-Z0-9][A-Z0-9-]{2,30}$/.test(idv)) e.id = "Use 3–31 characters: letters, digits and hyphens.";
    else if (all.some((r) => r.id === idv)) e.id = `${idv} already exists.`;
    if (form.title.trim().length < 4) e.title = "Give the control a title.";
    if (op.needsValue && !form.value.trim()) e.value = "This condition needs a value.";
    if (!allowedOps.some((o) => o.id === form.op)) e.op = `“${op.label}” does not apply to a ${paramType(form.param)} parameter.`;
    if (op.needsValue && paramType(form.param) === "number" && !/^-?\d+(\.\d+)?$/.test(form.value.trim())) e.value = "This parameter holds a number.";
    if (form.op === "regex") { try { new RegExp(form.value); } catch { e.value = "Not a valid regular expression."; } }
    setErrors(e);
    if (Object.keys(e).length) return;
    let value: string | number | boolean | undefined;
    if (op.needsValue) {
      const raw = form.value.trim();
      value = raw === "true" ? true : raw === "false" ? false : /^-?\d+(\.\d+)?$/.test(raw) ? parseFloat(raw) : raw;
    }
    const refs = FW_IDS.filter((f) => form[f].trim()).map((f) => ({ framework: f, id: form[f].trim() }));
    if (!refs.length) refs.push({ framework: "iso", id: "Org. policy" });
    const paramDef = SBM_PARAMS.find((p) => p.key === form.param);
    const rule: Rule = {
      id: idv,
      title: form.title.trim(),
      category: form.category,
      severity: form.severity,
      description: form.description.trim() || "Organisation-specific control.",
      expected: form.expected.trim() || `${paramDef?.label ?? form.param} ${op.label}${op.needsValue ? ` ${form.value.trim()}` : ""}`,
      check: { param: form.param, op: form.op, ...(value !== undefined ? { value } : {}) },
      refs,
      remediation: { generic: form.remediation.trim() || "Apply the organisation hardening standard for this parameter." },
      custom: true,
    };
    if (!addCustomRule(rule)) return setErrors({ id: `${idv} already exists.` });
    setOpen(false);
    toast.ok("Control added", `${rule.id} is now evaluated on every device in scope.`);
    setForm((f) => ({ ...f, id: nextId(customRules.length + 2), title: "", expected: "", description: "", remediation: "" }));
  };

  return (
    <Page
      title="Frameworks & controls"
      status={<StatusLine items={[<><strong>{active.length}</strong> active of {all.length} controls</>, <><strong>{SBM_PARAMS.length}</strong> baseline parameters</>, "Selecting a framework scopes the audit; adding a control is data, not code"]} />}
      actions={<button type="button" className="btn btn--primary" onClick={() => setOpen(true)}><Plus /> Add custom control</button>}
    >
      <div className="grid grid--4">
        {FW_IDS.map((f) => {
          const on = frameworks.includes(f);
          const r = fleetRate[f];
          const rate = r.pass + r.fail ? pct(r.pass, r.pass + r.fail) : null;
          return (
            <div key={f} className={cn("box box--pad stack")} style={{ gap: 8, borderColor: on ? "var(--accent)" : undefined }}>
              <div className="row between">
                <FwTag framework={f} />
                <Switch checked={on} onChange={(v) => setFrameworks(v ? [...frameworks, f] : frameworks.filter((x) => x !== f))} ariaLabel={`${FRAMEWORKS[f].name} in scope`} label={<span className="small">{on ? "in scope" : "excluded"}</span>} />
              </div>
              <strong>{FRAMEWORKS[f].name}</strong>
              <span className="small muted">{FRAMEWORKS[f].blurb}</span>
              <div className="row between" style={{ marginTop: 4 }}>
                <span className="small faint">{FRAMEWORKS[f].edition}</span>
              </div>
              <div className="row between" style={{ borderTop: "1px solid var(--line)", paddingTop: 8 }}>
                <span className="small muted">{perFramework(f)} mapped controls</span>
                <span className="small num" style={{ color: rate === null ? "var(--muted)" : rate >= 85 ? "var(--pass)" : rate >= 65 ? "var(--warn)" : "var(--fail)", fontWeight: 600 }}>{rate === null ? "no evidence" : `${rate}% fleet pass rate`}</span>
              </div>
            </div>
          );
        })}
      </div>

      <Section
        id="fw-library"
        title="Control library"
        sub="Toggle a control to exclude it from every audit; custom controls carry the same evidence and remediation flow"
        box
        flush
        actions={
          <>
            <select className="select input--sm" style={{ width: 190 }} value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Control family"><option value="all">All families</option>{SBM_CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}</select>
            <select className="select input--sm" style={{ width: 150 }} value={fw} onChange={(e) => setFw(e.target.value as FrameworkId | "all")} aria-label="Framework"><option value="all">All frameworks</option>{FW_IDS.map((f) => <option key={f} value={f}>{FRAMEWORKS[f].short}</option>)}</select>
            <input className="input input--sm" style={{ width: 200 }} placeholder="Search controls…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search controls" />
            <span className="small muted">{rows.length} shown</span>
          </>
        }
      >
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>On</th><th>Control</th><th>Family</th><th>Severity</th><th>Checks</th><th>CIS</th><th>NIST 800-53</th><th>DISA STIG</th><th>ISO 27001</th><th>Applies to</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {rows.map((r) => {
                const on = !disabled.includes(r.id);
                const refsOf = (f: FrameworkId) => r.refs.filter((x) => x.framework === f);
                const keys = Array.from(new Set(paramsOf(r.check)));
                return (
                  <tr key={r.id} style={{ opacity: on ? 1 : 0.55 }}>
                    <td><Switch checked={on} onChange={(v) => toggleRule(r.id, v)} ariaLabel={`Enable ${r.id}`} /></td>
                    <td><div className="mono small">{r.id}{r.custom && <span className="pill pill--accent" style={{ marginLeft: 6 }}>custom</span>}</div><strong>{r.title}</strong><div className="small muted" style={{ maxWidth: 380 }}>{r.expected}</div></td>
                    <td className="dim small nowrap">{r.category}</td>
                    <td><Sev severity={r.severity} /></td>
                    <td className="small" style={{ minWidth: 170 }}>{keys.map((k) => SBM_INDEX[k]?.label ?? k).join(" · ")}<div className="mono tiny faint" style={{ overflowWrap: "anywhere" }}>{keys.join(" ")}</div></td>
                    {FW_IDS.map((f) => (
                      <td key={f}><div className="stack" style={{ gap: 3 }}>{refsOf(f).map((x, i) => <span key={i}><FwTag framework={f} id={x.id} title={x.title} /></span>)}{!refsOf(f).length && <span className="faint">—</span>}</div></td>
                    ))}
                    <td className="small dim">{r.appliesTo ? r.appliesTo.map((v) => VENDOR_META[v].short).join(", ") : "all vendors"}</td>
                    <td>{r.custom && <Confirm label="Remove" danger icon={<Trash2 size={13} />} onConfirm={() => { removeCustomRule(r.id); toast.info("Custom control removed", r.id); }} />}</td>
                  </tr>
                );
              })}
              {!rows.length && <tr><td colSpan={11} className="muted" style={{ textAlign: "center", padding: 30 }}>No control matches.</td></tr>}
            </tbody>
          </table>
        </div>
      </Section>

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Add a custom control"
        foot={<><span className="small muted grow">Applies to all {VENDOR_IDS.length} vendor families. Placeholders like {"{{syslog_host}}"} in the remediation are filled from Settings.</span><button type="button" className="btn" onClick={() => setOpen(false)}>Cancel</button><button type="button" className="btn btn--primary" onClick={save}>Save control</button></>}
      >
        <div className="grid grid--2">
          <div className="field"><label htmlFor="cr-id">Control ID</label><input id="cr-id" data-autofocus className="input mono" value={form.id} onChange={(e) => set("id", e.target.value)} aria-invalid={Boolean(errors.id)} />{errors.id && <span className="error">{errors.id}</span>}</div>
          <div className="field"><label htmlFor="cr-sev">Severity</label><select id="cr-sev" className="select" value={form.severity} onChange={(e) => set("severity", e.target.value)}>{["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s}</option>)}</select></div>
          <div className="field" style={{ gridColumn: "span 2" }}><label htmlFor="cr-title">Title</label><input id="cr-title" className="input" value={form.title} onChange={(e) => set("title", e.target.value)} placeholder="e.g. Idle timeout must be 5 minutes or less" aria-invalid={Boolean(errors.title)} />{errors.title && <span className="error">{errors.title}</span>}</div>
          <div className="field"><label htmlFor="cr-cat">Family</label><select id="cr-cat" className="select" value={form.category} onChange={(e) => set("category", e.target.value)}>{SBM_CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}</select></div>
          <div className="field"><label htmlFor="cr-param">Baseline parameter</label><select id="cr-param" className="select" value={form.param} onChange={(e) => { const next = e.target.value; const ok = OPS_BY_TYPE[paramType(next)] ?? []; setForm((f) => ({ ...f, param: next, op: ok.includes(f.op) ? f.op : (ok[0] ?? f.op) })); }}>{SBM_CATEGORIES.map((c) => <optgroup key={c} label={c}>{SBM_PARAMS.filter((p) => p.category === c).map((p) => <option key={p.key} value={p.key}>{p.label} ({p.type})</option>)}</optgroup>)}</select></div>
          <div className="field"><label htmlFor="cr-op">Condition</label><select id="cr-op" className="select" value={form.op} onChange={(e) => set("op", e.target.value)} aria-invalid={Boolean(errors.op)}>{allowedOps.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}</select>{errors.op ? <span className="error">{errors.op}</span> : <span className="hint">Conditions are filtered to the parameter type ({paramType(form.param)}).</span>}</div>
          <div className="field"><label htmlFor="cr-val">Value</label><input id="cr-val" className="input" value={form.value} onChange={(e) => set("value", e.target.value)} disabled={!op.needsValue} placeholder="true / 12 / text" aria-invalid={Boolean(errors.value)} />{errors.value ? <span className="error">{errors.value}</span> : <span className="hint">true/false, a number, or text</span>}</div>
          <div className="field" style={{ gridColumn: "span 2" }}><label htmlFor="cr-exp">Expected state (shown in reports)</label><input id="cr-exp" className="input" value={form.expected} onChange={(e) => set("expected", e.target.value)} /></div>
          <div className="field" style={{ gridColumn: "span 2" }}><label htmlFor="cr-desc">Rationale</label><textarea id="cr-desc" className="textarea" style={{ minHeight: 70, fontFamily: "var(--font-body)" }} value={form.description} onChange={(e) => set("description", e.target.value)} /></div>
          {FW_IDS.map((f) => <div key={f} className="field"><label htmlFor={`cr-${f}`}>{FRAMEWORKS[f].short} reference</label><input id={`cr-${f}`} className="input" value={form[f]} onChange={(e) => set(f, e.target.value)} placeholder={f === "cis" ? "IOS 1.2.9" : f === "nist" ? "AC-12" : f === "stig" ? "SRG-APP-000190-NDM-000267" : "A.8.5"} /></div>)}
          <div className="field" style={{ gridColumn: "span 2" }}><label htmlFor="cr-rem">Remediation guidance</label><textarea id="cr-rem" className="textarea" style={{ minHeight: 70 }} value={form.remediation} onChange={(e) => set("remediation", e.target.value)} placeholder="CLI or procedure." /></div>
        </div>
      </Modal>
    </Page>
  );
}
