import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "wouter";
import { BrainCircuit, ChevronDown, ChevronRight, Download, GraduationCap, Pencil, Sparkles, Trash2, Upload, Wand2 } from "lucide-react";
import { useFleet, useStore } from "../store";
import { useUi } from "../components/Shell";
import { Empty, Modal, Page, Section, StatusLine, Vendor, toast } from "../components/ui";
import { confidenceLabel, suggestForLine } from "../engine/classifier";
import { modeFitsType, polarityOf, testMapping } from "../engine/mappings";
import { SBM_CATEGORIES, SBM_INDEX, SBM_PARAMS, VENDOR_META } from "../engine/sbm";
import { suggestWithLlm } from "../engine/llm";
import { mappingPack, parseMappingPack } from "../engine/report/exports";
import { EXOS_STARTER_PACK } from "../engine/samples/packs";
import { downloadText, escapeRegex, plural } from "../lib/util";
import type { Mapping, ParamValue, Suggestion, ValueMode, VendorId } from "../engine/types";

type Draft = { name: string; vendor: VendorId | "any"; param: string; valueMode: ValueMode; pattern: string; constValue: string; captureGroup: number; transform: "string" | "number" | "boolean" };
const MODES: { id: ValueMode; label: string }[] = [
  { id: "polarity", label: "Polarity — enable/disable words decide true/false" },
  { id: "flag", label: "Flag — presence of the line means true" },
  { id: "const", label: "Constant — fixed value" },
  { id: "capture", label: "Capture — a regex group holds the value" },
  { id: "list", label: "List — append the captured value to a list" },
  { id: "count", label: "Count — increment per matching line" },
];
const transformFor = (param: string): Draft["transform"] => { const t = SBM_INDEX[param]?.type; return t === "number" ? "number" : t === "boolean" ? "boolean" : "string"; };
const parseConst = (v: string): ParamValue => (v === "true" ? true : v === "false" ? false : /^-?\d+(\.\d+)?$/.test(v) ? parseFloat(v) : v);

export default function Training() {
  const fleet = useFleet();
  const mappings = useStore((s) => s.mappings);
  const addMapping = useStore((s) => s.addMapping);
  const updateMapping = useStore((s) => s.updateMapping);
  const removeMapping = useStore((s) => s.removeMapping);
  const importMappings = useStore((s) => s.importMappings);
  const llm = useStore((s) => s.settings.llm);
  const log = useStore((s) => s.log);
  const trainingDevice = useUi((s) => s.trainingDevice);
  const setTrainingDevice = useUi((s) => s.setTrainingDevice);

  const candidates = useMemo(() => fleet.devices.filter((d) => d.parse.unrecognized.length > 0).sort((a, b) => b.parse.unrecognized.length - a.parse.unrecognized.length), [fleet.devices]);
  const [deviceId, setDeviceId] = useState<string>(trainingDevice ?? candidates[0]?.record.id ?? "");
  const device = fleet.devices.find((d) => d.record.id === deviceId) ?? candidates[0];
  const lines = useMemo(() => device?.parse.unrecognized ?? [], [device]);
  const [filter, setFilter] = useState("");
  const [selectedLine, setSelectedLine] = useState<number | null>(null);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [llmResults, setLlmResults] = useState<Record<number, Suggestion>>({});
  const [llmBusy, setLlmBusy] = useState(false);
  const [editing, setEditing] = useState<Mapping | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => { if (trainingDevice) { setDeviceId(trainingDevice); setTrainingDevice(null); } }, [trainingDevice, setTrainingDevice]);
  useEffect(() => { if (!device && candidates[0]) setDeviceId(candidates[0].record.id); }, [device, candidates]);

  const visible = lines.filter((l) => !filter || l.text.toLowerCase().includes(filter.toLowerCase()));
  const groups = useMemo(() => {
    const m = new Map<string, typeof visible>();
    for (const l of visible) { const k = l.context ?? "top level"; m.set(k, [...(m.get(k) ?? []), l]); }
    return Array.from(m.entries());
  }, [visible]);
  const line = lines.find((l) => l.line === selectedLine) ?? visible[0] ?? null;
  const suggestions = useMemo(() => (line ? suggestForLine(line.text, mappings, 3) : []), [line, mappings]);
  const llmFor = line ? llmResults[line.line] : undefined;
  const topByLine = useMemo(() => {
    const m = new Map<number, Suggestion | undefined>();
    for (const l of lines) m.set(l.line, llmResults[l.line] ?? suggestForLine(l.text, mappings, 1)[0]);
    return m;
  }, [lines, mappings, llmResults]);
  const highConfidence = useMemo(() => lines.filter((l) => (topByLine.get(l.line)?.confidence ?? 0) >= 0.72).length, [lines, topByLine]);

  const [draft, setDraft] = useState<Draft | null>(null);
  const applySuggestion = (s: Suggestion) => {
    if (!line) return;
    const def = SBM_INDEX[s.param];
    setDraft({ name: `${device?.parse.identity.os ?? "Custom"} · ${def?.label ?? s.param}`, vendor: device?.vendor === "generic" ? "any" : (device?.vendor ?? "any"), param: s.param, valueMode: s.valueMode, pattern: s.pattern, constValue: s.constValue === undefined ? "true" : String(s.constValue), captureGroup: s.captureGroup ?? 1, transform: s.transform ?? transformFor(s.param) });
  };
  useEffect(() => {
    if (llmFor) applySuggestion(llmFor);
    else if (suggestions[0]) applySuggestion(suggestions[0]);
    else if (line) setDraft({ name: `Custom · ${line.text.slice(0, 30)}`, vendor: device?.vendor === "generic" ? "any" : (device?.vendor ?? "any"), param: SBM_PARAMS[0].key, valueMode: "flag", pattern: `^${escapeRegex(line.text).replace(/\s+/g, "\\s+")}$`, constValue: "true", captureGroup: 1, transform: "boolean" });
    else setDraft(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [line?.line, llmFor, device?.record.id]);

  const patternError = useMemo(() => { if (!draft) return null; try { new RegExp(draft.pattern, "i"); return null; } catch (e) { return String(e); } }, [draft]);
  const matches = useMemo(() => (draft && !patternError ? testMapping(draft.pattern, "i", lines) : []), [draft, patternError, lines]);
  const previewValue = (m: { text: string; groups: string[] }): string => {
    if (!draft) return "";
    switch (draft.valueMode) {
      case "const": return draft.constValue;
      case "flag": return "true";
      case "polarity": return String(polarityOf(m.text, m.groups[draft.captureGroup - 1]));
      case "count": return "+1";
      default: return m.groups[draft.captureGroup - 1] ?? "(no capture)";
    }
  };

  const save = () => {
    if (!draft) return;
    if (patternError) return toast.err("Invalid regular expression", patternError);
    if (!matches.length) return toast.err("The pattern matches nothing", "Adjust the regex until at least the selected line matches.");
    if (!modeFitsType(draft.param, draft.valueMode)) return toast.err("This extraction mode cannot fill that parameter", `${SBM_INDEX[draft.param]?.label ?? draft.param} is a ${SBM_INDEX[draft.param]?.type ?? "string"} parameter — choose a compatible value extraction.`);
    if ((draft.valueMode === "capture" || draft.valueMode === "list") && !((matches.find((m) => m.line === line?.line) ?? matches[0]).groups[draft.captureGroup - 1] ?? "").trim()) return toast.err("The pattern captures no value", `Capture group ${draft.captureGroup} is empty on this line. Put parentheses around the value the parameter should store.`);
    addMapping({ name: draft.name.trim() || `Mapping · ${draft.param}`, vendor: draft.vendor, pattern: draft.pattern, flags: "i", param: draft.param, valueMode: draft.valueMode, constValue: draft.valueMode === "const" ? parseConst(draft.constValue.trim()) : undefined, captureGroup: draft.captureGroup, transform: draft.transform, createdBy: llmFor ? "llm" : "admin", sampleLine: line?.text });
    toast.ok("Mapping learned", `${plural(matches.length, "line")} now map to ${SBM_INDEX[draft.param]?.label ?? draft.param}. The fleet was re-parsed and re-evaluated.`);
    setSelectedLine(null);
  };

  const autoAccept = () => {
    let n = 0;
    const seen = new Set<string>();
    for (const l of lines) {
      const s = topByLine.get(l.line);
      if (!s || s.confidence < 0.72) continue;
      if (s.extractionValid === false || !modeFitsType(s.param, s.valueMode)) continue;
      if ((s.valueMode === "capture" || s.valueMode === "list") && !(testMapping(s.pattern, "i", [l])[0]?.groups[(s.captureGroup ?? 1) - 1] ?? "").trim()) continue;
      const key = `${s.param}|${s.pattern}`;
      if (seen.has(key)) continue;
      seen.add(key);
      addMapping({ name: `${device?.parse.identity.os ?? "Auto"} · ${SBM_INDEX[s.param]?.label ?? s.param}`, vendor: device?.vendor === "generic" ? "any" : (device?.vendor ?? "any"), pattern: s.pattern, flags: "i", param: s.param, valueMode: s.valueMode, constValue: s.constValue, captureGroup: s.captureGroup ?? 1, transform: s.transform, createdBy: s.source === "llm" ? "llm" : "classifier", sampleLine: l.text });
      n++;
    }
    if (!n) return toast.info("Nothing above the confidence threshold", "Review the remaining lines by hand or ask the LLM.");
    toast.ok(`${plural(n, "high-confidence mapping")} accepted`, "The engine re-parsed the fleet with the new knowledge.");
  };

  const askLlm = async () => {
    if (!device) return;
    if (!llm.apiKey) return toast.err("No API key for this session", "Add your Anthropic API key under Settings → LLM assist. It is kept only for this browser tab.");
    setLlmBusy(true);
    try {
      const res = await suggestWithLlm(lines, device.vendor, `${device.parse.identity.vendorName} ${device.parse.identity.os}`, llm);
      setLlmResults((prev) => ({ ...prev, ...res.suggestions }));
      log({ actor: "llm", action: "LLM suggestions", target: `${Object.keys(res.suggestions).length} lines · ${res.model}`, detail: `${res.inputTokens} in / ${res.outputTokens} out tokens` });
      toast.ok(`${Object.keys(res.suggestions).length} LLM proposals`, "Review each one — nothing is applied until you accept it.");
    } catch (e) {
      toast.err("LLM assist failed", e instanceof Error ? e.message : String(e));
    } finally {
      setLlmBusy(false);
    }
  };

  const importFile = async (f: File) => {
    try {
      const r = importMappings(parseMappingPack(await f.text()));
      if (!r.imported) toast.info("Nothing imported", r.skipped ? `${r.skipped} entries were invalid or already present.` : "The pack was empty.");
      else toast.ok(`${plural(r.imported, "mapping")} imported`, `${r.skipped ? `${r.skipped} skipped · ` : ""}devices were re-parsed with the pack.`);
    } catch (e) {
      toast.err("Import failed", String(e));
    }
  };
  const remove = (m: Mapping) => {
    removeMapping(m.id);
    toast.info("Mapping removed", m.name, { label: "Undo", onClick: () => addMapping({ ...m }) });
  };
  const saveEdit = () => {
    if (!editing) return;
    try { new RegExp(editing.pattern, editing.flags ?? "i"); } catch (e) { return toast.err("Invalid regular expression", String(e)); }
    updateMapping(editing.id, { name: editing.name, param: editing.param, pattern: editing.pattern, valueMode: editing.valueMode, constValue: editing.valueMode === "const" ? parseConst(String(editing.constValue ?? "true")) : undefined, captureGroup: editing.captureGroup, vendor: editing.vendor, transform: transformFor(editing.param) });
    setEditing(null);
    toast.ok("Mapping updated", "The fleet was re-parsed.");
  };
  const toggleGroup = (k: string) => setCollapsed((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });

  return (
    <Page
      title="Training Studio"
      status={<StatusLine items={[<><strong>{fleet.unrecognized}</strong> unrecognised lines across {plural(candidates.length, "device")}</>, <><strong>{mappings.length}</strong> learned mappings</>, "A confirmed mapping applies fleet-wide on the next parse — no redeploy"]} />}
      actions={
        <>
          <input ref={fileInput} id="pack-input" type="file" accept="application/json,.json" hidden aria-hidden="true" onChange={(e) => { const f = e.target.files?.[0]; if (f) importFile(f); e.target.value = ""; }} />
          <button type="button" className="btn" onClick={() => fileInput.current?.click()}><Upload /> Import pack</button>
          <button type="button" className="btn" onClick={() => { downloadText(mappingPack(mappings), "netsentinel-mapping-pack.json", "application/json"); toast.ok("Mapping pack exported"); }} disabled={!mappings.length}><Download /> Export pack</button>
          <button type="button" className="btn" onClick={askLlm} disabled={llmBusy || !lines.length}><Sparkles /> {llmBusy ? "Asking…" : "Ask LLM"}</button>
          <button type="button" className="btn btn--primary" onClick={autoAccept} disabled={!highConfidence}><Wand2 /> Accept {highConfidence} high-confidence</button>
        </>
      }
    >
      {!candidates.length ? (
        <div className="box box--pad">
          <Empty icon={<GraduationCap />} title="Every line in the fleet is understood" hint={<span>Ingest an unknown vendor to see the training loop — the Extreme EXOS sample on the <Link href="/ingest">Ingest</Link> page is built for it.</span>} />
        </div>
      ) : (
        <div className="grid">
          <Section
            className="span-5"
            id="tr-queue"
            title="Unrecognised lines"
            sub={device ? `${device.name} · ${VENDOR_META[device.vendor].short} parser · grouped by configuration block` : ""}
            box
            flush
            actions={
              <select className="select input--sm" style={{ width: 210 }} value={device?.record.id ?? ""} onChange={(e) => { setDeviceId(e.target.value); setSelectedLine(null); setLlmResults({}); }} aria-label="Device">
                {candidates.map((d) => <option key={d.record.id} value={d.record.id}>{d.name} ({d.parse.unrecognized.length})</option>)}
              </select>
            }
          >
            <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--line)" }}>
              <input className="input input--sm" placeholder="Filter lines…" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter lines" />
            </div>
            <div className="queue" style={{ maxHeight: 640, overflowY: "auto" }} role="listbox" aria-label="Unrecognised lines">
              {groups.map(([k, ls]) => {
                const closed = collapsed.has(k);
                return (
                  <div key={k} className="queue__group">
                    <button type="button" className="queue__grouphead" style={{ width: "100%", border: 0, textAlign: "left", color: "inherit" }} aria-expanded={!closed} onClick={() => toggleGroup(k)}>
                      <span className="row" style={{ gap: 6 }}>{closed ? <ChevronRight size={14} /> : <ChevronDown size={14} />}<span className="mono">{k}</span></span>
                      <span className="badge">{ls.length}</span>
                    </button>
                    {!closed && ls.map((l) => {
                      const top = topByLine.get(l.line);
                      const on = line?.line === l.line;
                      return (
                        <button type="button" key={l.line} role="option" aria-selected={on} className={`queue__item ${on ? "on" : ""}`} onClick={() => setSelectedLine(l.line)}>
                          <span className="queue__n">L{l.line}</span>
                          <span><span className="queue__cmd">{l.text}</span></span>
                          {top ? <SuggestionBadge s={top} /> : <span className="small faint">no match</span>}
                        </button>
                      );
                    })}
                  </div>
                );
              })}
              {!visible.length && <div className="empty">No lines match the filter.</div>}
            </div>
          </Section>

          <Section className="span-7" id="tr-editor" title={line ? `Map line ${line.line}` : "Select a line"} sub={line && <span className="mono">{line.text}</span>} box actions={line && <span className="small muted">{Object.keys(llmResults).length ? `${Object.keys(llmResults).length} LLM proposals loaded` : "offline classifier"}</span>}>
            {line && draft ? (
              <div className="stack" style={{ gap: 18 }}>
                <div>
                  <div className="eyebrow row" style={{ marginBottom: 8, gap: 6 }}><BrainCircuit size={12} aria-hidden="true" /> Proposals</div>
                  <div className="suggest">
                    {llmFor && <SuggestionCard s={llmFor} on={draft.param === llmFor.param && draft.pattern === llmFor.pattern} onPick={() => applySuggestion(llmFor)} />}
                    {suggestions.map((s) => <SuggestionCard key={s.param} s={s} on={draft.param === s.param && draft.pattern === s.pattern} onPick={() => applySuggestion(s)} />)}
                    {!suggestions.length && !llmFor && <div className="small muted">No keyword or corpus match — choose the parameter manually below.</div>}
                  </div>
                </div>
                <div className="grid grid--2" style={{ gap: 12 }}>
                  <div className="field" style={{ gridColumn: "span 2" }}><label htmlFor="m-name">Mapping name</label><input id="m-name" className="input input--sm" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} /></div>
                  <div className="field"><label htmlFor="m-param">Baseline parameter</label>
                    <select id="m-param" className="select input--sm" value={draft.param} onChange={(e) => { const def = SBM_INDEX[e.target.value]; setDraft({ ...draft, param: e.target.value, transform: transformFor(e.target.value), valueMode: def?.type === "list" ? "list" : def?.type === "number" ? "capture" : draft.valueMode === "list" || draft.valueMode === "capture" ? "polarity" : draft.valueMode }); }}>
                      {SBM_CATEGORIES.map((c) => <optgroup key={c} label={c}>{SBM_PARAMS.filter((p) => p.category === c).map((p) => <option key={p.key} value={p.key}>{p.label} ({p.type})</option>)}</optgroup>)}
                    </select>
                    <span className="hint">{SBM_INDEX[draft.param]?.description}</span>
                  </div>
                  <div className="field"><label htmlFor="m-mode">Value extraction</label>
                    <select id="m-mode" className="select input--sm" value={draft.valueMode} onChange={(e) => setDraft({ ...draft, valueMode: e.target.value as ValueMode })}>
                      {MODES.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
                    </select>
                  </div>
                  {draft.valueMode === "const" && <div className="field"><label htmlFor="m-const">Constant value</label><input id="m-const" className="input input--sm" value={draft.constValue} onChange={(e) => setDraft({ ...draft, constValue: e.target.value })} /></div>}
                  {(draft.valueMode === "capture" || draft.valueMode === "list") && <div className="field"><label htmlFor="m-group">Capture group</label><input id="m-group" type="number" min={1} className="input input--sm" value={draft.captureGroup} onChange={(e) => setDraft({ ...draft, captureGroup: parseInt(e.target.value, 10) || 1 })} /></div>}
                  <div className="field"><label htmlFor="m-vendor">Scope</label>
                    <select id="m-vendor" className="select input--sm" value={draft.vendor} onChange={(e) => setDraft({ ...draft, vendor: e.target.value as VendorId | "any" })}>
                      <option value="any">Any vendor</option>
                      {(Object.keys(VENDOR_META) as VendorId[]).map((v) => <option key={v} value={v}>{VENDOR_META[v].short} only</option>)}
                    </select>
                  </div>
                  <div className="field" style={{ gridColumn: "span 2" }}><label htmlFor="m-pattern">Pattern (JavaScript regular expression, case-insensitive)</label><input id="m-pattern" className="input input--sm mono" value={draft.pattern} onChange={(e) => setDraft({ ...draft, pattern: e.target.value })} spellCheck={false} aria-invalid={Boolean(patternError)} />{patternError ? <span className="error">{patternError}</span> : <span className="hint">Generated from the selected line — variable parts became capture groups. Edit freely; the live test shows what it matches.</span>}</div>
                </div>
                <div>
                  <div className="eyebrow" style={{ marginBottom: 6 }}>Live test · {matches.length} of {lines.length} unrecognised lines match</div>
                  <div className="stack" style={{ gap: 4, maxHeight: 200, overflowY: "auto" }}>
                    {matches.slice(0, 40).map((m) => <div key={m.line} className="match"><span className="n">L{m.line}</span><span>{m.text}</span><span style={{ color: "var(--pass)" }}>→ {previewValue(m)}</span></div>)}
                    {!matches.length && <div className="callout callout--warn small">{patternError ? "Fix the regular expression first." : "The pattern does not match the selected line. Fix the regex or pick another proposal."}</div>}
                  </div>
                </div>
                <div className="row" style={{ justifyContent: "flex-end" }}>
                  <button type="button" className="btn btn--primary" onClick={save} disabled={!matches.length}><GraduationCap /> Save mapping &amp; re-parse fleet</button>
                </div>
              </div>
            ) : (
              <Empty title="Pick a line on the left" hint="The classifier proposes a baseline parameter and a value extraction rule; confirm or edit it here." />
            )}
          </Section>
        </div>
      )}

      <Section
        id="tr-learned"
        title="Learned mappings"
        sub={`${mappings.length} rules · applied on every parse · exportable as a vendor pack`}
        box
        flush
        actions={<button type="button" className="btn btn--sm" onClick={() => { const r = importMappings(EXOS_STARTER_PACK); toast.ok(r.imported ? `${plural(r.imported, "EXOS mapping")} imported` : "Starter pack already present", "A shareable vendor pack, produced by one training session."); }}><Upload /> Load EXOS starter pack</button>}
      >
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Name</th><th>Scope</th><th>Parameter</th><th>Mode</th><th>Pattern</th><th className="right">Hits</th><th>Origin</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {mappings.map((m) => (
                <tr key={m.id}>
                  <td><strong>{m.name}</strong>{m.sampleLine && <div className="small muted mono">{m.sampleLine}</div>}</td>
                  <td>{m.vendor === "any" ? <span className="dim small">any vendor</span> : <Vendor vendor={m.vendor} />}</td>
                  <td className="small">{SBM_INDEX[m.param]?.label ?? m.param}</td>
                  <td><span className="pill pill--accent">{m.valueMode}</span></td>
                  <td className="mono small" style={{ maxWidth: 320, wordBreak: "break-all" }}>{m.pattern}</td>
                  <td className="right num">{fleet.mappingHits[m.id] ?? 0}</td>
                  <td className="small dim">{m.createdBy}</td>
                  <td className="nowrap">
                    <button type="button" className="btn btn--ghost btn--sm btn--icon" onClick={() => setEditing({ ...m })} title="Edit mapping" aria-label={`Edit ${m.name}`}><Pencil size={14} /></button>
                    <button type="button" className="btn btn--ghost btn--sm btn--icon" onClick={() => remove(m)} title="Remove mapping" aria-label={`Remove ${m.name}`}><Trash2 size={14} /></button>
                  </td>
                </tr>
              ))}
              {!mappings.length && <tr><td colSpan={8}><Empty title="No learned mappings yet" hint="Accept a proposal above or import a mapping pack." /></td></tr>}
            </tbody>
          </table>
        </div>
      </Section>

      <Modal open={Boolean(editing)} onClose={() => setEditing(null)} title={editing ? `Edit mapping — ${editing.name}` : ""} foot={<><span className="grow" /><button type="button" className="btn" onClick={() => setEditing(null)}>Cancel</button><button type="button" className="btn btn--primary" onClick={saveEdit}>Save</button></>}>
        {editing && (
          <div className="grid grid--2" style={{ gap: 12 }}>
            <div className="field" style={{ gridColumn: "span 2" }}><label htmlFor="e-name">Name</label><input id="e-name" data-autofocus className="input" value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} /></div>
            <div className="field"><label htmlFor="e-param">Baseline parameter</label><select id="e-param" className="select" value={editing.param} onChange={(e) => setEditing({ ...editing, param: e.target.value })}>{SBM_CATEGORIES.map((c) => <optgroup key={c} label={c}>{SBM_PARAMS.filter((p) => p.category === c).map((p) => <option key={p.key} value={p.key}>{p.label} ({p.type})</option>)}</optgroup>)}</select></div>
            <div className="field"><label htmlFor="e-mode">Value extraction</label><select id="e-mode" className="select" value={editing.valueMode} onChange={(e) => setEditing({ ...editing, valueMode: e.target.value as ValueMode })}>{MODES.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}</select></div>
            {editing.valueMode === "const" && <div className="field"><label htmlFor="e-const">Constant value</label><input id="e-const" className="input" value={String(editing.constValue ?? "")} onChange={(e) => setEditing({ ...editing, constValue: e.target.value })} /></div>}
            {(editing.valueMode === "capture" || editing.valueMode === "list") && <div className="field"><label htmlFor="e-group">Capture group</label><input id="e-group" type="number" min={1} className="input" value={editing.captureGroup ?? 1} onChange={(e) => setEditing({ ...editing, captureGroup: parseInt(e.target.value, 10) || 1 })} /></div>}
            <div className="field"><label htmlFor="e-vendor">Scope</label><select id="e-vendor" className="select" value={editing.vendor} onChange={(e) => setEditing({ ...editing, vendor: e.target.value as VendorId | "any" })}><option value="any">Any vendor</option>{(Object.keys(VENDOR_META) as VendorId[]).map((v) => <option key={v} value={v}>{VENDOR_META[v].short} only</option>)}</select></div>
            <div className="field" style={{ gridColumn: "span 2" }}><label htmlFor="e-pattern">Pattern</label><input id="e-pattern" className="input mono" value={editing.pattern} onChange={(e) => setEditing({ ...editing, pattern: e.target.value })} spellCheck={false} /></div>
          </div>
        )}
      </Modal>
    </Page>
  );
}

function SuggestionBadge({ s }: { s: Suggestion }) {
  const label = confidenceLabel(s.confidence);
  return (
    <span className="stack" style={{ gap: 3, alignItems: "flex-end" }}>
      <span className="small" style={{ fontWeight: 600, whiteSpace: "nowrap" }}>{SBM_INDEX[s.param]?.label ?? s.param}</span>
      <span className="conf" style={{ color: label === "High" ? "var(--pass)" : label === "Medium" ? "var(--warn)" : "var(--muted)" }}><span className="conf__bar"><i style={{ width: `${Math.round(s.confidence * 100)}%`, background: "currentColor" }} /></span>{Math.round(s.confidence * 100)}%{s.source === "llm" ? " · LLM" : ""}</span>
    </span>
  );
}

function SuggestionCard({ s, on, onPick }: { s: Suggestion; on: boolean; onPick: () => void }) {
  const def = SBM_INDEX[s.param];
  return (
    <button type="button" className={`suggest__item ${on ? "on" : ""}`} onClick={onPick} aria-pressed={on}>
      <span className="row between">
        <strong>{def?.label ?? s.param} <span className="muted small mono">{s.param}</span></strong>
        <SuggestionBadge s={s} />
      </span>
      <span className="small muted">{s.reasons.join(" · ")}</span>
      <span className="small"><span className="pill pill--accent">{s.valueMode}</span> <span className="mono muted">{s.pattern}</span>{s.extractedValue !== undefined && <span className="muted"> → {String(s.extractedValue)}</span>}</span>
    </button>
  );
}
