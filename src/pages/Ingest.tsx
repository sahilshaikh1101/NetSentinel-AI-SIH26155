import { useRef, useState } from "react";
import { Link, useLocation } from "wouter";
import { ClipboardPaste, FolderOpen, Layers, Trash2, UploadCloud } from "lucide-react";
import JSZip from "jszip";
import { useFleet, useStore, type IngestOutcome } from "../store";
import { Modal, Page, ScoreCell, Section, StatusLine, Vendor, toast } from "../components/ui";
import { SAMPLES } from "../engine/samples";
import { VENDOR_IDS, VENDOR_META } from "../engine/sbm";
import { sha256Hex } from "../lib/hash";
import type { VendorId } from "../engine/types";
import { plural, relTime } from "../lib/util";

const TEXT_EXT = /\.(cfg|conf|config|txt|log|rsc|set|xml|json|xsf|ios|junos|bak|running|startup|cli|nv|yaml|yml)$/i;
const MAX_BYTES = 4 * 1024 * 1024;

async function readFiles(files: File[]): Promise<{ parsed: { fileName: string; raw: string; sha256: string }[]; rejected: string[] }> {
  const parsed: { fileName: string; raw: string; sha256: string }[] = [];
  const rejected: string[] = [];
  for (const f of files) {
    if (f.size > MAX_BYTES) { rejected.push(`${f.name} (larger than 4 MB)`); continue; }
    if (/\.zip$/i.test(f.name)) {
      const zip = await JSZip.loadAsync(await f.arrayBuffer());
      for (const entry of Object.values(zip.files)) {
        if (entry.dir) continue;
        const base = entry.name.split("/").pop() ?? entry.name;
        if (!TEXT_EXT.test(base) && !/^[^.]+$/.test(base)) continue;
        const raw = await entry.async("string");
        if (!raw.trim()) continue;
        parsed.push({ fileName: base, raw, sha256: await sha256Hex(raw) });
      }
      continue;
    }
    const raw = await f.text();
    if (!raw.trim()) { rejected.push(`${f.name} (empty)`); continue; }
    if (/[\x00-\x08\x0e-\x1f]/.test(raw.slice(0, 2000))) { rejected.push(`${f.name} (binary)`); continue; }
    parsed.push({ fileName: f.name, raw, sha256: await sha256Hex(raw) });
  }
  return { parsed, rejected };
}

/** One toast that tells the operator exactly what happened to each file. */
export function announceIngest(outcome: IngestOutcome, rejected: string[] = []) {
  const parts: string[] = [];
  if (outcome.added.length) parts.push(`${outcome.added.length} added`);
  if (outcome.replaced.length) parts.push(`${outcome.replaced.length} new version${outcome.replaced.length > 1 ? "s" : ""} (previous archived for drift)`);
  if (outcome.skipped.length) parts.push(`${outcome.skipped.length} duplicate${outcome.skipped.length > 1 ? "s" : ""} skipped`);
  if (rejected.length) parts.push(`${rejected.length} rejected`);
  const detail = [
    ...outcome.added.map((r) => `${r.fileName} → ${VENDOR_META[r.detection.vendor].short}`),
    ...outcome.replaced.map((r) => `${r.record.fileName} → new version`),
    ...outcome.skipped.map((s) => `${s.fileName}: ${s.reason}`),
    ...rejected,
  ].join(" · ");
  if (!outcome.added.length && !outcome.replaced.length) toast.info(parts.join(", ") || "Nothing ingested", detail);
  else toast.ok(parts.join(", "), detail);
}

export default function Ingest() {
  const fleet = useFleet();
  const addDevices = useStore((s) => s.addDevices);
  const removeDevice = useStore((s) => s.removeDevice);
  const restoreDevice = useStore((s) => s.restoreDevice);
  const setVendorOverride = useStore((s) => s.setVendorOverride);
  const [, navigate] = useLocation();
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasteName, setPasteName] = useState("pasted-config.cfg");
  const [pasteText, setPasteText] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const dirInput = useRef<HTMLInputElement>(null);

  const ingest = async (files: File[]) => {
    if (!files.length) return;
    setBusy(true);
    try {
      const { parsed, rejected } = await readFiles(files);
      if (!parsed.length) {
        toast.err("Nothing to ingest", rejected.length ? rejected.join(" · ") : "No readable text configuration was found in the selection.");
        return;
      }
      announceIngest(addDevices(parsed), rejected);
    } catch (e) {
      toast.err("Ingestion failed", String(e));
    } finally {
      setBusy(false);
    }
  };

  const loadSample = async (id: string) => {
    const s = SAMPLES.find((x) => x.id === id);
    if (!s) return;
    const already = fleet.devices.find((d) => d.record.fileName === s.fileName && d.record.sample);
    if (already) {
      navigate(`/devices/${already.record.id}`);
      return;
    }
    const sha = await sha256Hex(s.raw);
    announceIngest(addDevices([{ fileName: s.fileName, raw: s.raw, sha256: sha, sample: true }]));
  };
  const loadAllSamples = async () => {
    const missing = SAMPLES.filter((s) => !fleet.devices.some((d) => d.record.fileName === s.fileName));
    if (!missing.length) return toast.info("Every sample is already loaded");
    const files = await Promise.all(missing.map(async (s) => ({ fileName: s.fileName, raw: s.raw, sha256: await sha256Hex(s.raw), sample: true })));
    announceIngest(addDevices(files));
  };

  const submitPaste = async () => {
    if (!pasteText.trim()) return;
    const sha = await sha256Hex(pasteText);
    const outcome = addDevices([{ fileName: pasteName.trim() || "pasted-config.cfg", raw: pasteText, sha256: sha }]);
    setPasteOpen(false);
    setPasteText("");
    announceIngest(outcome);
    const rec = outcome.added[0] ?? outcome.replaced[0]?.record;
    if (rec) navigate(`/devices/${rec.id}`);
  };

  const remove = (id: string) => {
    const versions = useStore.getState().history[id];
    const rec = removeDevice(id);
    if (!rec) return;
    toast.info("Device removed", rec.fileName, { label: "Undo", onClick: () => restoreDevice(rec, versions) });
  };

  return (
    <Page
      title="Ingest configurations"
      status={<StatusLine items={["Files, folders, ZIP archives or pasted text from any vendor", "Detection, normalisation and the audit run immediately, in this browser"]} />}
    >
      <div className="grid">
        <Section className="span-7" id="in-upload" num="01" title="Upload">
          <div
            className={`dropzone ${over ? "over" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setOver(true); }}
            onDragLeave={() => setOver(false)}
            onDrop={(e) => { e.preventDefault(); setOver(false); ingest(Array.from(e.dataTransfer.files)); }}
            onClick={() => fileInput.current?.click()}
            role="button"
            tabIndex={0}
            aria-busy={busy}
            onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.current?.click(); } }}
          >
            <UploadCloud aria-hidden="true" />
            <strong>{busy ? "Reading files…" : "Drop configuration files here"}</strong>
            <span className="muted small">or press Enter to browse · running-config, set-format, XML and JSON exports · .zip archives are unpacked</span>
          </div>
          <input ref={fileInput} id="file-input" type="file" multiple hidden aria-hidden="true" onChange={(e) => { ingest(Array.from(e.target.files ?? [])); e.target.value = ""; }} />
          <input ref={dirInput} id="dir-input" type="file" multiple hidden aria-hidden="true" {...({ webkitdirectory: "" } as Record<string, string>)} onChange={(e) => { ingest(Array.from(e.target.files ?? [])); e.target.value = ""; }} />
          <div className="row">
            <button type="button" className="btn" onClick={() => dirInput.current?.click()}><FolderOpen /> Upload a folder</button>
            <button type="button" className="btn" onClick={() => setPasteOpen(true)}><ClipboardPaste /> Paste text</button>
            <span className="small muted">Upload a newer file for a hostname already in the fleet and the previous version is kept for drift analysis.</span>
          </div>
        </Section>
        <Section className="span-5" id="in-samples" num="02" title="Sample fleet" sub="Realistic configurations with deliberate weaknesses" actions={<button type="button" className="btn btn--sm" onClick={loadAllSamples}><Layers /> Load all</button>} box>
          <div>
            {SAMPLES.map((s) => {
              const loaded = fleet.devices.find((d) => d.record.fileName === s.fileName);
              return (
                <div key={s.id} className="sample">
                  <span className="sample__dot" style={{ background: VENDOR_META[s.expectedVendor].color }} aria-hidden="true" />
                  <div className="sample__meta">
                    <strong>{s.label} <span className="muted" style={{ fontWeight: 400 }}>· {s.vendorLabel}</span></strong>
                    <span title={s.note}>{s.note}</span>
                  </div>
                  {loaded ? <Link href={`/devices/${loaded.record.id}`} className="btn btn--sm">Open</Link> : <button type="button" className="btn btn--sm" onClick={() => loadSample(s.id)}>Load</button>}
                </div>
              );
            })}
          </div>
        </Section>
      </div>

      <Section id="in-log" num="03" title="Ingestion log" sub="Every file, its detected syntax family and how much of it the engine understood" box flush>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr><th>File</th><th>Detected</th><th className="right">Confidence</th><th className="right">Lines</th><th className="right">Understood</th><th className="right">Params</th><th className="right">Unparsed</th><th style={{ minWidth: 140 }}>Score</th><th>Parse as</th><th><span className="sr-only">Actions</span></th></tr>
            </thead>
            <tbody>
              {fleet.devices.map((d) => {
                const det = d.record.detection;
                const open = expanded === d.record.id;
                const understood = Math.round((d.parse.recognized / Math.max(1, d.parse.meaningfulLines)) * 100);
                return (
                  <tr key={d.record.id}>
                    <td>
                      <Link href={`/devices/${d.record.id}`} className="rowlink">{d.name}</Link>
                      <div className="small muted mono">{d.record.fileName} · {relTime(d.record.ingestedAt)}</div>
                      <div className="small faint mono" title={d.record.sha256}>sha256 {d.record.sha256.slice(0, 16)}…</div>
                    </td>
                    <td>
                      <Vendor vendor={d.vendor} label={`${d.parse.identity.vendorName} ${d.parse.identity.os}`} />
                      <div className="small muted" style={{ marginTop: 2 }}>
                        <button type="button" className="btn btn--ghost btn--sm" style={{ padding: "0 4px", minHeight: 22 }} aria-expanded={open} onClick={() => setExpanded(open ? null : d.record.id)}>
                          {open ? "hide reasons" : det.reasons.length ? plural(det.reasons.length, "signature") + " matched" : "no signature matched"}
                        </button>
                        {open && <ul style={{ margin: "4px 0 0", paddingLeft: 16 }}>{det.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>}
                      </div>
                    </td>
                    <td className="right num">{det.vendor === "generic" ? <span className="muted">—</span> : `${Math.round(det.confidence * 100)}%`}</td>
                    <td className="right num dim">{d.parse.meaningfulLines}</td>
                    <td className="right num" style={{ color: understood === 100 ? "var(--pass)" : understood < 25 ? "var(--warn)" : undefined }}>{understood}%</td>
                    <td className="right num">{Object.values(d.parse.model.params).filter((p) => p.source !== "default").length}</td>
                    <td className="right num">{d.parse.unrecognized.length ? <Link href="/training" className="badge badge--accent" title="Open in the Training Studio">{d.parse.unrecognized.length}</Link> : <span className="dim">0</span>}</td>
                    <td><ScoreCell score={d.summary.score} assessable={d.assessable} /></td>
                    <td>
                      <select className="select input--sm" value={d.record.vendorOverride ?? ""} onChange={(e) => setVendorOverride(d.record.id, (e.target.value || undefined) as VendorId | undefined)} aria-label={`Parser for ${d.name}`}>
                        <option value="">Auto ({VENDOR_META[det.vendor].short})</option>
                        {VENDOR_IDS.map((v) => <option key={v} value={v}>{VENDOR_META[v].short}</option>)}
                      </select>
                    </td>
                    <td><button type="button" className="btn btn--ghost btn--sm btn--icon" title="Remove device" aria-label={`Remove ${d.name}`} onClick={() => remove(d.record.id)}><Trash2 size={14} /></button></td>
                  </tr>
                );
              })}
              {!fleet.devices.length && <tr><td colSpan={10} className="muted" style={{ textAlign: "center", padding: 30 }}>Nothing ingested yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </Section>

      <Modal
        open={pasteOpen}
        onClose={() => setPasteOpen(false)}
        title="Paste a configuration"
        foot={
          <>
            <span className="small muted grow">{pasteText.trim() ? `${pasteText.split("\n").length} lines` : "Paste the output of show running-config, show configuration or an export"}</span>
            <button type="button" className="btn" onClick={() => setPasteOpen(false)}>Cancel</button>
            <button type="button" className="btn btn--primary" onClick={submitPaste} disabled={!pasteText.trim()}>Ingest</button>
          </>
        }
      >
        <div className="field">
          <label htmlFor="paste-name">File name</label>
          <input id="paste-name" className="input" value={pasteName} onChange={(e) => setPasteName(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="paste-text">Configuration text</label>
          <textarea id="paste-text" data-autofocus className="textarea" style={{ minHeight: 260 }} value={pasteText} onChange={(e) => setPasteText(e.target.value)} placeholder={"hostname EDGE-01\n!\nip ssh version 2\n..."} spellCheck={false} />
        </div>
      </Modal>
    </Page>
  );
}
