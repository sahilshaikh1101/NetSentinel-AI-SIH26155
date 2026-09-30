import { useState } from "react";
import { Link } from "wouter";
import { Archive, Download, FileJson, FileText, Files, Wrench } from "lucide-react";
import { useFleet, useStore } from "../store";
import { Modal, Page, ScoreCell, Section, SortTh, StatusLine, Vendor, toast, useSort, type Getters } from "../components/ui";
import { buildDevicePdf, buildFleetPdf, savePdf } from "../engine/report/pdf";
import { deviceJson, findingsCsv } from "../engine/report/exports";
import { fleetRemediationBundle, remediationBundle } from "../engine/report/remediation-bundle";
import { buildEvidenceBundle } from "../engine/report/evidence-bundle";
import { FRAMEWORKS } from "../engine/rules/library";
import { formatValue, paramLabel } from "../engine/sbm";
import { SEVERITY_ORDER } from "../engine/rules/evaluate";
import { downloadBlob, downloadText, fmtDate } from "../lib/util";
import type { DeviceView } from "../engine/fleet";
import type { Status } from "../engine/types";

const STATUS_ORDER: Status[] = ["fail", "warning", "pass", "na"];
const STATUS_TEXT: Record<Status, string> = { pass: "PASS", fail: "FAIL", warning: "NOT ASSESSED", na: "N/A" };
const identityFields = (v: DeviceView) => [v.parse.identity.hostname, v.parse.identity.osVersion, v.parse.identity.model, v.parse.identity.serial, v.parse.identity.mgmtIp].filter(Boolean).length;
const GETTERS: Getters<DeviceView> = {
  name: (v) => v.name,
  vendor: (v) => `${v.parse.identity.vendorName} ${v.parse.identity.os}`,
  score: (v) => (v.assessable ? v.summary.score : -1),
  fail: (v) => v.summary.fail,
  accepted: (v) => v.summary.accepted,
  identity: (v) => identityFields(v),
};

export function ReportPreview({ view }: { view: DeviceView }) {
  const settings = useStore((s) => s.settings);
  const frameworks = useStore((s) => s.frameworks);
  const id = view.parse.identity;
  const ordered = [...view.findings].sort((a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const failed = ordered.filter((f) => f.status === "fail");
  const accepted = failed.filter((f) => f.exception);
  const params = Object.values(view.parse.model.params).filter((p) => p.source !== "default");
  const tone = view.summary.score >= 85 ? "#127a4a" : view.summary.score >= 65 ? "#8a5a00" : "#b42335";
  return (
    <article className="report">
      <div style={{ display: "flex", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 16 }}>NetSentinel AI</div>
          <div className="meta">AI-driven multi-vendor network security compliance auditor</div>
        </div>
        <div className="meta" style={{ textAlign: "right" }}>{settings.organisation}<br />Generated {new Date().toLocaleString()} by {settings.operator}</div>
      </div>
      <h1 style={{ marginTop: 18 }}>Device compliance report — {view.name}</h1>
      <div className="meta">{id.vendorName} {id.os}{id.osVersion ? ` ${id.osVersion}` : ""} · Frameworks: {frameworks.map((f) => FRAMEWORKS[f].short).join(" · ") || "all controls"}</div>
      <div style={{ display: "flex", gap: 24, alignItems: "center", marginTop: 14, padding: 12, background: "#f2f3f0", borderRadius: 6 }}>
        <div style={{ fontSize: 34, fontWeight: 700, color: view.assessable ? tone : "#666" }}>{view.assessable ? view.summary.score : "—"}<span style={{ fontSize: 12, color: "#666", fontWeight: 500 }}> / 100</span></div>
        <div className="meta">
          {view.assessable ? `${view.summary.pass} passed · ${view.summary.fail} failed (${view.summary.bySeverity.critical} critical, ${view.summary.bySeverity.high} high, ${view.summary.bySeverity.medium} medium, ${view.summary.bySeverity.low} low) · ${view.summary.warning} not assessed · ${view.summary.na} not applicable` : `Not assessed: only ${view.parse.recognized} of ${view.parse.meaningfulLines} lines were understood by the parser.`}
          {accepted.length > 0 && <><br />{accepted.length} accepted risk{accepted.length > 1 ? "s" : ""} · adjusted score {view.summary.adjustedScore}</>}
        </div>
      </div>
      <h2>1. Device identification</h2>
      <table>
        <tbody>
          <tr><th style={{ width: 180 }}>Hostname</th><td>{id.hostname ?? "—"}</td></tr>
          <tr><th>Vendor / OS</th><td>{id.vendorName} {id.os}</td></tr>
          <tr><th>Software version</th><td>{id.osVersion ?? "not present in the configuration"}</td></tr>
          <tr><th>Hardware model</th><td>{id.model ?? "not present in the configuration"}</td></tr>
          <tr><th>Serial number</th><td>{id.serial ?? "not present in the configuration"}</td></tr>
          <tr><th>Management address</th><td>{id.mgmtIp ?? "—"}</td></tr>
          {view.record.site && <tr><th>Site</th><td>{view.record.site}</td></tr>}
          {view.record.owner && <tr><th>Owner</th><td>{view.record.owner}</td></tr>}
          <tr><th>Source file</th><td>{view.record.fileName}</td></tr>
          <tr><th>Configuration SHA-256</th><td style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>{view.record.sha256}</td></tr>
          <tr><th>Parser</th><td>{view.parse.recognized}/{view.parse.meaningfulLines} lines understood · {view.parse.mappingsApplied.length} learned mappings applied · detection {Math.round(view.record.detection.confidence * 100)}%</td></tr>
        </tbody>
      </table>
      <h2>2. Compliance findings</h2>
      <table>
        <thead><tr><th>Control</th><th>Title</th><th>Severity</th><th>Result</th><th>References</th></tr></thead>
        <tbody>
          {ordered.map((f) => <tr key={f.id}><td style={{ whiteSpace: "nowrap" }}>{f.ruleId}</td><td>{f.title}</td><td>{f.severity.toUpperCase()}</td><td className={`mark-${f.status}`}>{STATUS_TEXT[f.status]}{f.exception ? " (accepted)" : ""}</td><td>{f.refs.map((r) => `${FRAMEWORKS[r.framework].short} ${r.id}`).join(", ")}</td></tr>)}
        </tbody>
      </table>
      <h2>3. Remediation paths ({failed.length} failed controls)</h2>
      {failed.map((f) => (
        <div key={f.id} style={{ marginTop: 14 }}>
          <div style={{ fontWeight: 600 }}>{f.ruleId} — {f.title} <span style={{ float: "right", fontSize: 11 }} className="mark-fail">{f.severity.toUpperCase()}</span></div>
          <div className="meta">Observed: {f.observed}</div>
          <div className="meta">Expected: {f.expected}</div>
          {f.exception && <div className="meta">Risk accepted by {f.exception.by} on {fmtDate(f.exception.at)}{f.exception.expires ? ` until ${fmtDate(f.exception.expires)}` : ""}: {f.exception.reason}{f.exception.ticket ? ` (${f.exception.ticket})` : ""}</div>}
          <div style={{ marginTop: 4 }}>{f.rationale}</div>
          {f.evidence.length > 0 && <pre>{f.evidence.slice(0, 6).map((e) => (e.line ? `L${e.line}: ${e.text}` : e.text)).join("\n")}</pre>}
          <div style={{ marginTop: 6, fontSize: 11, fontWeight: 600 }}>Remediation ({id.vendorName} CLI)</div>
          <pre>{f.remediation}</pre>
        </div>
      ))}
      {!failed.length && <div className="meta" style={{ marginTop: 8 }}>No failed controls.</div>}
      <h2>4. Normalised Security Baseline Model</h2>
      <table>
        <thead><tr><th>Parameter</th><th>Value</th><th>Source</th><th>Evidence</th></tr></thead>
        <tbody>{params.map((p) => <tr key={p.key}><td>{paramLabel(p.key)}</td><td>{formatValue(p.value)}</td><td>{p.source}</td><td style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>{p.evidence.slice(0, 2).map((e) => `L${e.line}: ${e.text}`).join(" · ")}</td></tr>)}</tbody>
      </table>
    </article>
  );
}

export default function Reports() {
  const fleet = useFleet();
  const settings = useStore((s) => s.settings);
  const frameworks = useStore((s) => s.frameworks);
  const log = useStore((s) => s.log);
  const [preview, setPreview] = useState<DeviceView | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const { sorted, sort, toggle } = useSort(fleet.devices, GETTERS, { key: "fail", dir: "desc" });
  const meta = { organisation: settings.organisation, operator: settings.operator, frameworks };

  const devicePdf = async (v: DeviceView) => {
    try {
      const doc = buildDevicePdf(v, meta);
      const outcome = await savePdf(doc, `netsentinel-${v.name}-compliance.pdf`);
      if (outcome === "declined") return toast.info("Download cancelled");
      log({ actor: "admin", action: "Report exported", target: `${v.name} device PDF` });
      toast.ok(`${v.name} report generated`, "Identification, findings, remediation CLI and baseline model in one PDF.");
    } catch (e) {
      toast.err("Could not build the PDF", String(e));
    }
  };
  const allPdfs = async () => {
    setBusy("pdfs");
    try { for (const v of fleet.devices) await devicePdf(v); } finally { setBusy(null); }
  };
  const fleetPdf = async () => {
    try {
      const doc = buildFleetPdf(fleet, meta);
      const outcome = await savePdf(doc, `netsentinel-fleet-summary-${new Date().toISOString().slice(0, 10)}.pdf`);
      if (outcome === "declined") return toast.info("Download cancelled");
      log({ actor: "admin", action: "Report exported", target: "Fleet summary PDF" });
      toast.ok("Fleet summary PDF generated");
    } catch (e) {
      toast.err("Could not build the PDF", String(e));
    }
  };
  const evidence = async () => {
    setBusy("bundle");
    try {
      const blob = await buildEvidenceBundle(fleet, fleet.devices, meta);
      const outcome = await downloadBlob(blob, `netsentinel-evidence-${new Date().toISOString().slice(0, 10)}.zip`);
      if (outcome === "declined") return toast.info("Download cancelled");
      log({ actor: "admin", action: "Evidence bundle exported", target: `${fleet.devices.length} devices` });
      toast.ok("Evidence bundle saved", "Every configuration, report, script and finding, plus a SHA-256 manifest for tamper evidence.");
    } catch (e) {
      toast.err("Could not build the bundle", String(e));
    } finally {
      setBusy(null);
    }
  };
  const fleetScript = async () => {
    const outcome = await downloadText(fleetRemediationBundle(fleet.devices, meta), `netsentinel-fleet-remediation-${new Date().toISOString().slice(0, 10)}.txt`);
    if (outcome === "declined") return toast.info("Download cancelled");
    log({ actor: "admin", action: "Remediation plan exported", target: `${fleet.devices.filter((d) => d.summary.fail).length} devices` });
    toast.ok("Fleet remediation plan saved", "Devices ordered by weighted risk, each with its own reviewable script.");
  };
  const script = async (v: DeviceView) => {
    const outcome = await downloadText(remediationBundle(v, meta), `netsentinel-${v.name}-remediation.txt`);
    if (outcome !== "declined") log({ actor: "admin", action: "Remediation script exported", target: v.name });
  };

  return (
    <Page
      title="Reports"
      status={<StatusLine items={["Generated in the browser — nothing leaves the machine", `Header: ${settings.organisation} · ${settings.operator}`, <Link href="/settings">change identity</Link>]} />}
      actions={
        <>
          <button type="button" className="btn" onClick={() => downloadText(findingsCsv(fleet), "netsentinel-findings.csv", "text/csv")} disabled={!fleet.findings.length}><Download /> All findings CSV</button>
          <button type="button" className="btn" onClick={fleetScript} disabled={!fleet.summary.fail}><Wrench /> Fleet remediation plan</button>
          <button type="button" className="btn" onClick={allPdfs} disabled={!fleet.devices.length || busy !== null}><Files /> {busy === "pdfs" ? "Generating…" : "All device PDFs"}</button>
          <button type="button" className="btn" onClick={evidence} disabled={!fleet.devices.length || busy !== null}><Archive /> {busy === "bundle" ? "Bundling…" : "Evidence bundle (ZIP)"}</button>
          <button type="button" className="btn btn--primary" onClick={fleetPdf} disabled={!fleet.devices.length}><FileText /> Fleet summary PDF</button>
        </>
      }
    >
      <Section id="rp-table" title="Per-device reports" sub="One PDF per device: identification, pass/fail findings with severity and evidence, vendor CLI remediation, baseline model" box flush>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <SortTh label="Device" k="name" sort={sort} onSort={toggle} />
                <SortTh label="Vendor / OS" k="vendor" sort={sort} onSort={toggle} />
                <SortTh label="Score" k="score" sort={sort} onSort={toggle} style={{ minWidth: 150 }} />
                <SortTh label="Failed" k="fail" sort={sort} onSort={toggle} align="right" />
                <SortTh label="Accepted" k="accepted" sort={sort} onSort={toggle} align="right" />
                <SortTh label="Identity" k="identity" sort={sort} onSort={toggle} />
                <th><span className="sr-only">Exports</span></th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((v) => {
                const n = identityFields(v);
                return (
                  <tr key={v.record.id}>
                    <td><Link href={`/devices/${v.record.id}`} className="rowlink">{v.name}</Link><div className="small muted mono">{v.parse.identity.serial ?? "serial n/a"} · {v.parse.identity.model ?? "model n/a"}</div></td>
                    <td><Vendor vendor={v.vendor} label={`${v.parse.identity.vendorName} ${v.parse.identity.os} ${v.parse.identity.osVersion ?? ""}`} /></td>
                    <td><ScoreCell score={v.summary.score} assessable={v.assessable} /></td>
                    <td className="right num" style={{ color: v.summary.fail ? "var(--fail)" : undefined, fontWeight: 600 }}>{v.assessable ? v.summary.fail : "—"}</td>
                    <td className="right num dim">{v.summary.accepted || "—"}</td>
                    <td className="small" title="hostname, version, model, serial, management address"><span className={`pill ${n === 5 ? "pill--pass" : n >= 3 ? "pill--warning" : "pill--na"}`}>{n} of 5 fields</span></td>
                    <td className="nowrap">
                      <div className="row" style={{ gap: 4, justifyContent: "flex-end" }}>
                        <button type="button" className="btn btn--sm btn--primary" onClick={() => devicePdf(v)}><FileText /> PDF</button>
                        <button type="button" className="btn btn--sm" onClick={() => setPreview(v)}>Preview</button>
                        <button type="button" className="btn btn--sm btn--icon" title="Remediation script" aria-label={`Remediation script for ${v.name}`} onClick={() => script(v)} disabled={!v.summary.fail}><Wrench /></button>
                        <button type="button" className="btn btn--sm btn--icon" title="JSON" aria-label={`JSON for ${v.name}`} onClick={() => downloadText(deviceJson(v), `netsentinel-${v.name}.json`, "application/json")}><FileJson /></button>
                        <button type="button" className="btn btn--sm btn--icon" title="CSV" aria-label={`CSV for ${v.name}`} onClick={() => downloadText(findingsCsv(fleet, v.record.id), `netsentinel-${v.name}-findings.csv`, "text/csv")}><Download /></button>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {!fleet.devices.length && <tr><td colSpan={7} className="muted" style={{ textAlign: "center", padding: 30 }}>No devices yet — <Link href="/ingest">ingest a configuration</Link>.</td></tr>}
            </tbody>
          </table>
        </div>
      </Section>
      <div className="callout small">Hosted viewers ask you to confirm each file save. The <em>Preview</em> shows the exact report content in-page; the evidence bundle adds a SHA-256 manifest (<span className="mono">sha256sum -c MANIFEST.sha256</span>) so a reviewer can verify that nothing changed after export.</div>
      <Modal open={Boolean(preview)} onClose={() => setPreview(null)} title={preview ? `Report preview — ${preview.name}` : ""} wide foot={preview && <><span className="grow" /><button type="button" className="btn btn--primary" onClick={() => devicePdf(preview)}><FileText /> Download PDF</button></>}>
        {preview && <ReportPreview view={preview} />}
      </Modal>
    </Page>
  );
}
