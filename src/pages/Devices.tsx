import { Fragment, useMemo, useRef, useState } from "react";
import { Link, useLocation, useParams } from "wouter";
import { Archive, Download, FileJson, FileText, GitCompareArrows, Pencil, Server, Trash2, UploadCloud, Wrench } from "lucide-react";
import { useActiveRules, useFleet, useStore } from "../store";
import { CodeViewer, Confirm, Empty, EvidenceList, FwTag, Gauge, Modal, Page, ScoreCell, Section, Segmented, Sev, SortTh, Stamp, StatusLine, TabPanel, Tabs, Vendor, toast, useSort, type Getters, type LineMark } from "../components/ui";
import { FindingDrawer } from "../components/FindingDrawer";
import { useUi } from "../components/Shell";
import { SBM_CATEGORIES, SBM_INDEX, formatValue } from "../engine/sbm";
import { buildDevicePdf, savePdf } from "../engine/report/pdf";
import { deviceJson, findingsCsv } from "../engine/report/exports";
import { remediationBundle } from "../engine/report/remediation-bundle";
import { buildEvidenceBundle } from "../engine/report/evidence-bundle";
import { buildDeviceView, type DeviceView } from "../engine/fleet";
import { diffFindings, diffLines, diffModels, diffStats, type DiffOp } from "../engine/diff";
import { downloadBlob, downloadText, fmtDateTime, plural, relTime } from "../lib/util";
import { sha256Hex } from "../lib/hash";
import type { Status } from "../engine/types";
import type { TriagedFinding } from "../engine/exceptions";
import { SEVERITY_ORDER } from "../engine/rules/evaluate";
import { ReportPreview } from "./Reports";
import { announceIngest } from "./Ingest";

const STATUS_ORDER: Status[] = ["fail", "warning", "pass", "na"];
const LIST_GETTERS: Getters<DeviceView> = {
  name: (d) => d.name,
  vendor: (d) => `${d.parse.identity.vendorName} ${d.parse.identity.os}`,
  model: (d) => d.parse.identity.model,
  serial: (d) => d.parse.identity.serial,
  ip: (d) => d.parse.identity.mgmtIp,
  site: (d) => d.record.site,
  score: (d) => (d.assessable ? d.summary.score : -1),
  fail: (d) => d.summary.fail,
  unparsed: (d) => d.parse.unrecognized.length,
  ingested: (d) => d.record.ingestedAt,
};

export function DeviceList() {
  const fleet = useFleet();
  const [, navigate] = useLocation();
  const [q, setQ] = useState("");
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return fleet.devices;
    return fleet.devices.filter((d) => `${d.name} ${d.vendor} ${d.parse.identity.model ?? ""} ${d.parse.identity.serial ?? ""} ${d.parse.identity.mgmtIp ?? ""} ${d.record.site ?? ""} ${(d.record.tags ?? []).join(" ")} ${d.record.owner ?? ""}`.toLowerCase().includes(needle));
  }, [fleet.devices, q]);
  const { sorted, sort, toggle } = useSort(rows, LIST_GETTERS, { key: "fail", dir: "desc" });
  const identityComplete = fleet.devices.filter((d) => d.parse.identity.hostname && d.parse.identity.osVersion && d.parse.identity.model && d.parse.identity.serial).length;
  return (
    <Page
      title="Devices"
      status={<StatusLine items={[<><strong>{fleet.devices.length}</strong> devices</>, <><strong>{identityComplete}</strong> with complete identity (hostname, version, model, serial)</>, <><strong>{fleet.unrecognized}</strong> unparsed lines</>]} />}
      actions={<input className="input input--sm" style={{ width: 240 }} placeholder="Filter by name, model, serial, site, tag…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter devices" />}
    >
      <Section id="dv-list" box flush>
        <div className="table-wrap">
          <table className="table table--hover">
            <thead>
              <tr>
                <SortTh label="Device" k="name" sort={sort} onSort={toggle} />
                <SortTh label="Vendor / OS" k="vendor" sort={sort} onSort={toggle} />
                <SortTh label="Model" k="model" sort={sort} onSort={toggle} />
                <SortTh label="Serial" k="serial" sort={sort} onSort={toggle} />
                <SortTh label="Mgmt IP" k="ip" sort={sort} onSort={toggle} />
                <SortTh label="Site / tags" k="site" sort={sort} onSort={toggle} />
                <SortTh label="Score" k="score" sort={sort} onSort={toggle} style={{ minWidth: 150 }} />
                <SortTh label="Failed" k="fail" sort={sort} onSort={toggle} align="right" />
                <SortTh label="Unparsed" k="unparsed" sort={sort} onSort={toggle} align="right" />
                <SortTh label="Ingested" k="ingested" sort={sort} onSort={toggle} />
              </tr>
            </thead>
            <tbody>
              {sorted.map((d) => (
                <tr key={d.record.id} onClick={() => navigate(`/devices/${d.record.id}`)}>
                  <td><Link href={`/devices/${d.record.id}`} className="rowlink">{d.name}</Link><div className="small muted">{d.parse.identity.role ?? "unknown role"}</div></td>
                  <td><Vendor vendor={d.vendor} label={`${d.parse.identity.vendorName} ${d.parse.identity.os} ${d.parse.identity.osVersion ?? ""}`} /></td>
                  <td className="mono small">{d.parse.identity.model ?? <span className="muted">—</span>}</td>
                  <td className="mono small">{d.parse.identity.serial ?? <span className="muted">—</span>}</td>
                  <td className="mono small">{d.parse.identity.mgmtIp ?? <span className="muted">—</span>}</td>
                  <td className="small">{d.record.site ?? <span className="muted">—</span>}{d.record.tags?.length ? <div className="row" style={{ gap: 4, marginTop: 2 }}>{d.record.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div> : null}</td>
                  <td><ScoreCell score={d.summary.score} assessable={d.assessable} /></td>
                  <td className="right num" style={{ color: d.summary.fail ? "var(--fail)" : undefined, fontWeight: 600 }}>{d.assessable ? d.summary.fail : <span className="muted" style={{ fontWeight: 400 }}>—</span>}</td>
                  <td className="right num">{d.parse.unrecognized.length || <span className="dim">0</span>}</td>
                  <td className="dim nowrap">{relTime(d.record.ingestedAt)}</td>
                </tr>
              ))}
              {!sorted.length && <tr><td colSpan={10}><Empty icon={<Server />} title={fleet.devices.length ? "No device matches the filter" : "No devices"} hint={<Link href="/ingest">Ingest a configuration to begin.</Link>} /></td></tr>}
            </tbody>
          </table>
        </div>
      </Section>
    </Page>
  );
}

type StatusFilter = Status | "all";

export function DeviceDetail() {
  const { id } = useParams<{ id: string }>();
  const fleet = useFleet();
  const settings = useStore((s) => s.settings);
  const frameworks = useStore((s) => s.frameworks);
  const mappings = useStore((s) => s.mappings);
  const history = useStore((s) => s.history);
  const removeDevice = useStore((s) => s.removeDevice);
  const restoreDevice = useStore((s) => s.restoreDevice);
  const updateDevice = useStore((s) => s.updateDevice);
  const addDevices = useStore((s) => s.addDevices);
  const log = useStore((s) => s.log);
  const rules = useActiveRules();
  const setTrainingDevice = useUi((s) => s.setTrainingDevice);
  const [, navigate] = useLocation();
  const view = fleet.devices.find((d) => d.record.id === id);
  const [tab, setTab] = useState("findings");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [focusLine, setFocusLine] = useState<number | undefined>();
  const [metaOpen, setMetaOpen] = useState(false);
  const [meta, setMeta] = useState({ site: "", tags: "", owner: "" });
  const [versionSha, setVersionSha] = useState<string | null>(null);
  const versionInput = useRef<HTMLInputElement>(null);

  const marks = useMemo(() => {
    const m = new Map<number, LineMark>();
    if (!view) return m;
    for (const f of view.findings) if (f.status === "fail") for (const e of f.evidence) if (e.line) m.set(e.line, "fail");
    for (const u of view.parse.unrecognized) m.set(u.line, "unknown");
    return m;
  }, [view]);

  const versions = view ? history[view.record.id] ?? [] : [];
  const version = versions.find((v) => v.sha256 === versionSha) ?? versions[0];
  const drift = useMemo(() => {
    if (!view || !version) return null;
    const previous = buildDeviceView({ ...view.record, raw: version.raw, sha256: version.sha256, ingestedAt: version.ingestedAt, fileName: version.fileName }, mappings, rules, frameworks, settings.remediation).view;
    const ops = diffLines(version.raw, view.record.raw);
    return { previous, ops, stats: diffStats(ops), params: diffModels(previous.parse.model, view.parse.model), findings: diffFindings(previous.findings, view.findings) };
  }, [view, version, mappings, rules, frameworks, settings.remediation]);

  if (!view) {
    return (
      <Page title="Device not found" status={<span className="mono">{id}</span>}>
        <div className="box box--pad"><Empty icon={<Server />} title="This device is not in the fleet" hint="It may have been removed, or the link belongs to another browser's workspace." action={<Link href="/devices" className="btn btn--primary">All devices</Link>} /></div>
      </Page>
    );
  }
  const idn = view.parse.identity;
  const findings = [...view.findings].filter((f) => statusFilter === "all" || f.status === statusFilter).sort((a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const selected: TriagedFinding | null = selectedId ? view.findings.find((f) => f.id === selectedId) ?? null : null;
  const params = Object.values(view.parse.model.params);
  const observed = params.filter((p) => p.source !== "default");
  const counts = { all: view.findings.length, fail: view.findings.filter((f) => f.status === "fail").length, warning: view.findings.filter((f) => f.status === "warning").length, pass: view.findings.filter((f) => f.status === "pass").length, na: view.findings.filter((f) => f.status === "na").length };
  const reportMeta = { organisation: settings.organisation, operator: settings.operator, frameworks };

  const pdf = async () => {
    try {
      const doc = buildDevicePdf(view, reportMeta);
      const outcome = await savePdf(doc, `netsentinel-${view.name}-compliance.pdf`);
      if (outcome === "declined") return toast.info("Download cancelled");
      log({ actor: "admin", action: "Report exported", target: `${view.name} device PDF` });
      toast.ok("PDF report generated", "Identification, findings, remediation CLI and the normalised baseline model.");
    } catch (e) {
      toast.err("Could not build the PDF", String(e));
    }
  };
  const script = async () => {
    const outcome = await downloadText(remediationBundle(view, reportMeta), `netsentinel-${view.name}-remediation.txt`);
    if (outcome === "declined") return toast.info("Download cancelled");
    log({ actor: "admin", action: "Remediation script exported", target: view.name });
    toast.ok("Remediation script saved", `${counts.fail} failed controls in severity order, wrapped in review comments.`);
  };
  const bundle = async () => {
    try {
      const blob = await buildEvidenceBundle(fleet, [view], reportMeta);
      const outcome = await downloadBlob(blob, `netsentinel-evidence-${view.name}.zip`);
      if (outcome === "declined") return toast.info("Download cancelled");
      log({ actor: "admin", action: "Evidence bundle exported", target: view.name });
      toast.ok("Evidence bundle saved", "Configuration, PDF, JSON, CSV, remediation script and a SHA-256 manifest.");
    } catch (e) {
      toast.err("Could not build the bundle", String(e));
    }
  };
  const remove = () => {
    const rec = view.record;
    const versionsCopy = history[rec.id];
    removeDevice(rec.id);
    navigate("/devices");
    toast.info("Device removed", rec.fileName, { label: "Undo", onClick: () => restoreDevice(rec, versionsCopy) });
  };
  const jump = (line: number) => {
    setSelectedId(null);
    setTab("config");
    setFocusLine(line);
  };
  const openMeta = () => {
    setMeta({ site: view.record.site ?? "", tags: (view.record.tags ?? []).join(", "), owner: view.record.owner ?? "" });
    setMetaOpen(true);
  };
  const saveMeta = () => {
    updateDevice(view.record.id, { site: meta.site.trim() || undefined, tags: meta.tags.split(",").map((t) => t.trim()).filter(Boolean), owner: meta.owner.trim() || undefined });
    setMetaOpen(false);
    toast.ok("Device details saved");
  };
  const uploadVersion = async (file: File | undefined) => {
    if (!file) return;
    const raw = await file.text();
    if (!raw.trim()) return toast.err("The file is empty");
    const outcome = addDevices([{ fileName: file.name, raw, sha256: await sha256Hex(raw) }]);
    announceIngest(outcome);
    if (outcome.added.length && !outcome.replaced.length) toast.info("Ingested as a separate device", "The hostname in the file does not match this device, so no version history was created.");
  };
  const toTraining = () => { setTrainingDevice(view.record.id); navigate("/training"); };

  return (
    <Page
      eyebrow={<Link href="/devices">Devices</Link>}
      title={view.name}
      status={
        <StatusLine items={[<Vendor vendor={view.vendor} label={`${idn.vendorName} ${idn.os}${idn.osVersion ? ` ${idn.osVersion}` : ""}`} />, idn.role, <span className="mono">{view.record.fileName}</span>, view.record.site && <>site <strong>{view.record.site}</strong></>, view.record.owner && <>owner <strong>{view.record.owner}</strong></>, `ingested ${relTime(view.record.ingestedAt)}`]} />
      }
      actions={
        <>
          <button type="button" className="btn" onClick={openMeta}><Pencil /> Details</button>
          <button type="button" className="btn" onClick={() => downloadText(findingsCsv(fleet, view.record.id), `netsentinel-${view.name}-findings.csv`, "text/csv")}><Download /> CSV</button>
          <button type="button" className="btn" onClick={() => downloadText(deviceJson(view), `netsentinel-${view.name}.json`, "application/json")}><FileJson /> JSON</button>
          <button type="button" className="btn" onClick={script} disabled={!counts.fail}><Wrench /> Remediation script</button>
          <button type="button" className="btn" onClick={bundle}><Archive /> Evidence bundle</button>
          <button type="button" className="btn btn--primary" onClick={pdf}><FileText /> PDF report</button>
          <Confirm label="Remove" danger small={false} icon={<Trash2 />} onConfirm={remove} />
        </>
      }
    >
      <div className="grid">
        <Section className="span-4" id="dd-score" title="Compliance" sub={view.assessable ? `${view.summary.assessed} controls assessed · ${view.summary.warning} without evidence · coverage ${view.coverage}%` : "Too little of the configuration was understood to score this device"} box>
          <Gauge score={view.summary.score} assessable={view.assessable} coverage={view.coverage} bySeverity={view.summary.bySeverity} label="Device score" sub={view.summary.accepted > 0 ? <>Adjusted for {view.summary.accepted} accepted risk{view.summary.accepted > 1 ? "s" : ""}: <strong>{view.summary.adjustedScore}</strong></> : undefined} />
          {view.assessable ? (
            <div className="kv small" style={{ marginTop: 16, gridTemplateColumns: "1fr auto" }}>
              <span className="muted">Passed</span><strong className="num right" style={{ color: "var(--pass)" }}>{view.summary.pass}</strong>
              <span className="muted">Failed</span><strong className="num right" style={{ color: "var(--fail)" }}>{view.summary.fail}</strong>
              <span className="muted">Critical / high</span><strong className="num right">{view.summary.bySeverity.critical} / {view.summary.bySeverity.high}</strong>
              <span className="muted">Weighted risk points</span><strong className="num right">{view.risk}</strong>
            </div>
          ) : (
            <div className="callout callout--warn small" style={{ marginTop: 14 }}>
              {view.parse.recognized} of {view.parse.meaningfulLines} lines were understood and {observed.length} parameters observed. <button type="button" className="rowbtn" onClick={toTraining}>Teach the parser in the Training Studio</button> to make this device assessable.
            </div>
          )}
        </Section>
        <Section className="span-8" id="dd-identity" title="Device identification" sub="Extracted from the configuration and any pasted show-version output" box>
          <dl className="kv">
            <dt>Hostname</dt><dd><strong>{idn.hostname ?? "—"}</strong></dd>
            <dt>Vendor / OS</dt><dd>{idn.vendorName} {idn.os}</dd>
            <dt>Software version</dt><dd className={idn.osVersion ? "mono" : "missing"}>{idn.osVersion ?? "not present in the configuration"}</dd>
            <dt>Hardware model</dt><dd className={idn.model ? "mono" : "missing"}>{idn.model ?? "not present in the configuration"}</dd>
            <dt>Serial number</dt><dd className={idn.serial ? "mono" : "missing"}>{idn.serial ?? "not present in the configuration"}</dd>
            <dt>Management address</dt><dd className="mono">{idn.mgmtIp ?? "—"}</dd>
            <dt>Configuration SHA-256</dt><dd className="mono small">{view.record.sha256}</dd>
            <dt>Detection</dt><dd>{view.record.detection.vendor === "generic" ? "no vendor signature matched" : `${Math.round(view.record.detection.confidence * 100)}% · ${view.record.detection.reasons.slice(0, 3).join("; ")}`}{view.record.vendorOverride ? " · parser overridden manually" : ""}</dd>
            <dt>Parser coverage</dt><dd>{view.parse.recognized} of {view.parse.meaningfulLines} lines understood · {observed.length} parameters observed · {plural(view.parse.mappingsApplied.length, "learned mapping")} applied</dd>
            {versions.length > 0 && <><dt>Versions</dt><dd>{plural(versions.length, "previous version")} archived · <button type="button" className="rowbtn" onClick={() => setTab("drift")}>view drift</button></dd></>}
          </dl>
        </Section>
      </div>

      <div className="box box--flush">
        <Tabs
          label="Device sections"
          tabs={[
            { id: "findings", label: "Findings", badge: counts.fail },
            { id: "baseline", label: "Baseline model", badge: observed.length },
            { id: "config", label: "Configuration" },
            { id: "unknown", label: "Unparsed lines", badge: view.parse.unrecognized.length },
            { id: "drift", label: "Drift", badge: versions.length },
            { id: "report", label: "Report preview" },
          ]}
          value={tab}
          onChange={setTab}
        />
        <TabPanel id="findings" active={tab === "findings"}>
          <div className="row" style={{ padding: "12px 16px" }}>
            <Segmented<StatusFilter>
              label="Result filter"
              value={statusFilter}
              onChange={setStatusFilter}
              options={[
                { id: "all", label: "All", count: counts.all },
                { id: "fail", label: "Failed", count: counts.fail },
                { id: "warning", label: "Not assessed", count: counts.warning },
                { id: "pass", label: "Passed", count: counts.pass },
                { id: "na", label: "N/A", count: counts.na },
              ]}
            />
            <span className="small muted">{plural(findings.length, "control")}</span>
          </div>
          <div className="table-wrap">
            <table className="table table--hover">
              <thead><tr><th>Control</th><th>Title</th><th>Severity</th><th>Result</th><th>Triage</th><th>Observed</th><th>References</th></tr></thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} onClick={() => setSelectedId(f.id)}>
                    <td className="mono small nowrap">{f.ruleId}</td>
                    <td><button type="button" className="rowbtn" onClick={(e) => { e.stopPropagation(); setSelectedId(f.id); }}>{f.title}</button><div className="small muted">{f.category}</div></td>
                    <td><Sev severity={f.severity} /></td>
                    <td><Stamp status={f.status} accepted={Boolean(f.exception)} /></td>
                    <td className="small">{f.triage && f.triage.state !== "accepted" && f.triage.state !== "open" ? <span className="pill pill--info">{f.triage.state === "in-progress" ? "In progress" : "Remediated"}</span> : <span className="muted">—</span>}</td>
                    <td className="small ellipsis" title={f.observed}>{f.observed}</td>
                    <td><div className="row" style={{ gap: 4 }}>{f.refs.slice(0, 3).map((r, i) => <FwTag key={i} framework={r.framework} id={r.id} title={r.title} />)}</div></td>
                  </tr>
                ))}
                {!findings.length && <tr><td colSpan={7}><Empty title="No controls in this state" /></td></tr>}
              </tbody>
            </table>
          </div>
        </TabPanel>
        <TabPanel id="baseline" active={tab === "baseline"}>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Parameter</th><th>Value</th><th>Source</th><th>Evidence</th></tr></thead>
              <tbody>
                {SBM_CATEGORIES.map((cat) => {
                  const rows = params.filter((p) => SBM_INDEX[p.key]?.category === cat);
                  if (!rows.length) return null;
                  return (
                    <Fragment key={cat}>
                      <tr className="group"><td colSpan={4}>{cat}</td></tr>
                      {rows.map((p) => (
                        <tr key={p.key}>
                          <td><strong>{SBM_INDEX[p.key]?.label ?? p.key}</strong><div className="small muted mono">{p.key}</div></td>
                          <td className="mono small">{formatValue(p.value)}</td>
                          <td><span className={`pill ${p.source === "parser" ? "pill--info" : p.source === "mapping" ? "pill--accent" : p.source === "llm" ? "pill--ai" : "pill--na"}`}>{p.source === "default" ? "platform default" : p.source === "mapping" ? "learned mapping" : p.source}</span></td>
                          <td><EvidenceList evidence={p.evidence} onJump={jump} limit={3} /></td>
                        </tr>
                      ))}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </TabPanel>
        <TabPanel id="config" active={tab === "config"} pad>
          <div className="legend"><span><i style={{ background: "var(--fail-soft)", borderColor: "var(--fail)" }} /> evidence of a failed control</span><span><i style={{ background: "var(--warn-soft)", borderColor: "var(--warn)" }} /> not understood by the parser</span><span><i style={{ background: "var(--accent-soft)", borderColor: "var(--accent)" }} /> focused line</span></div>
          <CodeViewer raw={view.record.raw} marks={marks} focusLine={focusLine} maxHeight={720} />
        </TabPanel>
        <TabPanel id="unknown" active={tab === "unknown"} pad>
          {view.parse.unrecognized.length ? (
            <>
              <div className="callout small">These lines were not understood by the {idn.vendorName} parser. <button type="button" className="rowbtn" onClick={toTraining}>Map them in the Training Studio</button> — a mapping is reused for every device of this vendor without redeploying anything.</div>
              <div className="code" style={{ maxHeight: 520 }}>
                {view.parse.unrecognized.map((u) => (
                  <div key={u.line} className="code__line unknown"><span className="code__n">{u.line}</span><span className="code__t">{u.text}{u.context ? `    # ${u.context}` : ""}</span></div>
                ))}
              </div>
            </>
          ) : (
            <Empty title="Every meaningful line was understood" hint="The parser recognised 100% of this configuration." />
          )}
        </TabPanel>
        <TabPanel id="drift" active={tab === "drift"} pad>
          <input ref={versionInput} type="file" hidden aria-hidden="true" onChange={(e) => { uploadVersion(e.target.files?.[0]); e.target.value = ""; }} />
          {!versions.length || !drift ? (
            <Empty icon={<GitCompareArrows />} title="No previous version yet" hint={<>Upload a newer configuration for <strong>{idn.hostname ?? view.name}</strong> and NetSentinel keeps this one, then shows what changed, which baseline parameters moved and which controls regressed or were fixed.</>} action={<button type="button" className="btn btn--primary" onClick={() => versionInput.current?.click()}><UploadCloud /> Upload a newer version</button>} />
          ) : (
            <>
              <div className="row between">
                <div className="row">
                  <label htmlFor="drift-version" className="small muted">Compare current with</label>
                  <select id="drift-version" className="select input--sm" style={{ width: 300 }} value={version?.sha256 ?? ""} onChange={(e) => setVersionSha(e.target.value)}>
                    {versions.map((v, i) => <option key={v.sha256} value={v.sha256}>{i === 0 ? "previous" : `${i + 1} versions back`} · {v.fileName} · {fmtDateTime(v.ingestedAt)}</option>)}
                  </select>
                  <span className="diffstats"><span className="add">+{drift.stats.added}</span><span className="del">−{drift.stats.removed}</span><span className="muted">{drift.stats.unchanged} unchanged</span></span>
                </div>
                <button type="button" className="btn btn--sm" onClick={() => versionInput.current?.click()}><UploadCloud /> Upload newer version</button>
              </div>
              <div className="grid">
                <Section className="span-6" id="dr-findings" title="Control changes" sub={`score ${drift.previous.summary.score} → ${view.summary.score}`} box flush>
                  {drift.findings.length ? (
                    <table className="table">
                      <tbody>
                        {drift.findings.map((d) => (
                          <tr key={d.ruleId}>
                            <td><span className={`pill ${d.kind === "regressed" ? "pill--fail" : d.kind === "fixed" ? "pill--pass" : "pill--na"}`}>{d.kind}</span></td>
                            <td><strong>{d.ruleId}</strong><div className="small muted">{d.title}</div></td>
                            <td><Sev severity={d.severity} /></td>
                            <td className="small nowrap">{d.before === "absent" ? "absent" : <Stamp status={d.before} />} → {d.after === "absent" ? "absent" : <Stamp status={d.after} />}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="empty">No control changed its result.</div>
                  )}
                </Section>
                <Section className="span-6" id="dr-params" title="Baseline parameter changes" sub={plural(drift.params.length, "parameter")} box flush>
                  {drift.params.length ? (
                    <div className="table-wrap" style={{ maxHeight: 320, overflowY: "auto" }}>
                      <table className="table">
                        <tbody>
                          {drift.params.map((p) => (
                            <tr key={p.key}>
                              <td><strong>{p.label}</strong><div className="small muted mono">{p.key}</div></td>
                              <td className="mono small"><span style={{ color: "var(--fail)" }}>{p.before ?? "—"}</span> → <span style={{ color: "var(--pass)" }}>{p.after ?? "—"}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="empty">The normalised model is identical.</div>
                  )}
                </Section>
              </div>
              <DiffView ops={drift.ops} />
            </>
          )}
        </TabPanel>
        <TabPanel id="report" active={tab === "report"} pad>
          <div className="row between"><span className="small muted">Exact content of the PDF, rendered in-page.</span><button type="button" className="btn btn--sm btn--primary" onClick={pdf}><FileText /> Download PDF</button></div>
          <ReportPreview view={view} />
        </TabPanel>
      </div>

      <FindingDrawer finding={selected} view={view} onClose={() => setSelectedId(null)} onJump={jump} />

      <Modal
        open={metaOpen}
        onClose={() => setMetaOpen(false)}
        title="Device details"
        foot={<><span className="grow" /><button type="button" className="btn" onClick={() => setMetaOpen(false)}>Cancel</button><button type="button" className="btn btn--primary" onClick={saveMeta}>Save</button></>}
      >
        <div className="field"><label htmlFor="md-site">Site</label><input id="md-site" data-autofocus className="input" value={meta.site} onChange={(e) => setMeta({ ...meta, site: e.target.value })} placeholder="Mumbai DC-1" /></div>
        <div className="field"><label htmlFor="md-tags">Tags</label><input id="md-tags" className="input" value={meta.tags} onChange={(e) => setMeta({ ...meta, tags: e.target.value })} placeholder="edge, pci, critical" /><span className="hint">Comma separated. Tags are searchable on the Devices page.</span></div>
        <div className="field"><label htmlFor="md-owner">Owner</label><input id="md-owner" className="input" value={meta.owner} onChange={(e) => setMeta({ ...meta, owner: e.target.value })} placeholder="network-core@example.in" /></div>
      </Modal>
    </Page>
  );
}

/** Unified diff with unchanged runs collapsed to three lines of context. */
function DiffView({ ops }: { ops: DiffOp[] }) {
  const rows = useMemo(() => {
    const out: (DiffOp | { kind: "gap"; count: number })[] = [];
    const keep = new Set<number>();
    ops.forEach((o, i) => { if (o.kind !== "same") for (let k = i - 3; k <= i + 3; k++) keep.add(k); });
    let gap = 0;
    ops.forEach((o, i) => {
      if (o.kind === "same" && !keep.has(i)) { gap++; return; }
      if (gap) { out.push({ kind: "gap", count: gap }); gap = 0; }
      out.push(o);
    });
    if (gap) out.push({ kind: "gap", count: gap });
    return out;
  }, [ops]);
  if (!ops.some((o) => o.kind !== "same")) return <div className="callout small">The two configurations are textually identical.</div>;
  return (
    <div className="code" style={{ maxHeight: 560 }} aria-label="Configuration diff">
      {rows.map((r, i) =>
        r.kind === "gap" ? (
          <div key={i} className="code__line"><span className="code__n">…</span><span className="code__t muted">{r.count} unchanged lines</span></div>
        ) : (
          <div key={i} className={`code__line ${r.kind === "add" ? "add" : r.kind === "del" ? "del" : ""}`}>
            <span className="code__n">{r.kind === "del" ? r.a : r.b}</span>
            <span className="code__t">{r.kind === "add" ? "+ " : r.kind === "del" ? "− " : "  "}{r.text}</span>
          </div>
        ),
      )}
    </div>
  );
}
