import { Fragment, useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Download, FileJson, ShieldCheck } from "lucide-react";
import { useFleet, useStore } from "../store";
import { useUi } from "../components/Shell";
import { Empty, FwTag, Kpi, Kpis, Page, Pager, Segmented, Sev, SortTh, StackBar, Stamp, StatusLine, Vendor, useSort, type Getters } from "../components/ui";
import { FindingDrawer } from "../components/FindingDrawer";
import { SBM_CATEGORIES } from "../engine/sbm";
import { FRAMEWORKS } from "../engine/rules/library";
import { SEVERITY_ORDER } from "../engine/rules/evaluate";
import { findingsCsv } from "../engine/report/exports";
import { downloadText, plural } from "../lib/util";
import type { TriagedFinding } from "../engine/exceptions";
import type { FrameworkId, Severity, Status, VendorId } from "../engine/types";

const STATUS_ORDER: Status[] = ["fail", "warning", "pass", "na"];
const PAGE = 50;
type StatusFilter = Status | "all";
type Row = TriagedFinding & { device: string; vendor: VendorId };

const ROW_GETTERS: Getters<Row> = {
  device: (f) => f.device,
  control: (f) => f.ruleId,
  title: (f) => f.title,
  severity: (f) => SEVERITY_ORDER.indexOf(f.severity),
  status: (f) => STATUS_ORDER.indexOf(f.status),
  observed: (f) => f.observed,
};

export default function Findings() {
  const fleet = useFleet();
  const frameworks = useStore((s) => s.frameworks);
  const query = useUi((s) => s.query);
  const setQuery = useUi((s) => s.setQuery);
  const [status, setStatus] = useState<StatusFilter>("fail");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [framework, setFramework] = useState<FrameworkId | "all">("all");
  const [category, setCategory] = useState<string>("all");
  const [device, setDevice] = useState<string>("all");
  const [view, setView] = useState<"rows" | "controls">("rows");
  const [page, setPage] = useState(0);
  const [openControl, setOpenControl] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const byDevice = useMemo(() => new Map(fleet.devices.map((d) => [d.record.id, d])), [fleet.devices]);

  const rows = useMemo<Row[]>(() => {
    const q = query.trim().toLowerCase();
    return fleet.findings
      .map((f) => { const d = byDevice.get(f.deviceId); return { ...f, device: d?.name ?? f.deviceId, vendor: d?.vendor ?? "generic" } as Row; })
      .filter((f) => status === "all" || f.status === status)
      .filter((f) => severity === "all" || f.severity === severity)
      .filter((f) => framework === "all" || f.frameworks.includes(framework))
      .filter((f) => category === "all" || f.category === category)
      .filter((f) => device === "all" || f.deviceId === device)
      .filter((f) => !q || `${f.ruleId} ${f.title} ${f.category} ${f.observed} ${f.device} ${f.refs.map((r) => r.id).join(" ")}`.toLowerCase().includes(q));
  }, [fleet.findings, byDevice, status, severity, framework, category, device, query]);
  const { sorted, sort, toggle } = useSort(rows, ROW_GETTERS, { key: "severity", dir: "asc" });
  useEffect(() => setPage(0), [status, severity, framework, category, device, query, sort]);
  const pageRows = sorted.slice(page * PAGE, (page + 1) * PAGE);

  const controls = useMemo(() => {
    const m = new Map<string, { ruleId: string; title: string; severity: Severity; category: string; rows: Row[]; fail: number; pass: number; warning: number; accepted: number }>();
    for (const f of rows) {
      const e = m.get(f.ruleId) ?? { ruleId: f.ruleId, title: f.title, severity: f.severity, category: f.category, rows: [], fail: 0, pass: 0, warning: 0, accepted: 0 };
      e.rows.push(f);
      if (f.status === "fail") { e.fail++; if (f.exception) e.accepted++; } else if (f.status === "pass") e.pass++; else if (f.status === "warning") e.warning++;
      m.set(f.ruleId, e);
    }
    return Array.from(m.values()).sort((a, b) => b.fail - a.fail || SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.ruleId.localeCompare(b.ruleId));
  }, [rows]);

  const failedAll = fleet.findings.filter((f) => f.status === "fail");
  const topControl = useMemo(() => {
    const m = new Map<string, { title: string; count: number }>();
    for (const f of failedAll) { const e = m.get(f.ruleId) ?? { title: f.title, count: 0 }; e.count++; m.set(f.ruleId, e); }
    return Array.from(m.entries()).sort((a, b) => b[1].count - a[1].count)[0];
  }, [failedAll]);
  const selected: TriagedFinding | null = selectedId ? fleet.findings.find((f) => f.id === selectedId) ?? null : null;
  const selectedView = selected ? byDevice.get(selected.deviceId) : undefined;
  const exportJson = () => downloadText(JSON.stringify(sorted.map(({ device: dev, vendor: v, ...f }) => ({ device: dev, vendor: v, ...f })), null, 2), "netsentinel-findings.json", "application/json");
  const FILTER_LABEL = (s: StatusFilter) => (s === "all" ? "All" : s === "fail" ? "Failed" : s === "warning" ? "Not assessed" : s === "pass" ? "Passed" : "N/A");

  return (
    <Page
      title="Findings"
      status={<StatusLine items={[<><strong>{fleet.findings.length}</strong> control evaluations across {plural(fleet.devices.length, "device")}</>, <>scope <strong>{frameworks.map((f) => FRAMEWORKS[f].short).join(" · ") || "none"}</strong></>]} />}
      actions={
        <>
          <button type="button" className="btn" onClick={exportJson} disabled={!sorted.length}><FileJson /> JSON ({sorted.length})</button>
          <button type="button" className="btn" onClick={() => downloadText(findingsCsv(fleet), "netsentinel-findings.csv", "text/csv")} disabled={!fleet.findings.length}><Download /> CSV (all)</button>
        </>
      }
    >
      <Kpis cols={4}>
        <Kpi label="Failed controls" value={fleet.summary.fail} tone="fail" hint={`${fleet.summary.bySeverity.critical} critical · ${fleet.summary.bySeverity.high} high`} onClick={() => setStatus("fail")} active={status === "fail"} />
        <Kpi label="Risk accepted" value={fleet.summary.accepted} tone="info" hint={fleet.summary.accepted ? `adjusted fleet score ${fleet.adjustedScore}` : "documented exceptions leave the adjusted score"} />
        <Kpi label="Not assessed" value={fleet.summary.warning} tone="warn" hint="no evidence either way — train the parser or verify manually" onClick={() => setStatus("warning")} active={status === "warning"} />
        <Kpi label="Most common failure" value={topControl ? topControl[1].count : 0} unit={topControl ? ` of ${fleet.assessableDevices} devices` : ""} hint={topControl ? `${topControl[0]} · ${topControl[1].title}` : "—"} onClick={topControl ? () => { setQuery(topControl[0]); setStatus("fail"); } : undefined} />
      </Kpis>

      <div className="box box--flush">
        <div className="row" style={{ padding: "12px 16px", gap: 10 }}>
          <Segmented<StatusFilter> label="Result" value={status} onChange={setStatus} options={(["fail", "warning", "pass", "all"] as StatusFilter[]).map((s) => ({ id: s, label: FILTER_LABEL(s) }))} />
          <select className="select input--sm" style={{ width: 140 }} value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "all")} aria-label="Severity">
            <option value="all">All severities</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </select>
          <select className="select input--sm" style={{ width: 170 }} value={framework} onChange={(e) => setFramework(e.target.value as FrameworkId | "all")} aria-label="Framework">
            <option value="all">All frameworks</option>
            {frameworks.map((f) => <option key={f} value={f}>{FRAMEWORKS[f].name}</option>)}
          </select>
          <select className="select input--sm" style={{ width: 190 }} value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Control family">
            <option value="all">All families</option>
            {SBM_CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <select className="select input--sm" style={{ width: 170 }} value={device} onChange={(e) => setDevice(e.target.value)} aria-label="Device">
            <option value="all">All devices</option>
            {fleet.devices.map((d) => <option key={d.record.id} value={d.record.id}>{d.name}</option>)}
          </select>
          <input className="input input--sm" style={{ width: 200 }} placeholder="Filter text…" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Filter findings by text" />
          <span className="small muted">{sorted.length} of {fleet.findings.length}</span>
          <span className="grow" />
          <Segmented<"rows" | "controls"> label="View" value={view} onChange={setView} options={[{ id: "rows", label: "By device" }, { id: "controls", label: "By control", count: controls.length }]} />
        </div>

        {view === "rows" ? (
          <>
            <div className="table-wrap">
              <table className="table table--hover">
                <thead>
                  <tr>
                    <SortTh label="Device" k="device" sort={sort} onSort={toggle} />
                    <SortTh label="Control" k="control" sort={sort} onSort={toggle} />
                    <SortTh label="Title" k="title" sort={sort} onSort={toggle} />
                    <SortTh label="Severity" k="severity" sort={sort} onSort={toggle} />
                    <SortTh label="Result" k="status" sort={sort} onSort={toggle} />
                    <SortTh label="Observed" k="observed" sort={sort} onSort={toggle} />
                    <th>Frameworks</th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map((f) => (
                    <tr key={f.id} onClick={() => setSelectedId(f.id)}>
                      <td className="nowrap"><Vendor vendor={f.vendor} label={f.device} /></td>
                      <td className="mono small nowrap">{f.ruleId}</td>
                      <td><button type="button" className="rowbtn" onClick={(e) => { e.stopPropagation(); setSelectedId(f.id); }}>{f.title}</button><div className="small muted">{f.category}</div></td>
                      <td><Sev severity={f.severity} /></td>
                      <td><Stamp status={f.status} accepted={Boolean(f.exception)} /></td>
                      <td className="small ellipsis" title={f.observed}>{f.observed}</td>
                      <td><div className="row" style={{ gap: 4 }}>{f.frameworks.map((fw) => <FwTag key={fw} framework={fw} />)}</div></td>
                    </tr>
                  ))}
                  {!sorted.length && <tr><td colSpan={7}><Empty icon={<ShieldCheck />} title="No findings match" hint="Loosen the filters or ingest more devices." /></td></tr>}
                </tbody>
              </table>
            </div>
            <Pager page={page} pageSize={PAGE} total={sorted.length} onPage={setPage} />
          </>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th style={{ width: 28 }} /><th>Control</th><th>Family</th><th>Severity</th><th className="right">Failed</th><th className="right">Passed</th><th className="right">Not assessed</th><th style={{ minWidth: 160 }}>Across devices</th></tr></thead>
              <tbody>
                {controls.map((c) => {
                  const open = openControl === c.ruleId;
                  return (
                    <Fragment key={c.ruleId}>
                      <tr className="table--hover" style={{ cursor: "pointer" }} onClick={() => setOpenControl(open ? null : c.ruleId)}>
                        <td><button type="button" className="btn btn--ghost btn--sm btn--icon" aria-expanded={open} aria-label={`${open ? "Collapse" : "Expand"} ${c.ruleId}`} onClick={(e) => { e.stopPropagation(); setOpenControl(open ? null : c.ruleId); }}>{open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</button></td>
                        <td><span className="mono small">{c.ruleId}</span> <strong>{c.title}</strong></td>
                        <td className="dim small nowrap">{c.category}</td>
                        <td><Sev severity={c.severity} /></td>
                        <td className="right num" style={{ color: c.fail ? "var(--fail)" : undefined, fontWeight: 600 }}>{c.fail}{c.accepted ? <span className="small muted" style={{ fontWeight: 400 }}> ({c.accepted} accepted)</span> : null}</td>
                        <td className="right num">{c.pass}</td>
                        <td className="right num dim">{c.warning}</td>
                        <td><StackBar label={c.ruleId} parts={[{ value: c.fail, color: "var(--fail)", label: "failed" }, { value: c.pass, color: "var(--pass)", label: "passed" }, { value: c.warning, color: "var(--warn)", label: "not assessed" }]} /></td>
                      </tr>
                      {open && [...c.rows].sort((a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status)).map((f) => (
                        <tr key={f.id} onClick={() => setSelectedId(f.id)} style={{ cursor: "pointer", background: "var(--bg-2)" }}>
                          <td />
                          <td colSpan={3}><button type="button" className="rowbtn" style={{ fontWeight: 500 }} onClick={(e) => { e.stopPropagation(); setSelectedId(f.id); }}><Vendor vendor={f.vendor} label={f.device} /></button></td>
                          <td colSpan={2}><Stamp status={f.status} accepted={Boolean(f.exception)} /></td>
                          <td colSpan={2} className="small ellipsis" title={f.observed}>{f.observed}</td>
                        </tr>
                      ))}
                    </Fragment>
                  );
                })}
                {!controls.length && <tr><td colSpan={8}><Empty icon={<ShieldCheck />} title="No findings match" hint="Loosen the filters or ingest more devices." /></td></tr>}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <FindingDrawer finding={selected} view={selectedView} onClose={() => setSelectedId(null)} />
    </Page>
  );
}
