import { useEffect, useMemo } from "react";
import { Link, useLocation } from "wouter";
import { FileText, RefreshCw } from "lucide-react";
import { useFleet, useStore } from "../store";
import { Bars, Gauge, HeatLegend, Page, ScoreCell, Section, SortTh, Sparkline, StatusLine, Vendor, heatColor, toast, useSort, type Getters } from "../components/ui";
import { CATEGORY_SHORT, SBM_CATEGORIES } from "../engine/sbm";
import { FRAMEWORKS } from "../engine/rules/library";
import { SEVERITY_ORDER } from "../engine/rules/evaluate";
import { buildFleetPdf, savePdf } from "../engine/report/pdf";
import { relTime } from "../lib/util";
import type { DeviceView } from "../engine/fleet";
import type { ControlCategory, Severity } from "../engine/types";

const SEV_COLOR: Record<Severity, string> = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)" };
const GETTERS: Getters<DeviceView> = {
  name: (d) => d.name,
  vendor: (d) => `${d.parse.identity.vendorName} ${d.parse.identity.os}`,
  version: (d) => d.parse.identity.osVersion,
  role: (d) => d.parse.identity.role,
  score: (d) => (d.assessable ? d.summary.score : -1),
  fail: (d) => d.summary.fail,
  crit: (d) => d.summary.bySeverity.critical * 100 + d.summary.bySeverity.high,
  coverage: (d) => d.coverage,
  ingested: (d) => d.record.ingestedAt,
};

export default function Overview() {
  const fleet = useFleet();
  const frameworks = useStore((s) => s.frameworks);
  const activity = useStore((s) => s.activity);
  const scans = useStore((s) => s.scans);
  const recordScan = useStore((s) => s.recordScan);
  const log = useStore((s) => s.log);
  const settings = useStore((s) => s.settings);
  const [, navigate] = useLocation();
  const { sorted, sort, toggle } = useSort(fleet.devices, GETTERS, { key: "fail", dir: "desc" });

  // Record a trend point whenever the fleet posture materially changes.
  useEffect(() => {
    const last = scans[scans.length - 1];
    if (!fleet.devices.length) return;
    if (!last || last.score !== fleet.score || last.devices !== fleet.devices.length || last.fail !== fleet.summary.fail) {
      recordScan({ score: fleet.score, devices: fleet.devices.length, fail: fleet.summary.fail });
    }
  }, [fleet.score, fleet.devices.length, fleet.summary.fail, scans, recordScan]);

  const families = useMemo(() => new Set(fleet.devices.filter((d) => d.vendor !== "generic").map((d) => d.vendor)).size, [fleet.devices]);
  const unknownVendor = fleet.devices.filter((d) => d.vendor === "generic").length;
  const avgConfidence = fleet.devices.length ? Math.round((fleet.devices.reduce((s, d) => s + d.record.detection.confidence, 0) / fleet.devices.length) * 100) : 0;
  const assessed = fleet.summary.assessed;
  const notAssessable = fleet.devices.length - fleet.assessableDevices;
  const worst = useMemo(() => [...fleet.devices].filter((d) => d.assessable).sort((a, b) => b.risk - a.risk || b.summary.fail - a.summary.fail).slice(0, 5), [fleet.devices]);
  const heat = useMemo(
    () =>
      fleet.devices.map((d) => ({
        device: d,
        cells: SBM_CATEGORIES.map((cat) => {
          if (!d.assessable) return null;
          const fs = d.findings.filter((f) => f.category === (cat as ControlCategory) && (f.status === "pass" || f.status === "fail"));
          if (!fs.length) return null;
          const fail = fs.filter((f) => f.status === "fail").length;
          return { fail, total: fs.length, rate: Math.round(((fs.length - fail) / fs.length) * 100) };
        }),
      })),
    [fleet.devices],
  );

  const rerun = () => {
    recordScan({ score: fleet.score, devices: fleet.devices.length, fail: fleet.summary.fail });
    log({ actor: "engine", action: "Audit run", target: `${fleet.devices.length} devices · ${assessed} controls assessed`, detail: `Fleet score ${fleet.score}. ${fleet.summary.fail} failed, ${fleet.summary.warning} not assessed, ${fleet.summary.accepted} accepted.` });
    toast.ok("Audit complete", `${assessed} controls assessed across ${fleet.assessableDevices} assessable devices. Fleet score ${fleet.score}/100.`);
  };
  const fleetPdf = async () => {
    try {
      const doc = buildFleetPdf(fleet, { organisation: settings.organisation, operator: settings.operator, frameworks });
      const outcome = await savePdf(doc, `netsentinel-fleet-summary-${new Date().toISOString().slice(0, 10)}.pdf`);
      if (outcome === "declined") return toast.info("Download cancelled");
      log({ actor: "admin", action: "Report exported", target: "Fleet summary PDF" });
      toast.ok("Fleet summary PDF generated", "Inventory with model and serial, scores and every failed control.");
    } catch (e) {
      toast.err("Could not build the PDF", String(e));
    }
  };
  const lastScan = scans[scans.length - 1];

  return (
    <Page
      title="Fleet posture"
      status={
        <StatusLine
          items={[
            <><strong>{fleet.devices.length}</strong> devices</>,
            <><strong>{fleet.assessableDevices}</strong> assessable{notAssessable > 0 && <span className="muted"> · {notAssessable} not assessed</span>}</>,
            <>scope <strong>{frameworks.map((f) => FRAMEWORKS[f].short).join(" · ") || "none selected"}</strong></>,
            lastScan && <>last audit {relTime(lastScan.at)}</>,
          ]}
        />
      }
      actions={
        <>
          <button type="button" className="btn" onClick={fleetPdf} disabled={!fleet.devices.length}><FileText /> Fleet PDF</button>
          <button type="button" className="btn btn--primary" onClick={rerun} disabled={!fleet.devices.length}><RefreshCw /> Run audit</button>
        </>
      }
    >
      <div className="pipeline" aria-label="Audit pipeline">
        <Link href="/ingest" className="stage"><span className="stage__dot" aria-hidden="true" /><span className="stage__k">1 · Ingest</span><span className="stage__v">{fleet.devices.length}<small> files</small></span><span className="stage__s">{fleet.meaningfulLines.toLocaleString()} configuration lines</span></Link>
        <Link href="/devices" className="stage"><span className="stage__dot" aria-hidden="true" /><span className="stage__k">2 · Detect</span><span className="stage__v">{families}<small> families</small></span><span className="stage__s">{avgConfidence}% mean signature confidence{unknownVendor > 0 && <> · <i>{unknownVendor} unknown vendor{unknownVendor > 1 ? "s" : ""}</i></>}</span></Link>
        <Link href="/training" className="stage"><span className="stage__dot" aria-hidden="true" /><span className="stage__k">3 · Normalise</span><span className="stage__v">{fleet.paramsExtracted}<small> params</small></span><span className="stage__s">{fleet.unrecognized > 0 ? <><i>{fleet.unrecognized}</i> lines awaiting training</> : "every line understood"}</span></Link>
        <Link href="/findings" className="stage"><span className="stage__dot" aria-hidden="true" /><span className="stage__k">4 · Evaluate</span><span className="stage__v">{assessed}<small> checks</small></span><span className="stage__s"><b>{fleet.summary.fail} failed</b> · {fleet.summary.warning} not assessed</span></Link>
        <Link href="/reports" className="stage"><span className="stage__dot" aria-hidden="true" /><span className="stage__k">5 · Report</span><span className="stage__v">{fleet.devices.length}<small> reports</small></span><span className="stage__s">PDF · CSV · JSON · evidence bundle</span></Link>
      </div>

      <div className="grid">
        <Section className="span-4" id="ov-score" title="Compliance score" sub="Severity-weighted share of passed controls" box>
          <Gauge score={fleet.score} assessable={fleet.summary.assessable} coverage={fleet.summary.coverage} bySeverity={fleet.summary.bySeverity} label="Fleet score" sub={fleet.summary.accepted > 0 ? <>Adjusted for {fleet.summary.accepted} accepted risk{fleet.summary.accepted > 1 ? "s" : ""}: <strong>{fleet.adjustedScore}</strong></> : `${fleet.summary.coverage}% of applicable controls had evidence`} />
          <div className="kv small" style={{ marginTop: 16, gridTemplateColumns: "1fr auto" }}>
            <span className="muted">Passed</span><strong className="num right" style={{ color: "var(--pass)" }}>{fleet.summary.pass}</strong>
            <span className="muted">Failed</span><strong className="num right" style={{ color: "var(--fail)" }}>{fleet.summary.fail}</strong>
            <span className="muted">Not assessed</span><strong className="num right" style={{ color: "var(--warn)" }}>{fleet.summary.warning}</strong>
            <span className="muted">Not applicable</span><strong className="num right muted">{fleet.summary.na}</strong>
          </div>
          <div style={{ marginTop: 16 }}>
            <div className="eyebrow" style={{ marginBottom: 6 }}>Trend · {scans.length} audit runs</div>
            <Sparkline points={scans.map((s) => s.score)} />
          </div>
        </Section>
        <Section className="span-4" id="ov-sev" title="Failed controls by severity" sub="Open findings across assessable devices" box>
          <Bars rows={SEVERITY_ORDER.map((s) => ({ label: <span className={`sev sev--${s}`}><i />{s[0].toUpperCase() + s.slice(1)}</span>, value: fleet.summary.bySeverity[s], max: Math.max(1, ...SEVERITY_ORDER.map((x) => fleet.summary.bySeverity[x])), color: SEV_COLOR[s] }))} />
          <div className="small muted" style={{ marginTop: 14 }}>Weights: critical 10 · high 6 · medium 3 · low 1. Accepted risks stay in these counts but leave the adjusted score.</div>
        </Section>
        <Section className="span-4" id="ov-worst" title="Devices needing attention first" sub="Ranked by weighted risk of failed controls" box flush>
          {worst.length ? (
            <div className="table-wrap"><table className="table table--hover">
              <tbody>
                {worst.map((d) => (
                  <tr key={d.record.id} onClick={() => navigate(`/devices/${d.record.id}`)}>
                    <td><Link href={`/devices/${d.record.id}`} className="rowlink">{d.name}</Link><div className="small muted"><Vendor vendor={d.vendor} /></div></td>
                    <td className="right num nowrap"><strong style={{ color: d.summary.fail ? "var(--fail)" : undefined }}>{d.summary.fail}</strong> <span className="muted small">failed</span></td>
                    <td className="right num small muted nowrap">{d.summary.bySeverity.critical}c / {d.summary.bySeverity.high}h</td>
                    <td style={{ width: 120 }}><ScoreCell score={d.summary.score} assessable={d.assessable} /></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          ) : (
            <div className="empty">No assessable device yet.</div>
          )}
        </Section>
      </div>

      <Section id="ov-devices" title="Devices" sub="Sort any column · open a row for identity, baseline model, evidence, drift and the report" box flush>
        <div className="table-wrap">
          <table className="table table--hover">
            <thead>
              <tr>
                <SortTh label="Device" k="name" sort={sort} onSort={toggle} />
                <SortTh label="Vendor / OS" k="vendor" sort={sort} onSort={toggle} />
                <SortTh label="Version" k="version" sort={sort} onSort={toggle} />
                <SortTh label="Role" k="role" sort={sort} onSort={toggle} />
                <SortTh label="Score" k="score" sort={sort} onSort={toggle} style={{ minWidth: 150 }} />
                <SortTh label="Failed" k="fail" sort={sort} onSort={toggle} align="right" />
                <SortTh label="Crit / High" k="crit" sort={sort} onSort={toggle} align="right" />
                <SortTh label="Coverage" k="coverage" sort={sort} onSort={toggle} align="right" />
                <SortTh label="Ingested" k="ingested" sort={sort} onSort={toggle} />
              </tr>
            </thead>
            <tbody>
              {sorted.map((d) => (
                <tr key={d.record.id} onClick={() => navigate(`/devices/${d.record.id}`)}>
                  <td><Link href={`/devices/${d.record.id}`} className="rowlink">{d.name}</Link><div className="small muted mono">{d.record.fileName}</div></td>
                  <td><Vendor vendor={d.vendor} label={`${d.parse.identity.vendorName} ${d.parse.identity.os}`} /></td>
                  <td className="mono small">{d.parse.identity.osVersion ?? <span className="muted">—</span>}</td>
                  <td className="dim">{d.parse.identity.role ?? "—"}</td>
                  <td><ScoreCell score={d.summary.score} assessable={d.assessable} /></td>
                  <td className="right num" style={{ color: d.summary.fail ? "var(--fail)" : undefined, fontWeight: 600 }}>{d.assessable ? d.summary.fail : <span className="muted" style={{ fontWeight: 400 }}>—</span>}</td>
                  <td className="right num dim">{d.assessable ? `${d.summary.bySeverity.critical} / ${d.summary.bySeverity.high}` : "—"}</td>
                  <td className="right num dim" title="Applicable controls with evidence either way">{d.coverage}%</td>
                  <td className="dim nowrap">{relTime(d.record.ingestedAt)}</td>
                </tr>
              ))}
              {!fleet.devices.length && <tr><td colSpan={9} className="muted" style={{ textAlign: "center", padding: 30 }}>No devices yet — <Link href="/ingest">ingest a configuration</Link>.</td></tr>}
            </tbody>
          </table>
        </div>
      </Section>

      <div className="grid">
        <Section className="span-8" id="ov-heat" title="Control families by device" sub="Failed of assessed controls per family; colour follows the pass rate" box>
          <div className="table-wrap">
            <div className="heat" style={{ gridTemplateColumns: `150px repeat(${SBM_CATEGORIES.length}, minmax(0, 1fr))` }} role="table" aria-label="Failed controls per family and device">
              <div />
              {SBM_CATEGORIES.map((c) => <div key={c} className="heat__col" title={c}>{CATEGORY_SHORT[c]}</div>)}
              {heat.map(({ device, cells }) => (
                <div key={device.record.id} style={{ display: "contents" }}>
                  <div className="heat__label" title={device.name}><Link href={`/devices/${device.record.id}`} className="rowlink" style={{ fontWeight: 500 }}>{device.name}</Link></div>
                  {cells.map((v, i) => (
                    <div key={i} className="heat__cell" title={v === null ? `${SBM_CATEGORIES[i]}: no assessed control` : `${SBM_CATEGORIES[i]}: ${v.fail} of ${v.total} failed`} style={{ background: heatColor(v === null ? null : v.rate), color: v === null ? "var(--faint)" : undefined }}>
                      {v === null ? "·" : `${v.fail}/${v.total}`}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 12 }}><HeatLegend /></div>
        </Section>
        <Section className="span-4" id="ov-activity" title="Activity" sub="Audit trail of engine and administrator actions" box>
          <div className="activity" style={{ maxHeight: 460, overflowY: "auto" }}>
            {activity.slice(0, 14).map((a) => (
              <div key={a.id} className="activity__row">
                <span className="activity__dot" style={{ background: a.actor === "admin" ? "var(--accent)" : a.actor === "engine" ? "var(--info)" : "var(--ai)" }} aria-hidden="true" />
                <div>
                  <div className="row between"><strong>{a.action}</strong><span className="small faint nowrap">{relTime(a.at)}</span></div>
                  <div className="small muted">{a.target}</div>
                  {a.detail && <div className="small faint" style={{ marginTop: 2 }}>{a.detail}</div>}
                </div>
              </div>
            ))}
            {!activity.length && <div className="empty">No activity yet.</div>}
          </div>
        </Section>
      </div>
    </Page>
  );
}
