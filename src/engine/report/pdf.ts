import { jsPDF } from "jspdf";
import { autoTable } from "jspdf-autotable";
import { downloadBlob, type SaveOutcome } from "../../lib/util";

/** Save a built document through the host-aware download path. */
export function savePdf(doc: jsPDF, filename: string): Promise<SaveOutcome> {
  return downloadBlob(doc.output("blob"), filename);
}
import type { DeviceView, FleetView } from "../fleet";
import type { FrameworkId, Severity, Status } from "../types";
import { VENDOR_META, formatValue, paramLabel } from "../sbm";
import { FRAMEWORKS } from "../rules/library";
import { SEVERITY_ORDER, scoreLabel } from "../rules/evaluate";

export interface ReportMeta {
  organisation: string;
  operator: string;
  frameworks: FrameworkId[];
  generatedAt?: Date;
}

const INK = [17, 24, 39] as const;
const MUTED = [100, 110, 130] as const;
const STATUS_COLOR: Record<Status, readonly [number, number, number]> = {
  pass: [21, 138, 94],
  fail: [211, 59, 87],
  warning: [169, 122, 10],
  na: [130, 130, 130],
};
const SEV_COLOR: Record<Severity, readonly [number, number, number]> = {
  critical: [211, 59, 87],
  high: [217, 107, 37],
  medium: [169, 122, 10],
  low: [92, 111, 144],
};

function statusText(s: Status): string {
  return s === "pass" ? "PASS" : s === "fail" ? "FAIL" : s === "warning" ? "NOT ASSESSED" : "N/A";
}

function header(doc: jsPDF, title: string, subtitle: string, meta: ReportMeta): number {
  const w = doc.internal.pageSize.getWidth();
  doc.setFillColor(11, 15, 23);
  doc.rect(0, 0, w, 64, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("NetSentinel AI", 40, 30);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(180, 190, 210);
  doc.text("AI-driven multi-vendor network security compliance auditor", 40, 46);
  doc.setFontSize(9);
  doc.text(`${meta.organisation}`, w - 40, 30, { align: "right" });
  doc.text(`Generated ${(meta.generatedAt ?? new Date()).toLocaleString()} by ${meta.operator}`, w - 40, 44, { align: "right" });
  doc.setTextColor(...INK);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.text(title, 40, 92);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(...MUTED);
  doc.text(subtitle, 40, 108);
  doc.setTextColor(...INK);
  return 124;
}

function footer(doc: jsPDF, label: string): void {
  const pages = doc.getNumberOfPages();
  const w = doc.internal.pageSize.getWidth();
  const h = doc.internal.pageSize.getHeight();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(...MUTED);
    doc.text(`${label} · Confidential — for authorised security personnel`, 40, h - 24);
    doc.text(`Page ${i} of ${pages}`, w - 40, h - 24, { align: "right" });
  }
}

function sectionTitle(doc: jsPDF, y: number, text: string): number {
  const h = doc.internal.pageSize.getHeight();
  if (y > h - 90) {
    doc.addPage();
    y = 56;
  }
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(...INK);
  doc.text(text, 40, y);
  doc.setDrawColor(220, 224, 232);
  doc.line(40, y + 5, doc.internal.pageSize.getWidth() - 40, y + 5);
  doc.setFont("helvetica", "normal");
  return y + 16;
}

function lastY(doc: jsPDF, fallback: number): number {
  const anyDoc = doc as unknown as { lastAutoTable?: { finalY?: number } };
  return anyDoc.lastAutoTable?.finalY ?? fallback;
}

export function buildDevicePdf(view: DeviceView, meta: ReportMeta): jsPDF {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const id = view.parse.identity;
  const vm = VENDOR_META[view.vendor];
  const frameworksLabel = meta.frameworks.map((f) => FRAMEWORKS[f].short).join(" · ") || "All controls";
  let y = header(doc, `Device compliance report — ${view.name}`, `${id.vendorName} ${id.os}${id.osVersion ? ` ${id.osVersion}` : ""} · Frameworks: ${frameworksLabel}`, meta);

  // Score strip
  const s = view.summary;
  doc.setFillColor(243, 245, 249);
  doc.roundedRect(40, y, doc.internal.pageSize.getWidth() - 80, 58, 6, 6, "F");
  const label = scoreLabel(s.score, view.assessable, { coverage: view.coverage, bySeverity: s.bySeverity });
  doc.setFont("helvetica", "bold");
  doc.setFontSize(26);
  const tone = !view.assessable ? MUTED : label.tone === "good" ? STATUS_COLOR.pass : label.tone === "bad" ? STATUS_COLOR.fail : STATUS_COLOR.warning;
  doc.setTextColor(...tone);
  doc.text(view.assessable ? `${s.score}` : "—", 56, y + 34);
  doc.setFontSize(8);
  doc.text(label.label.toUpperCase(), 56, y + 45);
  doc.setFontSize(7.5);
  doc.setTextColor(...MUTED);
  doc.text(view.assessable ? `SCORE / 100 · COVERAGE ${view.coverage}%` : "PARSER UNDERSTOOD TOO LITTLE TO SCORE", 56, y + 54);
  doc.setFontSize(10);
  doc.setTextColor(...INK);
  const cols = [
    ["Pass", String(s.pass)],
    ["Fail", String(s.fail)],
    ["Accepted", String(s.accepted)],
    ["Not assessed", String(s.warning)],
    ["Not applicable", String(s.na)],
    ["Critical", String(s.bySeverity.critical)],
    ["High", String(s.bySeverity.high)],
    ["Medium", String(s.bySeverity.medium)],
  ];
  cols.forEach(([k, v], i) => {
    const x = 196 + i * 44;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text(v, x, y + 30);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(...MUTED);
    doc.text(k.toUpperCase(), x, y + 44);
    doc.setTextColor(...INK);
  });
  y += 76;

  // Identification
  y = sectionTitle(doc, y, "1. Device identification");
  autoTable(doc, {
    startY: y,
    theme: "grid",
    styles: { fontSize: 9, cellPadding: 4, textColor: [17, 24, 39] },
    headStyles: { fillColor: [235, 238, 244], textColor: [17, 24, 39], fontStyle: "bold" },
    columnStyles: { 0: { cellWidth: 150, fontStyle: "bold" } },
    body: [
      ["Hostname", id.hostname ?? "—"],
      ["Vendor / OS", `${id.vendorName} ${id.os}`],
      ["Software version", id.osVersion ?? "not present in configuration"],
      ["Hardware model", id.model ?? "not present in configuration"],
      ["Serial number", id.serial ?? "not present in configuration"],
      ["Management address", id.mgmtIp ?? "—"],
      ["Device role", id.role ?? "—"],
      ["Source file", view.record.fileName],
      ["Configuration SHA-256", view.record.sha256],
      ["Ingested", new Date(view.record.ingestedAt).toLocaleString()],
      ["Parser", `${vm.short} parser · ${view.parse.recognized}/${view.parse.meaningfulLines} lines understood · ${view.parse.mappingsApplied.length} learned mappings applied`],
      ["Vendor detection", `${Math.round(view.record.detection.confidence * 100)}% — ${view.record.detection.reasons.slice(0, 3).join("; ")}`],
    ],
    margin: { left: 40, right: 40 },
  });
  y = lastY(doc, y) + 18;

  // Findings summary
  y = sectionTitle(doc, y, "2. Compliance findings");
  const ordered = [...view.findings].sort((a, b) => {
    const st = (x: Status) => (x === "fail" ? 0 : x === "warning" ? 1 : x === "pass" ? 2 : 3);
    return st(a.status) - st(b.status) || SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  });
  autoTable(doc, {
    startY: y,
    theme: "striped",
    styles: { fontSize: 8, cellPadding: 3.5, textColor: [17, 24, 39], overflow: "linebreak" },
    headStyles: { fillColor: [11, 15, 23], textColor: [255, 255, 255] },
    columnStyles: { 0: { cellWidth: 62 }, 1: { cellWidth: 150 }, 2: { cellWidth: 50 }, 3: { cellWidth: 58 }, 4: { cellWidth: "auto" } },
    head: [["Control", "Title", "Severity", "Result", "References"]],
    body: ordered.map((f) => [f.ruleId, f.title, f.severity.toUpperCase(), f.exception ? `${statusText(f.status)} (ACCEPTED)` : statusText(f.status), f.refs.map((r) => `${FRAMEWORKS[r.framework].short} ${r.id}`).join(", ")]),
    didParseCell: (data) => {
      if (data.section !== "body") return;
      const f = ordered[data.row.index];
      if (data.column.index === 3) {
        data.cell.styles.textColor = [...STATUS_COLOR[f.status]];
        data.cell.styles.fontStyle = "bold";
      }
      if (data.column.index === 2) data.cell.styles.textColor = [...SEV_COLOR[f.severity]];
    },
    margin: { left: 40, right: 40 },
  });
  y = lastY(doc, y) + 18;

  // Detailed findings with remediation
  const failed = ordered.filter((f) => f.status === "fail");
  y = sectionTitle(doc, y, `3. Remediation paths (${failed.length} failed controls)`);
  const w = doc.internal.pageSize.getWidth() - 80;
  const h = doc.internal.pageSize.getHeight();
  for (const f of failed) {
    const rem = doc.splitTextToSize(f.remediation || "Refer to vendor hardening guide.", w - 16);
    const rationale = doc.splitTextToSize(f.rationale, w);
    const evidence = f.evidence.slice(0, 6).map((e) => (e.line ? `L${e.line}: ${e.text}` : e.text));
    const evLines = evidence.flatMap((e) => doc.splitTextToSize(e, w - 16));
    const needed = 60 + rationale.length * 11 + evLines.length * 10 + rem.length * 10 + 40;
    if (y + Math.min(needed, 300) > h - 60) {
      doc.addPage();
      y = 56;
    }
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10.5);
    doc.setTextColor(...INK);
    doc.text(`${f.ruleId} — ${f.title}`, 40, y);
    doc.setFontSize(8.5);
    doc.setTextColor(...SEV_COLOR[f.severity]);
    doc.text(f.severity.toUpperCase(), doc.internal.pageSize.getWidth() - 40, y, { align: "right" });
    y += 14;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(...MUTED);
    doc.text(`Observed: ${f.observed}`, 40, y, { maxWidth: w });
    y += 11 * doc.splitTextToSize(`Observed: ${f.observed}`, w).length;
    doc.text(`Expected: ${f.expected}`, 40, y, { maxWidth: w });
    y += 11 * doc.splitTextToSize(`Expected: ${f.expected}`, w).length + 2;
    if (f.exception) {
      const note = `Risk accepted by ${f.exception.by} on ${new Date(f.exception.at).toLocaleDateString()}${f.exception.expires ? ` until ${new Date(f.exception.expires).toLocaleDateString()}` : ""}${f.exception.ticket ? ` (${f.exception.ticket})` : ""}: ${f.exception.reason}`;
      const lines = doc.splitTextToSize(note, w);
      doc.setTextColor(...STATUS_COLOR.warning);
      doc.text(lines, 40, y);
      y += lines.length * 11 + 2;
      doc.setTextColor(...MUTED);
    }
    doc.setTextColor(...INK);
    doc.text(rationale, 40, y);
    y += rationale.length * 11 + 4;
    if (evLines.length) {
      doc.setFont("courier", "normal");
      doc.setFontSize(8);
      doc.setFillColor(246, 247, 250);
      doc.roundedRect(40, y - 8, w, evLines.length * 10 + 10, 3, 3, "F");
      doc.setTextColor(60, 70, 90);
      doc.text(evLines, 48, y + 2);
      y += evLines.length * 10 + 12;
    }
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(...INK);
    doc.text(`Remediation (${vm.short} CLI)`, 40, y);
    y += 10;
    if (y + rem.length * 10 > h - 60) {
      doc.addPage();
      y = 56;
    }
    doc.setFont("courier", "normal");
    doc.setFontSize(8);
    doc.setFillColor(238, 241, 247);
    doc.roundedRect(40, y - 8, w, rem.length * 10 + 10, 3, 3, "F");
    doc.setTextColor(20, 30, 50);
    doc.text(rem, 48, y + 2);
    y += rem.length * 10 + 22;
    doc.setFont("helvetica", "normal");
  }

  // Security baseline model
  y = sectionTitle(doc, y, "4. Normalised Security Baseline Model (evidence)");
  const params = Object.values(view.parse.model.params).filter((p) => p.source !== "default");
  autoTable(doc, {
    startY: y,
    theme: "striped",
    styles: { fontSize: 7.5, cellPadding: 3, textColor: [17, 24, 39], overflow: "linebreak" },
    headStyles: { fillColor: [235, 238, 244], textColor: [17, 24, 39] },
    columnStyles: { 0: { cellWidth: 150 }, 1: { cellWidth: 90 }, 2: { cellWidth: 50 }, 3: { cellWidth: "auto", font: "courier" } },
    head: [["Parameter", "Value", "Source", "Evidence"]],
    body: params.map((p) => [paramLabel(p.key), formatValue(p.value), p.source, p.evidence.slice(0, 3).map((e) => `L${e.line}: ${e.text}`).join("\n")]),
    margin: { left: 40, right: 40 },
  });

  footer(doc, `NetSentinel AI · ${view.name}`);
  return doc;
}

export function buildFleetPdf(fleet: FleetView, meta: ReportMeta): jsPDF {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const frameworksLabel = meta.frameworks.map((f) => FRAMEWORKS[f].short).join(" · ") || "All controls";
  let y = header(doc, "Fleet compliance summary", `${fleet.devices.length} devices · Frameworks: ${frameworksLabel}`, meta);
  const s = fleet.summary;
  const label = scoreLabel(fleet.score, s.assessable, { coverage: s.coverage, bySeverity: s.bySeverity });
  doc.setFont("helvetica", "bold");
  doc.setFontSize(28);
  const tone = !s.assessable ? MUTED : label.tone === "good" ? STATUS_COLOR.pass : label.tone === "bad" ? STATUS_COLOR.fail : STATUS_COLOR.warning;
  doc.setTextColor(...tone);
  doc.text(s.assessable ? `${fleet.score}` : "—", 40, y + 22);
  doc.setFontSize(8.5);
  doc.text(label.label.toUpperCase(), 40, y + 34);
  doc.setFontSize(8);
  doc.setTextColor(...MUTED);
  doc.text("FLEET SCORE / 100", 40, y + 45);
  doc.setFontSize(10);
  doc.setTextColor(...INK);
  doc.setFont("helvetica", "normal");
  doc.text(`${s.fail} failed controls (${s.bySeverity.critical} critical, ${s.bySeverity.high} high, ${s.bySeverity.medium} medium, ${s.bySeverity.low} low) · ${s.pass} passed · ${s.warning} not assessed${s.accepted ? ` · ${s.accepted} risk-accepted (adjusted score ${fleet.adjustedScore})` : ""}`, 170, y + 18, { maxWidth: 370 });
  doc.setTextColor(...MUTED);
  doc.setFontSize(8.5);
  doc.text(`${fleet.assessableDevices} of ${fleet.devices.length} devices had enough of their configuration understood to be scored; mean coverage ${s.coverage}% of applicable controls.`, 170, y + 42, { maxWidth: 370 });
  doc.setTextColor(...INK);
  y += 56;
  y = sectionTitle(doc, y, "1. Device inventory");
  autoTable(doc, {
    startY: y,
    theme: "striped",
    styles: { fontSize: 8, cellPadding: 3.5, textColor: [17, 24, 39] },
    headStyles: { fillColor: [11, 15, 23], textColor: [255, 255, 255] },
    head: [["Device", "Vendor / OS", "Version", "Model", "Serial", "Score", "Coverage", "Fail", "Critical", "High"]],
    body: fleet.devices.map((d) => [d.name, `${d.parse.identity.vendorName} ${d.parse.identity.os}`, d.parse.identity.osVersion ?? "—", d.parse.identity.model ?? "—", d.parse.identity.serial ?? "—", d.assessable ? String(d.summary.score) : "not assessed", `${d.coverage}%`, d.assessable ? String(d.summary.fail) : "—", d.assessable ? String(d.summary.bySeverity.critical) : "—", d.assessable ? String(d.summary.bySeverity.high) : "—"]),
    margin: { left: 40, right: 40 },
  });
  y = lastY(doc, y) + 18;

  // Compliance by framework — the same arithmetic the Frameworks page shows.
  y = sectionTitle(doc, y, "2. Compliance by framework");
  const perFramework = meta.frameworks.map((f) => {
    let pass = 0, fail = 0;
    for (const fd of fleet.findings) {
      if (fd.status !== "pass" && fd.status !== "fail") continue;
      if (fd.refs.some((r) => r.framework === f)) fd.status === "pass" ? pass++ : fail++;
    }
    return [FRAMEWORKS[f].name, FRAMEWORKS[f].edition, String(pass + fail), String(pass), String(fail), pass + fail ? `${Math.round((pass / (pass + fail)) * 100)}%` : "no evidence"];
  });
  autoTable(doc, {
    startY: y,
    theme: "grid",
    styles: { fontSize: 8, cellPadding: 3.5, textColor: [17, 24, 39] },
    headStyles: { fillColor: [235, 238, 244], textColor: [17, 24, 39], fontStyle: "bold" },
    head: [["Framework", "Edition", "Assessed", "Pass", "Fail", "Pass rate"]],
    body: perFramework.length ? perFramework : [["No framework selected", "—", "0", "0", "0", "—"]],
    margin: { left: 40, right: 40 },
  });
  y = lastY(doc, y) + 18;

  // Most repeated weaknesses — where fleet-wide effort pays off first.
  y = sectionTitle(doc, y, "3. Most common failures across the fleet");
  const byControl = new Map<string, { title: string; severity: Severity; devices: Set<string> }>();
  for (const f of fleet.findings) {
    if (f.status !== "fail") continue;
    const e = byControl.get(f.ruleId) ?? { title: f.title, severity: f.severity, devices: new Set<string>() };
    e.devices.add(f.deviceId);
    byControl.set(f.ruleId, e);
  }
  const top = Array.from(byControl.entries())
    .sort((a, b) => b[1].devices.size - a[1].devices.size || SEVERITY_ORDER.indexOf(a[1].severity) - SEVERITY_ORDER.indexOf(b[1].severity))
    .slice(0, 12);
  autoTable(doc, {
    startY: y,
    theme: "striped",
    styles: { fontSize: 8, cellPadding: 3.5, textColor: [17, 24, 39], overflow: "linebreak" },
    headStyles: { fillColor: [235, 238, 244], textColor: [17, 24, 39] },
    columnStyles: { 0: { cellWidth: 62 }, 1: { cellWidth: "auto" }, 2: { cellWidth: 50 }, 3: { cellWidth: 90 } },
    head: [["Control", "Title", "Severity", "Devices affected"]],
    body: top.length ? top.map(([id, e]) => [id, e.title, e.severity.toUpperCase(), `${e.devices.size} of ${fleet.assessableDevices}`]) : [["—", "No failed control across the fleet", "—", "—"]],
    didParseCell: (data) => {
      if (data.section === "body" && data.column.index === 2 && top[data.row.index]) data.cell.styles.textColor = [...SEV_COLOR[top[data.row.index][1].severity]];
    },
    margin: { left: 40, right: 40 },
  });
  y = lastY(doc, y) + 18;
  y = sectionTitle(doc, y, "4. Failed controls across the fleet");
  const failed = fleet.findings.filter((f) => f.status === "fail").sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const nameOf = (id: string) => fleet.devices.find((d) => d.record.id === id)?.name ?? id;
  autoTable(doc, {
    startY: y,
    theme: "striped",
    styles: { fontSize: 8, cellPadding: 3.5, textColor: [17, 24, 39], overflow: "linebreak" },
    headStyles: { fillColor: [235, 238, 244], textColor: [17, 24, 39] },
    columnStyles: { 0: { cellWidth: 90 }, 1: { cellWidth: 62 }, 2: { cellWidth: 160 }, 3: { cellWidth: 50 }, 4: { cellWidth: "auto" } },
    head: [["Device", "Control", "Title", "Severity", "Observed"]],
    body: failed.map((f) => [nameOf(f.deviceId), f.ruleId, f.title, f.severity.toUpperCase(), f.observed]),
    didParseCell: (data) => {
      if (data.section === "body" && data.column.index === 3) data.cell.styles.textColor = [...SEV_COLOR[failed[data.row.index].severity]];
    },
    margin: { left: 40, right: 40 },
  });
  footer(doc, "NetSentinel AI · Fleet summary");
  return doc;
}
