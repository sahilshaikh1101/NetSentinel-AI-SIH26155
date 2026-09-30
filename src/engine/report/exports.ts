import type { DeviceView, FleetView } from "../fleet";
import type { Mapping } from "../types";
import { FRAMEWORKS } from "../rules/library";

function csvCell(v: unknown): string {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function findingsCsv(fleet: FleetView, deviceId?: string): string {
  const rows = [["Device", "Site", "Vendor", "Control", "Title", "Category", "Severity", "Status", "Risk accepted", "Triage", "Owner", "Due", "Observed", "Expected", "Evidence lines", "References", "Remediation"]];
  for (const d of fleet.devices) {
    if (deviceId && d.record.id !== deviceId) continue;
    for (const f of d.findings) {
      rows.push([
        d.name,
        d.record.site ?? "",
        d.vendor,
        f.ruleId,
        f.title,
        f.category,
        f.severity,
        f.status,
        f.exception ? `${f.exception.reason}${f.exception.expires ? ` (until ${f.exception.expires})` : ""}${f.exception.ticket ? ` [${f.exception.ticket}]` : ""}` : "",
        f.triage?.state ?? "",
        f.triage?.owner ?? "",
        f.triage?.due ?? "",
        f.observed,
        f.expected,
        f.evidence.map((e) => (e.line ? `L${e.line}` : "default")).join(" "),
        f.refs.map((r) => `${FRAMEWORKS[r.framework].short} ${r.id}`).join("; "),
        f.remediation,
      ]);
    }
  }
  return rows.map((r) => r.map(csvCell).join(",")).join("\n");
}

export function deviceJson(view: DeviceView): string {
  return JSON.stringify(
    {
      generator: "NetSentinel AI 2.0",
      generatedAt: new Date().toISOString(),
      device: { id: view.record.id, fileName: view.record.fileName, sha256: view.record.sha256, vendor: view.vendor, detection: view.record.detection, identity: view.parse.identity },
      securityBaselineModel: view.parse.model.params,
      parse: { totalLines: view.parse.totalLines, meaningfulLines: view.parse.meaningfulLines, recognized: view.parse.recognized, unrecognized: view.parse.unrecognized, mappingsApplied: view.parse.mappingsApplied },
      summary: view.summary,
      findings: view.findings,
    },
    null,
    2,
  );
}

export function mappingPack(mappings: Mapping[], name = "NetSentinel mapping pack"): string {
  return JSON.stringify({ format: "netsentinel-mapping-pack", version: 1, name, exportedAt: new Date().toISOString(), mappings }, null, 2);
}

export function parseMappingPack(text: string): Mapping[] {
  const data = JSON.parse(text);
  const list = Array.isArray(data) ? data : data?.mappings;
  if (!Array.isArray(list)) throw new Error("Not a mapping pack: expected an array of mappings.");
  return list as Mapping[];
}
