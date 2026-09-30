import type { DeviceRecord, Finding, FrameworkId, Mapping, ParseResult, Rule, Severity, VendorId } from "./types";
import { parseConfig } from "./parsers";
import { evaluateDevice, riskPoints, summarize } from "./rules/evaluate";
import type { RemediationSettings } from "./rules/remediation";
import { applyTriage, summarizeTriaged, type AdjustedSummary, type RiskException, type Triage, type TriagedFinding } from "./exceptions";

export interface DeviceView {
  record: DeviceRecord;
  vendor: VendorId;
  parse: ParseResult;
  findings: TriagedFinding[];
  summary: AdjustedSummary;
  risk: number;
  name: string;
  /** stable key for exceptions/triage: hostname when known, else record id */
  key: string;
  /** parser understood enough of the file for the score to mean something */
  assessable: boolean;
  coverage: number;
}

export interface FleetView {
  devices: DeviceView[];
  findings: TriagedFinding[];
  summary: AdjustedSummary;
  score: number;
  adjustedScore: number;
  paramsExtracted: number;
  unrecognized: number;
  meaningfulLines: number;
  recognizedLines: number;
  mappingHits: Record<string, number>;
  assessableDevices: number;
  bySeverity: Record<Severity, number>;
}

export interface FleetInputs {
  exceptions?: Record<string, RiskException>;
  triage?: Record<string, Triage>;
}

/** A device is assessable when the parser understood a meaningful share of it. */
export function isAssessable(parse: ParseResult): boolean {
  const observed = Object.values(parse.model.params).filter((p) => p.source !== "default").length;
  const ratio = parse.meaningfulLines ? parse.recognized / parse.meaningfulLines : 0;
  if (parse.vendor !== "generic") return ratio >= 0.25 && observed >= 3;
  return ratio >= 0.25 && observed >= 8;
}

export function buildDeviceView(record: DeviceRecord, mappings: Mapping[], rules: Rule[], frameworks: FrameworkId[], settings: RemediationSettings, inputs: FleetInputs = {}): { view: DeviceView; hits: Record<string, number> } {
  const vendor = record.vendorOverride ?? record.detection.vendor;
  const { result, hits } = parseConfig(record.raw, vendor, mappings);
  const assessable = isAssessable(result);
  const recognitionRatio = result.meaningfulLines ? result.recognized / result.meaningfulLines : 0;
  const base: Finding[] = evaluateDevice(record.id, result.model, vendor, rules, { frameworks, settings, assessable, recognitionRatio, context: { osVersion: result.identity.osVersion, hostname: result.identity.hostname } });
  const key = result.identity.hostname ?? record.id;
  const findings = applyTriage(base, key, inputs.exceptions ?? {}, inputs.triage ?? {});
  const summary = summarizeTriaged(findings);
  const s2 = summarize(base, assessable);
  summary.coverage = s2.coverage;
  summary.assessable = s2.assessable;
  const name = result.identity.hostname ?? record.fileName.replace(/\.[^.]+$/, "");
  return { view: { record, vendor, parse: result, findings, summary, risk: riskPoints(base), name, key, assessable: summary.assessable, coverage: summary.coverage }, hits };
}

export function buildFleet(records: DeviceRecord[], mappings: Mapping[], rules: Rule[], frameworks: FrameworkId[], settings: RemediationSettings, inputs: FleetInputs = {}): FleetView {
  const devices: DeviceView[] = [];
  const mappingHits: Record<string, number> = {};
  for (const r of records) {
    try {
      const { view, hits } = buildDeviceView(r, mappings, rules, frameworks, settings, inputs);
      devices.push(view);
      for (const [k, v] of Object.entries(hits)) mappingHits[k] = (mappingHits[k] ?? 0) + v;
    } catch (e) {
      // A single unparseable record must never take the fleet down.
      console.error("device build failed", r.fileName, e);
    }
  }
  const findings = devices.flatMap((d) => d.findings);
  const summary = summarizeTriaged(findings);
  // Fleet score: weighted mean of assessable device scores, weighted by assessed controls.
  let num = 0, den = 0, numAdj = 0;
  for (const d of devices) {
    if (!d.assessable) continue;
    num += d.summary.score * d.summary.assessed;
    numAdj += d.summary.adjustedScore * d.summary.assessed;
    den += d.summary.assessed;
  }
  const assessableDevices = devices.filter((d) => d.assessable).length;
  summary.assessable = assessableDevices > 0;
  summary.coverage = devices.length ? Math.round(devices.reduce((s, d) => s + d.coverage, 0) / devices.length) : 0;
  return {
    devices,
    findings,
    summary,
    score: den === 0 ? 0 : Math.round(num / den),
    adjustedScore: den === 0 ? 0 : Math.round(numAdj / den),
    paramsExtracted: devices.reduce((s, d) => s + Object.values(d.parse.model.params).filter((p) => p.source !== "default").length, 0),
    unrecognized: devices.reduce((s, d) => s + d.parse.unrecognized.length, 0),
    meaningfulLines: devices.reduce((s, d) => s + d.parse.meaningfulLines, 0),
    recognizedLines: devices.reduce((s, d) => s + d.parse.recognized, 0),
    mappingHits,
    assessableDevices,
    bySeverity: summary.bySeverity,
  };
}
