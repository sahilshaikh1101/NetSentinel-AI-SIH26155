/**
 * NetSentinel AI — core engine types.
 *
 * Pipeline:  raw config text -> detect vendor -> parse into the vendor-neutral
 *            Security Baseline Model (SBM) -> evaluate against framework rule packs
 *            -> findings + remediation -> PDF / CSV / JSON reports.
 *
 * Everything here is plain data so rule packs, vendor signatures and learned
 * mappings can be added at runtime without code changes.
 */

export type VendorId =
  | "cisco-ios"
  | "cisco-nxos"
  | "arista-eos"
  | "juniper-junos"
  | "fortinet-fortios"
  | "paloalto-panos"
  | "mikrotik-routeros"
  | "huawei-vrp"
  | "generic";

export type ParamValue = string | number | boolean | string[];

export interface Evidence {
  /** 1-based line number in the source configuration */
  line: number;
  text: string;
}

export interface ParamObservation {
  key: string;
  value: ParamValue;
  evidence: Evidence[];
  /** who produced the observation */
  source: "parser" | "default" | "mapping" | "llm";
  mappingId?: string;
}

/** The vendor-neutral Security Baseline Model. */
export interface SecurityBaselineModel {
  params: Record<string, ParamObservation>;
}

export interface DeviceIdentity {
  hostname?: string;
  vendor: VendorId;
  vendorName: string;
  os: string;
  osVersion?: string;
  model?: string;
  serial?: string;
  mgmtIp?: string;
  /** e.g. "router", "switch", "firewall" — heuristic */
  role?: string;
  extra?: Record<string, string>;
}

export interface DetectionResult {
  vendor: VendorId;
  confidence: number; // 0..1
  reasons: string[];
  scores: Partial<Record<VendorId, number>>;
}

export interface UnrecognizedLine {
  line: number;
  text: string;
  /** parent block / section path, when the format is hierarchical */
  context?: string;
}

export interface ParseResult {
  vendor: VendorId;
  identity: DeviceIdentity;
  model: SecurityBaselineModel;
  totalLines: number;
  /** non-blank, non-comment lines */
  meaningfulLines: number;
  /** meaningful lines the parser or a learned mapping understood */
  recognized: number;
  unrecognized: UnrecognizedLine[];
  /** mapping ids that fired during this parse */
  mappingsApplied: string[];
}

export type ValueMode = "const" | "capture" | "polarity" | "list" | "count" | "flag";

/** A learned, low-code mapping from a raw command pattern to an SBM parameter. */
export interface Mapping {
  id: string;
  name: string;
  vendor: VendorId | "any";
  /** JavaScript regular-expression source, tested against a trimmed line */
  pattern: string;
  flags?: string;
  param: string;
  valueMode: ValueMode;
  constValue?: ParamValue;
  captureGroup?: number;
  transform?: "string" | "number" | "boolean";
  createdAt: string;
  createdBy: "admin" | "classifier" | "llm" | "seed";
  sampleLine?: string;
  hits: number;
}

export type Severity = "critical" | "high" | "medium" | "low";
export type FrameworkId = "cis" | "nist" | "stig" | "iso";

export interface FrameworkRef {
  framework: FrameworkId;
  id: string;
  title?: string;
}

export type Operator =
  | "eq"
  | "neq"
  | "gte"
  | "lte"
  | "in"
  | "notIn"
  | "includes"
  | "excludes"
  | "exists"
  | "notExists"
  | "empty"
  | "notEmpty"
  | "countGte"
  | "countLte"
  | "regex";

export interface RuleCondition {
  param: string;
  op: Operator;
  value?: ParamValue;
}

export type RuleCheckNode = RuleCondition | { all: RuleCheckNode[] } | { any: RuleCheckNode[] };
export type RuleCheck = RuleCheckNode;

export type ControlCategory =
  | "Management Plane"
  | "Authentication & AAA"
  | "Logging & Audit"
  | "Time Synchronization"
  | "SNMP"
  | "Unnecessary Services"
  | "Routing Security"
  | "Access Control"
  | "Cryptography"
  | "Device Identity";

export interface Rule {
  id: string;
  title: string;
  category: ControlCategory;
  severity: Severity;
  /** why the control matters (rationale) */
  description: string;
  /** human readable expected state */
  expected: string;
  check: RuleCheck;
  refs: FrameworkRef[];
  /** restrict to vendor families; omitted = all */
  appliesTo?: VendorId[];
  /** remediation CLI templates by vendor family; {{placeholders}} resolved at render time */
  remediation: Partial<Record<VendorId, string>>;
  remediationNote?: string;
  custom?: boolean;
  enabled?: boolean;
}

export type Status = "pass" | "fail" | "warning" | "na";

export interface Finding {
  id: string;
  deviceId: string;
  ruleId: string;
  title: string;
  category: ControlCategory;
  severity: Severity;
  status: Status;
  observed: string;
  expected: string;
  evidence: Evidence[];
  rationale: string;
  remediation: string;
  remediationNote?: string;
  refs: FrameworkRef[];
  frameworks: FrameworkId[];
}

export interface Suggestion {
  param: string;
  confidence: number; // 0..1
  valueMode: ValueMode;
  constValue?: ParamValue;
  captureGroup?: number;
  transform?: "string" | "number" | "boolean";
  pattern: string;
  reasons: string[];
  extractedValue?: ParamValue;
  /** false when the proposal had to guess the value (no real candidate on the line). */
  extractionValid?: boolean;
  source: "classifier" | "llm";
}

export interface DeviceRecord {
  id: string;
  fileName: string;
  ingestedAt: string;
  raw: string;
  sha256: string;
  detection: DetectionResult;
  /** manual vendor override chosen by the admin */
  vendorOverride?: VendorId;
  sample?: boolean;
  site?: string;
  tags?: string[];
  owner?: string;
}

export interface EvaluationSummary {
  score: number;
  pass: number;
  fail: number;
  warning: number;
  na: number;
  bySeverity: Record<Severity, number>;
  assessed: number;
  total: number;
  /** assessed / (total - na): how much of the applicable library had evidence */
  coverage: number;
  /** false when too little of the configuration was understood for the score to mean anything */
  assessable: boolean;
}
