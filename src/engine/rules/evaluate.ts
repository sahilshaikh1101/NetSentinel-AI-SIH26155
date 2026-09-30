import type { Evidence, EvaluationSummary, Finding, FrameworkId, ParamObservation, ParamValue, Rule, RuleCheck, RuleCondition, SecurityBaselineModel, Severity, Status, VendorId } from "../types";
import { formatValue, paramLabel, SBM_INDEX, VENDOR_META } from "../sbm";
import { renderRemediation, type RemediationContext, type RemediationSettings } from "./remediation";

export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 10, high: 6, medium: 3, low: 1 };
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

type CondResult = { status: Status; params: string[] };

/**
 * How much the parser understood of this device.
 * `assessable`: enough for the score to mean anything at all.
 * `thorough`: nearly every line was understood, so "no such command is present"
 * really is evidence of absence rather than a gap in the parser.
 */
export interface EvalContext {
  assessable: boolean;
  thorough: boolean;
}

function asContext(v: boolean | EvalContext): EvalContext {
  return typeof v === "boolean" ? { assessable: v, thorough: v } : v;
}

/** Did the parser observe anything at all in this parameter's family? */
function areaCovered(model: SecurityBaselineModel, param: string): boolean {
  const prefix = `${param.split(".")[0]}.`;
  for (const [key, obs] of Object.entries(model.params)) {
    if (obs.source !== "default" && key.startsWith(prefix)) return true;
  }
  return false;
}

function num(v: ParamValue | undefined): number | undefined {
  if (typeof v === "number") return v;
  if (typeof v === "string" && /^-?\d+(\.\d+)?$/.test(v)) return parseFloat(v);
  return undefined;
}

/**
 * `assessable` is false when the parser understood too little of the file to
 * claim that anything is absent: then "not observed" means "not assessed",
 * never "not configured".
 */
function evalCondition(c: RuleCondition, model: SecurityBaselineModel, ctx: EvalContext): CondResult {
  const { assessable } = ctx;
  // On a device the parser barely understood, platform defaults are not evidence either.
  const stored = model.params[c.param];
  const obs = !assessable && stored?.source === "default" ? undefined : stored;
  const v = obs?.value;
  const params = [c.param];
  const ok = (b: boolean): CondResult => ({ status: b ? "pass" : "fail", params });
  if (obs === undefined && !assessable) return { status: "warning", params };
  switch (c.op) {
    case "exists":
      return ok(obs !== undefined);
    case "notExists":
      // "the bad thing is absent" is only evidence when the parser read the whole
      // configuration, or at least understood something else in the same family.
      if (obs !== undefined) return ok(false);
      return ctx.thorough || areaCovered(model, c.param) ? ok(true) : { status: "warning", params };
    default:
      break;
  }
  if (obs === undefined) return { status: "warning", params };
  switch (c.op) {
    case "eq":
      if (typeof c.value === "string" && typeof v === "string") return ok(v.toLowerCase() === c.value.toLowerCase());
      return ok(v === c.value);
    case "neq":
      if (typeof c.value === "string" && typeof v === "string") return ok(v.toLowerCase() !== c.value.toLowerCase());
      return ok(v !== c.value);
    case "gte": {
      const n = num(v);
      return n === undefined ? { status: "warning", params } : ok(n >= Number(c.value));
    }
    case "lte": {
      const n = num(v);
      return n === undefined ? { status: "warning", params } : ok(n <= Number(c.value));
    }
    case "in": {
      const set = Array.isArray(c.value) ? c.value.map((x) => String(x).toLowerCase()) : [];
      return ok(Array.isArray(v) ? v.some((x) => set.includes(String(x).toLowerCase())) : set.includes(String(v).toLowerCase()));
    }
    case "notIn": {
      const set = Array.isArray(c.value) ? c.value.map((x) => String(x).toLowerCase()) : [];
      return ok(Array.isArray(v) ? !v.some((x) => set.includes(String(x).toLowerCase())) : !set.includes(String(v).toLowerCase()));
    }
    case "includes":
      return ok(Array.isArray(v) && v.includes(String(c.value)));
    case "excludes":
      return ok(!Array.isArray(v) || !v.includes(String(c.value)));
    case "empty":
      return ok(Array.isArray(v) ? v.length === 0 : v === "" || v === 0 || v === false);
    case "notEmpty":
      // false and 0 are not "not empty": a polarity mapping on a list parameter must not pass the rule.
      return ok(Array.isArray(v) ? v.length > 0 : typeof v === "string" ? v !== "" : typeof v === "number" ? v > 0 : v === true);
    case "countGte": {
      const n = Array.isArray(v) ? v.length : num(v);
      return n === undefined ? { status: "warning", params } : ok(n >= Number(c.value));
    }
    case "countLte": {
      const n = Array.isArray(v) ? v.length : num(v);
      return n === undefined ? { status: "warning", params } : ok(n <= Number(c.value));
    }
    case "regex":
      try {
        return ok(new RegExp(String(c.value), "i").test(String(v)));
      } catch {
        return { status: "warning", params };
      }
    default:
      return { status: "warning", params };
  }
}

export function evalCheck(check: RuleCheck, model: SecurityBaselineModel, assessable: boolean | EvalContext = true): CondResult {
  const ctx = asContext(assessable);
  if ("all" in check) {
    const results = check.all.map((c) => ("all" in c || "any" in c ? evalCheck(c, model, ctx) : evalCondition(c, model, ctx)));
    const params = results.flatMap((r) => r.params);
    if (results.some((r) => r.status === "fail")) return { status: "fail", params };
    if (results.some((r) => r.status === "warning")) return { status: "warning", params };
    return { status: "pass", params };
  }
  if ("any" in check) {
    const results = check.any.map((c) => ("all" in c || "any" in c ? evalCheck(c, model, ctx) : evalCondition(c, model, ctx)));
    const params = results.flatMap((r) => r.params);
    if (results.some((r) => r.status === "pass")) return { status: "pass", params };
    if (results.some((r) => r.status === "warning")) return { status: "warning", params };
    return { status: "fail", params };
  }
  return evalCondition(check, model, ctx);
}

export interface EvaluateOptions {
  frameworks: FrameworkId[];
  settings: RemediationSettings;
  /** include rules that have no reference in the selected frameworks */
  includeUnmapped?: boolean;
  /** false for barely-parsed devices: absence cannot be claimed */
  assessable?: boolean;
  /** recognised / meaningful lines — when high, an absent command is evidence of absence */
  recognitionRatio?: number;
  context?: RemediationContext;
}

function observedText(params: string[], model: SecurityBaselineModel): string {
  const uniq = Array.from(new Set(params));
  const parts = uniq.map((p) => {
    const obs = model.params[p];
    const label = paramLabel(p);
    if (!obs) return `${label}: not observed`;
    const suffix = obs.source === "default" ? " (platform default)" : obs.source === "mapping" ? " (learned mapping)" : "";
    return `${label}: ${formatValue(obs.value)}${suffix}`;
  });
  return parts.join(" · ");
}

function evidenceOf(params: string[], model: SecurityBaselineModel): Evidence[] {
  const out: Evidence[] = [];
  const seen = new Set<string>();
  for (const p of Array.from(new Set(params))) {
    const obs: ParamObservation | undefined = model.params[p];
    if (!obs) continue;
    for (const e of obs.evidence) {
      const k = `${e.line}:${e.text}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(e);
    }
  }
  return out.sort((a, b) => a.line - b.line).slice(0, 12);
}

export function evaluateDevice(deviceId: string, model: SecurityBaselineModel, vendor: VendorId, rules: Rule[], opts: EvaluateOptions): Finding[] {
  const findings: Finding[] = [];
  const assessable = opts.assessable ?? true;
  const ctx: EvalContext = { assessable, thorough: opts.recognitionRatio !== undefined ? opts.recognitionRatio >= 0.9 : assessable };
  const vendorName = `${VENDOR_META[vendor].name} ${VENDOR_META[vendor].os}`;
  for (const rule of rules) {
    if (rule.enabled === false) continue;
    const frameworksHit = rule.refs.filter((r) => opts.frameworks.includes(r.framework)).map((r) => r.framework);
    const frameworks = Array.from(new Set(frameworksHit));
    if (!frameworks.length && !opts.includeUnmapped && opts.frameworks.length) continue;
    let status: Status;
    let params: string[] = [];
    // A generic (learned) device is evaluated on every control: the parameter either has
    // evidence (pass/fail) or it does not (not assessed). Otherwise training could never
    // unlock a vendor-scoped control.
    if (rule.appliesTo && vendor !== "generic" && !rule.appliesTo.includes(vendor)) {
      status = "na";
    } else {
      const r = evalCheck(rule.check, model, ctx);
      status = r.status;
      params = r.params;
    }
    let remediation = status === "fail" || status === "warning" ? renderRemediation(rule, vendor, model, opts.settings, opts.context) : "";
    if (status === "warning" && remediation) {
      remediation = `${VENDOR_META[vendor].comment} VERIFY FIRST: this control could not be assessed from the configuration. Confirm the current state on the device before applying anything below.
${remediation}`;
    }
    findings.push({
      id: `${deviceId}::${rule.id}`,
      deviceId,
      ruleId: rule.id,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      status,
      observed: status === "na" ? `Not applicable to ${vendorName}` : observedText(params, model),
      expected: rule.expected,
      evidence: status === "na" ? [] : evidenceOf(params, model),
      rationale: rule.description,
      remediation,
      remediationNote: rule.remediationNote,
      refs: rule.refs.filter((r) => !opts.frameworks.length || opts.frameworks.includes(r.framework)),
      frameworks,
    });
  }
  return findings;
}

export function summarize(findings: Finding[], assessable = true): EvaluationSummary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let pass = 0, fail = 0, warning = 0, na = 0;
  let wPass = 0, wTotal = 0;
  for (const f of findings) {
    if (f.status === "pass") { pass++; wPass += SEVERITY_WEIGHT[f.severity]; wTotal += SEVERITY_WEIGHT[f.severity]; }
    else if (f.status === "fail") { fail++; bySeverity[f.severity]++; wTotal += SEVERITY_WEIGHT[f.severity]; }
    else if (f.status === "warning") warning++;
    else na++;
  }
  const assessed = pass + fail;
  const applicable = findings.length - na;
  const score = wTotal === 0 ? 0 : Math.round((wPass / wTotal) * 100);
  return { score, pass, fail, warning, na, bySeverity, assessed, total: findings.length, coverage: applicable === 0 ? 0 : Math.round((assessed / applicable) * 100), assessable: assessable && assessed > 0 };
}

export interface ScoreContext {
  /** share of applicable controls that had evidence either way */
  coverage?: number;
  bySeverity?: Record<Severity, number>;
}

/**
 * The label is deliberately stricter than the number: a score computed from a
 * handful of assessed controls, or one that leaves a critical finding open,
 * must never read as "Hardened".
 */
export function scoreLabel(score: number, assessable = true, ctx: ScoreContext = {}): { label: string; tone: "good" | "warn" | "bad" | "none" } {
  if (!assessable) return { label: "Not assessed", tone: "none" };
  if (ctx.coverage !== undefined && ctx.coverage < 50) return { label: "Partially assessed", tone: "warn" };
  if (score < 65) return { label: "At risk", tone: "bad" };
  const critical = ctx.bySeverity?.critical ?? 0;
  const high = ctx.bySeverity?.high ?? 0;
  if (score >= 85 && critical === 0 && high === 0) return { label: "Hardened", tone: "good" };
  return { label: "Needs attention", tone: "warn" };
}

export function riskPoints(findings: Finding[]): number {
  return findings.filter((f) => f.status === "fail").reduce((s, f) => s + SEVERITY_WEIGHT[f.severity], 0);
}

export { SBM_INDEX };
