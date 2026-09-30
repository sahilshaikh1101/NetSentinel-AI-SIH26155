import type { EvaluationSummary, Finding, Severity } from "./types";
import { SEVERITY_WEIGHT } from "./rules/evaluate";

/**
 * Risk acceptance ("exceptions") and triage state for findings.
 * Keyed by `${hostname or device id}::${ruleId}` so an acceptance survives a
 * re-upload of the same device.
 */
export interface RiskException {
  key: string;
  ruleId: string;
  deviceKey: string;
  reason: string;
  by: string;
  at: string;
  expires?: string;
  ticket?: string;
}

export type TriageState = "open" | "in-progress" | "remediated" | "accepted";

export interface Triage {
  key: string;
  state: TriageState;
  owner?: string;
  due?: string;
  note?: string;
  updatedAt: string;
}

export function findingKey(deviceKey: string, ruleId: string): string {
  return `${deviceKey}::${ruleId}`;
}

export function isActive(e: RiskException, now = Date.now()): boolean {
  return !e.expires || new Date(e.expires).getTime() > now;
}

export interface TriagedFinding extends Finding {
  exception?: RiskException;
  triage?: Triage;
}

export function applyTriage(findings: Finding[], deviceKey: string, exceptions: Record<string, RiskException>, triage: Record<string, Triage>): TriagedFinding[] {
  return findings.map((f) => {
    const key = findingKey(deviceKey, f.ruleId);
    const ex = exceptions[key];
    const t = triage[key];
    return { ...f, exception: ex && isActive(ex) ? ex : undefined, triage: t };
  });
}

export interface AdjustedSummary extends EvaluationSummary {
  accepted: number;
  adjustedScore: number;
  inProgress: number;
}

/** Summary that treats actively accepted risks as neither pass nor fail for the adjusted score. */
export function summarizeTriaged(findings: TriagedFinding[]): AdjustedSummary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let pass = 0, fail = 0, warning = 0, na = 0, accepted = 0, inProgress = 0;
  let wPass = 0, wTotal = 0, wPassAdj = 0, wTotalAdj = 0;
  for (const f of findings) {
    const w = SEVERITY_WEIGHT[f.severity];
    if (f.status === "pass") { pass++; wPass += w; wTotal += w; wPassAdj += w; wTotalAdj += w; }
    else if (f.status === "fail") {
      fail++; bySeverity[f.severity]++; wTotal += w;
      if (f.exception) accepted++;
      else wTotalAdj += w;
      if (f.triage?.state === "in-progress") inProgress++;
    } else if (f.status === "warning") warning++;
    else na++;
  }
  const assessed = pass + fail;
  const applicable = findings.length - na;
  return {
    score: wTotal === 0 ? 0 : Math.round((wPass / wTotal) * 100),
    adjustedScore: wTotalAdj === 0 ? 0 : Math.round((wPassAdj / wTotalAdj) * 100),
    pass, fail, warning, na, bySeverity, accepted, inProgress,
    assessed,
    total: findings.length,
    coverage: applicable === 0 ? 0 : Math.round((assessed / applicable) * 100),
    assessable: assessed > 0,
  };
}
