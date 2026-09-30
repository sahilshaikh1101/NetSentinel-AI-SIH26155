import type { Finding, ParamObservation, SecurityBaselineModel } from "./types";
import { formatValue, paramLabel } from "./sbm";

/**
 * Configuration drift: line-level diff between two configurations plus the
 * semantic delta of the normalised model and the findings.
 */
export type DiffOp = { kind: "same" | "add" | "del"; text: string; a?: number; b?: number };

function trimCommon(a: string[], b: string[]): { prefix: number; suffix: number } {
  let prefix = 0;
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) prefix++;
  let suffix = 0;
  while (suffix < a.length - prefix && suffix < b.length - prefix && a[a.length - 1 - suffix] === b[b.length - 1 - suffix]) suffix++;
  return { prefix, suffix };
}

/** Line diff (LCS). Blank/whitespace differences are ignored for matching but original text is kept. */
export function diffLines(oldText: string, newText: string): DiffOp[] {
  const a = oldText.replace(/\r\n?/g, "\n").split("\n");
  const b = newText.replace(/\r\n?/g, "\n").split("\n");
  const na = a.map((l) => l.trim());
  const nb = b.map((l) => l.trim());
  const { prefix, suffix } = trimCommon(na, nb);
  const ops: DiffOp[] = [];
  for (let i = 0; i < prefix; i++) ops.push({ kind: "same", text: a[i], a: i + 1, b: i + 1 });
  const ma = na.slice(prefix, na.length - suffix);
  const mb = nb.slice(prefix, nb.length - suffix);
  const n = ma.length, m = mb.length;
  if (n * m > 4_000_000) {
    // very large middle: fall back to a coarse replace to stay responsive
    for (let i = 0; i < n; i++) ops.push({ kind: "del", text: a[prefix + i], a: prefix + i + 1 });
    for (let j = 0; j < m; j++) ops.push({ kind: "add", text: b[prefix + j], b: prefix + j + 1 });
  } else {
    const dp = new Uint32Array((n + 1) * (m + 1));
    const idx = (i: number, j: number) => i * (m + 1) + j;
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[idx(i, j)] = ma[i] === mb[j] ? dp[idx(i + 1, j + 1)] + 1 : Math.max(dp[idx(i + 1, j)], dp[idx(i, j + 1)]);
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (ma[i] === mb[j]) { ops.push({ kind: "same", text: a[prefix + i], a: prefix + i + 1, b: prefix + j + 1 }); i++; j++; }
      else if (dp[idx(i + 1, j)] >= dp[idx(i, j + 1)]) { ops.push({ kind: "del", text: a[prefix + i], a: prefix + i + 1 }); i++; }
      else { ops.push({ kind: "add", text: b[prefix + j], b: prefix + j + 1 }); j++; }
    }
    while (i < n) { ops.push({ kind: "del", text: a[prefix + i], a: prefix + i + 1 }); i++; }
    while (j < m) { ops.push({ kind: "add", text: b[prefix + j], b: prefix + j + 1 }); j++; }
  }
  for (let k = 0; k < suffix; k++) {
    const ai = a.length - suffix + k;
    const bi = b.length - suffix + k;
    ops.push({ kind: "same", text: a[ai], a: ai + 1, b: bi + 1 });
  }
  return ops;
}

export interface ParamDelta {
  key: string;
  label: string;
  before?: string;
  after?: string;
  kind: "added" | "removed" | "changed";
  improved?: boolean;
}

export function diffModels(before: SecurityBaselineModel, after: SecurityBaselineModel): ParamDelta[] {
  const keys = new Set([...Object.keys(before.params), ...Object.keys(after.params)]);
  const out: ParamDelta[] = [];
  const val = (p?: ParamObservation) => (p ? formatValue(p.value) : undefined);
  for (const key of Array.from(keys).sort()) {
    const b = before.params[key];
    const a = after.params[key];
    const bv = val(b), av = val(a);
    if (bv === av) continue;
    out.push({ key, label: paramLabel(key), before: bv, after: av, kind: !b ? "added" : !a ? "removed" : "changed" });
  }
  return out;
}

export interface FindingDelta {
  ruleId: string;
  title: string;
  severity: Finding["severity"];
  before: Finding["status"] | "absent";
  after: Finding["status"] | "absent";
  kind: "regressed" | "fixed" | "changed";
}

export function diffFindings(before: Finding[], after: Finding[]): FindingDelta[] {
  const byRule = (fs: Finding[]) => new Map(fs.map((f) => [f.ruleId, f]));
  const b = byRule(before), a = byRule(after);
  const out: FindingDelta[] = [];
  for (const ruleId of new Set([...b.keys(), ...a.keys()])) {
    const fb = b.get(ruleId), fa = a.get(ruleId);
    const sb = fb?.status ?? "absent", sa = fa?.status ?? "absent";
    if (sb === sa) continue;
    const f = fa ?? fb!;
    const kind: FindingDelta["kind"] = sa === "fail" ? "regressed" : sb === "fail" && sa === "pass" ? "fixed" : "changed";
    out.push({ ruleId, title: f.title, severity: f.severity, before: sb, after: sa, kind });
  }
  const order = { regressed: 0, fixed: 1, changed: 2 };
  return out.sort((x, y) => order[x.kind] - order[y.kind]);
}

export function diffStats(ops: DiffOp[]): { added: number; removed: number; unchanged: number } {
  let added = 0, removed = 0, unchanged = 0;
  for (const o of ops) { if (o.kind === "add") added++; else if (o.kind === "del") removed++; else unchanged++; }
  return { added, removed, unchanged };
}
