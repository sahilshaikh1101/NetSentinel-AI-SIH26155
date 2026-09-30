import type { Mapping, ParamObservation, ParamValue, ParseResult, ValueMode, VendorId } from "./types";
import { SBM_INDEX } from "./sbm";
import type { ParamType } from "./sbm";

/**
 * Whole-token state words. ACL verbs (deny / drop / reject) are *actions*, not
 * state: "deny ip any any log" proves an explicit logged deny EXISTS, and
 * "ip access-list extended NO-TELNET" says nothing about polarity.
 */
const NEGATION_WORDS = new Set(["disable", "disabled", "off", "false", "no", "undo", "shutdown", "never", "none"]);

function countNegations(text: string): number {
  let n = 0;
  for (const raw of String(text).split(/\s+/)) {
    const tok = raw.replace(/^[^\w=-]+|[^\w=-]+$/g, "").toLowerCase();
    if (!tok) continue;
    const eq = tok.match(/^([\w-]+)=(.+)$/);
    if (eq) {
      // "disabled=yes" is one negation, "disabled=no" is two (i.e. enabled).
      if (NEGATION_WORDS.has(eq[1])) n++;
      if (NEGATION_WORDS.has(eq[2])) n++;
      continue;
    }
    if (NEGATION_WORDS.has(tok)) n++;
  }
  return n;
}

const hasStateWord = (text: string): boolean => countNegations(text) > 0 || /(^|\s)(enable|enabled|yes|on|true|permit|allow)(\s|$)/i.test(text);

/**
 * Even number of negation words = enabled ("no shutdown" = enabled).
 * When the mapping's regex captured the state word, pass it as `group`: the
 * polarity is then read from "off" rather than from an unrelated "autodst off"
 * elsewhere on the line.
 */
export function polarityOf(text: string, group?: string): boolean {
  const subject = group && group.trim() && hasStateWord(group) ? group : text;
  return countNegations(subject) % 2 === 0;
}

export function compileMapping(m: Mapping): RegExp | null {
  try {
    // "g"/"y" make String.match return whole matches instead of capture groups.
    return new RegExp(m.pattern, (m.flags || "i").replace(/[gy]/g, ""));
  } catch {
    return null;
  }
}

/** Which value modes can legally feed which SBM parameter type. */
const MODES_BY_TYPE: Record<ParamType, ValueMode[]> = {
  boolean: ["polarity", "flag", "const", "capture"],
  number: ["capture", "count", "const"],
  string: ["capture", "const"],
  list: ["list", "const"],
};

export function modeFitsType(param: string, mode: ValueMode): boolean {
  const type = SBM_INDEX[param]?.type;
  if (!type) return true;
  return MODES_BY_TYPE[type].includes(mode);
}

/** How many capture groups a pattern declares (0 when it is a plain literal). */
export function captureGroupCount(pattern: string, flags?: string): number {
  try {
    return new RegExp(`${pattern}|`, (flags || "i").replace(/[gy]/g, "")).exec("")!.length - 1;
  } catch {
    return 0;
  }
}

function fitsType(value: ParamValue | undefined, type: ParamType | undefined): boolean {
  if (value === undefined) return false;
  if (!type) return true;
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  if (type === "boolean") return typeof value === "boolean";
  if (type === "list") return Array.isArray(value) || typeof value === "string";
  return typeof value === "string" || typeof value === "number";
}

function transformValue(raw: string, transform: Mapping["transform"], paramKey: string): ParamValue | undefined {
  const t = transform ?? (SBM_INDEX[paramKey]?.type === "number" ? "number" : SBM_INDEX[paramKey]?.type === "boolean" ? "boolean" : "string");
  if (t === "number") {
    // Strict: "10.10.50.10" is an address, not the number 10.1. "v2"/"tls1.2" are versions.
    const m = raw.trim().match(/^v?(\d+(?:\.\d+)?)$/i);
    return m ? Number(m[1]) : undefined;
  }
  if (t === "boolean") return polarityOf(raw) && !/^(0|false|no|disable|disabled|off)$/i.test(raw.trim());
  return raw.replace(/^["']|["']$/g, "");
}

function warn(m: Mapping, line: number, why: string): void {
  if (typeof console !== "undefined") console.warn(`[mapping ${m.id} -> ${m.param}] skipped line ${line}: ${why}`);
}

function upsert(params: Record<string, ParamObservation>, key: string, value: ParamValue, line: number, text: string, mappingId: string): void {
  const existing = params[key];
  const ev = { line, text };
  if (existing && existing.source !== "default") {
    existing.value = value;
    existing.evidence.push(ev);
    existing.source = "mapping";
    existing.mappingId = mappingId;
  } else {
    params[key] = { key, value, evidence: [ev], source: "mapping", mappingId };
  }
}

/**
 * Applies learned mappings to the lines a parser did not understand.
 * Returns a new ParseResult and the hit-count per mapping id.
 * A mapping whose captured value does not fit the parameter type is skipped
 * (with a console warning) rather than storing a boolean in a number field.
 */
export function applyMappings(result: ParseResult, mappings: Mapping[]): { result: ParseResult; hits: Record<string, number> } {
  const applicable = mappings
    .filter((m) => m.vendor === "any" || m.vendor === result.vendor)
    .map((m) => ({ m, re: compileMapping(m) }))
    .filter((x): x is { m: Mapping; re: RegExp } => Boolean(x.re));
  if (!applicable.length) return { result, hits: {} };

  const params: Record<string, ParamObservation> = JSON.parse(JSON.stringify(result.model.params));
  const hits: Record<string, number> = {};
  const stillUnknown = [] as ParseResult["unrecognized"];
  const applied = new Set<string>(result.mappingsApplied);

  for (const u of result.unrecognized) {
    let matched = false;
    for (const { m, re } of applicable) {
      const mm = u.text.match(re);
      if (!mm) continue;
      const group = mm[m.captureGroup ?? 1];
      const def = SBM_INDEX[m.param];
      const type = def?.type;
      let stored = true;
      switch (m.valueMode) {
        case "const": {
          const v = m.constValue ?? true;
          if (!fitsType(v, type)) { warn(m, u.line, `constant ${JSON.stringify(v)} does not fit a ${type} parameter`); stored = false; break; }
          upsert(params, m.param, v, u.line, u.text, m.id);
          break;
        }
        case "flag":
          if (type && type !== "boolean") { warn(m, u.line, `flag mode cannot fill a ${type} parameter`); stored = false; break; }
          upsert(params, m.param, true, u.line, u.text, m.id);
          break;
        case "polarity":
          if (type && type !== "boolean") { warn(m, u.line, `polarity mode cannot fill a ${type} parameter`); stored = false; break; }
          upsert(params, m.param, polarityOf(u.text, group), u.line, u.text, m.id);
          break;
        case "capture": {
          if (group === undefined || group === "") {
            if (m.constValue !== undefined && fitsType(m.constValue, type)) { upsert(params, m.param, m.constValue, u.line, u.text, m.id); break; }
            warn(m, u.line, "capture mode but the pattern captured nothing");
            stored = false;
            break;
          }
          const v = transformValue(group, m.transform, m.param);
          if (!fitsType(v, type)) { warn(m, u.line, `captured ${JSON.stringify(group)} is not a valid ${type}`); stored = false; break; }
          upsert(params, m.param, v as ParamValue, u.line, u.text, m.id);
          break;
        }
        case "list": {
          if (type && type !== "list") { warn(m, u.line, `list mode cannot fill a ${type} parameter`); stored = false; break; }
          if (group === undefined || !String(group).trim()) { warn(m, u.line, "list mode but the pattern captured nothing"); stored = false; break; }
          const item = String(transformValue(String(group), "string", m.param) ?? "").trim();
          if (!item) { warn(m, u.line, "list mode captured an empty value"); stored = false; break; }
          const existing = params[m.param];
          if (existing && Array.isArray(existing.value) && existing.source !== "default") {
            if (!existing.value.includes(item)) existing.value.push(item);
            existing.evidence.push({ line: u.line, text: u.text });
            existing.mappingId = m.id;
          } else {
            params[m.param] = { key: m.param, value: [item], evidence: [{ line: u.line, text: u.text }], source: "mapping", mappingId: m.id };
          }
          break;
        }
        case "count": {
          if (type && type !== "number") { warn(m, u.line, `count mode cannot fill a ${type} parameter`); stored = false; break; }
          const existing = params[m.param];
          if (existing && typeof existing.value === "number" && existing.source !== "default") {
            existing.value += 1;
            existing.evidence.push({ line: u.line, text: u.text });
          } else {
            params[m.param] = { key: m.param, value: 1, evidence: [{ line: u.line, text: u.text }], source: "mapping", mappingId: m.id };
          }
          break;
        }
      }
      if (!stored) continue;
      matched = true;
      hits[m.id] = (hits[m.id] ?? 0) + 1;
      applied.add(m.id);
      if (type === "list" && params[m.param] && !Array.isArray(params[m.param].value)) params[m.param].value = [String(params[m.param].value)];
    }
    if (!matched) stillUnknown.push(u);
  }
  const recognized = result.meaningfulLines - stillUnknown.length;
  return {
    result: { ...result, model: { params }, unrecognized: stillUnknown, recognized, mappingsApplied: Array.from(applied) },
    hits,
  };
}

export function testMapping(pattern: string, flags: string | undefined, lines: { line: number; text: string }[]): { line: number; text: string; groups: string[] }[] {
  let re: RegExp;
  try {
    re = new RegExp(pattern, (flags || "i").replace(/[gy]/g, ""));
  } catch {
    return [];
  }
  const out: { line: number; text: string; groups: string[] }[] = [];
  for (const l of lines) {
    const m = l.text.match(re);
    if (m) out.push({ line: l.line, text: l.text, groups: m.slice(1).map((g) => g ?? "") });
  }
  return out;
}

export const vendorLabelForMapping = (v: VendorId | "any") => (v === "any" ? "All vendors" : v);
