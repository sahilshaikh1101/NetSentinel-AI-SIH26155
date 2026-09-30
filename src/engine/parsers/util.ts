import type { DeviceIdentity, Evidence, ParamObservation, ParamValue, SecurityBaselineModel, UnrecognizedLine, VendorId } from "../types";
import { SBM_INDEX, VENDOR_META } from "../sbm";

export interface Line {
  /** 1-based */
  n: number;
  raw: string;
  /** trimmed */
  text: string;
  indent: number;
}

export function toLines(raw: string): Line[] {
  return raw.replace(/\r\n?/g, "\n").split("\n").map((rawLine, i) => {
    const text = rawLine.trim();
    const indent = rawLine.length - rawLine.replace(/^\s+/, "").length;
    return { n: i + 1, raw: rawLine, text, indent };
  });
}

export function isBlank(l: Line): boolean {
  return l.text.length === 0;
}

/** Tree node for indentation-structured CLIs (IOS, EOS, VRP). */
export interface Node {
  line: Line;
  children: Node[];
  parent?: Node;
}

export function buildIndentTree(lines: Line[], isCommentOrBlank: (l: Line) => boolean): Node[] {
  const roots: Node[] = [];
  const stack: Node[] = [];
  for (const line of lines) {
    if (isCommentOrBlank(line)) {
      // IOS uses "!" as a block separator; reset nesting.
      if ((line.text === "!" || line.text === "#") && line.indent === 0) stack.length = 0;
      continue;
    }
    const node: Node = { line, children: [] };
    while (stack.length && stack[stack.length - 1].line.indent >= line.indent) stack.pop();
    if (stack.length) {
      node.parent = stack[stack.length - 1];
      node.parent.children.push(node);
    } else {
      roots.push(node);
    }
    stack.push(node);
  }
  return roots;
}

export function pathOf(node: Node): string {
  const parts: string[] = [];
  let cur: Node | undefined = node.parent;
  while (cur) {
    parts.unshift(cur.line.text);
    cur = cur.parent;
  }
  return parts.join(" > ");
}

/**
 * Accumulates SBM observations and tracks which source lines were understood.
 */
export class ModelBuilder {
  params: Record<string, ParamObservation> = {};
  recognized = new Set<number>();
  identity: DeviceIdentity;
  mappingsApplied: string[] = [];

  constructor(public vendor: VendorId) {
    const meta = VENDOR_META[vendor];
    this.identity = { vendor, vendorName: meta.name, os: meta.os, role: meta.role };
  }

  mark(line: Line | number): void {
    this.recognized.add(typeof line === "number" ? line : line.n);
  }

  has(key: string): boolean {
    return key in this.params;
  }

  get(key: string): ParamValue | undefined {
    return this.params[key]?.value;
  }

  private ev(line?: Line | Evidence): Evidence[] {
    if (!line) return [];
    if ("n" in line) return [{ line: line.n, text: line.text }];
    return [line];
  }

  /** Set a scalar parameter (later evidence appended; value overwritten). */
  set(key: string, value: ParamValue, line?: Line | Evidence, source: ParamObservation["source"] = "parser"): void {
    const existing = this.params[key];
    if (existing && existing.source !== "default") {
      existing.value = value;
      existing.evidence.push(...this.ev(line));
      existing.source = source;
    } else {
      this.params[key] = { key, value, evidence: this.ev(line), source };
    }
    if (line && "n" in line) this.mark(line);
  }

  /** Set only if not already observed by the parser (defaults / weak evidence). */
  setDefault(key: string, value: ParamValue, note: string): void {
    if (!this.params[key]) this.params[key] = { key, value, evidence: [{ line: 0, text: note }], source: "default" };
  }

  /** Boolean helper: once true stays true unless force. */
  setTrue(key: string, line?: Line | Evidence): void {
    this.set(key, true, line);
  }

  setFalse(key: string, line?: Line | Evidence): void {
    this.set(key, false, line);
  }

  /** Append to a list parameter, de-duplicated. */
  add(key: string, item: string, line?: Line | Evidence, source: ParamObservation["source"] = "parser"): void {
    const existing = this.params[key];
    if (existing && Array.isArray(existing.value) && existing.source !== "default") {
      if (!existing.value.includes(item)) existing.value.push(item);
      existing.evidence.push(...this.ev(line));
    } else {
      this.params[key] = { key, value: [item], evidence: this.ev(line), source };
    }
    if (line && "n" in line) this.mark(line);
  }

  /** Increment a numeric counter parameter. */
  inc(key: string, line?: Line | Evidence, by = 1): void {
    const existing = this.params[key];
    if (existing && typeof existing.value === "number" && existing.source !== "default") {
      existing.value += by;
      existing.evidence.push(...this.ev(line));
    } else {
      this.params[key] = { key, value: by, evidence: this.ev(line), source: "parser" };
    }
    if (line && "n" in line) this.mark(line);
  }

  /** Keep the maximum numeric value seen (e.g. worst timeout across lines). */
  max(key: string, value: number, line?: Line | Evidence): void {
    const existing = this.params[key];
    if (existing && typeof existing.value === "number" && existing.source !== "default") {
      existing.value = Math.max(existing.value, value);
      existing.evidence.push(...this.ev(line));
    } else {
      this.set(key, value, line);
    }
    if (line && "n" in line) this.mark(line);
  }

  model(): SecurityBaselineModel {
    // Ensure list params are lists, number params numbers.
    for (const p of Object.values(this.params)) {
      const def = SBM_INDEX[p.key];
      if (!def) continue;
      if (def.type === "list" && !Array.isArray(p.value)) p.value = [String(p.value)];
    }
    return { params: this.params };
  }

  unrecognized(lines: Line[], isCommentOrBlank: (l: Line) => boolean, contextOf?: (l: Line) => string | undefined): UnrecognizedLine[] {
    const out: UnrecognizedLine[] = [];
    for (const l of lines) {
      if (isCommentOrBlank(l) || this.recognized.has(l.n)) continue;
      out.push({ line: l.n, text: l.text, context: contextOf?.(l) });
    }
    return out;
  }
}

/** Try a list of regexes in priority order; first capture wins. */
export function firstOf(raw: string, patterns: RegExp[], group = 1): string | undefined {
  for (const re of patterns) {
    const v = first(raw, re, group);
    if (v) return v;
  }
  return undefined;
}

/** First regex match group across the raw text (multiline). */
export function first(raw: string, re: RegExp, group = 1): string | undefined {
  const m = raw.match(re);
  return m?.[group]?.trim();
}

export const IPV4 = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;
export const IP_ANY = /\b((?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})\b/i;

export function toMinutes(minutes: string, seconds?: string): number {
  const m = parseInt(minutes, 10) || 0;
  const s = parseInt(seconds ?? "0", 10) || 0;
  const total = m + s / 60;
  // 0 0 means "never" on IOS-style CLIs
  return total === 0 ? 9999 : Math.round(total * 100) / 100;
}

export function unquote(s: string): string {
  return s.replace(/^["']|["']$/g, "");
}

/** Detects weak/legacy cipher names inside an algorithm list. */
export function hasWeakCipher(text: string): boolean {
  return /\b(3des|des-cbc|arcfour|rc4|blowfish|cast128|md5|sha1|aes\d+-cbc|hmac-sha1\b|diffie-hellman-group1|diffie-hellman-group14-sha1|group1|group2|dh-group1|modp1024|modp768)\b/i.test(text);
}

/** Shared prefix table: mark lines as understood-but-not-security-relevant. */
export function markKnownPrefixes(builder: ModelBuilder, lines: Line[], prefixes: (string | RegExp)[]): void {
  for (const l of lines) {
    if (builder.recognized.has(l.n) || !l.text) continue;
    const t = l.text;
    for (const p of prefixes) {
      if (typeof p === "string" ? t.startsWith(p) : p.test(t)) {
        builder.mark(l);
        break;
      }
    }
  }
}
