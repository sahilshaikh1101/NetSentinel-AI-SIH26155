import type { ParseResult } from "../types";
import { first, ModelBuilder, toLines, type Line } from "./util";

const isCommentOrBlank = (l: Line) => !l.text || /^(#|!|\/\/|;|\/\*|\*)/.test(l.text) || l.text === "{" || l.text === "}" || l.text === "}," || l.text === "]" || l.text === "],";

/** Flatten JSON into "path = value" virtual lines, mapping each leaf back to a source line number. */
export function flattenJson(raw: string): { text: string; line: number }[] | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  const src = raw.replace(/\r\n?/g, "\n").split("\n");
  const out: { text: string; line: number }[] = [];
  let cursor = 0;
  const findLine = (key: string, value: unknown): number => {
    const needle = `"${key}"`;
    for (let i = cursor; i < src.length; i++) {
      if (src[i].includes(needle)) {
        cursor = i;
        return i + 1;
      }
    }
    // maybe an array element without key
    const v = JSON.stringify(value);
    for (let i = cursor; i < src.length; i++) if (src[i].includes(v)) { cursor = i; return i + 1; }
    return cursor + 1;
  };
  const walk = (node: unknown, path: string[], lastKey: string) => {
    if (Array.isArray(node)) {
      node.forEach((item, i) => {
        if (item !== null && typeof item === "object") walk(item, [...path, `${lastKey}[${i}]`].slice(1), `${lastKey}[${i}]`);
        else out.push({ text: `${[...path].join(" ")} = ${String(item)}`, line: findLine(lastKey, item) });
      });
      return;
    }
    if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (v !== null && typeof v === "object") {
          const isLeafArray = Array.isArray(v) && v.every((x) => x === null || typeof x !== "object");
          if (isLeafArray) {
            out.push({ text: `${[...path, k].join(" ")} = ${(v as unknown[]).map(String).join(",")}`, line: findLine(k, v) });
          } else {
            walk(v, [...path, k], k);
          }
        } else {
          out.push({ text: `${[...path, k].join(" ")} = ${String(v)}`, line: findLine(k, v) });
        }
      }
    }
  };
  walk(data, [], "");
  return out;
}

/** Flatten XML into "path text" virtual lines. */
export function flattenXml(raw: string): { text: string; line: number }[] {
  const out: { text: string; line: number }[] = [];
  const stack: string[] = [];
  const re = /<\/?([\w:.-]+)([^>]*?)(\/?)>|<!--[\s\S]*?-->|<\?[\s\S]*?\?>|([^<]+)/g;
  let m: RegExpExecArray | null;
  let lastText = "";
  const lineAt = (idx: number) => raw.slice(0, idx).split("\n").length;
  let lastTextIdx = 0;
  while ((m = re.exec(raw))) {
    if (m[0].startsWith("<!--") || m[0].startsWith("<?")) continue;
    if (m[4] !== undefined) {
      lastText = m[4].trim();
      lastTextIdx = m.index;
      continue;
    }
    const tag = m[1];
    const attrs = m[2] ?? "";
    const isClose = m[0].startsWith("</");
    const selfClose = m[3] === "/";
    if (isClose) {
      if (lastText) {
        out.push({ text: `${stack.join(" ")} ${lastText}`.trim(), line: lineAt(lastTextIdx) });
        lastText = "";
      }
      stack.pop();
      continue;
    }
    const name = attrs.match(/name="([^"]*)"/);
    const seg = name ? `${tag} ${name[1]}` : tag;
    if (selfClose) {
      out.push({ text: `${[...stack, seg].join(" ")}`, line: lineAt(m.index) });
      continue;
    }
    stack.push(seg);
    lastText = "";
  }
  return out;
}

/**
 * Generic parser for unknown vendors. It understands nothing by itself:
 * every meaningful line goes to the Training Studio unless a learned
 * mapping claims it. Structured (JSON/XML) inputs are flattened first.
 */
export function parseGeneric(raw: string): ParseResult {
  const trimmed = raw.trimStart();
  const b = new ModelBuilder("generic");
  const id = b.identity;
  id.hostname =
    first(raw, /^\s*(?:hostname|host-name|sysname|system-name|set system name|configure snmp sysname|configure snmp sysName|set hostname|name)\s+"?([\w.-]+)"?/mi) ??
    first(raw, /"(?:hostname|host_name|device_name|name)"\s*:\s*"([^"]+)"/i);
  id.osVersion = first(raw, /\b(?:version|Version|software version|sw-version|image)\s*[:=]?\s*"?v?([\d]+\.[\d.]+[\w.-]*)/) ?? undefined;
  id.model = first(raw, /\b(?:model|platform|product|chassis)\s*[:=]\s*"?([\w./-]+)/i);
  id.serial = first(raw, /\b(?:serial(?:[-_ ]?number)?|sn|s\/n)\s*[:=]\s*"?([\w-]{5,})/i);
  id.mgmtIp =
    trimmed.startsWith("{") || trimmed.startsWith("[")
      ? undefined
      : (first(raw, /\b(?:ipaddress|ip address|address)\s+(\d{1,3}(?:\.\d{1,3}){3})(?!\/0)/i) ??
        first(raw, /\b(\d{1,3}(?:\.\d{1,3}){3})\/(?:[12]\d|3[0-2]|[1-9])\b/) ??
        first(raw, /\b((?!0\.0\.0\.0)\d{1,3}(?:\.\d{1,3}){3})\b/));
  if (/EXOS|ExtremeXOS|Extreme Networks/i.test(raw)) { id.vendorName = "Extreme Networks"; id.os = "EXOS"; id.role = "switch"; }
  else if (/VyOS|EdgeOS|vyatta/i.test(raw)) { id.vendorName = "VyOS / Ubiquiti"; id.os = "VyOS"; id.role = "router"; }
  else if (/SONiC|sonic-cfggen|config_db/i.test(raw)) { id.vendorName = "SONiC (white box)"; id.os = "SONiC"; id.role = "switch"; }
  else if (/Cumulus|nclu|nv set/i.test(raw)) { id.vendorName = "NVIDIA Cumulus"; id.os = "Cumulus Linux"; id.role = "switch"; }
  else if (/"GroupId"|"IpPermissions"|SecurityGroup/i.test(raw)) { id.vendorName = "AWS"; id.os = "VPC Security Group"; id.role = "cloud firewall"; }
  else if (/TiMOS|Nokia|Alcatel/i.test(raw)) { id.vendorName = "Nokia"; id.os = "SR OS"; id.role = "router"; }
  else if (/aruba|ArubaOS|AOS-CX/i.test(raw)) { id.vendorName = "HPE Aruba"; id.os = "AOS-CX"; id.role = "switch"; }
  else if (/sonicwall|SonicOS/i.test(raw)) { id.vendorName = "SonicWall"; id.os = "SonicOS"; id.role = "firewall"; }
  else if (/checkpoint|Check Point|Gaia/i.test(raw)) { id.vendorName = "Check Point"; id.os = "Gaia"; id.role = "firewall"; }

  let lines: Line[];
  let virtual: { text: string; line: number }[] | null = null;
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) virtual = flattenJson(raw);
  else if (trimmed.startsWith("<")) virtual = flattenXml(raw);
  if (virtual) {
    lines = virtual.map((v, i) => ({ n: v.line, raw: v.text, text: v.text, indent: 0 }));
    // de-duplicate identical line numbers by offsetting nothing: evidence may point to the same source line — acceptable
    const meaningful = lines.filter((l) => l.text);
    return {
      vendor: "generic",
      identity: id,
      model: b.model(),
      totalLines: raw.split("\n").length,
      meaningfulLines: meaningful.length,
      recognized: 0,
      unrecognized: meaningful.map((l) => ({ line: l.n, text: l.text })),
      mappingsApplied: [],
    };
  }
  lines = toLines(raw);
  const meaningful = lines.filter((l) => !isCommentOrBlank(l));
  return {
    vendor: "generic",
    identity: id,
    model: b.model(),
    totalLines: lines.length,
    meaningfulLines: meaningful.length,
    recognized: 0,
    unrecognized: meaningful.map((l) => ({ line: l.n, text: l.text })),
    mappingsApplied: [],
  };
}
