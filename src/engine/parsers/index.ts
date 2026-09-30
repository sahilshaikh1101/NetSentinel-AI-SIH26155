import type { Mapping, ParseResult, VendorId } from "../types";
import { detectVendor } from "../detect";
import { applyMappings } from "../mappings";
import { parseAristaEos, parseCiscoIos, parseCiscoNxos } from "./cisco-ios";
import { parseFortiOS } from "./fortios";
import { parseGeneric } from "./generic";
import { parseJunos } from "./junos";
import { parsePanOS } from "./panos";
import { parseRouterOS } from "./routeros";
import { parseVRP } from "./vrp";

/** Parser registry — a new vendor is one more entry here. */
export const PARSERS: Record<VendorId, (raw: string) => ParseResult> = {
  "cisco-ios": parseCiscoIos,
  "cisco-nxos": parseCiscoNxos,
  "arista-eos": parseAristaEos,
  "juniper-junos": parseJunos,
  "fortinet-fortios": parseFortiOS,
  "paloalto-panos": parsePanOS,
  "mikrotik-routeros": parseRouterOS,
  "huawei-vrp": parseVRP,
  generic: parseGeneric,
};

export function parseConfig(raw: string, vendor: VendorId, mappings: Mapping[] = []): { result: ParseResult; hits: Record<string, number> } {
  const base = PARSERS[vendor](raw);
  return applyMappings(base, mappings);
}

export function detectAndParse(raw: string, mappings: Mapping[] = [], override?: VendorId) {
  const detection = detectVendor(raw);
  const vendor = override ?? detection.vendor;
  const { result, hits } = parseConfig(raw, vendor, mappings);
  return { detection, result, hits };
}

export { detectVendor };
