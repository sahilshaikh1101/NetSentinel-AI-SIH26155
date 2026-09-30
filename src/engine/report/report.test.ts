import { describe, expect, it } from "vitest";
import { buildDevicePdf, buildFleetPdf } from "./pdf";
import { deviceJson, findingsCsv } from "./exports";
import { fleetRemediationBundle, remediationBundle } from "./remediation-bundle";
import { buildEvidenceBundle } from "./evidence-bundle";
import JSZip from "jszip";
import { buildFleet } from "../fleet";
import { RULES } from "../rules/library";
import { DEFAULT_REMEDIATION_SETTINGS } from "../rules/remediation";
import { SAMPLES } from "../samples";
import { VENDOR_META } from "../sbm";
import { detectVendor } from "../detect";
import { sha256Bytes, sha256Sync } from "../../lib/hash";
import type { DeviceRecord, FrameworkId } from "../types";

const frameworks: FrameworkId[] = ["cis", "nist", "stig", "iso"];
const records: DeviceRecord[] = SAMPLES.filter((s) => s.seed).map((s, i) => ({ id: `dev-${s.id}`, fileName: s.fileName, ingestedAt: new Date(1758400000000 + i * 1000).toISOString(), raw: s.raw, sha256: sha256Sync(s.raw), detection: detectVendor(s.raw), sample: true }));
const meta = { organisation: "Example Corp", operator: "netops@example.in", frameworks };


/** Minimal RFC 4180 reader so the test validates the quoting, not just the text. */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n") { row.push(cell); rows.push(row); row = []; cell = ""; }
    else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows;
}

describe("report generation", () => {
  const fleet = buildFleet(records, [], RULES, frameworks, DEFAULT_REMEDIATION_SETTINGS);

  it("builds a device PDF for every sample vendor", () => {
    for (const view of fleet.devices) {
      const pdf = buildDevicePdf(view, meta).output("arraybuffer");
      expect(pdf.byteLength).toBeGreaterThan(3000);
    }
  });

  it("builds the fleet PDF over the whole sample fleet", () => {
    expect(buildFleetPdf(fleet, meta).output("arraybuffer").byteLength).toBeGreaterThan(5000);
    expect(fleet.assessableDevices).toBeLessThan(fleet.devices.length);
    // a fleet with no framework selected must still produce a document
    expect(buildFleetPdf(fleet, { ...meta, frameworks: [] }).output("arraybuffer").byteLength).toBeGreaterThan(5000);
  });

  it("never scores a device the parser did not understand", () => {
    const untrained = fleet.devices.find((d) => !d.assessable);
    expect(untrained).toBeDefined();
    expect(untrained!.summary.assessed).toBe(0);
    expect(buildDevicePdf(untrained!, meta).output("arraybuffer").byteLength).toBeGreaterThan(3000);
  });

  it("exports CSV and JSON with one row per finding and the evidence attached", () => {
    const csv = findingsCsv(fleet);
    const rows = parseCsv(csv);
    expect(rows).toHaveLength(fleet.findings.length + 1);
    expect(rows[0][0]).toBe("Device");
    expect(rows.every((r) => r.length === rows[0].length)).toBe(true);
    const remediationCol = rows[0].indexOf("Remediation");
    expect(rows.slice(1).some((r) => r[remediationCol].includes("\n"))).toBe(true);
    const json = JSON.parse(deviceJson(fleet.devices[0]));
    expect(json.device).toHaveProperty("identity");
    expect(json.device.sha256).toHaveLength(64);
    expect(json.findings).toHaveLength(fleet.devices[0].findings.length);
    expect(Object.keys(json.securityBaselineModel).length).toBeGreaterThan(10);
    expect(json.summary).toHaveProperty("coverage");
  });

  it("orders the fleet remediation plan by weighted risk", () => {
    const plan = fleetRemediationBundle(fleet.devices, meta);
    const order = [...plan.matchAll(/^#\s+\d+\. (\S+) —/gm)].map((m) => m[1]);
    const expected = [...fleet.devices].filter((d) => d.summary.fail > 0).sort((a, b) => b.risk - a.risk).map((d) => d.name);
    expect(order).toEqual(expected);
    for (const name of expected) expect(plan).toContain(name);
    expect(fleetRemediationBundle([], meta)).toContain("No failed controls");
  });

  it("packs a tamper-evident evidence bundle whose manifest matches the files", async () => {
    const blob = await buildEvidenceBundle(fleet, fleet.devices.slice(0, 2), meta);
    const zip = await JSZip.loadAsync(await blob.arrayBuffer());
    const names = Object.keys(zip.files);
    expect(names).toContain("MANIFEST.json");
    expect(names).toContain("MANIFEST.sha256");
    const manifest = JSON.parse(await zip.file("MANIFEST.json")!.async("string"));
    const entries: { path: string; sha256: string }[] = manifest.files ?? manifest;
    expect(entries.length).toBeGreaterThan(4);
    for (const e of entries) {
      expect(names).toContain(e.path);
      expect(e.sha256).toHaveLength(64);
    }
    const digest = await zip.file("MANIFEST.sha256")!.async("string");
    for (const e of entries) expect(digest).toContain(`${e.sha256}  ${e.path}`);
    // the digests must actually match the packed bytes
    const sample = entries.find((e) => e.path.endsWith(".json"))!;
    const bytes = await zip.file(sample.path)!.async("uint8array");
    expect(sha256Bytes(bytes)).toBe(sample.sha256);
  });

  it("writes a reviewable remediation script with the vendor's own comment marker", () => {
    for (const view of fleet.devices.filter((d) => d.summary.fail > 0)) {
      const script = remediationBundle(view, meta);
      const marker = VENDOR_META[view.vendor].comment;
      expect(script.startsWith(`${marker} =`)).toBe(true);
      expect(script).toContain("REVIEW BEFORE APPLYING");
      expect(script).not.toMatch(/\{\{/);
    }
  });
});
