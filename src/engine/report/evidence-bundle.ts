import JSZip from "jszip";
import type { DeviceView, FleetView } from "../fleet";
import { buildDevicePdf, buildFleetPdf, type ReportMeta } from "./pdf";
import { deviceJson, findingsCsv } from "./exports";
import { remediationBundle } from "./remediation-bundle";
import { sha256Bytes, sha256Hex } from "../../lib/hash";

/**
 * Tamper-evident evidence bundle: every artefact of the audit plus a manifest
 * of SHA-256 digests, so a reviewer can verify nothing changed after export.
 */
export async function buildEvidenceBundle(fleet: FleetView, views: DeviceView[], meta: ReportMeta): Promise<Blob> {
  const zip = new JSZip();
  const manifest: { path: string; sha256: string; bytes: number }[] = [];
  const add = async (path: string, data: string | ArrayBuffer) => {
    const text = typeof data === "string" ? data : undefined;
    const bytes = typeof data === "string" ? new TextEncoder().encode(data).length : data.byteLength;
    const digest = text !== undefined ? await sha256Hex(text) : await digestBuffer(data as ArrayBuffer);
    manifest.push({ path, sha256: digest, bytes });
    zip.file(path, data);
  };
  for (const v of views) {
    const dir = `devices/${safe(v.name)}`;
    await add(`${dir}/config.${extOf(v.record.fileName)}`, v.record.raw);
    await add(`${dir}/audit.json`, deviceJson(v));
    await add(`${dir}/findings.csv`, findingsCsv(fleet, v.record.id));
    await add(`${dir}/remediation.txt`, remediationBundle(v, { organisation: meta.organisation, operator: meta.operator }));
    await add(`${dir}/report.pdf`, buildDevicePdf(v, meta).output("arraybuffer"));
  }
  await add("fleet-summary.pdf", buildFleetPdf(fleet, meta).output("arraybuffer"));
  await add("fleet-findings.csv", findingsCsv(fleet));
  const manifestText = JSON.stringify(
    {
      generator: "NetSentinel AI 2.0",
      generatedAt: (meta.generatedAt ?? new Date()).toISOString(),
      organisation: meta.organisation,
      operator: meta.operator,
      frameworks: meta.frameworks,
      devices: views.map((v) => ({ name: v.name, file: v.record.fileName, sha256: v.record.sha256, score: v.summary.score, failed: v.summary.fail })),
      files: manifest,
    },
    null,
    2,
  );
  zip.file("MANIFEST.json", manifestText);
  // A plain checksum list so a reviewer can run `sha256sum -c MANIFEST.sha256` on the unpacked bundle.
  const lines = [...manifest.map((m) => `${m.sha256}  ${m.path}`), `${await sha256Hex(manifestText)}  MANIFEST.json`];
  zip.file("MANIFEST.sha256", `${lines.join("\n")}\n`);
  return zip.generateAsync({ type: "blob", compression: "DEFLATE" });
}

async function digestBuffer(buf: ArrayBuffer): Promise<string> {
  try {
    if (globalThis.crypto?.subtle) {
      const d = await globalThis.crypto.subtle.digest("SHA-256", buf);
      return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
  } catch {
    /* fall through */
  }
  return sha256Bytes(new Uint8Array(buf));
}

function safe(s: string): string {
  return s.replace(/[^\w.-]+/g, "_");
}

function extOf(name: string): string {
  const m = name.match(/\.([a-z0-9]+)$/i);
  return m ? m[1] : "txt";
}
