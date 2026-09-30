import type { DeviceView } from "../fleet";
import { VENDOR_META } from "../sbm";
import { SEVERITY_ORDER } from "../rules/evaluate";

const NL = String.fromCharCode(10);


/**
 * One reviewable remediation script per device: every failed control's CLI in
 * severity order, wrapped in comments that carry the control id, evidence and
 * the operator's sign-off checklist. Meant for change-management review, not
 * blind execution.
 */
export function remediationBundle(view: DeviceView, meta: { organisation: string; operator: string }): string {
  // Each vendor's own comment marker: "!" is a syntax error on Junos/FortiOS/PAN-OS/RouterOS.
  const c = VENDOR_META[view.vendor].comment;
  const id = view.parse.identity;
  const failed = [...view.findings].filter((f) => f.status === "fail").sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const lines: string[] = [];
  const hr = `${c} ${"=".repeat(70)}`;
  lines.push(hr, `${c} NetSentinel AI — remediation script`, `${c} Device   : ${view.name} (${id.vendorName} ${id.os}${id.osVersion ? ` ${id.osVersion}` : ""})`, `${c} Model    : ${id.model ?? "n/a"}   Serial: ${id.serial ?? "n/a"}   Mgmt IP: ${id.mgmtIp ?? "n/a"}`, `${c} Source   : ${view.record.fileName}   sha256 ${view.record.sha256}`, `${c} Prepared : ${new Date().toISOString()} by ${meta.operator} — ${meta.organisation}`, `${c} Controls : ${failed.length} failed of ${view.summary.assessed} assessed (score ${view.summary.score}/100)`, `${c}`, `${c} REVIEW BEFORE APPLYING. Replace <placeholders>, apply in a maintenance window,`, `${c} keep a console session open, and re-audit the saved configuration afterwards.`, hr, "");
  let n = 0;
  for (const f of failed) {
    n++;
    lines.push(`${c} ${"-".repeat(70)}`, `${c} [${n}/${failed.length}] ${f.ruleId} — ${f.title}   severity: ${f.severity.toUpperCase()}`, `${c} Observed : ${f.observed}`, `${c} Expected : ${f.expected}`);
    for (const e of f.evidence.slice(0, 4)) lines.push(`${c} Evidence : ${e.line ? `L${e.line} ` : ""}${e.text}`);
    if (f.refs.length) lines.push(`${c} Refs     : ${f.refs.map((r) => `${r.framework.toUpperCase()} ${r.id}`).join(", ")}`);
    lines.push(`${c} ${"-".repeat(70)}`);
    lines.push(f.remediation || `${c} (no template for ${VENDOR_META[view.vendor].short}: ${f.expected})`);
    lines.push("");
  }
  if (!failed.length) lines.push(`${c} No failed controls — nothing to remediate.`);
  lines.push(hr, `${c} End of script — ${failed.length} remediation blocks`, hr);
  return lines.join("\n");
}

/**
 * One change-review document for the whole fleet: every device's script in
 * order of weighted risk, with a contents block so a reviewer can plan the
 * maintenance window.
 */
export function fleetRemediationBundle(views: DeviceView[], meta: { organisation: string; operator: string }): string {
  const ordered = [...views].filter((v) => v.summary.fail > 0).sort((a, b) => b.risk - a.risk);
  const head = [
    `# ${"=".repeat(70)}`,
    "# NetSentinel AI — fleet remediation plan",
    `# Prepared : ${new Date().toISOString()} by ${meta.operator} — ${meta.organisation}`,
    `# Devices  : ${ordered.length} of ${views.length} have failed controls`,
    "#",
    "# Order of work (highest weighted risk first):",
    ...ordered.map((v, i) => `#   ${String(i + 1).padStart(2, " ")}. ${v.name} — ${v.summary.fail} failed, ${v.summary.bySeverity.critical} critical, risk ${v.risk} (${v.parse.identity.vendorName} ${v.parse.identity.os})`),
    "#",
    "# Each section below is that device's own script. Apply per device, in a",
    "# maintenance window, with a console session open, then re-audit.",
    `# ${"=".repeat(70)}`,
    "",
  ].join(NL);
  if (!ordered.length) return `${head}# No failed controls in the fleet.${NL}`;
  return `${head}${ordered.map((v) => remediationBundle(v, meta)).join(NL + NL + NL)}${NL}`;
}
