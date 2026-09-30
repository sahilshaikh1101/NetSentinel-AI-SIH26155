import type { Rule, SecurityBaselineModel, VendorId } from "../types";
import { VENDOR_FAMILY, VENDOR_META } from "../sbm";

export interface RemediationSettings {
  syslogHost: string;
  ntpServer: string;
  ntpServer2: string;
  mgmtSubnetCidr: string; // e.g. 10.10.0.0/24
  tacacsServer: string;
  snmpManager: string;
  domain: string;
  banner: string;
}

export interface RemediationContext {
  osVersion?: string;
  hostname?: string;
}

export const DEFAULT_REMEDIATION_SETTINGS: RemediationSettings = {
  syslogHost: "10.10.50.20",
  ntpServer: "10.10.50.10",
  ntpServer2: "10.10.50.11",
  mgmtSubnetCidr: "10.10.0.0/24",
  tacacsServer: "10.10.50.30",
  snmpManager: "10.10.50.40",
  domain: "corp.example.in",
  banner: "UNAUTHORISED ACCESS PROHIBITED. This system is monitored; all activity is logged and may be disclosed to law enforcement.",
};

export interface CidrParts {
  network: string;
  mask: string;
  wildcard: string;
  bits: number;
  /** false when the operator's input was not a usable IPv4 prefix */
  valid: boolean;
}

const CIDR_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d|[12]\d|3[0-2]))?$/;

/**
 * Management prefix for ACL templates. A bare address means a single host
 * (/32) — silently widening it to /24 would authorise a whole subnet — and
 * anything that is not a valid IPv4 prefix is reported as invalid so the
 * template can emit a placeholder instead of a lock-out-capable ACL.
 */
export function cidrToParts(cidr: string): CidrParts {
  const m = CIDR_RE.exec((cidr ?? "").trim());
  const octets = m ? [m[1], m[2], m[3], m[4]].map((o) => parseInt(o, 10)) : [];
  if (!m || octets.some((o) => o > 255)) return { network: "<mgmt-subnet>", mask: "<mask>", wildcard: "<wildcard>", bits: 0, valid: false };
  const bits = m[5] === undefined ? 32 : parseInt(m[5], 10);
  const maskNum = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const addr = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const toDotted = (n: number) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
  return { network: toDotted((addr & maskNum) >>> 0), mask: toDotted(maskNum), wildcard: toDotted(~maskNum >>> 0), bits, valid: true };
}

/**
 * Fills {{placeholders}}, {{#each list}}…{{item}}…{{/each}} loops and
 * {{#if key}}…{{else}}…{{/if}} conditionals (nestable) in a remediation
 * template with values from the device model and settings, so the produced
 * CLI is specific to the audited device. A vendor without its own template
 * borrows its family's (NX-OS → IOS).
 */
export function renderRemediation(rule: Rule, vendor: VendorId, model: SecurityBaselineModel, settings: RemediationSettings, ctx: RemediationContext = {}, diagnostics?: string[]): string {
  const template = rule.remediation[vendor] ?? rule.remediation[VENDOR_FAMILY[vendor]] ?? rule.remediation.generic ?? `Refer to the vendor hardening guide: ${rule.expected}`;
  const comment = VENDOR_META[vendor].comment;
  const parts = cidrToParts(settings.mgmtSubnetCidr);
  const val = (key: string) => model.params[key]?.value;
  const list = (key: string): string[] => {
    const v = val(key);
    return Array.isArray(v) ? v : [];
  };
  const vtyMax = typeof val("management.vty_max") === "number" ? (val("management.vty_max") as number) : 15;
  const iosxe = /^(1[6-9]|2\d)\./.test(ctx.osVersion ?? "") || /XE/i.test(ctx.osVersion ?? "");
  const mgmtVrf = String(val("management.mgmt_vrf") ?? "");
  const vars: Record<string, string> = {
    syslog_host: settings.syslogHost,
    ntp_server: settings.ntpServer,
    ntp_server2: settings.ntpServer2,
    mgmt_subnet_cidr: parts.valid ? `${parts.network}/${parts.bits}` : "<mgmt-subnet>/<bits>",
    mgmt_subnet: `${parts.network} ${parts.wildcard}`,
    mgmt_subnet_mask: `${parts.network} ${parts.mask}`,
    mgmt_subnet_wild: `${parts.network} ${parts.wildcard}`,
    tacacs_server: settings.tacacsServer,
    snmp_manager: settings.snmpManager,
    domain: settings.domain,
    banner: settings.banner,
    hostname: ctx.hostname ?? String(val("identity.hostname") ?? ""),
    vty_max: String(vtyMax),
    mgmt_vrf: mgmtVrf,
    /** " vrf X" or "" — lets templates stay flat instead of nesting conditionals */
    vrf_clause: mgmtVrf ? ` vrf ${mgmtVrf}` : "",
    bgp_asn: String(val("routing.bgp_asn") ?? "<asn>"),
    eigrp_as: String(val("routing.eigrp_as") ?? "<asn>"),
    iosxe: iosxe ? "1" : "",
    ntp_hash: iosxe ? "hmac-sha2-256" : "md5",
  };
  const truthy = (key: string): boolean => {
    if (key in vars) return Boolean(vars[key]);
    const v = val(key);
    if (Array.isArray(v)) return v.length > 0;
    return Boolean(v);
  };
  const defaults = list("snmp.default_communities");
  const rw = list("snmp.rw_communities");
  const lists: Record<string, string[]> = {
    weak_users: list("auth.weak_local_users"),
    ifaces_telnet: interfacesWith(model, "management.telnet_enabled", "telnet", "management.telnet_interfaces"),
    ifaces_http: interfacesWith(model, "management.http_enabled", "http", "management.http_interfaces"),
    snmp_ro_communities: list("snmp.v1v2c_communities").filter((c) => !defaults.includes(c) && !rw.includes(c)),
  };
  let out = template;
  // {{#if key}}…{{else}}…{{/if}}, innermost first so conditionals can nest.
  const IF_RE = /\{\{#if ([\w.]+)\}\}((?:(?!\{\{#if )[\s\S])*?)(?:\{\{else\}\}((?:(?!\{\{#if )[\s\S])*?))?\{\{\/if\}\}/;
  for (let guard = 0; guard < 50 && IF_RE.test(out); guard++) {
    out = out.replace(IF_RE, (_m, key: string, yes: string, no?: string) => (truthy(key) ? yes : (no ?? "")));
  }
  // {{#each list}}…{{/each}}
  out = out.replace(/\{\{#each ([\w.]+)\}\}([\s\S]*?)\{\{\/each\}\}/g, (_m, key: string, body: string) => {
    const items = lists[key] ?? list(key);
    // Use the vendor's own comment marker: '!' is a syntax error on Junos/FortiOS/PAN-OS.
    if (!items.length) return `${comment} (no ${key.split(".").pop()?.replace(/_/g, " ")} were observed — verify on the device)\n`;
    return items.map((item) => body.replace(/\{\{item\}\}/g, item)).join("");
  });
  out = out.replace(/\{\{([\w.]+)\}\}/g, (_m, key: string) => {
    if (key in vars) return vars[key];
    // A template asked for something the renderer does not provide: a bug, not a placeholder.
    diagnostics?.push(key);
    return `<${key}>`;
  });
  if (diagnostics) for (const m of out.matchAll(/\{\{[^}]*\}\}|<else>/g)) diagnostics.push(m[0]);
  if (!parts.valid && /<mgmt-subnet>/.test(out)) {
    out = `${comment} Set a valid management prefix (Settings → Remediation defaults) before applying this ACL.\n${out}`;
  }
  return out.replace(/\n{3,}/g, "\n\n").trim();
}

/** Interface names carrying the service: the parser's own list first, evidence text as a fallback. */
function interfacesWith(model: SecurityBaselineModel, key: string, service: string, listKey?: string): string[] {
  const obs = model.params[key];
  if (!obs || obs.value !== true) return [];
  const fromList = listKey && Array.isArray(model.params[listKey]?.value) ? (model.params[listKey]!.value as string[]) : [];
  if (fromList.length) return Array.from(new Set(fromList));
  const names: string[] = [];
  for (const e of obs.evidence) {
    const m = e.text.match(/edit "?([\w.-]+)"?/);
    if (m) names.push(m[1]);
  }
  if (!names.length && obs.evidence.some((e) => new RegExp(service, "i").test(e.text))) names.push("<interface>");
  return Array.from(new Set(names));
}
