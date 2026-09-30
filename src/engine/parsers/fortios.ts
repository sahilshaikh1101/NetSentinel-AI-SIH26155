import type { Evidence, ParseResult } from "../types";
import { first, hasWeakCipher, ModelBuilder, toLines, unquote, type Line } from "./util";

export interface FortiEntry {
  /** section path without the multi-VDOM wrappers, e.g. "system global" or "system interface/ipv6" */
  section: string;
  /** innermost `edit` name (inherited from the parent table for un-keyed sub-tables such as `config ipv6`) */
  edit?: string;
  /** `edit` names from the outermost table inwards */
  edits: string[];
  editLine?: number;
  /** VDOM the entry belongs to (multi-VDOM configurations) */
  vdom?: string;
  /** human-readable block path, e.g. `config system snmp community > edit 1 > config hosts > edit 1` */
  context: string;
  key: string;
  values: string[];
  line: Line;
}

interface Frame { name: string; section: string; edit?: string; editLine?: number; vdom?: string; scope?: "global" | "vdom" }

const isCommentOrBlank = (l: Line) => !l.text || l.text.startsWith("#");
const q = (name: string) => (/^\d+$/.test(name) ? name : `"${name}"`);

/**
 * Flatten FortiOS config/edit/set/next/end blocks.
 * The multi-VDOM wrappers (`config global`, `config vdom > edit <name>`) are transparent scopes: they never
 * prefix the section path, and the VDOM name is carried on every entry instead.
 */
export function flattenFortiOS(lines: Line[]): { entries: FortiEntry[]; structural: Set<number>; sections: Set<string>; vdoms: string[] } {
  const entries: FortiEntry[] = [];
  const structural = new Set<number>();
  const sections = new Set<string>();
  const vdoms: string[] = [];
  const stack: Frame[] = [];
  const top = () => stack[stack.length - 1];
  for (const l of lines) {
    if (isCommentOrBlank(l)) continue;
    const t = l.text;
    let m: RegExpMatchArray | null;
    if ((m = t.match(/^config\s+(.+)$/))) {
      const parent = top();
      const name = m[1].trim();
      if (!parent && (name === "global" || name === "vdom")) stack.push({ name, section: "", scope: name });
      else {
        const section = parent?.section ? `${parent.section}/${name}` : name;
        stack.push({ name, section, vdom: parent?.vdom });
        sections.add(section);
      }
      structural.add(l.n);
      continue;
    }
    if ((m = t.match(/^edit\s+(.+)$/))) {
      const cur = top();
      if (cur) {
        cur.edit = unquote(m[1].trim());
        cur.editLine = l.n;
        if (cur.scope === "vdom") {
          cur.vdom = cur.edit;
          if (!vdoms.includes(cur.edit)) vdoms.push(cur.edit);
        }
      }
      structural.add(l.n);
      continue;
    }
    if (t === "next") {
      const cur = top();
      if (cur) {
        cur.edit = undefined;
        cur.editLine = undefined;
        if (cur.scope === "vdom") cur.vdom = undefined;
      }
      structural.add(l.n);
      continue;
    }
    if (t === "end") {
      stack.pop();
      structural.add(l.n);
      continue;
    }
    if (/^(purge|delete\s.+)$/.test(t)) {
      structural.add(l.n);
      continue;
    }
    if ((m = t.match(/^(set|unset|append|clear|unselect)\s+(\S+)\s*(.*)$/))) {
      const cur = top();
      const frames = stack.filter((f) => !f.scope);
      const values = m[3] ? (m[3].match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map(unquote) : [];
      const edits = frames.map((f) => f.edit).filter((x): x is string => x !== undefined);
      const owner = [...frames].reverse().find((f) => f.edit !== undefined);
      entries.push({
        section: cur?.section ?? "",
        edit: owner?.edit,
        edits,
        editLine: owner?.editLine,
        vdom: cur?.vdom,
        context: frames.map((f) => `config ${f.name}${f.edit !== undefined ? ` > edit ${q(f.edit)}` : ""}`).join(" > "),
        key: m[2],
        values: m[1] === "unset" ? ["<unset>"] : values,
        line: l,
      });
    }
  }
  return { entries, structural, sections, vdoms };
}

// ───────────────────────── vocabulary ─────────────────────────

/** Default "any" trusthost / host values FortiOS emits in `show full-configuration`. */
const ANY_HOST = /^(<unset>|any|0\.0\.0\.0(\s+0\.0\.0\.0|\/0)?|::(\/0)?)$/i;
const isAnyHost = (v: string[]) => v.length === 0 || ANY_HOST.test(v.join(" "));
/** Legacy algorithms in the explicit 7.2+/7.4 SSH lists (ssh-enc-algo / ssh-mac-algo / ssh-kex-algo / ssh-hostkey-algo). */
const WEAK_SSH_ALGO = /\b(hmac-(md5|sha1|ripemd160)\S*|umac-64\S*|3des-cbc|aes\d+-cbc|arcfour\S*|blowfish-cbc|cast128-cbc|rijndael-cbc\S*|diffie-hellman-group(1|14|-exchange)-sha1|ssh-dss)\b/i;
const WEAK_IKE_PROPOSAL = /\b(null|des|3des|md5|sha1)\b/i;
const WEAK_DH_GROUP = /\b(1|2|5)\b/;
const MGMT_SERVICES = ["https", "ssh", "http", "telnet"];
const LOG_DEST = /^log (syslogd\d?|fortianalyzer(?:2|3|-cloud)?|fortiguard) (setting|override-setting)$/;
const STRONG_OSPF_AUTH = ["message-digest", "md5", "esp", "ah", "ipsec"];

const tlsVersion = (tok: string): string | undefined => {
  const t = tok.toLowerCase();
  if (/^ssl-?v?3$/.test(t)) return "SSLv3";
  const m = t.match(/^tlsv?1(?:[-.](\d))?$/);
  return m ? `1.${m[1] ?? "0"}` : undefined;
};
const tlsRank = (v: string) => (v === "SSLv3" ? 0.3 : parseFloat(v));

/** Whole roots that never carry SBM-relevant settings (UTM profiles, objects, GUI state…). */
const BENIGN_ROOTS = new Set([
  "webfilter", "antivirus", "ips", "application", "dlp", "wireless-controller", "switch-controller", "switch", "report", "alertemail", "endpoint-control",
  "emailfilter", "voip", "waf", "authentication", "certificate", "dnsfilter", "web-proxy", "wanopt", "icap", "ssh-filter", "file-filter", "cifs",
  "extender-controller", "extension-controller", "ftp-proxy", "sctp-filter", "videofilter", "virtual-patch", "ztna", "casb", "diameter-filter", "monitoring",
  "nsxt", "rule", "spamfilter", "netscan", "sdwan", "automation", "credential-store", "dpdk", "gtp", "pfcp", "ethernet-oam", "wad", "icap", "vpn-certificate",
]);
/** Sections (top-level table names) the parser knows to be security-irrelevant; anything else stays unrecognised. */
const BENIGN_SECTIONS: RegExp[] = [
  /^system (accprofile|settings|dns|dns-database|dns-server|dns64|fortiguard|replacemsg(-group|-image)?( .+)?|ha|ha-monitor|central-management|dhcp6? server|zone|sdwan|virtual-wan-link|autoupdate( .+)?|session-helper|auto-install|email-server|npu|session-ttl|virtual-switch|physical-switch|switch-interface|sit-tunnel|arp-table|link-monitor|csf|fortimanager|federated-upgrade|automation-\S+|speed-test-\S+|vdom(-property|-link|-exception|-netflow|-sflow|-dns|-radius-server)?|storage|fortisandbox|fortiai|fortindr|ftm-push|geoip-\S+|sflow|netflow|gre-tunnel|ipip-tunnel|vxlan|wccp|object-tagging|custom-language|standalone-cluster|cluster-sync|fabric-vpn|ips|ips-urlfilter-dns6?|sso-admin|sso-forticloud-admin|sso-fortigate-cloud-admin|alias|affinity-\S+|external-resource|ipv6-neighbor-cache|ipv6-tunnel|lldp( .+)?|mobile-tunnel|nd-proxy|network-visibility|pppoe-interface|probe-response|proxy-arp|resource-limits|sms-server|tos-based-priority|vne-tunnel|wireless( .+)?|modem|ipsec-aggregate|evpn|lte-modem|dscp-based-priority|password-policy-guest|acme|ike|device-upgrade|mac-address-table|smc-ntp|vin-alarm|fsso-polling|ddns|dedicated-mgmt|auto-script|ipam|snmp (mib-view|rmon-stat)|admin (profile|group|setting|ldap|radius|tacacs)|flow-export|location|port-pair|flan-cloud|fsw-cloud|web|bug-report|sniffer-profile|certificate( .+)?|fortianalyzer\d?|debug|schedule( .+)?|locallog( .+)?|log( .+)?|backup( .+)?|route|mail|alert-console|alert-event|metadata|sql|report( .+)?|sniffer|dm|fips)$/,
  /^log (\S+ (filter|override-filter|global-setting)|threat-weight|custom-field|gui-display|null-device setting|webtrends setting|tacacs\+accounting\d? setting|azure-security-center\d? setting)$/,
  /^user (local|group|setting|peer|peergrp|fsso|fsso-polling|password-policy|device|device-group|device-access-list|device-category|quarantine|krb-keytab|domain-controller|exchange|nac-policy|saml|fortitoken|pop3|adgrp|certificate|external-identity-provider|security-exempt-list|scim|banned)$/,
  /^firewall (address6?|addrgrp6?|multicast-address6?|wildcard-fqdn \S+|service \S+|schedule \S+|vip6?|vipgrp6?|vip46|vip64|vipgrp46|vipgrp64|ippool6?|shaper \S+|shaping-policy|shaping-profile|profile-group|profile-protocol-options|ssl-ssh-profile|ssl-server|ssl setting|ldb-monitor|DoS-policy6?|interface-policy6?|multicast-policy6?|sniffer|ttl-policy|identity-based-route|auth-portal|central-snat-map|internet-service\S*|proxy-address|proxy-addrgrp|proxy-policy|access-proxy\S*|decrypted-traffic-mirror|dnstranslation|ipmacbinding \S+|ip-translation|region|city|country|traffic-class|global|ipv6-eh-filter|on-demand-sniffer|network-service-dynamic|ssh \S+|iprope .*|consolidated policy|acl6?|acl46|policy46|policy64|explicit-proxy-\S+|carrier-endpoint-\S+|mms-profile|vendor-mac|pfcp|gtp)$/,
  /^router (static6?|prefix-list6?|access-list6?|route-map|aspath-list|community-list|extcommunity-list|key-chain|policy6?|rip|ripng|isis|multicast6?|multicast-flow|setting|auth-path|bfd6?|ospf6|bgp6)$/,
  /^vpn (certificate \S+|ssl web \S+|ssl client|ipsec manualkey(-interface)?|ipsec concentrator|ipsec forticlient|ipsec fec|l2tp|pptp|kmip-server|ocvpn|qkd)$/,
];
function isBenign(section: string): boolean {
  const top = section.split("/")[0];
  return BENIGN_ROOTS.has(top.split(" ")[0]) || BENIGN_SECTIONS.some((re) => re.test(top));
}

interface Product { family: "fortigate" | "fortiswitch" | "appliance"; name: string; os: string; role: string; model: string }
const PRODUCTS: [RegExp, string, string, string, Product["family"]][] = [
  [/^FGVM/, "FortiGate-VM", "FortiOS", "firewall", "fortigate"],
  [/^FWF/, "FortiWiFi", "FortiOS", "firewall", "fortigate"],
  [/^FGR/, "FortiGateRugged", "FortiOS", "firewall", "fortigate"],
  [/^FFW/, "FortiFirewall", "FortiOS", "firewall", "fortigate"],
  [/^(FGT|FG)/, "FortiGate", "FortiOS", "firewall", "fortigate"],
  [/^(FS|S(?=\d))/, "FortiSwitch", "FortiSwitchOS", "switch", "fortiswitch"],
  [/^FAZ/, "FortiAnalyzer", "FortiAnalyzer", "log appliance", "appliance"],
  [/^FMG/, "FortiManager", "FortiManager", "management appliance", "appliance"],
  [/^FAC/, "FortiAuthenticator", "FortiAuthenticator", "authentication appliance", "appliance"],
  [/^FAD/, "FortiADC", "FortiADC", "load balancer", "appliance"],
  [/^FWB/, "FortiWeb", "FortiWeb", "web application firewall", "appliance"],
  [/^FML/, "FortiMail", "FortiMail", "mail gateway", "appliance"],
];
/** Derive the product line from the `#config-version=` model token (FG100F → FortiGate-100F, FS1E48 → FortiSwitch-1E48 …). */
export function fortiProduct(model: string): Product | undefined {
  const u = model.toUpperCase();
  for (const [re, name, os, role, family] of PRODUCTS) {
    const m = u.match(re);
    if (!m) continue;
    const rest = u.slice(m[0].length).replace(/^-/, "");
    return { family, name, os, role, model: rest ? `${name}${name.endsWith("VM") ? "" : "-"}${rest}` : name };
  }
  return undefined;
}

// ───────────────────────── trackers ─────────────────────────

interface IfaceInfo { name: string; vdom?: string; ip?: string; allow: Set<string>; allow6: Set<string>; dedicated?: boolean; role?: string; trustIp?: Evidence }
interface AdminInfo { name: string; api: boolean; edit: Evidence; wildcard: boolean; remote: boolean; group?: string; restricted: Evidence[]; twoFactor?: { on: boolean; ev: Evidence } }
interface LogDest { label: string; kind: "syslog" | "faz" | "cloud"; override: boolean; overrideOn?: boolean; enabled?: boolean; server?: string; serverEv?: Evidence; reliable?: boolean; transportEv?: Evidence; enc?: string; encEv?: Evidence; source?: Evidence; firstEv?: Evidence }
interface Policy { scope: string; srcintf: string[]; dstintf: string[]; srcaddr: string[]; dstaddr: string[]; service: string[]; action?: string; log?: string; enabled: boolean; ev: Evidence[] }
interface LocalIn { scope: string; intf: string[]; srcaddr: string[]; action?: string; enabled: boolean; ev: Evidence[] }
interface Peer { name: string; edit: Evidence; password?: Evidence; group?: string; prefix?: string }
interface Tunnel { table: string; name: string; weak: Evidence[]; ev?: Evidence }
interface Community { id: string; name?: string; nameEv?: Evidence; enabled: boolean; hosts: number }

export function parseFortiOS(rawInput: string): ParseResult {
  const raw = rawInput.replace(/^﻿/, "");
  const lines = toLines(raw);
  const b = new ModelBuilder("fortinet-fortios");
  const id = b.identity;
  const extra: Record<string, string> = {};

  const header = raw.match(/^#config-version=([A-Za-z0-9-]+?)-(\d+(?:\.\d+)*)-FW-build(\d+)(?:-\d+)?((?::[\w-]+=[^:\s]*)*)/m);
  if (header) {
    id.model = header[1];
    id.osVersion = `${header[2]} build ${header[3]}`;
    const flags = Object.fromEntries((header[4].match(/[\w-]+=[^:\s]*/g) ?? []).map((f) => f.split("=") as [string, string]));
    if (flags.opmode !== undefined) extra.opmode = flags.opmode === "1" ? "transparent" : "nat";
    if (flags.vdom !== undefined) extra.vdom_mode = flags.vdom === "1" ? "multi-vdom" : "single";
    const [major, minor = 0] = header[2].split(".").map((x) => parseInt(x, 10));
    const hdr: Evidence = { line: lines.find((l) => l.text.startsWith("#config-version="))?.n ?? 1, text: header[0] };
    b.set("identity.fortios_7plus", major >= 7, hdr);
    b.set("identity.fortios_74plus", major > 7 || (major === 7 && minor >= 4), hdr);
  }
  id.serial = first(raw, /^#\s*serial(?:[- ]?number)?\s*[:=]\s*(\S+)/mi) ?? first(raw, /Serial-Number:\s*(\S+)/i);
  const product = id.model ? fortiProduct(id.model) : undefined;
  if (product) {
    id.os = product.os;
    id.role = product.role;
    extra.product = product.model;
  } else id.role = "firewall";
  const isFirewall = !product || product.family === "fortigate";

  const d = (k: string, v: string | number | boolean | string[], note: string) => b.setDefault(k, v, `Platform default — ${note}`);
  d("management.ssh_version", 2, "FortiOS 7.x only supports SSHv2 (admin-ssh-v1 removed)");
  d("management.telnet_enabled", false, "telnet is not in 'allowaccess' on any interface");
  d("management.http_enabled", false, "http is not in 'allowaccess' on any interface");
  d("management.https_enabled", true, "GUI listens on admin-sport 443");
  d("management.ssh_enabled", false, "ssh is not in 'allowaccess' on any interface");
  d("management.idle_timeout_minutes", 5, "admintimeout defaults to 5 minutes");
  d("crypto.strong_crypto", true, "strong-crypto is enabled by default");
  d("auth.password_encryption", true, "FortiOS stores admin passwords hashed (ENC)");
  d("auth.login_lockout", true, "admin-lockout-threshold defaults to 3 attempts / 60 s");
  d("auth.max_login_attempts", 3, "admin-lockout-threshold defaults to 3");
  d("auth.password_complexity", false, "system password-policy is disabled by default");
  d("logging.timestamps", true, "FortiOS log records are timestamped");
  d("logging.enabled", true, "event logging is on");
  d("logging.buffered", true, "memory logging is enabled by default");
  d("logging.login_events", true, "log eventfilter event/system/user are enabled by default");
  d("management.login_banner", false, "pre-login-banner is disabled");
  d("management.mgmt_acl_applied", false, "admin trusthosts default to 0.0.0.0/0 and no local-in-policy exists");
  d("management.concurrent_sessions_limited", false, "admin-concurrent is enabled (multiple sessions allowed)");
  d("snmp.enabled", false, "snmp sysinfo status disabled");
  d("time.ntp_servers", ["ntp.fortiguard.com (FortiGuard default)"], "ntpsync is enabled against FortiGuard by default");
  d("time.ntp_authentication", false, "no ntpserver authentication");
  d("auth.aaa_enabled", false, "no remote admin authentication configured");
  d("auth.aaa_authentication_login", false, "admin accounts authenticate against the local password unless remote-auth is enabled");
  d("auth.remote_auth_servers", [], "no admin account is bound to a remote-auth user group");
  if (isFirewall) {
    d("services.ip_source_routing", false, "source-routed packets are dropped");
    d("services.directed_broadcast", false, "directed broadcast not forwarded");
    d("acl.default_deny", true, "FortiGate rulebase ends with implicit deny");
  }

  const { entries, structural, sections, vdoms } = flattenFortiOS(lines);
  structural.forEach((n) => b.mark(n));
  if (vdoms.length) extra.vdoms = vdoms.join(", ");

  const ifaces = new Map<string, IfaceInfo>();
  const haMgmt: string[] = [];
  const admins = new Map<string, AdminInfo>();
  const servers = new Map<string, { hosts: string[]; ev: Evidence[] }>();
  const groups = new Map<string, string[]>();
  const logDests = new Map<string, LogDest>();
  const localLog: { memory?: Evidence & { on: boolean }; disk?: Evidence & { on: boolean } } = {};
  const eventFilter = new Map<string, { event?: boolean; system?: boolean; user?: boolean; ev: Evidence[] }>();
  const implicitLog = new Map<string, { on: boolean; ev: Evidence }>();
  const policies = new Map<string, Policy>();
  const localIn = new Map<string, LocalIn>();
  const ntp: { seen: boolean; sync?: { on: boolean; ev: Evidence }; type?: { v: string; ev: Evidence }; servers: Map<string, { server?: string; ev: Evidence; auth?: { on: boolean; ev: Evidence } }> } = { seen: false, servers: new Map() };
  const snmp: { sysinfo?: { on: boolean; ev: Evidence }; communities: Map<string, Community>; users: Map<string, { enabled: boolean; level?: string; ev: Evidence }> } = { communities: new Map(), users: new Map() };
  const bgp: { seen: boolean; as?: { v: string; ev: Evidence }; neighbors: Map<string, Peer>; groups: Map<string, Peer>; ranges: Map<string, Peer> } = { seen: false, neighbors: new Map(), groups: new Map(), ranges: new Map() };
  const ospf: { seen: boolean; routerId?: { v: string; ev: Evidence }; areas: Map<string, { auth?: { v: string; ev: Evidence }; edit: Evidence }>; ifaces: Map<string, { auth?: { v: string; ev: Evidence }; edit: Evidence }>; networks: number } = { seen: false, areas: new Map(), ifaces: new Map(), networks: 0 };
  const tunnels = new Map<string, Tunnel>();
  const pwPolicy: { seen: boolean; status?: { on: boolean; ev: Evidence }; minLength?: { v: number; ev: Evidence }; classes: Evidence[]; applyTo?: { admin: boolean; ev: Evidence } } = { seen: false, classes: [] };
  let adminTelnetOff: Evidence | undefined;
  const weakCrypto: Evidence[] = [];
  const aclKeys = new Set<string>();

  const weakestTls = (val: string, ev: Evidence) => {
    const cur = b.get("crypto.tls_min_version");
    const keep = typeof cur === "string" && b.params["crypto.tls_min_version"].source !== "default" && tlsRank(cur) <= tlsRank(val) ? cur : val;
    b.set("crypto.tls_min_version", keep, ev);
  };
  const iface = (name: string) => {
    let i = ifaces.get(name);
    if (!i) ifaces.set(name, (i = { name, allow: new Set(), allow6: new Set() }));
    return i;
  };
  const admin = (e: FortiEntry, api: boolean) => {
    const name = e.edit ?? "";
    let a = admins.get(name);
    if (!a) admins.set(name, (a = { name, api, edit: { line: e.editLine ?? e.line.n, text: `edit "${name}"` }, wildcard: false, remote: false, restricted: [] }));
    return a;
  };
  const logDest = (e: FortiEntry, s: string) => {
    const key = `${s}|${e.vdom ?? ""}`;
    let x = logDests.get(key);
    if (!x) {
      const m = s.match(LOG_DEST) as RegExpMatchArray;
      const kind: LogDest["kind"] = m[1] === "fortiguard" ? "cloud" : m[1].startsWith("fortianalyzer") ? "faz" : "syslog";
      logDests.set(key, (x = { label: `${m[1]}${m[2] === "override-setting" ? " override" : ""}${e.vdom ? ` (vdom ${e.vdom})` : ""}`, kind, override: m[2] === "override-setting" }));
    }
    return x;
  };
  const scopeOf = (e: FortiEntry) => e.vdom ?? "";
  const anyIntf = (list: string[]) => list.some((x) => x === "any" || ifaces.get(x)?.role === "wan");

  for (const e of entries) {
    const { section: s, key: k, values: v, line: l } = e;
    const v0 = v[0] ?? "";
    const vs = v.join(" ");
    const sub = s.split("/").slice(1).map((x) => `config ${x}`);
    const ctx: Evidence = { line: l.n, text: `${e.edit !== undefined ? `edit ${q(e.edit)} > ` : ""}${sub.length ? `${sub.join(" > ")} > ` : ""}${l.text}` };
    let handled = true;
    if (s === "system global" || s === "system ssh-config") {
      switch (k) {
        case "hostname": id.hostname = v0; b.setTrue("identity.hostname_set", l); break;
        case "admin-sport": b.setTrue("management.https_enabled", l); break;
        case "admintimeout": b.set("management.idle_timeout_minutes", parseInt(v0, 10), l); break;
        case "admin-ssh-v1": b.set("management.ssh_version", v0 === "enable" ? 1 : 2, l); break;
        case "admin-telnet": if (v0 === "disable") adminTelnetOff = ctx; break; // `enable` is the factory default and proves nothing
        case "strong-crypto": if (v0 === "enable") b.set("crypto.strong_crypto", true, l); else weakCrypto.push(ctx); break;
        case "ssh-cbc-cipher": case "ssh-hmac-md5": case "ssh-kex-sha1": case "ssh-mac-weak": case "ssh-hmac-sha1":
          if (v0 === "enable") weakCrypto.push(ctx); break;
        case "ssh-enc-algo": case "ssh-mac-algo": case "ssh-kex-algo": case "ssh-hostkey-algo":
          if (hasWeakCipher(vs) || WEAK_SSH_ALGO.test(vs)) weakCrypto.push(ctx); break;
        case "admin-lockout-threshold": b.set("auth.max_login_attempts", parseInt(v0, 10), l); b.setTrue("auth.login_lockout", l); break;
        case "admin-lockout-duration": b.setTrue("auth.login_lockout", l); break;
        case "admin-concurrent": b.set("management.concurrent_sessions_limited", v0 === "disable", l); break;
        case "pre-login-banner": b.set("management.login_banner", v0 === "enable", l); break;
        case "admin-https-ssl-versions": {
          const seen = v.map(tlsVersion).filter((x): x is string => Boolean(x));
          if (seen.length) weakestTls(seen.sort((a, c) => tlsRank(a) - tlsRank(c))[0], ctx);
          break;
        }
        case "ssl-min-proto-version": { const t = tlsVersion(v0); if (t) weakestTls(t, ctx); break; }
        case "timezone": b.setTrue("time.timezone_set", l); break;
        case "cli-audit-log": b.set("logging.config_changes", v0 === "enable", l); break;
        default: break;
      }
    } else if (s === "system fips-cc") {
      if (k === "status") b.set("crypto.fips_mode", v0 === "enable", l);
    } else if (s === "system interface") {
      const i = iface(e.edit ?? "");
      if (k === "allowaccess") {
        i.allow = new Set(v);
        if (v.includes("telnet")) { b.set("management.telnet_enabled", true, ctx); b.add("management.telnet_interfaces", i.name, ctx); }
        if (v.includes("http")) { b.set("management.http_enabled", true, ctx); b.add("management.http_interfaces", i.name, ctx); }
        if (v.includes("https")) b.setTrue("management.https_enabled", ctx);
        if (v.includes("ssh")) b.setTrue("management.ssh_enabled", ctx);
        if (v.includes("snmp")) b.setTrue("snmp.enabled", ctx);
      } else if (k === "ip") i.ip = v0;
      else if (k === "vdom") i.vdom = v0;
      else if (k === "dedicated-to") i.dedicated = v0 === "management";
      else if (k === "role") i.role = v0;
      else if (/^trust-ip6?-\d+$/.test(k)) { if (!isAnyHost(v)) i.trustIp = ctx; }
      else if (k === "type" && v0 === "tunnel") b.inc("identity.tunnels", l);
      else if (k === "type" && v0 === "loopback") b.setTrue("identity.loopback_present", l);
    } else if (s === "system interface/ipv6") {
      const i = iface(e.edit ?? "");
      if (k === "ip6-allowaccess") {
        i.allow6 = new Set(v);
        if (v.includes("telnet")) { b.set("management.telnet_enabled", true, ctx); b.add("management.telnet_interfaces6", i.name, ctx); }
        if (v.includes("http")) { b.set("management.http_enabled", true, ctx); b.add("management.http_interfaces6", i.name, ctx); }
        if (v.includes("https")) b.setTrue("management.https_enabled", ctx);
        if (v.includes("ssh")) b.setTrue("management.ssh_enabled", ctx);
        if (v.includes("snmp")) b.setTrue("snmp.enabled", ctx);
      }
    } else if (/^system interface\//.test(s)) {
      // secondaryip / vrrp / tagging … — understood, not security-relevant
    } else if (s === "system admin" || s === "system admin user") {
      const a = admin(e, false);
      if (/^(ip6-)?trusthost\d+$/.test(k)) { if (!isAnyHost(v)) a.restricted.push(ctx); }
      else if (k === "password") { if (e.edit !== undefined) b.add("auth.local_users", e.edit, a.edit); }
      else if (k === "two-factor") a.twoFactor = { on: v0 !== "disable", ev: ctx };
      else if (k === "remote-auth") { if (v0 === "enable") { a.remote = true; b.setTrue("auth.aaa_enabled", ctx); b.setTrue("auth.aaa_authentication_login", ctx); } }
      else if (k === "user_type") { if (v0 && v0 !== "local") { a.remote = true; b.setTrue("auth.aaa_enabled", ctx); b.setTrue("auth.aaa_authentication_login", ctx); } }
      else if (k === "remote-group") a.group = v0;
      else if (k === "wildcard") a.wildcard = v0 === "enable";
    } else if (/^system admin\//.test(s)) {
      // gui-dashboard and other per-admin GUI state
    } else if (s === "system admin setting") {
      if (k === "idle_timeout") b.set("management.idle_timeout_minutes", parseInt(v0, 10), l);
    } else if (s === "system api-user") {
      admin(e, true);
    } else if (s === "system api-user/trusthost") {
      const a = admin({ ...e, edit: e.edits[0], editLine: undefined }, true);
      if (/^ipv[46]-trusthost$/.test(k) && !isAnyHost(v)) a.restricted.push(ctx);
    } else if (s === "system password-policy") {
      pwPolicy.seen = true;
      if (k === "status") pwPolicy.status = { on: v0 === "enable", ev: ctx };
      else if (k === "minimum-length") pwPolicy.minLength = { v: parseInt(v0, 10), ev: ctx };
      else if (/^min-(upper-case-letter|lower-case-letter|number|non-alphanumeric)$/.test(k)) { if (parseInt(v0, 10) >= 1) pwPolicy.classes.push(ctx); }
      else if (k === "apply-to") pwPolicy.applyTo = { admin: v.includes("admin-password"), ev: ctx };
    } else if (s === "system saml") {
      if (k === "status" && v0 === "enable") { b.setTrue("auth.aaa_enabled", ctx); b.setTrue("auth.aaa_authentication_login", ctx); }
    } else if (s === "system ha/ha-mgmt-interfaces") {
      if (k === "interface" && v0) haMgmt.push(v0);
    } else if (LOG_DEST.test(s)) {
      const x = logDest(e, s);
      x.firstEv ??= ctx;
      switch (k) {
        case "status": x.enabled = v0 === "enable"; break;
        case "override": x.overrideOn = v0 === "enable"; break;
        case "server": if (v0 && v0 !== "<unset>") { x.server = v0; x.serverEv = ctx; } break;
        case "mode": x.reliable = v0 === "reliable" || v0 === "legacy-reliable"; x.transportEv = ctx; break;
        case "reliable": x.reliable = v0 === "enable"; x.transportEv = ctx; break;
        case "enc-algorithm": x.enc = v0; x.encEv = ctx; break;
        case "source-ip": if (v0 && !/^(0\.0\.0\.0|::|<unset>)$/.test(v0)) x.source = ctx; break;
        case "interface-select-method": if (v0 === "specify") x.source = ctx; break;
        case "interface": if (v0 && v0 !== "<unset>") x.source = ctx; break;
        default: break;
      }
    } else if (/^log (syslogd\d?|fortianalyzer(?:2|3|-cloud)?|fortiguard) (setting|override-setting)\//.test(s)) {
      // custom-field-name sub-tables
    } else if (s === "log memory setting" || s === "log disk setting") {
      if (k === "status") localLog[s === "log memory setting" ? "memory" : "disk"] = { ...ctx, on: v0 === "enable" };
    } else if (s === "log eventfilter") {
      let f = eventFilter.get(scopeOf(e));
      if (!f) eventFilter.set(scopeOf(e), (f = { ev: [] }));
      if (k === "event" || k === "system" || k === "user") { f[k] = v0 === "enable"; f.ev.push(ctx); }
    } else if (s === "log setting") {
      if (k === "fwpolicy-implicit-log") implicitLog.set(scopeOf(e), { on: v0 === "enable", ev: ctx });
    } else if (s === "system ntp") {
      ntp.seen = true;
      if (k === "ntpsync") ntp.sync = { on: v0 !== "disable", ev: ctx };
      else if (k === "type") ntp.type = { v: v0, ev: ctx };
    } else if (s === "system ntp/ntpserver") {
      const idKey = e.edit ?? String(ntp.servers.size + 1);
      let srv = ntp.servers.get(idKey);
      if (!srv) ntp.servers.set(idKey, (srv = { ev: { line: e.editLine ?? l.n, text: `edit ${q(idKey)}` } }));
      if (k === "server") { srv.server = v0; srv.ev = ctx; }
      else if (k === "authentication") srv.auth = { on: v0 === "enable", ev: ctx };
    } else if (s === "system snmp sysinfo") {
      if (k === "status") snmp.sysinfo = { on: v0 === "enable", ev: ctx };
    } else if (s === "system snmp community") {
      const cid = e.edit ?? "";
      let c = snmp.communities.get(cid);
      if (!c) snmp.communities.set(cid, (c = { id: cid, enabled: true, hosts: 0 }));
      if (k === "name") { c.name = v0; c.nameEv = ctx; }
      else if (k === "status") c.enabled = v0 !== "disable";
    } else if (s === "system snmp community/hosts" || s === "system snmp community/hosts6") {
      const cid = e.edits[0] ?? "";
      let c = snmp.communities.get(cid);
      if (!c) snmp.communities.set(cid, (c = { id: cid, enabled: true, hosts: 0 }));
      if ((k === "ip" || k === "ipv6") && !isAnyHost(v)) c.hosts++;
    } else if (s === "system snmp user") {
      const uid = e.edit ?? "";
      let u = snmp.users.get(uid);
      if (!u) snmp.users.set(uid, (u = { enabled: true, ev: ctx }));
      if (k === "status") u.enabled = v0 !== "disable";
      else if (k === "security-level") { u.level = v0; u.ev = ctx; }
      else if (k === "notify-hosts") v.forEach((h, i) => b.add("snmp.trap_hosts", h, i === 0 ? ctx : undefined));
    } else if (/^user (tacacs\+|radius|ldap)$/.test(s)) {
      const name = e.edit ?? "";
      let srv = servers.get(name);
      if (!srv) servers.set(name, (srv = { hosts: [], ev: [] }));
      if ((k === "server" || k === "secondary-server" || k === "tertiary-server") && v0 && v0 !== "<unset>") { srv.hosts.push(v0); srv.ev.push(ctx); }
    } else if (s === "user group") {
      if (k === "member" && e.edit !== undefined) groups.set(e.edit, [...(groups.get(e.edit) ?? []), ...v]);
    } else if (/^user group\//.test(s)) {
      // match / guest sub-tables
    } else if (/^firewall (policy|policy6|security-policy)$/.test(s)) {
      const key = `${scopeOf(e)}/${s}/${e.edit ?? ""}`;
      if (!aclKeys.has(key)) { aclKeys.add(key); b.inc("acl.count", l); }
      let p = policies.get(key);
      if (!p) policies.set(key, (p = { scope: scopeOf(e), srcintf: [], dstintf: [], srcaddr: [], dstaddr: [], service: [], enabled: true, ev: [{ line: e.editLine ?? l.n, text: `edit ${q(e.edit ?? "")}` }] }));
      if (k === "srcintf" || k === "dstintf" || k === "srcaddr" || k === "dstaddr" || k === "service") { p[k] = v; p.ev.push(ctx); }
      else if (k === "action") { p.action = v0; p.ev.push(ctx); }
      else if (k === "logtraffic") { p.log = v0; p.ev.push(ctx); }
      else if (k === "status") p.enabled = v0 !== "disable";
    } else if (/^firewall local-in-policy6?$/.test(s)) {
      const key = `${scopeOf(e)}/${s}/${e.edit ?? ""}`;
      let p = localIn.get(key);
      if (!p) localIn.set(key, (p = { scope: scopeOf(e), intf: [], srcaddr: [], enabled: true, ev: [{ line: e.editLine ?? l.n, text: `edit ${q(e.edit ?? "")}` }] }));
      if (k === "srcaddr" || k === "intf" || k === "service") { if (k !== "service") p[k] = v; p.ev.push(ctx); }
      else if (k === "action") { p.action = v0; p.ev.push(ctx); }
      else if (k === "status") p.enabled = v0 !== "disable";
    } else if (s === "router bgp") {
      bgp.seen = true;
      if (k === "as") bgp.as = { v: v0, ev: ctx };
    } else if (s === "router bgp/neighbor" || s === "router bgp/neighbor-group" || /^router bgp\/neighbor-range6?$/.test(s)) {
      const name = e.edit ?? "";
      const table = s === "router bgp/neighbor" ? bgp.neighbors : s === "router bgp/neighbor-group" ? bgp.groups : bgp.ranges;
      let p = table.get(name);
      if (!p) table.set(name, (p = { name, edit: { line: e.editLine ?? l.n, text: `${sub.join(" > ")} > edit ${q(name)}` } }));
      if (k === "password") p.password = ctx;
      else if (k === "neighbor-group") p.group = v0;
      else if (k === "prefix" && table === bgp.ranges) p.prefix = vs;
    } else if (/^router bgp\//.test(s)) {
      // network / redistribute / aggregate-address … — presence alone does not make BGP run
    } else if (s === "router ospf") {
      ospf.seen = true;
      if (k === "router-id") ospf.routerId = { v: v0, ev: ctx };
    } else if (s === "router ospf/area") {
      const aid = e.edit ?? "";
      let a = ospf.areas.get(aid);
      if (!a) ospf.areas.set(aid, (a = { edit: { line: e.editLine ?? l.n, text: `config area > edit ${aid}` } }));
      if (k === "authentication") a.auth = { v: v0, ev: ctx };
    } else if (s === "router ospf/ospf-interface") {
      const name = e.edit ?? "";
      let i = ospf.ifaces.get(name);
      if (!i) ospf.ifaces.set(name, (i = { edit: { line: e.editLine ?? l.n, text: `config ospf-interface > edit ${q(name)}` } }));
      if (k === "authentication") i.auth = { v: v0, ev: ctx };
    } else if (s === "router ospf/network" || s === "router ospf/neighbor") {
      ospf.networks++;
    } else if (/^router ospf\//.test(s)) {
      // area ranges, md5-keys, redistribute, distribute-list …
    } else if (/^vpn ipsec phase[12](-interface)?$/.test(s)) {
      const key = `${s}/${e.edit ?? ""}`;
      let t = tunnels.get(key);
      if (!t) tunnels.set(key, (t = { table: s.replace(/^vpn ipsec /, ""), name: e.edit ?? "", weak: [] }));
      if (k === "proposal") { t.ev ??= ctx; if (WEAK_IKE_PROPOSAL.test(vs)) t.weak.push(ctx); }
      else if (k === "dhgrp") { t.ev ??= ctx; if (WEAK_DH_GROUP.test(vs)) t.weak.push(ctx); }
    } else if (/^vpn ipsec phase[12](-interface)?\//.test(s)) {
      // ipv4-exclude-range and similar sub-tables
    } else if (s === "vpn ssl settings") {
      if (k === "ssl-min-proto-ver") { const t = tlsVersion(v0); if (t) weakestTls(t, ctx); }
      else if (/^tlsv1-[0-3]$/.test(k)) { const t = tlsVersion(k); if (t && v0 === "enable") weakestTls(t, ctx); }
      else if (k === "algorithm" && v0 === "low") weakCrypto.push(ctx);
    } else if (/^vpn ssl settings\//.test(s)) {
      // authentication-rule
    } else if (s === "system console") {
      // login / baudrate
    } else {
      handled = isBenign(s);
    }
    if (handled) b.mark(l);
  }

  // ───────────────────────── derived parameters (order-independent) ─────────────────────────

  if (adminTelnetOff) b.set("management.telnet_enabled", false, adminTelnetOff);
  // Explicit weak algorithms outrank `strong-crypto enable`, whatever the order of the lines.
  weakCrypto.forEach((ev) => b.set("crypto.strong_crypto", false, ev));

  // Management IP: dedicated management port > HA management interface > "mgmt" > first non-WAN interface with https/ssh > any with https/ssh > first with an address.
  const withIp = [...ifaces.values()].filter((i) => i.ip);
  const managed = withIp.filter((i) => i.allow.has("https") || i.allow.has("ssh"));
  const mgmtIf = withIp.find((i) => i.dedicated) ?? haMgmt.map((n) => ifaces.get(n)).find((i) => i?.ip) ?? withIp.find((i) => i.name === "mgmt")
    ?? managed.find((i) => i.role !== "wan") ?? managed[0] ?? withIp[0];
  if (mgmtIf?.ip) { id.mgmtIp = mgmtIf.ip; extra.mgmt_interface = mgmtIf.name; }
  id.hostname ??= first(raw, /^\s*set hostname\s+"?([^"\n]+)"?/m);

  // Management ACL: every non-wildcard admin/API user restricted, or a local-in-policy / trust-ip fence in front of the management services.
  const considered = [...admins.values()].filter((a) => !a.wildcard);
  const unrestricted = considered.filter((a) => !a.restricted.length);
  const mgmtIfaces = [...ifaces.values()].filter((i) => MGMT_SERVICES.some((svc) => i.allow.has(svc) || i.allow6.has(svc)));
  // local-in-policy fences management only when a restricted accept is followed by a deny-from-all that covers every
  // management interface of that VDOM.
  const localInAccepts = [...localIn.values()].filter((p) => p.enabled && p.action === "accept" && p.srcaddr.length > 0 && !p.srcaddr.includes("all"));
  const localInDenies = [...localIn.values()].filter((p) => p.enabled && p.action === "deny" && p.srcaddr.includes("all"));
  const fenced = (i: IfaceInfo) => localInDenies.some((p) => (p.scope || "root") === (i.vdom ?? "root") && (p.intf.includes("any") || p.intf.includes(i.name)));
  const localInOk = localInAccepts.length > 0 && localInDenies.length > 0 && (mgmtIfaces.length ? mgmtIfaces.every(fenced) : localInDenies.some((p) => p.intf.includes("any")));
  const trustIpOk = mgmtIfaces.length > 0 && mgmtIfaces.every((i) => i.trustIp);
  if (considered.length || localIn.size || trustIpOk) {
    const ok = (considered.length > 0 && unrestricted.length === 0) || localInOk || trustIpOk;
    const evs: Evidence[] = ok
      ? [...(considered.length && !unrestricted.length ? considered.flatMap((a) => a.restricted) : []), ...(localInOk ? [...localIn.values()].flatMap((p) => p.ev) : []), ...(trustIpOk ? mgmtIfaces.map((i) => i.trustIp as Evidence) : [])]
      : unrestricted.map((a) => a.edit);
    (evs.length ? evs : [{ line: 0, text: "no admin trusthost or local-in-policy observed" }]).forEach((ev) => b.set("management.mgmt_acl_applied", ok, ev));
    if (!ok) {
      unrestricted.filter((a) => !a.api).forEach((a) => b.add("management.unrestricted_admins", a.name, a.edit));
      unrestricted.filter((a) => a.api).forEach((a) => b.add("management.unrestricted_api_users", a.name, a.edit));
    }
  }
  const mfa = considered.filter((a) => !a.api);
  if (mfa.some((a) => a.twoFactor)) {
    const all = mfa.every((a) => a.twoFactor?.on);
    mfa.forEach((a) => b.set("auth.two_factor", all, a.twoFactor?.ev ?? a.edit));
  }
  // Remote AAA servers count only when an admin account is bound to them through remote-group > user group > member.
  for (const a of admins.values()) {
    if (!a.remote || !a.group) continue;
    for (const member of groups.get(a.group) ?? []) {
      const srv = servers.get(member);
      srv?.hosts.forEach((h, i) => b.add("auth.remote_auth_servers", h, srv.ev[i]));
    }
  }

  // Password policy: enabled, applied to admin passwords and requiring at least one character class.
  if (pwPolicy.seen) {
    const on = pwPolicy.status?.on ?? false;
    const forAdmins = pwPolicy.applyTo?.admin ?? true;
    const effective = on && forAdmins;
    const anchor = pwPolicy.status?.ev ?? pwPolicy.applyTo?.ev ?? pwPolicy.minLength?.ev;
    if (anchor) {
      b.set("auth.password_complexity", effective && pwPolicy.classes.length > 0, anchor);
      if (pwPolicy.applyTo) b.set("auth.password_complexity", effective && pwPolicy.classes.length > 0, pwPolicy.applyTo.ev);
      pwPolicy.classes.forEach((ev) => b.set("auth.password_complexity", effective, ev));
      if (effective) b.set("auth.min_password_length", pwPolicy.minLength?.v ?? 8, pwPolicy.minLength?.ev ?? anchor);
      else if (pwPolicy.status || pwPolicy.minLength) b.set("auth.min_password_length", 0, pwPolicy.minLength?.ev ?? anchor);
    }
  }

  // Logging destinations: per instance status, never a shared reset; secure only when the transport is actually encrypted.
  let destinations = 0, secureAll = true;
  const secureEv: Evidence[] = [];
  for (const x of logDests.values()) {
    if (x.override && !x.overrideOn) continue;
    const active = x.enabled ?? (x.kind !== "cloud" && Boolean(x.server));
    if (!active) continue;
    const host = x.kind === "cloud" ? "FortiGate Cloud (fortiguard)" : x.kind === "faz" ? `${x.server} (FortiAnalyzer)` : x.server;
    if (!host) continue;
    b.add("logging.remote_hosts", host, x.serverEv ?? x.firstEv);
    b.setTrue("logging.enabled", x.serverEv ?? x.firstEv);
    const secure = x.kind === "cloud" ? true : x.kind === "faz" ? x.enc !== "disable" : Boolean(x.reliable) && x.enc !== undefined && x.enc !== "disable";
    destinations++;
    secureAll &&= secure;
    const transport = [x.transportEv, x.encEv, ...(x.transportEv || x.encEv ? [] : [x.serverEv ?? x.firstEv])].filter((ev): ev is Evidence => Boolean(ev));
    secureEv.push(...transport);
    if (x.source) b.setTrue("logging.source_interface", x.source);
  }
  if (destinations) (secureEv.length ? secureEv : [{ line: 0, text: "remote logging destinations observed" }]).forEach((ev) => b.set("logging.remote_secure", secureAll, ev));

  const localLogs = [localLog.memory, localLog.disk].filter((x): x is Evidence & { on: boolean } => Boolean(x));
  if (localLogs.some((x) => x.on)) localLogs.filter((x) => x.on).forEach((x) => b.set("logging.buffered", true, { line: x.line, text: x.text }));
  else if (localLogs.length === 2) localLogs.forEach((x) => b.set("logging.buffered", false, { line: x.line, text: x.text }));

  if (eventFilter.size) {
    const ok = [...eventFilter.values()].every((f) => (f.event ?? true) && ((f.system ?? true) || (f.user ?? true)));
    [...eventFilter.values()].flatMap((f) => f.ev).forEach((ev) => b.set("logging.login_events", ok, ev));
  }

  // Firewall policy semantics: logged catch-all deny, and permit-any rules that make the implicit deny unreachable.
  const enabledPolicies = [...policies.values()].filter((p) => p.enabled);
  const catchAllDeny = enabledPolicies.filter((p) => p.action === "deny" && (p.log === "all" || p.log === "utm") && p.srcintf.includes("any") && p.dstintf.includes("any") && p.srcaddr.includes("all") && p.dstaddr.includes("all") && p.service.includes("ALL"));
  const permitAny = enabledPolicies.filter((p) => p.action === "accept" && p.srcaddr.includes("all") && p.dstaddr.includes("all") && p.service.includes("ALL") && anyIntf(p.srcintf));
  if (implicitLog.size || policies.size) {
    const scopes = new Set([...implicitLog.keys(), ...[...policies.values()].map((p) => p.scope)]);
    const ok = [...scopes].every((sc) => implicitLog.get(sc)?.on || catchAllDeny.some((p) => p.scope === sc));
    const evs = [...[...implicitLog.values()].map((x) => x.ev), ...catchAllDeny.flatMap((p) => p.ev)];
    (evs.length ? evs : [...policies.values()][0].ev.slice(0, 1)).forEach((ev) => b.set("acl.explicit_deny_logged", ok, ev));
  }
  if (permitAny.length && isFirewall) permitAny.flatMap((p) => p.ev).forEach((ev) => b.set("acl.default_deny", false, ev));

  // NTP: servers count only while ntpsync is on; FortiGuard is the default source; authentication must hold for every server.
  if (ntp.seen) {
    if (ntp.sync && !ntp.sync.on) b.set("time.ntp_servers", [], ntp.sync.ev);
    else if (ntp.type?.v === "custom") {
      const custom = [...ntp.servers.entries()].filter(([, s]) => s.server);
      if (!custom.length) b.set("time.ntp_servers", [], ntp.type.ev);
      custom.forEach(([, s]) => b.add("time.ntp_servers", s.server as string, s.ev));
      if (custom.length) {
        const allAuth = custom.every(([, s]) => s.auth?.on);
        custom.forEach(([sid, s]) => {
          b.set("time.ntp_authentication", allAuth, s.auth?.ev ?? s.ev);
          if (!s.auth?.on) b.add("time.unauthenticated_ntp_ids", sid, s.auth?.ev ?? s.ev);
        });
      }
    } else b.add("time.ntp_servers", "fortiguard (ntp.fortiguard.com)", ntp.type?.ev ?? ntp.sync?.ev);
  }

  // SNMP: disabled communities are inert; the ACL must cover every enabled community; v3 privacy for every user.
  const enabledComms = [...snmp.communities.values()].filter((c) => c.enabled && c.name);
  for (const c of enabledComms) {
    const name = c.name as string;
    b.add("snmp.v1v2c_communities", name, c.nameEv);
    if (["public", "private"].includes(name.toLowerCase())) { b.add("snmp.default_communities", name, c.nameEv); b.add("snmp.default_community_ids", c.id, c.nameEv); }
  }
  if (enabledComms.length) {
    const ok = enabledComms.every((c) => c.hosts > 0);
    enabledComms.filter((c) => ok || c.hosts === 0).forEach((c) => b.set("snmp.community_acl", ok, c.nameEv));
  }
  const v3 = [...snmp.users.values()].filter((u) => u.enabled);
  if (v3.length) {
    const priv = v3.every((u) => u.level === "auth-priv");
    v3.forEach((u) => { b.setTrue("snmp.v3_enabled", u.ev); b.set("snmp.v3_priv", priv, u.ev); });
  }
  if (snmp.sysinfo) b.set("snmp.enabled", snmp.sysinfo.on, snmp.sysinfo.ev);
  else if (enabledComms.length || v3.length) b.setTrue("snmp.enabled", enabledComms[0]?.nameEv ?? v3[0].ev);

  // BGP: `set as 0` is the full-configuration placeholder; every neighbor (own or inherited group password) must authenticate.
  const asn = bgp.as && bgp.as.v !== "0" && bgp.as.v !== "" ? bgp.as : undefined;
  const peers: Peer[] = [...bgp.neighbors.values(), ...[...bgp.ranges.values()].map((r) => ({ ...r, name: r.prefix ? `${r.prefix} (neighbor-range)` : r.name }))];
  if (asn || peers.length) {
    b.setTrue("routing.bgp_configured", asn?.ev ?? peers[0].edit);
    if (asn) b.set("routing.bgp_asn", asn.v, asn.ev);
    const authOf = (p: Peer) => p.password ?? (p.group ? bgp.groups.get(p.group)?.password : undefined);
    if (peers.length) {
      const allAuth = peers.every((p) => authOf(p));
      peers.forEach((p) => b.set("routing.bgp_auth", allAuth, authOf(p) ?? p.edit));
      peers.filter((p) => !authOf(p)).forEach((p) => (p.group && !bgp.groups.get(p.group)?.password ? b.add("routing.bgp_unauth_groups", p.group, p.edit) : b.add("routing.bgp_unauth_neighbors", p.name, p.edit)));
    }
  } else if (bgp.seen && bgp.as) b.set("routing.bgp_configured", false, bgp.as.ev);

  // OSPF: configured only with real areas/networks/interfaces or a router-id; text/none authentication is not authentication.
  const ospfConfigured = ospf.areas.size > 0 || ospf.ifaces.size > 0 || ospf.networks > 0 || (ospf.routerId !== undefined && ospf.routerId.v !== "0.0.0.0");
  if (ospfConfigured) {
    b.setTrue("routing.ospf_configured", ospf.routerId?.ev ?? [...ospf.areas.values(), ...ospf.ifaces.values()][0]?.edit ?? { line: 0, text: "config router ospf" });
    const weak = [...ospf.areas.values(), ...ospf.ifaces.values()].filter((x) => x.auth && !STRONG_OSPF_AUTH.includes(x.auth.v));
    const strong = [...ospf.areas.values(), ...ospf.ifaces.values()].filter((x) => x.auth && STRONG_OSPF_AUTH.includes(x.auth.v));
    const ok = weak.length === 0 && strong.length > 0;
    const evs = [...weak, ...strong].map((x) => x.auth?.ev as Evidence);
    (evs.length ? evs : [...ospf.areas.values(), ...ospf.ifaces.values()].map((x) => x.edit)).forEach((ev) => b.set("routing.ospf_auth", ok, ev));
    if (!evs.length && !ospf.areas.size && !ospf.ifaces.size) b.set("routing.ospf_auth", false, ospf.routerId?.ev ?? { line: 0, text: "no OSPF authentication configured" });
    ospf.areas.forEach((a, aid) => b.add("routing.ospf_areas", aid, a.edit));
    ospf.ifaces.forEach((i, name) => b.add("routing.ospf_interfaces", name, i.edit));
  } else if (ospf.seen && ospf.routerId) b.set("routing.ospf_configured", false, ospf.routerId.ev);

  // IPsec: weak proposals / DH groups per tunnel, grouped by table for remediation.
  const listFor: Record<string, string> = { "phase1-interface": "crypto.weak_ike_phase1", phase1: "crypto.weak_ike_phase1_policy", "phase2-interface": "crypto.weak_ike_phase2", phase2: "crypto.weak_ike_phase2_policy" };
  const weakTunnels = [...tunnels.values()].filter((t) => t.weak.length);
  if (weakTunnels.length) {
    weakTunnels.forEach((t) => { t.weak.forEach((ev) => b.set("crypto.weak_ike", true, ev)); b.add(listFor[t.table], t.name, t.weak[0]); });
  } else {
    const strong = [...tunnels.values()].find((t) => t.ev);
    if (strong) b.set("crypto.weak_ike", false, strong.ev);
  }

  if (!b.has("acl.count") && sections.has("firewall policy")) b.set("acl.count", 0, undefined);
  if (Object.keys(extra).length) id.extra = extra;

  const meaningful = lines.filter((l) => !isCommentOrBlank(l));
  const unrecognized = b.unrecognized(lines, isCommentOrBlank, (l) => {
    const e = entries.find((x) => x.line.n === l.n);
    return e ? `${e.context}${e.vdom ? ` [vdom ${e.vdom}]` : ""}` : undefined;
  });
  return {
    vendor: "fortinet-fortios",
    identity: id,
    model: b.model(),
    totalLines: lines.length,
    meaningfulLines: meaningful.length,
    recognized: meaningful.length - unrecognized.length,
    unrecognized,
    mappingsApplied: [],
  };
}
