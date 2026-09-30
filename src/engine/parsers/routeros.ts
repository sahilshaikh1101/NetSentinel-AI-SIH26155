import type { ParseResult } from "../types";
import { first, ModelBuilder, toLines, unquote, type Line } from "./util";

const isCommentOrBlank = (l: Line) => !l.text || l.text.startsWith("#");

interface Entry {
  menu: string; // e.g. "/ip service"
  verb: string; // set | add | remove | enable | disable | ...
  target?: string; // for "set telnet ..." the item name or a "[ find … ]" selector
  /** item name recovered from a `[ find name=… ]` selector */
  name?: string;
  kv: Record<string, string>;
  line: Line;
}

const KNOWN_MENUS = [
  "/interface", "/ip", "/system", "/user", "/snmp", "/tool", "/routing", "/queue", "/ppp", "/certificate", "/port", "/radius", "/lcd", "/disk", "/file",
  "/caps-man", "/mpls", "/ipv6", "/container", "/iot", "/special-login", "/zerotier", "/partitions", "/console", "/password", "/import", "/export",
  "/log", "/wireless", "/bridge", "/vlan", "/dude", "/wifi", "/wifiwave2", "/led", "/lora", "/gps", "/ups",
];

/**
 * Splits a RouterOS argument string into tokens, keeping `"quoted values"` and
 * `[ find … ]` selectors whole. Splitting on whitespace alone lets a quoted
 * comment such as `comment="… disabled=yes"` inject a bogus key/value pair.
 */
export function tokenizeArgs(rest: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  let depth = 0;
  for (let i = 0; i < rest.length; i++) {
    const c = rest[i];
    if (quoted) {
      cur += c;
      if (c === "\\" && i + 1 < rest.length) cur += rest[++i];
      else if (c === '"') quoted = false;
      continue;
    }
    if (c === '"') { quoted = true; cur += c; continue; }
    if (c === "[") { depth++; cur += c; continue; }
    if (c === "]") { depth = Math.max(0, depth - 1); cur += c; continue; }
    if (depth === 0 && /\s/.test(c)) { if (cur) out.push(cur); cur = ""; continue; }
    cur += c;
  }
  if (cur) out.push(cur);
  return out;
}

/** `[ find name=telnet ]` / `[ find default-name=ether1 ]` → the item name. */
function selectorName(target?: string): string | undefined {
  if (!target || !target.startsWith("[")) return undefined;
  const m = target.match(/\b(?:name|default-name)=("[^"]*"|[^\s\]]+)/);
  return m ? unquote(m[1]) : undefined;
}

/** RouterOS 7 accepts `/ip/service/set …`; `/export` never emits it but operators paste it. */
function normalizeMenuPath(text: string): string {
  const head = text.match(/^\/[\w-]+(?:\/[\w-]+)+/);
  if (!head) return text;
  return `/${head[0].replace(/\//g, " ").trim()}${text.slice(head[0].length)}`;
}

export function flattenRouterOS(lines: Line[]): { entries: Entry[]; structural: Set<number> } {
  const entries: Entry[] = [];
  const structural = new Set<number>();
  let menu = "";
  let buffer: { text: string; line: Line } | null = null;
  const flush = (text: string, line: Line) => {
    let t = normalizeMenuPath(text.trim());
    let m: RegExpMatchArray | null;
    if ((m = t.match(/^(\/[\w-]+(?:\s+[\w-]+)*)\s+(set|add|remove|enable|disable|print|export|reset)\b(.*)$/))) {
      // one-line form: "/system identity set name=X"
      menu = m[1];
      t = `${m[2]}${m[3]}`;
    } else if (/^\//.test(t)) {
      menu = t;
      structural.add(line.n);
      return;
    }
    const vm = t.match(/^(set|add|remove|enable|disable|import|export|reset|print)\b\s*(.*)$/);
    if (!vm) {
      entries.push({ menu, verb: "?", kv: {}, line });
      return;
    }
    const kv: Record<string, string> = {};
    let target: string | undefined;
    for (const tok of tokenizeArgs(vm[2])) {
      const eq = tok.indexOf("=");
      if (eq > 0 && !tok.startsWith("[")) kv[tok.slice(0, eq)] = unquote(tok.slice(eq + 1));
      else if (target === undefined) target = tok;
    }
    entries.push({ menu, verb: vm[1], target, name: selectorName(target), kv, line });
  };
  for (const l of lines) {
    if (isCommentOrBlank(l)) continue;
    const t = l.text;
    if (buffer) {
      buffer.text += " " + t.replace(/\\$/, "");
      structural.add(l.n);
      if (!t.endsWith("\\")) {
        flush(buffer.text, buffer.line);
        buffer = null;
      }
      continue;
    }
    if (t.endsWith("\\")) {
      buffer = { text: t.replace(/\\$/, ""), line: l };
      continue;
    }
    flush(t, l);
  }
  if (buffer) flush(buffer.text, buffer.line);
  return { entries, structural };
}

const yes = (v: string | undefined) => v === "yes" || v === "true";

/** `/ip service` items that ship enabled on a factory RouterOS. */
const SERVICE_DEFAULT_ON: Record<string, boolean> = { telnet: true, ftp: true, www: true, ssh: true, api: true, winbox: true, "api-ssl": true, "www-ssl": false };
/** Services an operator legitimately keeps: each must then carry an `address=` restriction. */
const CORE_MGMT_SERVICES = new Set(["ssh", "winbox", "www-ssl", "api-ssl"]);
const SERVICE_PARAM: Record<string, string> = {
  telnet: "management.telnet_enabled",
  ftp: "management.ftp_enabled",
  www: "management.http_enabled",
  "www-ssl": "management.https_enabled",
  ssh: "management.ssh_enabled",
  api: "management.api_http_enabled",
};

/** Firewall match attributes that narrow a rule, so it cannot be the catch-all deny. */
const NARROWING_MATCHES = [
  "connection-state", "connection-nat-state", "connection-type", "protocol", "dst-port", "src-port", "port", "src-address", "dst-address",
  "src-address-list", "dst-address-list", "src-address-type", "dst-address-type", "content", "layer7-protocol", "p2p", "tcp-flags", "tcp-mss",
  "icmp-options", "limit", "dst-limit", "connection-limit", "connection-bytes", "connection-mark", "packet-mark", "routing-mark", "routing-table",
  "src-mac-address", "time", "ipsec-policy", "packet-size", "ttl", "dscp", "fragment", "hotspot", "nth", "psd", "random", "tls-host", "priority",
  "per-connection-classifier", "address-list", "ingress-priority", "jump-target",
];

const BOGUS_HOSTS = new Set(["", "0.0.0.0", "::", "0.0.0.0/0", "::/0", "none"]);
const WIDE_INTERFACE_LISTS = new Set(["all", "static", "dynamic", "!dynamic", "!static", "!none"]);
/** Services that a factory RouterOS exposes even when `/export` prints nothing about them. */
const MISC_DEFAULT_ON = ["mac-server", "mac-winbox", "bandwidth-server"];

interface AddressEntry { ip: string; iface: string; comment: string; disabled: boolean }

function pickMgmtAddress(addrs: AddressEntry[]): string | undefined {
  const live = addrs.filter((a) => !a.disabled);
  const pool = live.length ? live : addrs;
  const hinted = pool.find((a) => /\b(mgmt|manage|management|oob|loopback)\b/i.test(`${a.comment} ${a.iface}`) || /^lo(\d|opback)?$/i.test(a.iface));
  if (hinted) return hinted.ip;
  const private4 = pool.find((a) => /^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(a.ip));
  return (private4 ?? pool[0])?.ip;
}

export function parseRouterOS(raw: string): ParseResult {
  const lines = toLines(raw);
  const b = new ModelBuilder("mikrotik-routeros");
  const id = b.identity;
  id.osVersion = first(raw, /by RouterOS\s+v?([\d.]+\S*)/) ?? first(raw, /^#\s*RouterOS\s+v?([\d.]+\S*)/m);
  id.model = first(raw, /^#\s*model\s*=\s*(.+)$/m);
  id.serial = first(raw, /^#\s*serial number\s*=\s*(\S+)/m);

  const major = parseInt(id.osVersion ?? "", 10);
  // Unknown version → assume the current generation: 7.x syntax is what a modern box takes.
  const ros7 = Number.isFinite(major) ? major >= 7 : true;

  const d = (k: string, v: string | number | boolean | string[], note: string) => b.setDefault(k, v, `Platform default — ${note}`);
  d("management.telnet_enabled", true, "telnet service is enabled unless 'disabled=yes'");
  d("management.ftp_enabled", true, "ftp service is enabled unless 'disabled=yes'");
  d("management.http_enabled", true, "www service is enabled unless 'disabled=yes'");
  d("management.https_enabled", false, "www-ssl is disabled unless a certificate is configured");
  d("management.ssh_enabled", true, "ssh service is enabled");
  d("management.ssh_version", 2, "RouterOS supports SSH protocol version 2 only");
  d("management.api_http_enabled", true, "api (plain) service is enabled unless 'disabled=yes'");
  d("crypto.strong_crypto", false, "/ip ssh strong-crypto defaults to no");
  d("crypto.rsa_modulus", 2048, "host-key-size defaults to 2048");
  d("auth.password_encryption", true, "RouterOS stores user secrets hashed");
  d("auth.login_lockout", false, "no login lockout facility unless firewall rate-limiting");
  d("logging.timestamps", true, "log entries are timestamped");
  d("logging.enabled", true, "logging to memory is on by default");
  d("logging.buffered", true, "memory logging action holds 100 lines");
  d("time.ntp_servers", [], "NTP client disabled unless configured");
  d("time.ntp_authentication", false, ros7 ? "NTP servers carry no auth-key unless one is configured" : "the RouterOS 6 NTP client has no authentication support");
  d("snmp.enabled", false, "SNMP disabled unless '/snmp set enabled=yes'");
  d("services.lldp_enabled", true, "neighbor discovery runs on all interfaces unless restricted");
  d("management.login_banner", false, "no /system note shown at login");
  d("management.mgmt_acl_applied", false, "no address= restriction on management services");
  d("management.idle_timeout_minutes", 9999, "no idle timeout for management sessions");
  d("services.ip_source_routing", false, "/ip settings accept-source-route defaults to no");
  d("services.proxy_arp", false, "proxy-arp disabled unless configured per interface");
  d("services.icmp_redirects", true, "ICMP redirects sent unless 'send-redirects=no'");
  d("services.directed_broadcast", false, "directed broadcast not forwarded");
  d("services.unicast_rpf", false, "rp-filter defaults to no");
  d("auth.aaa_enabled", false, "use-radius=no");
  // An empty /ip firewall filter means the input chain accepts everything.
  d("acl.default_deny", false, "the input chain has no terminating drop unless /ip firewall filter provides one");
  d("acl.external_ingress_filter", false, "no /ip firewall filter rule guards the input chain");

  const { entries, structural } = flattenRouterOS(lines);
  structural.forEach((n) => b.mark(n));

  // Cross-line accumulators: a verdict that depends on every entry in a menu
  // cannot be decided while the first one is being read.
  const services = new Map<string, { enabled: boolean; address: boolean; line: Line }>();
  const addresses: AddressEntry[] = [];
  const misc = new Map<string, { on: boolean; line?: Line }>();
  const bgpUnauth: string[] = [];
  const ospfUnauth: string[] = [];
  const ntp = { seen: false, enabled: true, servers: [] as string[], unauth: [] as string[], authed: false, line: undefined as Line | undefined };
  const snmpV1: { name: string; restricted: boolean; line: Line }[] = [];
  const v3 = { any: false, priv: false, plain: false, line: undefined as Line | undefined };
  const note = { text: undefined as string | undefined, show: undefined as boolean | undefined, line: undefined as Line | undefined };
  let bgpLine: Line | undefined;
  let ospfLine: Line | undefined;
  let filterRules = 0;
  let explicitMisc = false;

  const setMisc = (name: string, on: boolean, l: Line) => { misc.set(name, { on, line: l }); explicitMisc = true; b.mark(l); };

  for (const e of entries) {
    const { menu, verb, target, name, kv, line: l } = e;
    let handled = true;
    const disabled = kv.disabled;
    switch (menu) {
      case "/system identity":
        if (kv.name) {
          // "MikroTik" is the factory identity: the device has not been named.
          id.hostname = kv.name;
          b.set("identity.hostname", kv.name, l);
          b.set("identity.hostname_set", kv.name.toLowerCase() !== "mikrotik", l);
        } else b.mark(l);
        break;
      case "/ip service": {
        const svc = (target && !target.startsWith("[") ? target : name) ?? "";
        const fallback = SERVICE_DEFAULT_ON[svc] ?? true;
        const enabled = verb === "enable" ? true : verb === "disable" ? false : disabled === undefined ? fallback : !yes(disabled);
        const param = SERVICE_PARAM[svc];
        if (param) b.set(param, enabled, l);
        if (svc) services.set(svc, { enabled, address: Boolean(kv.address) && !BOGUS_HOSTS.has(kv.address), line: l });
        b.mark(l);
        break;
      }
      case "/ip ssh":
        if (kv["strong-crypto"] !== undefined) b.set("crypto.strong_crypto", yes(kv["strong-crypto"]), l);
        // A server that still offers the "none" cipher is not hardened whatever strong-crypto says.
        if (yes(kv["allow-none-crypto"])) b.set("crypto.strong_crypto", false, l);
        if (kv["host-key-size"]) b.set("crypto.rsa_modulus", parseInt(kv["host-key-size"], 10), l);
        b.mark(l);
        break;
      case "/system logging action":
        if (yes(disabled)) { b.mark(l); break; }
        if (kv.remote && !BOGUS_HOSTS.has(kv.remote)) { b.add("logging.remote_hosts", kv.remote, l); b.setTrue("logging.enabled", l); }
        if (kv["src-address"]) b.setTrue("logging.source_interface", l);
        if (kv["memory-lines"] || kv["disk-file-name"]) b.setTrue("logging.buffered", l);
        b.mark(l);
        break;
      case "/system logging":
        if (yes(disabled)) { b.mark(l); break; }
        b.setTrue("logging.enabled", l);
        if (/(^|,)\s*!?\s*(account|info|system)\b/.test(kv.topics ?? "") && !/!\s*(account|info|system)\b/.test(kv.topics ?? "")) b.setTrue("logging.login_events", l);
        break;
      case "/system ntp client":
      case "/system sntp client":
        ntp.seen = true;
        ntp.line ??= l;
        if (kv.enabled !== undefined) ntp.enabled = yes(kv.enabled);
        for (const key of ["servers", "primary-ntp", "secondary-ntp", "server-dns-names"]) {
          if (kv[key]) kv[key].split(",").map((s) => s.trim()).filter((s) => !BOGUS_HOSTS.has(s)).forEach((s) => ntp.servers.push(s));
        }
        b.mark(l);
        break;
      case "/system ntp client servers":
        ntp.seen = true;
        ntp.line ??= l;
        if (kv.address && !BOGUS_HOSTS.has(kv.address) && !yes(disabled)) {
          ntp.servers.push(kv.address);
          if (kv["auth-key"] && kv["auth-key"] !== "none") ntp.authed = true;
          else ntp.unauth.push(kv.address);
        }
        b.mark(l);
        break;
      case "/system ntp key":
        if (kv.key || kv.id) ntp.authed = true;
        b.mark(l);
        break;
      case "/system clock":
        if (kv["time-zone-name"] || kv["time-zone-autodetect"]) b.setTrue("time.timezone_set", l); else b.mark(l);
        break;
      case "/snmp":
        if (kv.enabled !== undefined) b.set("snmp.enabled", yes(kv.enabled), l);
        if (kv["trap-target"]) kv["trap-target"].split(",").map((s) => s.trim()).filter((h) => !BOGUS_HOSTS.has(h)).forEach((h) => b.add("snmp.trap_hosts", h, l));
        if (kv["trap-community"] && kv["trap-version"] !== "3") {
          b.add("snmp.v1v2c_communities", kv["trap-community"], l);
          if (["public", "private"].includes(kv["trap-community"].toLowerCase())) {
            b.add("snmp.default_communities", kv["trap-community"], l);
            b.add("snmp.default_community_ids", kv["trap-community"], l);
          }
        }
        b.mark(l);
        break;
      case "/snmp community": {
        const cname = kv.name ?? name ?? (target && !target.startsWith("[") ? target : undefined);
        // security=authorized|private is an SNMPv3 USM entry, not a v1/v2c community string.
        const isV3 = kv.security === "authorized" || kv.security === "private";
        const restricted = Boolean(kv.addresses) && !BOGUS_HOSTS.has(kv.addresses);
        if (cname) {
          if (!isV3) {
            snmpV1.push({ name: cname, restricted, line: l });
            b.add("snmp.v1v2c_communities", cname, l);
            if (["public", "private"].includes(cname.toLowerCase())) {
              b.add("snmp.default_communities", cname, l);
              b.add("snmp.default_community_ids", cname, l);
            }
            if (yes(kv["write-access"])) b.add("snmp.rw_communities", cname, l);
          } else if (yes(kv["write-access"])) {
            b.mark(l);
          }
        }
        if (isV3) {
          v3.any = true;
          v3.line ??= l;
          if (kv.security === "private" && kv["encryption-protocol"]) v3.priv = true;
          else v3.plain = true;
        }
        b.mark(l);
        break;
      }
      case "/user": {
        const uname = kv.name ?? name ?? (target && !target.startsWith("[") ? target : undefined);
        if (!uname) { b.mark(l); break; }
        b.add("auth.local_users", uname, l);
        if (!yes(disabled)) {
          if (kv.address === undefined || BOGUS_HOSTS.has(kv.address)) b.add("management.unrestricted_admins", uname, l);
          // An export that carries a password carries it in the clear — empty means no password at all.
          if (kv.password !== undefined) {
            b.inc("auth.weak_password_hashes", l);
            b.add("auth.weak_local_users", uname, l);
          }
        }
        break;
      }
      case "/user aaa":
        if (kv["use-radius"] !== undefined) { b.set("auth.aaa_enabled", yes(kv["use-radius"]), l); b.set("auth.aaa_authentication_login", yes(kv["use-radius"]), l); }
        if (kv.accounting !== undefined) b.set("auth.aaa_accounting", yes(kv.accounting), l);
        b.mark(l);
        break;
      case "/user settings":
        if (kv["minimum-password-length"]) b.set("auth.min_password_length", parseInt(kv["minimum-password-length"], 10), l);
        if (kv["minimum-categories"]) b.set("auth.password_complexity", parseInt(kv["minimum-categories"], 10) > 1, l);
        b.mark(l);
        break;
      case "/radius":
        // Only a server that serves "login" authenticates administrators.
        if (kv.address && (kv.service === undefined || /\blogin\b/.test(kv.service)) && !yes(disabled)) b.add("auth.remote_auth_servers", kv.address, l);
        else b.mark(l);
        break;
      case "/ip address":
        if ((verb === "add" || verb === "set") && kv.address) {
          const ip = kv.address.match(/^(\d{1,3}(?:\.\d{1,3}){3})/)?.[1];
          if (ip) addresses.push({ ip, iface: kv.interface ?? "", comment: kv.comment ?? "", disabled: yes(disabled) });
        }
        b.mark(l);
        break;
      case "/ip firewall filter":
        if (verb === "add" && !yes(disabled)) {
          filterRules++;
          const denies = kv.action === "drop" || kv.action === "reject" || kv.action === "tarpit";
          if (kv.chain === "input") {
            if (denies) {
              b.setTrue("acl.external_ingress_filter", l);
              // Only a rule with no narrowing match is the terminating deny; "drop invalid" is not.
              if (!NARROWING_MATCHES.some((k) => k in kv)) b.setTrue("acl.default_deny", l);
            }
            // The MikroTik brute-force recipe: stage the source into a list, then drop it.
            if (kv.action === "add-src-to-address-list") b.setTrue("auth.login_lockout", l);
          }
          if (denies && yes(kv.log)) b.setTrue("acl.explicit_deny_logged", l);
          if (kv["in-interface-list"] || kv["in-interface"]) b.setTrue("acl.external_ingress_filter", l);
        }
        b.mark(l);
        break;
      case "/tool mac-server":
        setMisc("mac-server", Boolean(kv["allowed-interface-list"]) && kv["allowed-interface-list"] !== "none", l);
        break;
      case "/tool mac-server mac-winbox":
        setMisc("mac-winbox", Boolean(kv["allowed-interface-list"]) && kv["allowed-interface-list"] !== "none", l);
        break;
      case "/tool bandwidth-server":
        setMisc("bandwidth-server", kv.enabled === undefined || yes(kv.enabled), l);
        break;
      case "/tool romon":
        setMisc("romon", yes(kv.enabled), l);
        break;
      case "/ip neighbor discovery-settings": {
        const dl = kv["discover-interface-list"];
        // A named interface list is a restriction; "all"/"static"/"!dynamic" are not.
        if (dl !== undefined) b.set("services.lldp_enabled", WIDE_INTERFACE_LISTS.has(dl), l);
        else b.mark(l);
        break;
      }
      case "/ip dns":
        if (kv["allow-remote-requests"] !== undefined) setMisc("dns-remote-requests", yes(kv["allow-remote-requests"]), l);
        else b.mark(l);
        break;
      case "/ip proxy":
        setMisc("web-proxy", yes(kv.enabled), l);
        break;
      case "/ip socks":
        setMisc("socks", yes(kv.enabled), l);
        break;
      case "/ip upnp":
        setMisc("upnp", yes(kv.enabled), l);
        break;
      case "/ip smb":
        setMisc("smb", yes(kv.enabled), l);
        break;
      case "/ip cloud":
        if (kv["ddns-enabled"] !== undefined || kv["back-to-home-vpn"] !== undefined) setMisc("cloud-ddns", yes(kv["ddns-enabled"]) || yes(kv["back-to-home-vpn"]), l);
        else b.mark(l);
        break;
      case "/ip settings":
        if (kv["rp-filter"]) b.set("services.unicast_rpf", kv["rp-filter"] !== "no", l);
        if (kv["send-redirects"]) b.set("services.icmp_redirects", yes(kv["send-redirects"]), l);
        if (kv["accept-source-route"] !== undefined) b.set("services.ip_source_routing", yes(kv["accept-source-route"]), l);
        b.mark(l);
        break;
      case "/system note":
        if (kv.note !== undefined) note.text = kv.note;
        if (kv["show-at-login"] !== undefined) note.show = yes(kv["show-at-login"]);
        note.line ??= l;
        b.mark(l);
        break;
      case "/routing bgp connection":
      case "/routing bgp peer":
        if (verb === "add" || verb === "set") {
          b.setTrue("routing.bgp_configured", l);
          bgpLine ??= l;
          // Prefer the entry name: `/routing bgp … set [ find name=… ]` is how remediation selects a peer.
          if (!kv["tcp-md5-key"] && !yes(disabled)) bgpUnauth.push(kv.name ?? name ?? kv["remote.address"] ?? kv["remote-address"] ?? target ?? "<peer>");
        }
        b.mark(l);
        break;
      case "/routing ospf interface-template":
      case "/routing ospf interface":
        if (verb === "add" || verb === "set") {
          b.setTrue("routing.ospf_configured", l);
          ospfLine ??= l;
          const auth = (kv.auth && kv.auth !== "none") || (kv.authentication && kv.authentication !== "none");
          const where = kv.interfaces ?? kv.interface ?? kv.area ?? kv.name ?? name ?? target ?? "<interface>";
          b.add("routing.ospf_interfaces", where, l);
          if (!auth && !yes(disabled)) ospfUnauth.push(where);
        }
        b.mark(l);
        break;
      case "/routing ospf instance":
      case "/routing ospf area":
        b.setTrue("routing.ospf_configured", l);
        if (kv.area || kv.name) b.add("routing.ospf_areas", kv.name ?? kv.area ?? "backbone", l);
        break;
      case "/ip ipsec proposal":
      case "/ip ipsec profile":
        if (/\b(3des|des|md5|sha1|modp768|modp1024|modp1536|ec2n\d+|ecp192)\b/.test(`${kv["enc-algorithms"] ?? ""} ${kv["auth-algorithms"] ?? ""} ${kv["enc-algorithm"] ?? ""} ${kv["hash-algorithm"] ?? ""} ${kv["dh-group"] ?? ""} ${kv["pfs-group"] ?? ""}`)) b.setTrue("crypto.weak_ike", l);
        else if (!b.has("crypto.weak_ike")) b.set("crypto.weak_ike", false, l);
        else b.mark(l);
        break;
      case "/interface bridge":
      case "/interface ethernet":
        b.mark(l);
        break;
      default:
        handled = false;
    }
    if (!handled) {
      if (/^\/interface (gre|eoip|ipip|l2tp|pptp|sstp|ovpn|wireguard|6to4|vxlan)/.test(menu) && verb === "add") b.inc("identity.tunnels", l);
      else if (/^\/interface (bridge|ethernet|vlan|list|wireless|wifi|bonding|pppoe|lte|veth|ovpn|eoip|gre|detect-internet)/.test(menu)) b.mark(l);
      else if (/^\/ip (address|route|dhcp-client|dhcp-server|pool|firewall (nat|mangle|raw|address-list|connection|service-port|layer7)|cloud|hotspot|traffic-flow|kid-control|smb|arp|neighbor|dns static|dhcp-relay|vrf|tftp|ssh|proxy|socks|upnp)/.test(menu)) b.mark(l);
      else if (/^\/system (package|scheduler|script|routerboard|watchdog|resource|leds|console|logging|health|hardware|swos|note|ntp|clock|identity|upgrade|backup)/.test(menu)) b.mark(l);
      else if (/^\/(queue|ppp|certificate|port|lcd|disk|file|caps-man|mpls|ipv6|container|iot|special-login|zerotier|partitions|console|dude|led|lora|gps|ups|user group|radius incoming|snmp|tool (graphing|sniffer|traffic-monitor|e-mail|netwatch|fetch|mac-server ping|romon))/.test(menu)) b.mark(l);
      else if (KNOWN_MENUS.includes(menu.split(" ")[0]) && verb !== "?") b.mark(l);
    }
  }

  // ── Cross-entry verdicts ────────────────────────────────────────────────
  if (services.size) {
    const live = Array.from(services.entries()).filter(([, s]) => s.enabled);
    const openCore = live.filter(([n, s]) => CORE_MGMT_SERVICES.has(n) && !s.address);
    const restricted = live.filter(([, s]) => s.address);
    const evidence = (openCore.length ? openCore : restricted).map(([, s]) => s.line);
    for (const l of evidence) b.set("management.mgmt_acl_applied", openCore.length === 0, l);
  }
  id.mgmtIp = pickMgmtAddress(addresses) ?? first(raw, /\/ip address[\s\S]*?add address=(\d{1,3}(?:\.\d{1,3}){3})/);

  for (const name of MISC_DEFAULT_ON) if (!misc.has(name)) misc.set(name, { on: true });
  const miscOn = Array.from(misc.entries()).filter(([, s]) => s.on);
  if (explicitMisc) {
    const miscEv = miscOn.map(([, s]) => s.line).filter((l): l is Line => Boolean(l));
    b.set("services.misc_enabled", miscOn.map(([n]) => n), miscEv[0]);
    for (const l of miscEv.slice(1)) b.set("services.misc_enabled", miscOn.map(([n]) => n), l);
  } else {
    d("services.misc_enabled", miscOn.map(([n]) => n), "mac-server, mac-winbox and bandwidth-server ship enabled and /export omits default values");
  }

  if (ntp.seen && ntp.line) {
    const servers = Array.from(new Set(ntp.servers));
    b.set("time.ntp_servers", ntp.enabled ? servers : [], ntp.line);
    if (ntp.authed) b.set("time.ntp_authentication", true, ntp.line);
    else if (ntp.enabled && ntp.unauth.length) b.set("time.unauthenticated_ntp_ids", Array.from(new Set(ntp.unauth)), ntp.line);
  }

  if (snmpV1.length) {
    const open = snmpV1.filter((c) => !c.restricted);
    for (const c of open.length ? open : snmpV1) b.set("snmp.community_acl", open.length === 0, c.line);
  }
  if (v3.any && v3.line) {
    b.set("snmp.v3_enabled", true, v3.line);
    // A USM entry without privacy drags the whole agent below authPriv.
    b.set("snmp.v3_priv", v3.priv && !v3.plain, v3.line);
  }

  if (bgpLine) {
    b.set("routing.bgp_auth", bgpUnauth.length === 0, bgpLine);
    if (bgpUnauth.length) b.set("routing.bgp_unauth_neighbors", Array.from(new Set(bgpUnauth)), bgpLine);
  }
  if (ospfLine) b.set("routing.ospf_auth", ospfUnauth.length === 0, ospfLine);

  if (note.line) b.set("management.login_banner", Boolean(note.text) && note.show !== false, note.line);
  if (filterRules > 0) b.set("acl.count", filterRules, undefined);
  b.set("identity.routeros_7plus", ros7, undefined);

  const wireless = /^\/(interface (wireless|wifi|wifiwave2)|caps-man)\b/m.test(raw);
  id.role = /^(CRS|CSS)\d/i.test(id.model ?? "") ? "switch" : wireless ? "wireless router" : "router";

  const meaningful = lines.filter((l) => !isCommentOrBlank(l));
  const unrecognized = b.unrecognized(lines, isCommentOrBlank, (l) => entries.find((e) => e.line.n === l.n)?.menu);
  return {
    vendor: "mikrotik-routeros",
    identity: id,
    model: b.model(),
    totalLines: lines.length,
    meaningfulLines: meaningful.length,
    recognized: meaningful.length - unrecognized.length,
    unrecognized,
    mappingsApplied: [],
  };
}
