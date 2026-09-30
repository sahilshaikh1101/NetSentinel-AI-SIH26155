import type { ParamValue, ParseResult } from "../types";
import { first, hasWeakCipher, ModelBuilder, toLines, unquote, type Line } from "./util";

const isCommentOrBlank = (l: Line) => !l.text || l.text.startsWith("#");

const KNOWN_ROOTS = [
  "deviceconfig", "mgt-config", "shared", "network", "rulebase", "address", "address-group", "service", "service-group", "zone", "profiles",
  "profile-group", "application-group", "application-filter", "external-list", "tag", "import", "vsys", "log-settings", "schedule", "region",
  "dynamic-user-group", "pre-rulebase", "post-rulebase", "readonly", "template", "template-stack", "device-group", "config", "users", "user-id-collector",
  "application", "threats", "setting", "global-protect", "certificate", "ssl-decrypt", "response-page", "botnet", "user-id-agent",
  "ts-agent", "device-quarantine", "iot", "policy", "sdwan", "plugins", "vm-info-source", "log-collector", "log-collector-group", "display-name",
];

/** Header keys that a `show system info` paste puts in front of the configuration. */
const HEADER_KEY = /^[A-Za-z][\w-]*:\s*\S/;
/** `admin@PA-FW(active)> ` / `admin@PA-FW# ` terminal prompts. */
const PROMPT = /^[\w.-]+@[\w.()-]+\s*[>#]/;

/** Objects that every PAN-OS ships in its factory configuration. */
const FACTORY_CRYPTO = /^(default|Suite-B-GCM-128|Suite-B-GCM-256)$/i;
/** permitted-ip entries that restrict nothing. */
const ANY_SOURCE = /^(0\.0\.0\.0(\/0)?|::(\/0)?|any)$/i;

const WEAK_IKE: Record<string, RegExp> = {
  encryption: /\b(des|3des|null)\b/i,
  hash: /\b(md5|sha1)\b/i,
  authentication: /\b(md5|sha1)\b/i,
  "dh-group": /\bgroup[125]\b/i,
};

const XML_ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", "#34": '"', "#39": "'" };
const unescapeXml = (s: string) => s.replace(/&(#?\w+);/g, (m, e: string) => XML_ENTITIES[e] ?? m);
/** Quote a set-format token that carries whitespace, the way PAN-OS prints it. */
const q = (v: string) => (/\s/.test(v) ? `"${v.replace(/"/g, "'")}"` : v);

interface Frame {
  tag: string;
  /** path segment contributed by this element ("" for wrappers that are dropped) */
  seg: string;
  text: string;
  members: string[];
  emitted: boolean;
}

/**
 * Minimal XML -> set-format converter for PAN-OS XML exports and XML API
 * responses (no DOM dependency). `<response>/<result>/<config>/<devices>`
 * wrappers, the `localhost.localdomain` device entry and the single-vsys
 * `vsys1` prefix are dropped, `<entry name="x">` becomes a bare (quoted) name
 * and consecutive `<member>` children collapse into `[ a b ]`, so the result
 * is the same set syntax `show config running` prints.
 */
export function panosXmlToSet(xml: string): string {
  const out: string[] = [];
  const stack: Frame[] = [];
  const src = xml
    .replace(/<\?[\s\S]*?\?>/g, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");
  const re = /<\/([\w:.-]+)\s*>|<([\w:.-]+)((?:"[^"]*"|'[^']*'|[^>"'])*?)(\/?)>|([^<]+)/g;
  const emit = (path: string, value?: string) => {
    const p = path.replace(/^vsys vsys1 /, "");
    if (!p) return;
    out.push(value === undefined || value === "" ? `set ${p}` : `set ${p} ${value}`);
    for (const f of stack) f.emitted = true;
  };
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    if (m[5] !== undefined) {
      const t = unescapeXml(m[5]).replace(/\s+/g, " ").trim();
      const top = stack[stack.length - 1];
      if (t && top) top.text += top.text ? ` ${t}` : t;
      continue;
    }
    if (m[1] !== undefined) {
      const f = stack.pop();
      if (!f) continue;
      const parent = stack[stack.length - 1];
      if (f.tag === "member") {
        if (parent && f.text) parent.members.push(f.text);
        continue;
      }
      const path = [...stack.map((x) => x.seg), f.seg].filter(Boolean).join(" ");
      if (f.members.length) emit(path, `[ ${f.members.map(q).join(" ")} ]`);
      else if (f.text) emit(path, q(f.text));
      else if (!f.emitted) emit(path);
      else if (parent) parent.emitted = true;
      continue;
    }
    const tag = m[2];
    const attrs = m[3] ?? "";
    const selfClose = m[4] === "/";
    const nameAttr = attrs.match(/\bname\s*=\s*"([^"]*)"/) ?? attrs.match(/\bname\s*=\s*'([^']*)'/);
    const parent = stack[stack.length - 1];
    let seg: string;
    if (tag === "entry") seg = parent?.tag === "devices" ? "" : q(unescapeXml(nameAttr?.[1] ?? ""));
    else if (tag === "config" || tag === "response" || tag === "result" || tag === "devices") seg = "";
    else seg = tag;
    if (selfClose) {
      emit([...stack.map((x) => x.seg), seg].filter(Boolean).join(" "));
      continue;
    }
    stack.push({ tag, seg, text: "", members: [], emitted: false });
  }
  return out.join("\n");
}

interface Profile {
  svc: Map<string, boolean>;
  lines: Map<string, Line>;
  permitted: string[];
  permitLines: Line[];
}

interface SyslogServer {
  secure?: boolean;
  line?: Line;
}

export function parsePanOS(rawInput: string): ParseResult {
  const isXml = rawInput.trimStart().startsWith("<");
  const raw = isXml ? panosXmlToSet(rawInput) : rawInput;
  const lines = toLines(raw);
  const b = new ModelBuilder("paloalto-panos");
  const id = b.identity;
  id.hostname = first(raw, /^set deviceconfig system hostname\s+"?([^"\n]+)"?/m) ?? first(rawInput, /^hostname:\s*(\S+)/m);
  id.serial = first(rawInput, /^serial:\s*(\S+)/m) ?? first(rawInput, /^#\s*serial\s*[:=]\s*(\S+)/mi);
  id.model = first(rawInput, /^model:\s*(\S+)/m) ?? first(rawInput, /^#\s*model\s*[:=]\s*(\S+)/mi);
  // The version of an XML export lives on <config>, which only exists in the original input.
  id.osVersion = first(rawInput, /^sw-version:\s*(\S+)/m) ?? first(rawInput, /^#\s*(?:sw-)?version\s*[:=]\s*(\S+)/mi)
    ?? first(rawInput, /<config[^>]*\bdetail-version="([^"]+)"/i) ?? first(rawInput, /<config[^>]*\bversion="([\d.]+)"/i);
  id.mgmtIp = first(raw, /^set deviceconfig system ip-address\s+(\S+)/m) ?? first(rawInput, /^ip-address:\s*(\S+)/m);
  id.role = /^set (template|template-stack|device-group|log-collector-group)\s/m.test(raw) ? "manager" : "firewall";

  const d = (k: string, v: string | number | boolean, note: string) => b.setDefault(k, v, `Platform default — ${note}`);
  d("management.telnet_enabled", false, "management telnet is disabled unless 'service disable-telnet no'");
  d("management.http_enabled", false, "management http is disabled unless 'service disable-http no'");
  d("management.https_enabled", true, "management HTTPS is enabled");
  d("management.ssh_enabled", true, "management SSH is enabled");
  d("management.ssh_version", 2, "PAN-OS only supports SSHv2");
  d("management.idle_timeout_minutes", 60, "idle-timeout defaults to 60 minutes");
  d("auth.password_encryption", true, "PAN-OS stores administrator password hashes (phash)");
  d("auth.login_lockout", false, "admin-lockout failed-attempts defaults to 0 (disabled)");
  d("logging.timestamps", true, "PAN-OS logs carry receive/generate timestamps");
  d("logging.enabled", true, "system/config logs are always generated locally");
  d("logging.buffered", true, "logs are stored on the local log database");
  d("management.login_banner", false, "no login-banner configured");
  d("management.mgmt_acl_applied", false, "no permitted-ip on the management interface");
  d("snmp.enabled", false, "SNMP service disabled");
  d("time.ntp_authentication", false, "no NTP authentication configured");
  d("services.ip_source_routing", true, "source-routed packets are forwarded unless a zone protection profile discards them");
  d("services.icmp_redirects", false, "no ICMP redirects by default");
  d("services.directed_broadcast", false, "directed broadcasts not forwarded");
  d("acl.default_deny", true, "interzone-default rule denies traffic");
  d("acl.explicit_deny_logged", false, "interzone-default rule does not log unless 'log-end yes'");
  d("auth.aaa_enabled", false, "administrators authenticate against the local database");
  d("crypto.strong_crypto", false, "default SSH management profile allows CBC ciphers");
  d("crypto.tls_min_version", "1.0", "without an SSL/TLS service profile the web interface accepts TLS 1.0");

  /** Set a value and attach every evidence line that supports it. */
  const setAll = (key: string, value: ParamValue, evs: (Line | undefined)[]) => {
    const seen = evs.filter((l): l is Line => Boolean(l));
    if (!seen.length) { b.set(key, value, undefined); return; }
    for (const l of seen) b.set(key, value, l);
  };

  // ── deferred state: PAN-OS needs whole-file resolution, not last-line-wins ──
  const mgtSvc = new Map<string, boolean>();
  const mgtSvcLine = new Map<string, Line>();
  const mgtPermitted: string[] = [];
  const mgtPermitLines: Line[] = [];
  const profiles = new Map<string, Profile>();
  const boundProfiles = new Set<string>();
  const boundLines = new Map<string, Line>();
  const sshProfiles = new Map<string, { weak: boolean; line: Line }>();
  let sshLegacy: { weak: boolean; line: Line } | undefined;
  let sshBound: { name: string; line: Line } | undefined;
  const tlsProfiles = new Map<string, { version: string; line: Line }>();
  let tlsBound: { name: string; line: Line } | undefined;
  const ikeProfiles = new Map<string, { weak: boolean; line: Line }>();
  const ipsecProfiles = new Map<string, { weak: boolean; line: Line }>();
  const ikeRefs = new Set<string>();
  const ipsecRefs = new Set<string>();
  const ntpAuth = new Map<string, { ok: boolean; line: Line }>();
  const syslogServers = new Map<string, SyslogServer>();
  const matchLists = new Map<string, { filter?: string; forwards: boolean; line: Line }>();
  const authProfiles = new Map<string, { method: string; line: Line }>();
  const authProfileServer = new Map<string, string>();
  const authProfileLockout = new Map<string, { attempts: number; line: Line }>();
  const serverProfiles = new Map<string, { addresses: string[]; line: Line }>();
  const adminProfiles = new Map<string, Line>();
  const snmpV3Priv: Line[] = [];
  const zppDiscard = new Map<string, Set<string>>();
  const zones = new Map<string, { layer3: boolean; zpp?: string; line: Line }>();
  const rules = new Map<string, { action?: string; logged: boolean; line: Line }>();
  const interzone = new Map<string, { action: string; line: Line }>();
  const bgpPeers = new Map<string, { authenticated: boolean; target: string; line: Line }>();
  const ospfIfaces = new Map<string, { authenticated: boolean; target: string; line: Line }>();
  let adminLockout: { attempts: number; line: Line } | undefined;
  let localUsers = 0;

  const profile = (name: string): Profile => {
    let p = profiles.get(name);
    if (!p) { p = { svc: new Map(), lines: new Map(), permitted: [], permitLines: [] }; profiles.set(name, p); }
    return p;
  };

  for (const l of lines) {
    if (isCommentOrBlank(l)) continue;
    const m0 = l.text.match(/^set\s+(.*)$/);
    if (!m0) {
      const t = l.text;
      let hm: RegExpMatchArray | null;
      if ((hm = t.match(/^operational-mode:\s*(\S+)/))) { b.set("crypto.fips_mode", /fips/i.test(hm[1]), l); continue; }
      if ((hm = t.match(/^(multi-vsys|advanced-routing):\s*(\S+)/))) { id.extra = { ...id.extra, [hm[1]]: hm[2] }; b.mark(l); continue; }
      if (HEADER_KEY.test(t) || PROMPT.test(t) || /^\[edit/.test(t) || /^(Entering|Exiting) configuration mode/i.test(t)) b.mark(l);
      continue;
    }
    let p = m0[1];
    // Multi-vsys: every policy/zone line is prefixed with the vsys it belongs to.
    let vsys = "";
    const vm = p.match(/^vsys ("[^"]+"|\S+)\s+(.*)$/);
    if (vm) { vsys = unquote(vm[1]); p = vm[2]; }
    let m: RegExpMatchArray | null;
    if (/^deviceconfig system hostname\s/.test(p)) { b.setTrue("identity.hostname_set", l); continue; }
    if (/^deviceconfig system domain\s/.test(p)) { b.setTrue("identity.domain_set", l); continue; }
    if (/^deviceconfig system timezone\s/.test(p)) { b.setTrue("time.timezone_set", l); continue; }
    if (/^deviceconfig system login-banner\s/.test(p)) { b.setTrue("management.login_banner", l); continue; }
    if ((m = p.match(/^deviceconfig system service disable-(telnet|http|https|ssh|snmp|icmp|userid-service|userid-syslog-listener-ssl|userid-syslog-listener-udp)\s+(yes|no)/))) {
      if (["telnet", "http", "https", "ssh", "snmp"].includes(m[1])) { mgtSvc.set(m[1], m[2] === "no"); mgtSvcLine.set(m[1], l); }
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^deviceconfig system permitted-ip\s+("[^"]+"|\S+)/))) { mgtPermitted.push(unquote(m[1])); mgtPermitLines.push(l); b.mark(l); continue; }
    if ((m = p.match(/^deviceconfig system ntp-servers (primary|secondary)-ntp-server ntp-server-address\s+(\S+)/))) { b.add("time.ntp_servers", m[2], l); continue; }
    if ((m = p.match(/^deviceconfig system ntp-servers (primary|secondary)-ntp-server authentication-type (symmetric-key|autokey|none)/))) {
      ntpAuth.set(`${m[1]}-ntp-server`, { ok: m[2] !== "none", line: l });
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^deviceconfig system snmp-setting access-setting version v3 users ("[^"]+"|\S+)(.*)$/))) {
      b.setTrue("snmp.v3_enabled", l);
      if (/\bprivpwd\b/.test(m[2])) snmpV3Priv.push(l);
      continue;
    }
    if (/^deviceconfig system snmp-setting access-setting version v3/.test(p)) { b.setTrue("snmp.v3_enabled", l); continue; }
    if ((m = p.match(/^deviceconfig system snmp-setting access-setting version v2c snmp-community-string\s+("[^"]+"|\S+)/))) {
      const c = unquote(m[1]);
      b.add("snmp.v1v2c_communities", c, l);
      if (["public", "private"].includes(c.toLowerCase())) b.add("snmp.default_communities", c, l);
      continue;
    }
    if (/^deviceconfig system snmp-setting/.test(p)) { b.mark(l); continue; }
    // PAN-OS 10.0+: ssh profiles mgmt-profiles server-profiles <name> <algo> [ ... ]
    if ((m = p.match(/^deviceconfig system ssh profiles mgmt-profiles (?:server-profiles )?("[^"]+"|\S+) (?:ciphers|kex|mac)\s+(.*)$/))) {
      const name = unquote(m[1]);
      const prev = sshProfiles.get(name);
      sshProfiles.set(name, { weak: (prev?.weak ?? false) || hasWeakCipher(m[2]), line: prev?.line ?? l });
      b.mark(l);
      continue;
    }
    // PAN-OS 9.x: ssh <algo> mgmt [ ... ]
    if ((m = p.match(/^deviceconfig system ssh (?:ciphers|kex|mac) mgmt\s+(.*)$/))) {
      sshLegacy = { weak: (sshLegacy?.weak ?? false) || hasWeakCipher(m[1]), line: sshLegacy?.line ?? l };
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^deviceconfig system ssh mgmt server-profile\s+("[^"]+"|\S+)/))) { sshBound = { name: unquote(m[1]), line: l }; b.mark(l); continue; }
    if (/^deviceconfig system ssh/.test(p)) { b.mark(l); continue; }
    if (/^deviceconfig system fips-cc/.test(p)) { b.setTrue("crypto.fips_mode", l); continue; }
    if ((m = p.match(/^deviceconfig system ssl-tls-service-profile\s+("[^"]+"|\S+)/))) { tlsBound = { name: unquote(m[1]), line: l }; b.mark(l); continue; }
    if (/^deviceconfig system /.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^deviceconfig setting management idle-timeout\s+(\d+)/))) { b.set("management.idle_timeout_minutes", parseInt(m[1], 10) === 0 ? 9999 : parseInt(m[1], 10), l); continue; }
    if ((m = p.match(/^deviceconfig setting management admin-lockout failed-attempts\s+(\d+)/))) { adminLockout = { attempts: parseInt(m[1], 10), line: l }; b.mark(l); continue; }
    if (/^deviceconfig setting management admin-lockout lockout-time/.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^deviceconfig setting management authentication-profile\s+("[^"]+"|\S+)/))) { adminProfiles.set(unquote(m[1]), l); b.mark(l); continue; }
    if (/^deviceconfig setting management min-password-complexity enabled yes/.test(p) || /^mgt-config password-complexity enabled yes/.test(p)) { b.setTrue("auth.password_complexity", l); continue; }
    if ((m = p.match(/^(?:deviceconfig setting management min-password-complexity|mgt-config password-complexity) minimum-length\s+(\d+)/))) { b.set("auth.min_password_length", parseInt(m[1], 10), l); continue; }
    if (/^(deviceconfig setting management min-password-complexity|mgt-config password-complexity)/.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^deviceconfig setting management admin-session max-session-count\s+(\d+)/))) { b.set("management.concurrent_sessions_limited", parseInt(m[1], 10) > 0, l); continue; }
    if (/^deviceconfig setting management admin-session/.test(p)) { b.mark(l); continue; }
    if (/^deviceconfig /.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^mgt-config users ("[^"]+"|\S+) (?:permissions|phash|client-certificate-only|public-key)/))) { b.add("auth.local_users", unquote(m[1]), l); localUsers++; continue; }
    if ((m = p.match(/^mgt-config users ("[^"]+"|\S+) authentication-profile\s+("[^"]+"|\S+)/))) { b.add("auth.local_users", unquote(m[1]), l); adminProfiles.set(unquote(m[2]), l); continue; }
    if ((m = p.match(/^mgt-config authentication-profile\s+("[^"]+"|\S+)/))) { adminProfiles.set(unquote(m[1]), l); b.mark(l); continue; }
    if (/^mgt-config /.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^shared authentication-profile ("[^"]+"|\S+) method (tacplus|radius|ldap|kerberos|saml-idp)(?:\s+server-profile\s+("[^"]+"|\S+))?/))) {
      const name = unquote(m[1]);
      authProfiles.set(name, { method: m[2], line: l });
      if (m[3]) authProfileServer.set(name, `${m[2]}/${unquote(m[3])}`);
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^shared authentication-profile ("[^"]+"|\S+) lockout failed-attempts\s+(\d+)/))) { authProfileLockout.set(unquote(m[1]), { attempts: parseInt(m[2], 10), line: l }); b.mark(l); continue; }
    if ((m = p.match(/^shared server-profile (tacplus|radius|ldap|kerberos) ("[^"]+"|\S+) server ("[^"]+"|\S+) (?:address|ip-address|host)\s+(\S+)/))) {
      const key = `${m[1]}/${unquote(m[2])}`;
      const sp = serverProfiles.get(key) ?? { addresses: [], line: l };
      if (!sp.addresses.includes(m[4])) sp.addresses.push(m[4]);
      serverProfiles.set(key, sp);
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^shared log-settings syslog ("[^"]+"|\S+) server ("[^"]+"|\S+) server\s+(\S+)/))) {
      b.add("logging.remote_hosts", m[3], l);
      const key = `${m[1]} server ${m[2]}`;
      syslogServers.set(key, { ...(syslogServers.get(key) ?? {}), line: syslogServers.get(key)?.line ?? l });
      continue;
    }
    if ((m = p.match(/^shared log-settings syslog ("[^"]+"|\S+) server ("[^"]+"|\S+) transport\s+(\S+)/))) {
      const key = `${m[1]} server ${m[2]}`;
      syslogServers.set(key, { secure: /^(ssl|tls)$/i.test(m[3]), line: l });
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^shared log-settings (system|config|userid|hipmatch|globalprotect|iptag|auth) match-list ("[^"]+"|\S+)\s+(.*)$/))) {
      const key = `${m[1]}:${unquote(m[2])}`;
      const entry = matchLists.get(key) ?? { forwards: false, line: l };
      const f = m[3].match(/filter\s+("[^"]+"|\S+)/);
      if (f) entry.filter = unquote(f[1]);
      if (/send-(syslog|snmptrap|email|http)\b/.test(m[3])) entry.forwards = true;
      matchLists.set(key, entry);
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^shared log-settings snmptrap ("[^"]+"|\S+) (?:version )?v\S+ server ("[^"]+"|\S+) manager\s+(\S+)/))) { b.add("snmp.trap_hosts", m[3], l); continue; }
    if ((m = p.match(/^shared log-settings snmptrap ("[^"]+"|\S+) (?:version )?v[12]c? server ("[^"]+"|\S+) community\s+("[^"]+"|\S+)/))) {
      const c = unquote(m[3]);
      b.add("snmp.v1v2c_communities", c, l);
      if (["public", "private"].includes(c.toLowerCase())) b.add("snmp.default_communities", c, l);
      continue;
    }
    if ((m = p.match(/^shared ssl-tls-service-profile ("[^"]+"|\S+) protocol-settings min-version\s+tls(\S+)/))) {
      tlsProfiles.set(unquote(m[1]), { version: m[2].replace("-", "."), line: l });
      b.mark(l);
      continue;
    }
    if (/^shared /.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^network profiles interface-management-profile ("[^"]+"|\S+) (telnet|http|https|ssh|ping|snmp|response-pages|userid-service|userid-syslog-listener-ssl|userid-syslog-listener-udp)\s+(yes|no)/))) {
      const pr = profile(unquote(m[1]));
      pr.svc.set(m[2], m[3] === "yes");
      if (m[3] === "yes") pr.lines.set(m[2], l);
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^network profiles interface-management-profile ("[^"]+"|\S+) permitted-ip\s+("[^"]+"|\S+)/))) {
      const pr = profile(unquote(m[1]));
      pr.permitted.push(unquote(m[2]));
      pr.permitLines.push(l);
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^network profiles zone-protection-profile ("[^"]+"|\S+) discard-(strict|loose)-source-routing yes/))) {
      const set = zppDiscard.get(unquote(m[1])) ?? new Set<string>();
      set.add(m[2]);
      zppDiscard.set(unquote(m[1]), set);
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^network ike crypto-profiles ike-crypto-profiles ("[^"]+"|\S+) (encryption|hash|dh-group)\s+(.*)$/))) {
      const name = unquote(m[1]);
      const prev = ikeProfiles.get(name);
      const weak = (prev?.weak ?? false) || WEAK_IKE[m[2]].test(m[3]);
      ikeProfiles.set(name, { weak, line: weak && !prev?.weak ? l : (prev?.line ?? l) });
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^network ike crypto-profiles ipsec-crypto-profiles ("[^"]+"|\S+) esp (encryption|authentication)\s+(.*)$/))) {
      const name = unquote(m[1]);
      const prev = ipsecProfiles.get(name);
      const weak = (prev?.weak ?? false) || WEAK_IKE[m[2]].test(m[3]);
      ipsecProfiles.set(name, { weak, line: weak && !prev?.weak ? l : (prev?.line ?? l) });
      b.mark(l);
      continue;
    }
    if (/^network ike crypto-profiles/.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^network ike gateway ("[^"]+"|\S+) protocol ikev\d(?:-\S+)? ike-crypto-profile\s+("[^"]+"|\S+)/))) { ikeRefs.add(unquote(m[2])); b.mark(l); continue; }
    if ((m = p.match(/^network tunnel ipsec ("[^"]+"|\S+) auto-key ipsec-crypto-profile\s+("[^"]+"|\S+)/))) { ipsecRefs.add(unquote(m[2])); b.mark(l); continue; }
    // Legacy virtual-router and PAN-OS 10.2+ Advanced Routing (logical-router / vrf).
    if ((m = p.match(/^network (?:virtual-router ("[^"]+"|\S+)|logical-router ("[^"]+"|\S+) vrf ("[^"]+"|\S+)) (?:protocol )?(bgp|ospf|ospfv3)\s+(.*)$/))) {
      const vr = m[1] ? `virtual-router ${m[1]} protocol` : `logical-router ${m[2]} vrf ${m[3]}`;
      const label = unquote(m[1] ?? m[2]);
      const proto = m[4];
      const rest = m[5];
      if (proto === "bgp") {
        let pm: RegExpMatchArray | null;
        if ((pm = rest.match(/^peer-group ("[^"]+"|\S+) peer ("[^"]+"|\S+)(.*)$/))) {
          const key = `${label}/${unquote(pm[1])}/${unquote(pm[2])}`;
          const prev = bgpPeers.get(key);
          const authenticated = (prev?.authenticated ?? false) || /connection-options authentication\s+\S+/.test(pm[3]);
          bgpPeers.set(key, { authenticated, target: `${vr} bgp peer-group ${pm[1]} peer ${pm[2]}`, line: prev?.line ?? l });
          b.setTrue("routing.bgp_configured", l);
          continue;
        }
        if (/^enable yes/.test(rest)) { b.setTrue("routing.bgp_configured", l); continue; }
        b.mark(l);
        continue;
      }
      let om: RegExpMatchArray | null;
      if ((om = rest.match(/^area ("[^"]+"|\S+)(?: interface ("[^"]+"|\S+))?(.*)$/))) {
        b.setTrue("routing.ospf_configured", l);
        b.add("routing.ospf_areas", unquote(om[1]), l);
        if (om[2]) {
          const key = `${label}/${unquote(om[1])}/${unquote(om[2])}`;
          const prev = ospfIfaces.get(key);
          const authenticated = (prev?.authenticated ?? false) || /\bauthentication\s+\S+/.test(om[3]);
          ospfIfaces.set(key, { authenticated, target: `${vr} ospf area ${om[1]} interface ${om[2]}`, line: prev?.line ?? l });
          b.add("routing.ospf_interfaces", unquote(om[2]), l);
        }
        continue;
      }
      if (/^enable yes/.test(rest)) { b.setTrue("routing.ospf_configured", l); continue; }
      b.mark(l);
      continue;
    }
    if (/^network routing-profile (bgp|ospf)/.test(p)) { b.mark(l); continue; }
    // Any interface flavour can carry a management profile: ethernet, aggregate-ethernet, vlan, loopback, tunnel.
    if ((m = p.match(/^network interface .*\binterface-management-profile\s+("[^"]+"|\S+)/))) {
      boundProfiles.add(unquote(m[1]));
      boundLines.set(unquote(m[1]), l);
      if (/^network interface loopback/.test(p)) b.setTrue("identity.loopback_present", l);
      b.mark(l);
      continue;
    }
    if (/^network interface loopback/.test(p)) { b.setTrue("identity.loopback_present", l); continue; }
    if (/^network interface tunnel units/.test(p)) { b.inc("identity.tunnels", l); continue; }
    if (/^network /.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^rulebase (?:security )?rules ("[^"]+"|\S+)(.*)$/))) {
      const key = `${vsys}:${unquote(m[1])}`;
      const entry = rules.get(key) ?? { logged: false, line: l };
      const am = m[2].match(/\baction\s+(\S+)/);
      if (am) entry.action = am[1];
      if (/\blog-(end|start)\s+yes\b/.test(m[2])) entry.logged = true;
      rules.set(key, entry);
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^rulebase default-security-rules rules (interzone|intrazone)-default action\s+(\S+)/))) {
      if (m[1] === "interzone") interzone.set(vsys, { action: m[2], line: l });
      b.mark(l);
      continue;
    }
    if (/^rulebase default-security-rules rules interzone-default log-(end|start) yes/.test(p)) { b.setTrue("acl.explicit_deny_logged", l); continue; }
    if (/^rulebase /.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^zone ("[^"]+"|\S+) network (layer3|zone-protection-profile)\s*(.*)$/))) {
      const name = `${vsys}:${unquote(m[1])}`;
      const z = zones.get(name) ?? { layer3: false, line: l };
      if (m[2] === "layer3") z.layer3 = true;
      else z.zpp = unquote(m[3].trim());
      zones.set(name, z);
      b.mark(l);
      continue;
    }
    const root = p.split(/\s+/)[0];
    if (KNOWN_ROOTS.includes(root) || vsys) b.mark(l);
  }

  // ───────────────── resolution: services on MGT and on bound profiles ─────────────────
  const exposedBy = (svc: string) => Array.from(profiles.entries()).filter(([n, pr]) => boundProfiles.has(n) && pr.svc.get(svc)).map(([n]) => n);
  const resolveSvc = (svc: string, key: string): string[] => {
    const exposing = exposedBy(svc);
    const evs: (Line | undefined)[] = [];
    let value: boolean | undefined;
    if (mgtSvc.has(svc)) { value = mgtSvc.get(svc); evs.push(mgtSvcLine.get(svc)); }
    for (const n of exposing) { evs.push(profiles.get(n)?.lines.get(svc)); evs.push(boundLines.get(n)); }
    if (exposing.length) value = true;
    if (value !== undefined) setAll(key, value, evs);
    return exposing;
  };
  const telnetProfiles = resolveSvc("telnet", "management.telnet_enabled");
  const httpProfiles = resolveSvc("http", "management.http_enabled");
  resolveSvc("https", "management.https_enabled");
  resolveSvc("ssh", "management.ssh_enabled");
  const snmpProfiles = resolveSvc("snmp", "snmp.enabled");
  if (telnetProfiles.length) b.set("management.telnet_profiles", telnetProfiles, undefined);
  if (httpProfiles.length) b.set("management.http_profiles", httpProfiles, undefined);

  // Management ACL: /0 entries restrict nothing, and every exposed endpoint must be restricted.
  const restricted = (list: string[]) => list.some((a) => !ANY_SOURCE.test(a));
  const mgmtEndpoints: { ok: boolean; evs: (Line | undefined)[] }[] = [];
  if (mgtPermitted.length || mgtSvc.size) mgmtEndpoints.push({ ok: restricted(mgtPermitted), evs: mgtPermitLines.length ? mgtPermitLines : [] });
  for (const svc of ["https", "ssh", "telnet", "http"]) {
    for (const n of exposedBy(svc)) {
      const pr = profiles.get(n);
      if (!pr) continue;
      mgmtEndpoints.push({ ok: restricted(pr.permitted), evs: pr.permitLines.length ? pr.permitLines : [boundLines.get(n)] });
    }
  }
  if (mgmtEndpoints.length) {
    const ok = mgmtEndpoints.every((e) => e.ok);
    const evs = (ok ? mgmtEndpoints : mgmtEndpoints.filter((e) => !e.ok)).flatMap((e) => e.evs).filter(Boolean);
    // With no permitted-ip anywhere there is nothing to cite: keep the platform default.
    if (evs.length) setAll("management.mgmt_acl_applied", ok, evs);
  }
  // SNMP reachability is restricted by the same permitted-ip lists, not by a community ACL.
  if (b.get("snmp.enabled") === true && Array.isArray(b.get("snmp.v1v2c_communities"))) {
    const endpoints: { ok: boolean; evs: (Line | undefined)[] }[] = [];
    if (mgtSvc.get("snmp")) endpoints.push({ ok: restricted(mgtPermitted), evs: mgtPermitLines.length ? mgtPermitLines : [mgtSvcLine.get("snmp")] });
    for (const n of snmpProfiles) {
      const pr = profiles.get(n);
      if (pr) endpoints.push({ ok: restricted(pr.permitted), evs: pr.permitLines.length ? pr.permitLines : [boundLines.get(n)] });
    }
    if (endpoints.length) setAll("snmp.community_acl", endpoints.every((e) => e.ok), endpoints.flatMap((e) => e.evs));
  }
  if (snmpV3Priv.length) setAll("snmp.v3_priv", true, snmpV3Priv);

  // ───────────────── SSH / TLS profiles are only effective once bound ─────────────────
  if (sshBound && sshProfiles.has(sshBound.name)) {
    const prof = sshProfiles.get(sshBound.name);
    if (prof) setAll("crypto.strong_crypto", !prof.weak, [prof.line, sshBound.line]);
  } else if (sshLegacy) {
    setAll("crypto.strong_crypto", !sshLegacy.weak, [sshLegacy.line]);
  }
  if (tlsBound) {
    const prof = tlsProfiles.get(tlsBound.name);
    if (prof) {
      setAll("crypto.tls_min_version", prof.version, [prof.line, tlsBound.line]);
      b.set("crypto.tls_profiles", [tlsBound.name], undefined);
    }
  }

  // ───────────────── IKE/IPsec: ignore the factory profiles nobody uses ─────────────────
  const weakIke = Array.from(ikeProfiles.entries()).filter(([n, v]) => v.weak && (ikeRefs.has(n) || !FACTORY_CRYPTO.test(n)));
  const weakIpsec = Array.from(ipsecProfiles.entries()).filter(([n, v]) => v.weak && (ipsecRefs.has(n) || !FACTORY_CRYPTO.test(n)));
  if (weakIke.length || weakIpsec.length) {
    setAll("crypto.weak_ike", true, [...weakIke, ...weakIpsec].map(([, v]) => v.line));
    if (weakIke.length) b.set("crypto.weak_ike_profiles", weakIke.map(([n]) => n), undefined);
    if (weakIpsec.length) b.set("crypto.weak_ipsec_profiles", weakIpsec.map(([n]) => n), undefined);
  } else if (ikeProfiles.size || ipsecProfiles.size) {
    setAll("crypto.weak_ike", false, [...ikeProfiles.values(), ...ipsecProfiles.values()].slice(0, 2).map((v) => v.line));
  }

  // ───────────────── administrator AAA: GlobalProtect profiles are not admin AAA ─────────────────
  const adminServers: string[] = [];
  const adminEvs: (Line | undefined)[] = [];
  for (const [name, line] of adminProfiles) {
    adminEvs.push(line);
    const prof = authProfiles.get(name);
    if (prof) adminEvs.push(prof.line);
    const spKey = authProfileServer.get(name);
    const sp = spKey ? serverProfiles.get(spKey) : undefined;
    if (sp) { adminServers.push(...sp.addresses.filter((a) => !adminServers.includes(a))); adminEvs.push(sp.line); }
  }
  if (adminProfiles.size) {
    setAll("auth.aaa_enabled", true, adminEvs);
    setAll("auth.aaa_authentication_login", true, adminEvs);
    if (adminServers.length) setAll("auth.remote_auth_servers", adminServers, adminEvs);
  } else if ((authProfiles.size || serverProfiles.size) && localUsers) {
    // Auth profiles exist but serve GlobalProtect/Captive Portal users, not administrators.
    const evs = [...authProfiles.values()].map((v) => v.line).slice(0, 3);
    setAll("auth.aaa_authentication_login", false, evs);
    setAll("auth.remote_auth_servers", [], evs);
  }
  const lockout = adminLockout ?? (adminProfiles.size ? [...adminProfiles.keys()].map((n) => authProfileLockout.get(n)).find(Boolean) : undefined);
  if (lockout) {
    setAll("auth.max_login_attempts", lockout.attempts, [lockout.line]);
    setAll("auth.login_lockout", lockout.attempts > 0, [lockout.line]);
  }

  // ───────────────── NTP / syslog: every server must qualify, not the last line ─────────────────
  if (ntpAuth.size) {
    const bad = [...ntpAuth.entries()].filter(([, v]) => !v.ok);
    setAll("time.ntp_authentication", bad.length === 0, (bad.length ? bad : [...ntpAuth.entries()]).map(([, v]) => v.line));
    if (bad.length) b.set("time.unauthenticated_ntp_ids", bad.map(([n]) => n), undefined);
  }
  const transports = [...syslogServers.entries()].filter(([, v]) => v.secure !== undefined);
  if (transports.length) {
    const insecure = transports.filter(([, v]) => !v.secure);
    setAll("logging.remote_secure", insecure.length === 0, (insecure.length ? insecure : transports).map(([, v]) => v.line));
    if (insecure.length) b.set("logging.insecure_syslog_targets", insecure.map(([k]) => k), undefined);
  }
  const authFilter = (f?: string) => !f || /all logs/i.test(f) || /subtype eq auth/i.test(f) || /severity (eq|geq) (informational|low)/i.test(f);
  const loginLists = [...matchLists.entries()].filter(([k, v]) => /^(system|config|auth):/.test(k) && v.forwards && authFilter(v.filter));
  if (loginLists.length) {
    setAll("logging.login_events", true, loginLists.map(([, v]) => v.line));
    setAll("logging.enabled", true, loginLists.map(([, v]) => v.line));
  } else if (matchLists.size) {
    setAll("logging.login_events", false, [...matchLists.values()].slice(0, 2).map((v) => v.line));
  }

  // ───────────────── zone protection decides whether source routing is dropped ─────────────────
  const layer3Zones = [...zones.values()].filter((z) => z.layer3);
  if (layer3Zones.length) {
    const covered = layer3Zones.filter((z) => {
      const set = z.zpp ? zppDiscard.get(z.zpp) : undefined;
      return Boolean(set?.has("strict") && set?.has("loose"));
    });
    if (covered.length === layer3Zones.length) setAll("services.ip_source_routing", false, covered.map((z) => z.line));
  }

  // ───────────────── rulebase ─────────────────
  if (rules.size) {
    setAll("acl.count", rules.size, [...rules.values()].slice(0, 8).map((r) => r.line));
    const deniedLogged = [...rules.values()].filter((r) => r.action && /^(deny|drop|reset-client|reset-server|reset-both)$/.test(r.action) && r.logged);
    if (deniedLogged.length) setAll("acl.explicit_deny_logged", true, deniedLogged.map((r) => r.line));
  } else if (/^set (?:vsys \S+ )?rulebase/m.test(raw)) {
    b.set("acl.count", 0, undefined);
  }
  if (interzone.size) {
    const allow = [...interzone.values()].filter((v) => v.action === "allow");
    setAll("acl.default_deny", allow.length === 0, (allow.length ? allow : [...interzone.values()]).map((v) => v.line));
  }

  // ───────────────── routing: a profile that is defined but never applied is not authentication ─────────────────
  if (bgpPeers.size) {
    const unauth = [...bgpPeers.entries()].filter(([, v]) => !v.authenticated);
    setAll("routing.bgp_auth", unauth.length === 0, (unauth.length ? unauth : [...bgpPeers.entries()]).map(([, v]) => v.line));
    if (unauth.length) {
      b.set("routing.bgp_unauth_neighbors", unauth.map(([k]) => k), undefined);
      b.set("routing.bgp_auth_targets", unauth.map(([, v]) => v.target), undefined);
    }
  } else if (b.get("routing.bgp_configured") === true && !b.has("routing.bgp_auth")) {
    b.set("routing.bgp_auth", false, undefined);
  }
  if (ospfIfaces.size) {
    const unauth = [...ospfIfaces.entries()].filter(([, v]) => !v.authenticated);
    setAll("routing.ospf_auth", unauth.length === 0, (unauth.length ? unauth : [...ospfIfaces.entries()]).map(([, v]) => v.line));
    if (unauth.length) b.set("routing.ospf_auth_targets", unauth.map(([, v]) => v.target), undefined);
  } else if (b.get("routing.ospf_configured") === true && !b.has("routing.ospf_auth")) {
    b.set("routing.ospf_auth", false, undefined);
  }

  const meaningful = lines.filter((l) => !isCommentOrBlank(l));
  const unrecognized = b.unrecognized(lines, isCommentOrBlank);
  return {
    vendor: "paloalto-panos",
    identity: id,
    model: b.model(),
    totalLines: lines.length,
    meaningfulLines: meaningful.length,
    recognized: meaningful.length - unrecognized.length,
    unrecognized,
    mappingsApplied: [],
  };
}
