import type { ParseResult } from "../types";
import { first, hasWeakCipher, ModelBuilder, toLines, type Line } from "./util";

interface Entry {
  path: string;
  line: Line;
}

const isCommentOrBlank = (l: Line) => !l.text || l.text.startsWith("#") || l.text.startsWith("/*") || l.text.startsWith("##");

/** Quoted strings may contain brackets ('description "Uplink [primary"'); look through them when detecting multi-line lists. */
const unquoted = (s: string) => s.replace(/"[^"]*"/g, "");

/**
 * Flattens Junos curly-brace configuration into "set"-style paths. Accepts set-format too.
 * Inactive configuration — 'inactive:' stanzas and leaves, and the statements under a
 * 'deactivate'/'delete' set line — is recognised but yields no entries, so a switched-off
 * service is never reported as enabled.
 */
export function flattenJunos(lines: Line[]): { entries: Entry[]; structural: Set<number> } {
  const entries: (Entry & { set?: boolean })[] = [];
  const structural = new Set<number>();
  const stack: string[] = [];
  let pending: { text: string; line: Line } | null = null;
  /** stack depth of the innermost open 'inactive:' stanza; -1 while active */
  let inactiveDepth = -1;
  const deactivated: string[] = [];
  const activated: string[] = [];
  const flushPending = () => {
    if (!pending) return;
    entries.push({ path: [...stack, pending.text.replace(/;$/, "").trim()].join(" "), line: pending.line });
    pending = null;
  };
  for (const l of lines) {
    if (isCommentOrBlank(l)) continue;
    let t = l.text.replace(/\s*##.*$/, "");
    const verb = t.match(/^(set|deactivate|delete|activate)\s+(.*)$/);
    if (verb) {
      const path = verb[2].replace(/;$/, "").trim();
      if (verb[1] === "set") entries.push({ path, line: l, set: true });
      else {
        (verb[1] === "activate" ? activated : deactivated).push(path);
        structural.add(l.n);
      }
      continue;
    }
    if (pending) {
      if (unquoted(t).includes("]")) {
        pending.text += " " + t;
        flushPending();
        structural.add(l.n);
        continue;
      }
      if (!/[{};]$/.test(t)) {
        pending.text += " " + t;
        structural.add(l.n);
        continue;
      }
      flushPending(); // unterminated list: keep what was collected and treat this line normally
    }
    const inactive = /^inactive:\s/.test(t);
    t = t.replace(/^(inactive|protect|replace):\s*/, "");
    if (t.endsWith("{")) {
      stack.push(t.slice(0, -1).trim());
      if (inactive && inactiveDepth < 0) inactiveDepth = stack.length;
      if (inactiveDepth < 0) entries.push({ path: [...stack].join(" "), line: l });
      structural.add(l.n);
      continue;
    }
    if (t === "}") {
      if (stack.length === inactiveDepth) inactiveDepth = -1;
      stack.pop();
      structural.add(l.n);
      continue;
    }
    if (inactive || inactiveDepth >= 0) {
      structural.add(l.n);
      continue;
    }
    const bare = unquoted(t);
    if (bare.includes("[") && !bare.includes("]")) {
      pending = { text: t, line: l };
      continue;
    }
    entries.push({ path: [...stack, t.replace(/;$/, "")].join(" "), line: l });
  }
  flushPending();
  // Set format: statements under a deactivated/deleted prefix are inactive unless re-activated.
  const off = deactivated.filter((p) => !activated.includes(p));
  const isOff = (path: string) => off.some((p) => path === p || path.startsWith(`${p} `));
  const active: Entry[] = [];
  for (const e of entries) {
    if (e.set && isOff(e.path)) structural.add(e.line.n);
    else active.push({ path: e.path, line: e.line });
  }
  return { entries: active, structural };
}

/**
 * Statements kept under 'groups <name>' take effect once the group is applied. Junos applies
 * re0/re1 (dual routing engines) and node0/node1 (chassis cluster) implicitly; anything else
 * needs a top-level 'apply-groups'. Applied group content is folded into the main hierarchy.
 */
export function applyJunosGroups(entries: Entry[]): Entry[] {
  const applied = new Set(["re0", "re1", "node0", "node1"]);
  for (const e of entries) {
    const m = e.path.match(/^apply-groups\s+(.+)$/);
    if (!m) continue;
    for (const name of m[1].replace(/[[\]"]/g, " ").split(/\s+/)) if (name && !name.startsWith("$")) applied.add(name);
  }
  return entries.map((e) => {
    const m = e.path.match(/^groups (\S+) (.+)$/);
    return m && applied.has(m[1]) ? { path: m[2], line: e.line } : e;
  });
}

const KNOWN_STANZAS = [
  "system", "interfaces", "routing-options", "policy-options", "protocols", "chassis", "vlans", "class-of-service", "security", "applications",
  "services", "groups", "apply-groups", "forwarding-options", "event-options", "access", "snmp", "firewall", "routing-instances", "version",
  "bridge-domains", "switch-options", "virtual-chassis", "poe", "ethernet-switching-options", "multicast-snooping-options", "accounting-options",
  "fabric", "jsrc", "jsrc-partition", "logical-systems", "dynamic-profiles", "unified-edge", "vmhost", "wlan", "multi-chassis", "diameter",
  "schedulers", "accounting", "session-limit-group", "tenants",
];

const SEVERITY_RANK: Record<string, number> = { any: 8, debug: 7, info: 6, notice: 5, warning: 4, error: 3, critical: 2, alert: 1, emergency: 0, none: -1 };
/** host-inbound-traffic services that map to SBM parameters; 'all' expands to these. */
const ZONE_PARAM: Record<string, string> = {
  telnet: "management.telnet_enabled", http: "management.http_enabled", https: "management.https_enabled", ssh: "management.ssh_enabled", ftp: "management.ftp_enabled", finger: "services.finger",
};
const MGMT_IFACE = /^interfaces (fxp0|me0|vme|em0)\b/;
const BUILTIN_CLASS = /^(super-user|operator|read-only|unauthorized)$/;
const IPV4 = /(\d{1,3}(?:\.\d{1,3}){3})/;

export function parseJunos(raw: string): ParseResult {
  const lines = toLines(raw);
  const b = new ModelBuilder("juniper-junos");
  const id = b.identity;
  const flat = flattenJunos(lines);
  const entries = applyJunosGroups(flat.entries);
  flat.structural.forEach((n) => b.mark(n));
  const has = (re: RegExp) => entries.some((e) => re.test(e.path));
  const firstPath = (re: RegExp): string | undefined => {
    for (const e of entries) {
      const m = e.path.match(re);
      if (m?.[1]) return m[1];
    }
    return undefined;
  };

  id.hostname = first(raw, /host-name\s+"?([\w.-]+)"?;?/) ?? firstPath(/^system host-name\s+"?([\w.-]+)"?$/);
  id.osVersion = first(raw, /^(?:set )?version\s+([\w.-]+);?/m) ?? first(raw, /Junos:\s*([\w.-]+)/i) ?? first(raw, /JUNOS\s+([\d.]+R[\d.-]+)/);
  id.model = first(raw, /^Model:\s*(\S+)/mi) ?? first(raw, /^(?:##\s*)?Chassis\s+[A-Z0-9]{8,}\s+(\S+)/m) ?? first(raw, /##\s*(?:model|platform)\s*[:=]\s*(\S+)/i);
  const vcSerials = entries.filter((e) => /^virtual-chassis member \d+ serial-number \S+$/.test(e.path)).map((e) => e.path.split(/\s+/).pop() as string);
  id.serial = first(raw, /^(?:##\s*)?Chassis\s+([A-Z0-9]{8,})\s+\S+/m) ?? first(raw, /Serial number:\s*(\S+)/i) ?? first(raw, /##\s*serial(?:\s*number)?\s*[:=]\s*(\S+)/i) ?? vcSerials[0];
  if (vcSerials.length > 1) id.extra = { ...id.extra, vc_members: vcSerials.join(", ") };
  // Management address: the dedicated management port (also when it lives under an RE/node group), then lo0, then any inet address.
  id.mgmtIp =
    firstPath(new RegExp(`^interfaces (?:fxp0|me0|vme|em0) unit \\d+ family inet address ${IPV4.source}`)) ??
    firstPath(new RegExp(`^interfaces lo0 unit 0 family inet address ${IPV4.source}`)) ??
    firstPath(new RegExp(`^interfaces \\S+ unit \\d+ family inet address ${IPV4.source}`));
  id.role = has(/^security (zones|policies)\b/) ? "firewall" : has(/family ethernet-switching\b|^vlans\b/) ? "switch" : "router";

  const d = (k: string, v: string | number | boolean | string[], note: string) => b.setDefault(k, v, `Platform default — ${note}`);
  d("management.telnet_enabled", false, "telnet service is off unless 'system services telnet'");
  d("management.http_enabled", false, "web-management http is off unless configured");
  d("management.api_http_enabled", false, "REST over http / xnm-clear-text are off unless configured");
  d("management.ftp_enabled", false, "ftp service is off unless 'system services ftp'");
  d("management.ssh_enabled", false, "ssh service is off unless 'system services ssh'");
  d("management.ssh_version", 2, "Junos 15+ negotiates SSHv2 only unless protocol-version v1 is set");
  d("auth.password_encryption", true, "Junos always stores hashed authentication secrets");
  d("logging.timestamps", true, "Junos syslog entries are timestamped");
  d("logging.enabled", true, "syslog daemon runs by default");
  d("logging.console_restricted", true, "nothing is logged to the console unless 'system syslog console' is configured");
  d("services.ip_source_routing", false, "source-routed packets are dropped unless 'system allow-v4-source-route'");
  d("services.proxy_arp", false, "proxy ARP is off unless configured");
  d("services.icmp_redirects", true, "ICMP redirects are sent unless 'system no-redirects'");
  d("services.directed_broadcast", false, "directed broadcasts are dropped by default");
  d("services.unicast_rpf", false, "rpf-check is off unless configured per interface");
  d("management.login_banner", false, "no 'system login message' configured");
  d("management.mgmt_acl_applied", false, "no lo0 / management-port input filter");
  d("time.ntp_authentication", false, "no ntp keys configured");
  d("snmp.enabled", false, "no snmp stanza");
  d("auth.root_login_ssh", true, "ssh root-login defaults to allow");
  d("auth.login_lockout", false, "no 'retry-options lockout-period' — accounts never lock");
  d("management.idle_timeout_minutes", 9999, "login class idle-timeout not set (never)");
  d("crypto.strong_crypto", false, "default SSH cipher list includes CBC modes");
  // Only routing-engine based chassis have an auxiliary port.
  const reBased = /^(MX|PTX|T\d|SRX4|SRX5|EX92|QFX10)/i.test(id.model ?? "") || has(/^chassis redundancy\b/);
  if (reBased) d("management.aux_disabled", false, "auxiliary port active unless 'system ports auxiliary disable'");
  else d("management.aux_disabled", true, "platform has no auxiliary port (only RE-based MX/PTX/T/SRX4x00-5x00 chassis do)");

  const aclNames = new Set<string>();
  const ntp = { keys: false, trusted: false, servers: new Map<string, { keyed: boolean; line: Line }>() };
  const zoneServices = new Map<string, Set<string>>();
  const zoneLines = new Map<string, Line>();
  const terms = new Map<string, { log: boolean; deny: boolean; line: Line }>();
  const bgpGroups = new Map<string, { auth: boolean; line: Line; neighbors: Map<string, { auth: boolean; line: Line }> }>();
  let bgpGlobalAuth: Line | undefined;
  const ospfIfaces = new Map<string, { auth: boolean; passive: boolean; line: Line }>();
  const communities = new Map<string, { acl: boolean; line: Line }>();
  const classes = new Map<string, { idle: boolean; line: Line }>();
  const userClasses: { user: string; cls: string; line: Line }[] = [];
  const authOrder = { line: undefined as Line | undefined, methods: new Set<string>() };
  const servers: { host: string; proto: string; line: Line }[] = [];
  const syslogHosts = new Map<string, { tls: boolean; line: Line }>();
  const l3Units = new Map<string, { noRedirects: boolean; line: Line }>();
  const ssh = { v1: undefined as Line | undefined, v2: undefined as Line | undefined };

  for (const e of entries) {
    const l = e.line;
    // Protocols inside routing-instances / logical-systems are ordinary protocols for the checks below.
    const inst = e.path.match(/^(?:routing-instances|logical-systems) (\S+) protocols /)?.[1];
    const p = inst ? e.path.replace(/^(?:routing-instances|logical-systems) \S+ /, "") : e.path;
    let m: RegExpMatchArray | null;

    // ── System ──
    if (/^system host-name\s/.test(p)) { b.setTrue("identity.hostname_set", l); continue; }
    if (/^system domain-name\s/.test(p)) { b.setTrue("identity.domain_set", l); continue; }
    if (/^system time-zone\s/.test(p)) { b.setTrue("time.timezone_set", l); continue; }
    if (/^system root-authentication (encrypted-password|ssh-)/.test(p)) {
      b.setTrue("auth.enable_secret", l);
      if (/encrypted-password "?\$1\$/.test(p)) b.inc("auth.weak_password_hashes", l);
      continue;
    }
    if (/^system root-authentication plain-text-password/.test(p)) { b.inc("auth.weak_password_hashes", l); continue; }
    if ((m = p.match(/^system login user (\S+)(.*)$/))) {
      b.add("auth.local_users", m[1], l);
      if (/plain-text-password|encrypted-password "?\$1\$/.test(m[2])) b.inc("auth.weak_password_hashes", l);
      const cls = m[2].match(/^ class (\S+)$/);
      if (cls) userClasses.push({ user: m[1], cls: cls[1], line: l });
      continue;
    }
    if (/^system login message\s/.test(p)) { b.setTrue("management.login_banner", l); continue; }
    if (/^system login announcement\s/.test(p)) { b.mark(l); continue; } // post-login MOTD, not a pre-login notice
    if ((m = p.match(/^system login retry-options tries-before-disconnect (\d+)/))) {
      b.setTrue("auth.login_lockout", l);
      b.set("auth.max_login_attempts", parseInt(m[1], 10), l);
      b.set("management.ssh_auth_retries", parseInt(m[1], 10), l);
      continue;
    }
    if (/^system login retry-options lockout-period/.test(p)) { b.setTrue("auth.login_lockout", l); continue; }
    if ((m = p.match(/^system login password minimum-length (\d+)/))) { b.set("auth.min_password_length", parseInt(m[1], 10), l); continue; }
    if ((m = p.match(/^system login password format (\S+)/))) {
      if (/^(md5|sha1|des)$/.test(m[1])) b.inc("auth.weak_password_hashes", l);
      else b.mark(l);
      continue;
    }
    if (/^system login password (change-type|minimum-changes|minimum-character-changes|minimum-(upper|lower|numeric|punctuation)s?)/.test(p)) { b.setTrue("auth.password_complexity", l); continue; }
    if ((m = p.match(/^system login class (\S+)(.*)$/))) {
      const cls = classes.get(m[1]) ?? { idle: false, line: l };
      classes.set(m[1], cls);
      const idle = m[2].match(/^ idle-timeout (\d+)$/);
      if (idle) {
        cls.idle = true;
        const v = parseInt(idle[1], 10);
        const cur = b.get("management.idle_timeout_minutes");
        if (b.params["management.idle_timeout_minutes"]?.source === "default" || typeof cur !== "number") b.set("management.idle_timeout_minutes", v, l);
        else b.max("management.idle_timeout_minutes", v, l);
      } else b.mark(l);
      continue;
    }
    if (/^system login (user|deny-sources|retry-options)/.test(p)) { b.mark(l); continue; }
    if (/^system authentication-order/.test(p)) {
      authOrder.line = authOrder.line ?? l;
      for (const w of p.replace(/^system authentication-order/, "").replace(/[[\]]/g, " ").split(/\s+/)) if (w) authOrder.methods.add(w);
      b.mark(l);
      continue;
    }
    if ((m = p.match(/^system (tacplus|radius)-server (\S+)/))) { servers.push({ host: m[2], proto: m[1], line: l }); b.mark(l); continue; }
    if (/^system accounting events/.test(p)) { b.setTrue("auth.aaa_accounting", l); continue; }
    if (/^system accounting/.test(p)) { b.mark(l); continue; }
    if (/^system services ssh protocol-version\b/.test(p)) {
      // '[ v1 v2 ]' (brace) or one line per member (set): v1 anywhere means SSHv1 is accepted.
      if (/\bv1\b/.test(p)) ssh.v1 = ssh.v1 ?? l;
      if (/\bv2\b/.test(p)) ssh.v2 = ssh.v2 ?? l;
      b.setTrue("management.ssh_enabled", l);
      continue;
    }
    if ((m = p.match(/^system services ssh root-login (\S+)/))) {
      b.set("auth.root_login_ssh", m[1] !== "deny", l);
      if (m[1] === "deny-password") id.extra = { ...id.extra, root_login: "deny-password (key-based root login still permitted)" };
      b.setTrue("management.ssh_enabled", l);
      continue;
    }
    if (/^system services ssh (connection-limit|max-sessions-per-connection|rate-limit)/.test(p)) { b.setTrue("management.concurrent_sessions_limited", l); b.setTrue("management.ssh_enabled", l); continue; }
    if ((m = p.match(/^system services ssh (ciphers|macs|key-exchange|hostkey-algorithm)\s+(.*)$/))) {
      const prev = b.params["crypto.strong_crypto"];
      const weakSeen = !!prev && prev.source !== "default" && prev.value === false;
      b.set("crypto.strong_crypto", !hasWeakCipher(m[2]) && !weakSeen, l);
      b.setTrue("management.ssh_enabled", l);
      continue;
    }
    if (/^system services ssh/.test(p)) { b.setTrue("management.ssh_enabled", l); continue; }
    if (/^system services telnet/.test(p)) { b.setTrue("management.telnet_enabled", l); continue; }
    if (/^system services ftp/.test(p)) { b.setTrue("management.ftp_enabled", l); continue; }
    if (/^system services finger/.test(p)) { b.setTrue("services.finger", l); continue; }
    if (/^system services web-management http\b/.test(p)) { b.setTrue("management.http_enabled", l); continue; }
    if (/^system services web-management https/.test(p)) { b.setTrue("management.https_enabled", l); continue; }
    if (/^system services (rest http\b|xnm-clear-text)/.test(p)) { b.setTrue("management.api_http_enabled", l); continue; }
    if (/^system services /.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^system syslog (host|file) (\S+)(.*)$/))) {
      const rest = m[3];
      if (m[1] === "host") {
        const h = syslogHosts.get(m[2]) ?? { tls: false, line: l };
        if (/transport tls/.test(rest)) { h.tls = true; h.line = l; }
        syslogHosts.set(m[2], h);
        b.add("logging.remote_hosts", m[2], l);
        if (/source-address/.test(rest)) b.setTrue("logging.source_interface", l);
      } else b.setTrue("logging.buffered", l);
      const sel = rest.match(/^ (any|authorization|daemon|kernel|user|security|firewall|interactive-commands|change-log|conflict-log|dfc|external|ftp|ntp|pfe) (\S+)$/);
      if (sel) {
        if (m[1] === "host") {
          const cur = b.get("logging.level");
          if (typeof cur !== "string" || (SEVERITY_RANK[sel[2]] ?? -1) > (SEVERITY_RANK[cur] ?? -1)) b.set("logging.level", sel[2], l);
        }
        if (/^(any|authorization|interactive-commands)$/.test(sel[1]) && /^(any|debug|info|notice)$/.test(sel[2])) b.setTrue("logging.login_events", l);
      }
      continue;
    }
    if ((m = p.match(/^system syslog console \S+ (\S+)/))) { b.set("logging.console_restricted", ["error", "critical", "alert", "emergency", "none"].includes(m[1]), l); continue; }
    if (/^system syslog source-address/.test(p)) { b.setTrue("logging.source_interface", l); continue; }
    if (/^system syslog time-format/.test(p)) { b.setTrue("logging.timestamps", l); continue; }
    if (/^system syslog/.test(p)) { b.mark(l); continue; }
    if ((m = p.match(/^system ntp server (\S+)(.*)$/))) {
      b.add("time.ntp_servers", m[1], l);
      const s = ntp.servers.get(m[1]) ?? { keyed: false, line: l };
      if (/\bkey \d+/.test(m[2])) s.keyed = true;
      ntp.servers.set(m[1], s);
      continue;
    }
    if (/^system ntp authentication-key/.test(p)) { ntp.keys = true; b.mark(l); continue; }
    if (/^system ntp trusted-key/.test(p)) { ntp.trusted = true; b.mark(l); continue; }
    if (/^system ntp/.test(p)) { b.mark(l); continue; }
    if (/^system no-redirects/.test(p)) { b.setFalse("services.icmp_redirects", l); continue; }
    if (/^system allow-v4-source-route|^system allow-v6-source-route/.test(p)) { b.setTrue("services.ip_source_routing", l); continue; }
    if (/^system ports auxiliary disable/.test(p)) { b.setTrue("management.aux_disabled", l); continue; }
    if (/^system fips/.test(p)) { b.setTrue("crypto.fips_mode", l); continue; }
    if (/^system (internet-options|ports|arp|name-server|scripts|archival|commit|processes|ddos-protection|license|auto-snapshot|max-|default-address-selection|backup-router|dump-on-panic|extensions|security-profile|autoinstallation|pic-console-authentication|no-ping|domain-search|static-host-mapping|location|encrypted-configuration|auto-configuration|compress-configuration-files|configuration|schema|tracing|master-password|dynamic-profile-options|phone-home|export-format|saved-core|nd-|kernel|health-monitor|management-instance|tacplus-options|radius-options|no-multicast-echo)/.test(p)) { b.mark(l); continue; }
    if (/^system$/.test(p) || /^system (login|syslog|services|ntp|accounting|authentication|root-authentication)$/.test(p)) { b.mark(l); continue; }
    if (/^version\s/.test(p)) { b.mark(l); continue; }

    // ── SNMP ──
    if ((m = p.match(/^snmp community (\S+)(.*)$/))) {
      b.setTrue("snmp.enabled", l);
      const name = m[1].replace(/"/g, "");
      b.add("snmp.v1v2c_communities", name, l);
      if (["public", "private"].includes(name.toLowerCase())) b.add("snmp.default_communities", name, l);
      if (/authorization read-write/.test(m[2])) b.add("snmp.rw_communities", name, l);
      const c = communities.get(name) ?? { acl: false, line: l };
      communities.set(name, c);
      // 'clients 0.0.0.0/0' (or 'default') without 'restrict' permits everyone — not an ACL.
      const cl = m[2].match(/^ clients (\S+)( restrict)?$/);
      if (cl && (cl[2] || !/^(0\.0\.0\.0\/0|default|::\/0)$/.test(cl[1]))) { c.acl = true; c.line = l; }
      continue;
    }
    if (/^snmp v3 usm .* privacy-(aes128|des|3des)\b/.test(p)) { b.setTrue("snmp.v3_enabled", l); b.setTrue("snmp.v3_priv", l); b.setTrue("snmp.enabled", l); continue; }
    if (/^snmp v3 usm .* (privacy-none|authentication-none)\b/.test(p)) { b.setTrue("snmp.v3_enabled", l); b.set("snmp.v3_priv", false, l); b.setTrue("snmp.enabled", l); continue; }
    if (/^snmp v3/.test(p)) { b.setTrue("snmp.v3_enabled", l); b.setTrue("snmp.enabled", l); if (!b.has("snmp.v3_priv")) b.set("snmp.v3_priv", false, l); continue; }
    if ((m = p.match(/^snmp trap-group \S+ targets (\S+)/))) { b.add("snmp.trap_hosts", m[1], l); b.setTrue("snmp.enabled", l); continue; }
    if (/^snmp/.test(p)) { b.setTrue("snmp.enabled", l); continue; }

    // ── Interfaces ──
    if (/^interfaces lo0\b/.test(p)) {
      b.setTrue("identity.loopback_present", l);
      if (/filter input/.test(p)) { b.setTrue("management.mgmt_acl_applied", l); b.setTrue("acl.external_ingress_filter", l); }
      continue;
    }
    // A filter on the dedicated management port is the management ACL (fxp0 bypasses lo0 filters and zones).
    if (MGMT_IFACE.test(p) && /filter input/.test(p)) { b.setTrue("management.mgmt_acl_applied", l); b.setTrue("acl.external_ingress_filter", l); continue; }
    if (/^interfaces \S+ unit \d+ family inet6? filter input/.test(p)) { b.setTrue("acl.external_ingress_filter", l); continue; }
    if (/^interfaces \S+ unit \d+ family inet6? rpf-check/.test(p)) { b.setTrue("services.unicast_rpf", l); continue; }
    if (/^interfaces \S+ unit \d+ proxy-arp/.test(p)) { b.setTrue("services.proxy_arp", l); continue; }
    if (/^interfaces \S+ unit \d+ family inet targeted-broadcast/.test(p)) { b.setTrue("services.directed_broadcast", l); continue; }
    if ((m = p.match(/^interfaces (\S+) unit (\d+) family inet (no-redirects|address \S+)$/))) {
      if (!MGMT_IFACE.test(p)) {
        const key = `${m[1]}.${m[2]}`;
        const u = l3Units.get(key) ?? { noRedirects: false, line: l };
        if (m[3] === "no-redirects") u.noRedirects = true;
        l3Units.set(key, u);
      }
      b.mark(l);
      continue;
    }
    if (/^interfaces (st0|gr-|ip-)/.test(p)) { if (/unit \d+$/.test(p)) b.inc("identity.tunnels", l); else b.mark(l); continue; }
    if (/^interfaces/.test(p)) { b.mark(l); continue; }

    // ── Firewall filters ──
    if ((m = p.match(/^firewall (?:family \S+ )?filter (\S+)(.*)$/))) {
      if (!aclNames.has(m[1])) { aclNames.add(m[1]); b.inc("acl.count", l); } else b.mark(l);
      const tm = m[2].match(/^ term (\S+) then (log|syslog|discard|reject)\b/);
      if (tm) {
        const key = `${m[1]}:${tm[1]}`;
        const t = terms.get(key) ?? { log: false, deny: false, line: l };
        if (/^(log|syslog)$/.test(tm[2])) t.log = true; else t.deny = true;
        terms.set(key, t);
      }
      continue;
    }
    if (/^firewall/.test(p)) { b.mark(l); continue; }

    // ── Security (SRX) ──
    if ((m = p.match(/^security zones (?:security-zone|functional-zone) (\S+) (?:interfaces \S+ )?host-inbound-traffic system-services (\S+)( except)?$/))) {
      const zone = zoneServices.get(m[1]) ?? new Set<string>();
      zoneServices.set(m[1], zone);
      const svcs = m[2] === "all" ? Object.keys(ZONE_PARAM) : [m[2]];
      for (const s of svcs) {
        if (m[3]) zone.delete(s);
        else { zone.add(s); zoneLines.set(`${m[1]}:${s}`, l); }
      }
      b.mark(l);
      continue;
    }
    if (/^security policies default-policy deny-all/.test(p)) { b.setTrue("acl.default_deny", l); continue; }
    if (/^security policies default-policy permit-all/.test(p)) { b.setFalse("acl.default_deny", l); continue; }
    if ((m = p.match(/^security policies from-zone (\S+) to-zone (\S+) policy (\S+)(.*)$/))) {
      const key = `policy:${m[3]}`;
      if (!aclNames.has(key)) { aclNames.add(key); b.inc("acl.count", l); } else b.mark(l);
      const then = m[4].match(/^ then (deny|reject|log)\b/);
      if (then) {
        const tk = `${m[1]}>${m[2]}:${m[3]}`;
        const t = terms.get(tk) ?? { log: false, deny: false, line: l };
        if (then[1] === "log") t.log = true; else t.deny = true;
        terms.set(tk, t);
      }
      continue;
    }
    // proposal-set basic/compatible/standard = DES/3DES + SHA-1 + DH group 1/2; aggressive-mode IKEv1 exposes the PSK hash.
    if (/^security (ike|ipsec) policy \S+ proposal-set (basic|compatible|standard)\b/.test(p) || /^security ike policy \S+ mode aggressive\b/.test(p) || /^security ike gateway \S+ version v1-only\b/.test(p)) { b.setTrue("crypto.weak_ike", l); continue; }
    if (/^security (ike|ipsec) proposal \S+ (authentication-algorithm (md5|sha1|hmac-md5-96|hmac-sha1-96)|encryption-algorithm (des-cbc|3des-cbc)|dh-group group[125]\b)/.test(p)) { b.setTrue("crypto.weak_ike", l); continue; }
    if (/^security (ike|ipsec) proposal \S+ (authentication-algorithm|encryption-algorithm|dh-group)/.test(p)) { if (!b.has("crypto.weak_ike")) b.set("crypto.weak_ike", false, l); else b.mark(l); continue; }
    if ((m = p.match(/^security log stream \S+ host (\S+)$/)) && !/^(port|source-address|routing-instance)$/.test(m[1])) { b.add("logging.remote_hosts", m[1], l); continue; }
    if (/^security log/.test(p)) { b.mark(l); continue; } // security-log TLS protects traffic logs, not the system syslog
    if (/^security/.test(p)) { b.mark(l); continue; }

    // ── Routing protocols ──
    if ((m = p.match(/^protocols bgp group (\S+)(.*)$/))) {
      b.setTrue("routing.bgp_configured", l);
      const gk = inst ? `${inst}:${m[1]}` : m[1];
      const g = bgpGroups.get(gk) ?? { auth: false, line: l, neighbors: new Map() };
      bgpGroups.set(gk, g);
      const nb = m[2].match(/^ neighbor (\S+)(.*)$/);
      if (nb) {
        const n = g.neighbors.get(nb[1]) ?? { auth: false, line: l };
        if (/\bauthentication-(key|algorithm|key-chain)\b/.test(nb[2])) n.auth = true;
        g.neighbors.set(nb[1], n);
      } else if (/^ authentication-(key|algorithm|key-chain)\b/.test(m[2])) { g.auth = true; g.line = l; }
      continue;
    }
    if (/^protocols bgp authentication-(key|algorithm|key-chain)\b/.test(p)) { bgpGlobalAuth = bgpGlobalAuth ?? l; b.setTrue("routing.bgp_configured", l); continue; }
    if (/^protocols bgp/.test(p)) { b.setTrue("routing.bgp_configured", l); continue; }
    if ((m = p.match(/^protocols (ospf3?) area \S+ interface (\S+)(.*)$/))) {
      b.setTrue("routing.ospf_configured", l);
      const key = `${m[1]}:${m[2]}`;
      const i = ospfIfaces.get(key) ?? { auth: false, passive: false, line: l };
      if (/\b(authentication md5|authentication-key-chain|ipsec-sa)\b/.test(m[3])) { i.auth = true; i.line = l; }
      if (/^ passive$/.test(m[3])) i.passive = true;
      ospfIfaces.set(key, i);
      continue;
    }
    if (/^protocols ospf3?/.test(p)) { b.setTrue("routing.ospf_configured", l); continue; }
    if (/^protocols lldp disable/.test(p)) { b.setFalse("services.lldp_enabled", l); continue; }
    if (/^protocols lldp/.test(p)) { b.setTrue("services.lldp_enabled", l); continue; }
    if (/^protocols/.test(p)) { b.mark(l); continue; }

    const top = p.split(/\s+/)[0];
    if (KNOWN_STANZAS.includes(top)) b.mark(l);
  }

  // ── Post-pass consolidation ──
  // AAA: Junos authenticates against local passwords unless authentication-order names a remote method; a stale server stanza does not count.
  const remote = ["tacplus", "radius", "ldap"].some((x) => authOrder.methods.has(x));
  if (authOrder.line) {
    b.set("auth.aaa_enabled", remote, authOrder.line);
    b.set("auth.aaa_authentication_login", remote, authOrder.line);
  } else {
    d("auth.aaa_enabled", false, "no 'system authentication-order' — local password authentication only");
    d("auth.aaa_authentication_login", false, "no 'system authentication-order' — local password authentication only");
  }
  for (const s of servers) if (authOrder.methods.has(s.proto)) b.add("auth.remote_auth_servers", s.host, s.line);
  if (!b.has("auth.remote_auth_servers")) {
    if (servers.length) b.set("auth.remote_auth_servers", [], { line: servers[0].line.n, text: `${servers[0].line.text} — not referenced by authentication-order` });
    else d("auth.remote_auth_servers", [], "no tacplus/radius server referenced by authentication-order");
  }
  if (ssh.v1) b.set("management.ssh_version", 1, ssh.v1);
  else if (ssh.v2) b.set("management.ssh_version", 2, ssh.v2);
  if (ntp.servers.size) {
    const unkeyed = [...ntp.servers.entries()].filter(([, s]) => !s.keyed);
    const auth = ntp.keys && ntp.trusted && unkeyed.length === 0;
    const why = !ntp.keys ? "no 'authentication-key'" : !ntp.trusted ? "no 'trusted-key'" : unkeyed.length ? `${unkeyed.length} server(s) without 'key N'` : "authentication-key + trusted-key + keyed servers";
    b.set("time.ntp_authentication", auth, unkeyed.length && ntp.keys && ntp.trusted ? { line: unkeyed[0][1].line.n, text: `server ${unkeyed[0][0]} — no 'key N'` } : { line: 0, text: `NTP authentication: ${why}` });
  }
  // Zone host-inbound-traffic only permits services that are configured under 'system services'; zone lines are extra evidence.
  for (const [zone, svcs] of zoneServices) {
    for (const s of svcs) {
      const obs = ZONE_PARAM[s] ? b.params[ZONE_PARAM[s]] : undefined;
      const zl = zoneLines.get(`${zone}:${s}`);
      if (obs?.source === "parser" && obs.value === true && zl) obs.evidence.push({ line: zl.n, text: `security-zone ${zone} permits ${s}` });
    }
    if (svcs.has("telnet")) b.add("management.telnet_zones", zone, zoneLines.get(`${zone}:telnet`));
  }
  const logged = [...terms.values()].find((t) => t.log && t.deny);
  if (logged) b.setTrue("acl.explicit_deny_logged", logged.line);
  else if (aclNames.size) b.set("acl.explicit_deny_logged", false, { line: 0, text: "no filter term or security policy combines discard/reject/deny with log" });
  if (bgpGroups.size || bgpGlobalAuth) {
    const unauth: { n: string; line: Line }[] = [];
    let total = 0;
    for (const g of bgpGroups.values()) for (const [n, nb] of g.neighbors) { total++; if (!(bgpGlobalAuth || g.auth || nb.auth)) unauth.push({ n, line: nb.line }); }
    const authLine = bgpGlobalAuth ?? [...bgpGroups.values()].find((g) => g.auth)?.line;
    if (total) {
      b.set("routing.bgp_auth", unauth.length === 0, unauth.length ? { line: unauth[0].line.n, text: `neighbor ${unauth[0].n} has no authentication-key${unauth.length > 1 ? ` (+${unauth.length - 1} more)` : ""}` } : authLine);
      if (unauth.length) b.set("routing.bgp_unauth_neighbors", unauth.map((u) => u.n), undefined);
    } else b.set("routing.bgp_auth", Boolean(authLine), authLine);
  }
  if (ospfIfaces.size) {
    const active = [...ospfIfaces.entries()].filter(([, i]) => !i.passive);
    const bad = active.filter(([, i]) => !i.auth);
    if (!active.length) b.set("routing.ospf_auth", true, { line: 0, text: "every OSPF interface is passive (no adjacencies)" });
    else b.set("routing.ospf_auth", bad.length === 0, bad.length ? { line: bad[0][1].line.n, text: `${bad[0][1].line.text} — no md5 / key-chain / ipsec-sa authentication${bad.length > 1 ? ` (+${bad.length - 1} more)` : ""}` } : active[0][1].line);
  } else if (b.get("routing.ospf_configured") === true) b.set("routing.ospf_auth", false, { line: 0, text: "no OSPF interface carries authentication" });
  if (communities.size) {
    const bad = [...communities.entries()].filter(([, c]) => !c.acl);
    b.set("snmp.community_acl", bad.length === 0, bad.length ? { line: bad[0][1].line.n, text: `community ${bad[0][0]} has no restrictive 'clients' list` } : [...communities.values()][0].line);
  }
  // Idle timeout is per login class; users in built-in classes (super-user …) can never time out.
  for (const [name, c] of classes) b.add("management.login_classes", name, c.line);
  const noIdle = [...classes.entries()].filter(([, c]) => !c.idle);
  const builtin = userClasses.filter((u) => BUILTIN_CLASS.test(u.cls));
  if (noIdle.length || builtin.length) {
    b.set("management.idle_timeout_minutes", 9999, noIdle.length ? { line: noIdle[0][1].line.n, text: `class ${noIdle[0][0]} has no idle-timeout` } : { line: builtin[0].line.n, text: `user ${builtin[0].user} is in built-in class ${builtin[0].cls} (no idle-timeout possible)` });
  }
  if (syslogHosts.size) {
    const plain = [...syslogHosts.entries()].filter(([, h]) => !h.tls);
    b.set("logging.remote_secure", plain.length === 0, plain.length ? { line: plain[0][1].line.n, text: `host ${plain[0][0]} — no 'transport tls' (Junos default: UDP)` } : [...syslogHosts.values()][0].line);
  }
  if (b.params["services.icmp_redirects"]?.source !== "parser" && l3Units.size) {
    const bad = [...l3Units.entries()].filter(([, u]) => !u.noRedirects);
    if (bad.length) b.set("services.icmp_redirects", true, { line: bad[0][1].line.n, text: `${bad[0][0]} — no 'family inet no-redirects'${bad.length > 1 ? ` (+${bad.length - 1} more)` : ""}` });
    else b.set("services.icmp_redirects", false, { line: [...l3Units.values()][0].line.n, text: "'no-redirects' on every L3 unit" });
  }
  if (has(/^security policies\b/)) d("acl.default_deny", true, "SRX default-policy is deny-all unless 'permit-all' is configured");
  if (id.hostname) {
    if (!b.has("identity.hostname_set")) b.set("identity.hostname_set", true, undefined);
    b.set("identity.hostname", id.hostname, undefined);
  }

  const meaningful = lines.filter((l) => !isCommentOrBlank(l));
  const unrecognized = b.unrecognized(lines, isCommentOrBlank);
  return {
    vendor: "juniper-junos",
    identity: id,
    model: b.model(),
    totalLines: lines.length,
    meaningfulLines: meaningful.length,
    recognized: meaningful.length - unrecognized.length,
    unrecognized,
    mappingsApplied: [],
  };
}
