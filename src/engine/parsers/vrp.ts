import type { ParseResult } from "../types";
import { buildIndentTree, first, firstOf, hasWeakCipher, markKnownPrefixes, ModelBuilder, pathOf, toLines, toMinutes, type Line, type Node } from "./util";

const isCommentOrBlank = (l: Line) => !l.text || l.text === "#" || l.text.startsWith("!");

const KNOWN_TOP: (string | RegExp)[] = [
  "sysname", "return", "vlan ", "dhcp ", "undo dhcp", "ip route-static", "ipv6 route-static", "dns ", "undo dns", "stp ", "clock ", "cpu-defend", "port-group",
  "drop-profile", "diffserv", "ip vpn-instance", "ssl policy", "aaa", "interface ", "user-interface ", "acl ", "bgp ", "ospf ", "isis ", "rip ", "info-center",
  "ntp-service", "snmp-agent", "undo snmp-agent", "stelnet", "telnet ", "undo telnet", "ssh ", "http ", "undo http", "header ", "lldp ", "undo lldp", "hwtacacs",
  "radius", "arp ", "undo arp", "ip ", "undo ip", "ipv6", "undo ipv6", "vrrp", "bfd", "mpls", "undo mpls", "l2vpn", "traffic ", "qos ", "route-policy", "ip ip-prefix",
  "ip community-filter", "ip as-path-filter", "ip extcommunity-filter", "set ", "undo set", "vlan batch", "sflow", "netstream", "mac-address", "undo mac-address",
  "device ", "board ", "power ", "fan ", "undo ftp", "ftp ", "tftp", "undo tftp", "sftp", "undo sftp", "web-manager", "undo web-manager", "local-aaa", "pki ", "undo pki",
  "observe-port", "mirroring", "loopback-detect", "undo loopback", "dldp", "undo dldp", "efm", "undo efm", "error-down", "port-security", "dot1x", "undo dot1x", "mac-authen",
  "undo mac-authen", "authentication ", "undo authentication", "authentication-profile", "ip pool", "dhcp snooping", "undo dhcp", "nqa", "undo nqa", "time-range",
  "traffic-policy", "traffic classifier", "traffic behavior", "undo traffic", "user-group", "undo user-group", "ssh server", "ssh client", "ssh user", "undo ssh",
  "undo icmp", "icmp ", "undo tcp", "tcp ", "undo ip source", "ip source", "assign ", "undo assign", "license ", "undo license", "configuration ", "undo configuration",
  "system-view", "quit", "save", "commit", "display ", "undo info-center", "vpn-instance", "stack ", "undo stack", "lacp ", "undo lacp", "eth-trunk", "undo eth-trunk",
  "cluster", "undo cluster", "easy-operation", "undo easy-operation", "smart-link", "monitor-link", "ip netstream", "undo ip netstream", "ipv6 netstream",
  "undo ipv6 netstream", "nat ", "undo nat", "firewall ", "undo firewall", "security-policy", "undo security", "ike ", "undo ike", "ipsec ", "undo ipsec",
  "undo user-interface", "info-center ", "undo ntp", "ntp ", "undo clock", "undo sysname", "undo ssl", "undo aaa", "undo acl", "undo bgp", "undo ospf", "undo isis",
  "undo rip", "undo interface", "undo vlan", "undo stp", "undo cpu-defend", "undo port-group", "undo drop-profile", "undo diffserv", "undo ip vpn", "undo header",
  "undo hwtacacs", "undo radius", "undo vrrp", "undo bfd", "undo l2vpn", "undo qos", "undo route-policy", "undo sflow", "undo device", "undo board", "undo power",
  "undo fan", "undo observe", "undo mirroring", "undo error-down", "undo port-security", "undo ip pool", "undo time-range", "undo traffic-policy", "undo smart-link",
  "undo monitor-link", "undo security-policy", "undo web-manager", "undo local-aaa", "undo display", "arp-miss", "undo arp-miss", "voice-vlan", "undo voice-vlan",
  "mac-spoofing", "undo mac-spoofing", "ip verify", "undo ip verify", "urpf", "undo urpf", "ntdp", "undo ntdp", "ndp", "undo ndp", "multicast", "undo multicast",
  "igmp", "undo igmp", "pim", "undo pim", "grpc", "undo grpc", "netconf", "undo netconf", "telemetry", "undo telemetry", "ops", "undo ops", "terminal ", "undo terminal",
  "banner", "undo banner", "super ", "undo super", "password-policy", "undo password-policy", "location", "undo location", "vty", "undo vty", "portal", "undo portal",
  "free-rule-template", "undo free-rule", "dhcp-server", "undo dhcp-server", "ssh ipv6", "stelnet ipv6", "telnet ipv6", "undo telnet ipv6", "lldp", "undo user-security",
  "user-security-policy", "undo local-user", "capwap", "undo capwap", "wlan", "undo wlan", "vcmp", "undo vcmp", "trap", "undo trap", "alarm", "undo alarm",
];

const KNOWN_CHILD: (string | RegExp)[] = [
  "description", "ip address", "undo ip address", "ipv6 address", "ipv6 enable", "port link-type", "port default vlan", "port trunk", "port hybrid", "stp edged-port",
  "shutdown", "undo shutdown", "dhcp select", "undo negotiation", "negotiation", "speed", "duplex", "eth-trunk", "mode lacp", "undo portswitch", "portswitch",
  "loopback-detect", "vrrp", "ospf ", "undo ospf", "isis ", "bfd ", "mpls", "traffic-filter", "traffic-policy", "qos ", "undo qos", "arp ", "undo arp", "icmp ", "undo icmp",
  "ip binding", "ip route", "ip netstream", "undo ip netstream", "storm-control", "broadcast-suppression", "multicast-suppression", "unicast-suppression", "port-security",
  "dot1x", "undo dot1x", "mac-authen", "authentication", "undo authentication", "user-vlan", "trust ", "undo trust", "jumboframe", "undo jumboframe", "mtu", "flow-control",
  "undo flow-control", "combo-port", "sflow", "undo sflow", "undo enable", "enable", "local-user", "undo local-user", "authentication-scheme", "authorization-scheme",
  "accounting-scheme", "domain", "undo domain", "recording-scheme", "service-scheme", "authentication-mode", "authorization-mode", "accounting-mode", "protocol inbound",
  "idle-timeout", "undo idle-timeout", "acl ", "undo acl", "user privilege", "screen-length", "undo screen-length", "history-command", "shell", "undo shell", "set authentication",
  "user-interface", "rule ", "undo rule", "step ", "peer ", "undo peer", "router-id", "network ", "import-route", "undo import", "area ", "authentication-mode", "silent-interface",
  "undo synchronization", "synchronization", "ipv4-family", "ipv6-family", "vpn-instance", "hwtacacs-server", "radius-server", "undo hwtacacs", "undo radius", "server ",
  "shared-key", "user-name", "undo user-name", "key ", "ssl ", "undo ssl", "certificate", "pki ", "password ", "undo password", "remark", "quit", "return", "port ",
  "undo port", "ip verify", "undo ip verify", "urpf", "undo urpf", "nat ", "undo nat", "zone ", "undo zone", "security-policy", "ike ", "ipsec ", "undo ipsec", "undo ike",
  "mode ", "undo mode", "instance", "undo instance", "priority", "undo priority", "timer", "undo timer", "cost", "undo cost", "ipv6 ", "undo ipv6", "ip ", "undo ip",
  "lldp", "undo lldp", "stp ", "undo stp", "undo speed", "undo duplex", "undo description", "undo vrrp", "undo mtu", "undo bfd", "undo mpls", "undo isis", "undo eth-trunk",
  "undo shutdown", "undo idle", "route-distinguisher", "vpn-target", "apply-label", "undo apply", "export ", "import ", "undo export", "match ", "undo match", "apply ", "index",
  "undo index", "filter ", "undo filter", "log ", "undo log", "counter", "undo counter", "recording", "undo recording", "vlan ", "undo vlan", "name ", "undo name",
  "region-name", "undo region-name", "revision-level", "undo revision-level", "active region-configuration", "check region-configuration", "bpdu", "undo bpdu",
  "max-hops", "undo max-hops", "service-type", "undo service-type", "state ", "level ", "ftp-directory", "access-limit", "undo access-limit", "group ", "undo group",
  "nms-interface", "undo nms-interface", "arp-proxy", "undo arp-proxy", "ip forward-broadcast", "undo ip forward-broadcast", "carrier", "undo carrier",
];

/** Header text pasted above a configuration: terminal prompts and `display version` / `display elabel` output. */
const DEVICE_BANNER: RegExp[] = [
  /^[<[][-\w.~/]+[>\]]/,
  /^Huawei Versatile Routing Platform/i,
  /^VRP \(R\) software/i,
  /^Copyright \(C\)/i,
  /\buptime is\b/,
  /^(ESN|Device serial number|Serial Number|MAC Address|BOM|Bar ?Code|Manufactured|VendorName|IssueNumber|Elabel)\b/i,
  /^\s*\d+\s*\.\s*[\w ()/-]+\s*[:=]/,
  /^(MPU|LPU|SFU|CMU|MCU|BKP|PWR|FAN|CARD|Slot|Board|Pcb|PCB|MAB|BootROM|BootLoad|CPLD|FPGA|SDRAM|DDR|Flash|NVRAM|Memory|Software|Hardware|Patch|System|Basic|Startup|Next|Current|Config)\b[^\n]*[:=]/i,
  /^[\w ()/-]+ version information\s*:/i,
];

function markBlock(b: ModelBuilder, node: Node): void {
  for (const c of node.children) {
    b.mark(c.line);
    markBlock(b, c);
  }
}

/** VRP stores passwords as `irreversible-cipher` (hash), `cipher` (reversible) or `simple` (cleartext). */
const REVERSIBLE = new Set(["cipher", "simple"]);

export function parseVRP(raw: string): ParseResult {
  const lines = toLines(raw);
  const b = new ModelBuilder("huawei-vrp");
  const id = b.identity;
  id.hostname = first(raw, /^\s*sysname\s+(\S+)/m);
  id.osVersion = firstOf(raw, [
    /!Software Version\s+(\S+)/,
    /VRP \(R\) software, Version\s+[\d.]+\s*\([^)]*?\b(V\d{3}R\d{3}\S*?)\)/,
    /\b(V\d{3}R\d{3}C\d{2}(?:SPC\d+)?(?:B\d+)?)\b/,
    /VRP \(R\) software, Version\s+([\d.]+)/,
  ]);
  id.model = firstOf(raw, [
    /^[!#]?\s*(?:Quidway|Huawei|HUAWEI|CloudEngine)\s+(\S+)\s[^\n]*\buptime is\b/m,
    /^\s*device board\s+\S+\s+board-type\s+(\S+)/m,
    /^\s*\d+\s*\.\s*Board\s+Type\s*[:=]\s*(\S+)/mi,
    /VRP \(R\) software, Version [\d.]+\s*\((\S+)\s+V\S+\)/,
    /^#\s*model\s*[:=]\s*(\S+)/mi,
  ]);
  id.serial = firstOf(raw, [
    /^\s*!?\s*ESN\b[^:=\n]*[:=]\s*(\S+)/mi,
    /Device serial number\s*[:=]\s*(\S+)/i,
    /Serial\s*Number\s*[:=]\s*(\S+)/i,
    /^#\s*serial(?:\s*number)?\s*[:=]\s*(\S+)/mi,
  ]);
  // Priority: dedicated OOB port, then loopback, then a management SVI — never "whichever interface came first".
  const ifaceIp = (name: string) => new RegExp(`^[ \\t]*interface ${name}[^\\n]*\\n(?:[ \\t]+[^\\n]*\\n)*?[ \\t]+ip address\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})`, "m");
  id.mgmtIp = firstOf(raw, [
    ifaceIp("MEth\\S*"),
    ifaceIp("Ethernet0/0/0"),
    ifaceIp("LoopBack\\d+"),
    ifaceIp("Vlanif99"),
    ifaceIp("Vlanif\\d+"),
    /^\s+ip address\s+(\d{1,3}(?:\.\d{1,3}){3})/m,
  ]);
  id.role = /\bRouter uptime is\b/.test(raw) || /^(AR|NE|ME|ATN|CX)\d/i.test(id.model ?? "")
    ? "router"
    : /\bRouting Switch uptime is\b/.test(raw) || /^(S\d|CE\d|Quidway)/i.test(id.model ?? "") || /^\s*(port link-type|vlan batch|interface Vlanif|stp (region-configuration|mode|enable))/m.test(raw)
      ? "switch"
      : /^\s*(firewall zone|security-policy)/m.test(raw)
        ? "firewall"
        : "router";
  if (id.hostname) b.set("identity.hostname", id.hostname, undefined);

  // V200R019 introduced syslog-over-TLS, GCM SSH ciphers, SHA2 SNMP auth and the
  // `password policy` sub-view; older releases need the legacy syntax in remediation.
  const rel = id.osVersion?.match(/V(\d{3})R(\d{3})/);
  const modern = rel ? parseInt(rel[1], 10) > 200 || parseInt(rel[2], 10) >= 19 : false;
  b.set("identity.vrp_r19plus", modern, {
    line: 0,
    text: rel ? `Software version ${id.osVersion}` : "software version not reported — assuming pre-V200R019 command syntax",
  });

  const d = (k: string, v: string | number | boolean, note: string) => b.setDefault(k, v, `Platform default — ${note}`);
  d("management.telnet_enabled", false, "telnet server disabled unless 'telnet server enable'");
  d("management.ssh_enabled", false, "stelnet server disabled unless 'stelnet server enable'");
  d("management.ssh_version", 2, "SSHv1 compatibility off unless 'ssh server compatible-ssh1x enable'");
  d("management.ssh_timeout_seconds", 60, "'ssh server timeout' defaults to 60 seconds");
  d("management.ssh_auth_retries", 3, "'ssh server authentication-retries' defaults to 3");
  d("management.http_enabled", false, "HTTP server disabled unless 'http server enable'");
  d("management.https_enabled", false, "HTTPS server disabled unless 'http secure-server enable'");
  d("management.idle_timeout_minutes", 10, "VTY idle-timeout defaults to 10 minutes");
  d("management.console_timeout_minutes", 10, "console idle-timeout defaults to 10 minutes");
  d("management.aux_disabled", true, "no 'user-interface aux' block — the AUX port is absent (S/CE series) or left at its default, which rejects login");
  d("auth.password_encryption", true, "VRP V200R+ stores irreversible ciphers for local users");
  d("auth.aaa_enabled", true, "AAA is always present on VRP");
  d("logging.enabled", true, "info-center is enabled by default");
  d("logging.timestamps", true, "info-center timestamps logs (date format)");
  d("logging.buffered", true, "logbuffer enabled by default (512 entries)");
  d("time.ntp_authentication", false, "'ntp-service authentication enable' not configured");
  d("snmp.enabled", false, "snmp-agent not enabled");
  d("management.login_banner", false, "no 'header login' configured");
  d("management.mgmt_acl_applied", false, "no 'acl inbound' under user-interface vty");
  d("services.ip_source_routing", false, "IP source-routed packets are dropped by default");
  d("services.icmp_redirects", true, "ICMP redirects sent unless 'undo icmp redirect send'");
  d("services.proxy_arp", false, "proxy ARP disabled unless 'arp-proxy enable'");
  d("services.directed_broadcast", false, "directed broadcast disabled unless 'ip forward-broadcast'");
  d("services.lldp_enabled", false, "LLDP disabled unless 'lldp enable'");
  d("crypto.strong_crypto", false, "default SSH cipher list includes CBC/3DES");

  /**
   * The SSH algorithm lists are three separate commands; one weak list spoils the
   * set. A platform default must never be mistaken for a parser observation here.
   */
  const setCrypto = (strong: boolean, l: Line) => {
    const cur = b.params["crypto.strong_crypto"];
    if (!strong) return b.set("crypto.strong_crypto", false, l);
    if (cur && cur.source !== "default" && cur.value === false) return b.mark(l);
    b.set("crypto.strong_crypto", true, l);
  };

  const roots = buildIndentTree(lines, isCommentOrBlank);
  const aclNames = new Set<string>();
  // Telnet reachability is decided once, at the end: `telnet server enable` opens TCP/23
  // whatever a single VTY range says, and one permissive VTY range is enough.
  let telnetServer: boolean | undefined;
  let telnetServerLine: Line | undefined;
  let vtyTelnetLine: Line | undefined;
  // `authentication-mode` differs per VTY range: the weakest range is the device's posture.
  let vtyAaa: boolean | undefined;
  let vtyAaaLine: Line | undefined;
  let aaaLine: Line | undefined;
  let infoCenterOff: Line | undefined;

  const walkTop = (node: Node) => {
    const l = node.line;
    const t = l.text;
    let m: RegExpMatchArray | null;
    if (/^sysname\s+\S+/.test(t)) return b.setTrue("identity.hostname_set", l);
    if (/^stelnet (ipv6 )?server enable$/.test(t)) return b.setTrue("management.ssh_enabled", l);
    if (/^undo stelnet (ipv6 )?server enable$/.test(t) || t === "stelnet server disable") return b.setFalse("management.ssh_enabled", l);
    if (/^telnet (ipv6 )?server enable$/.test(t)) { telnetServer = true; telnetServerLine = l; return b.mark(l); }
    if (/^undo telnet (ipv6 )?server enable$/.test(t) || /^telnet (ipv6 )?server disable$/.test(t)) {
      if (telnetServer === undefined) { telnetServer = false; telnetServerLine = l; }
      return b.mark(l);
    }
    if (t === "ssh server compatible-ssh1x enable") return b.set("management.ssh_version", 1, l);
    if (t === "undo ssh server compatible-ssh1x enable" || t === "ssh server compatible-ssh1x disable") return b.set("management.ssh_version", 2, l);
    if ((m = t.match(/^ssh server dh-exchange min-len\s+(\d+)/))) return setCrypto(parseInt(m[1], 10) >= 2048, l);
    if ((m = t.match(/^ssh server (cipher|hmac|key-exchange)\s+(.*)$/))) return setCrypto(!hasWeakCipher(m[2].replace(/_/g, "-")), l);
    if ((m = t.match(/^ssh server timeout\s+(\d+)/))) return b.set("management.ssh_timeout_seconds", parseInt(m[1], 10), l);
    if ((m = t.match(/^ssh server authentication-retries\s+(\d+)/))) return b.set("management.ssh_auth_retries", parseInt(m[1], 10), l);
    if (/^ssh server(-source)? /.test(t) || /^ssh (user|client|authentication-type|authorization-type|ipv6)/.test(t)) return b.mark(l);
    if (t === "http server enable" || t === "web-manager enable") return b.setTrue("management.http_enabled", l);
    if (t === "undo http server enable" || t === "undo web-manager enable") return b.setFalse("management.http_enabled", l);
    if (t === "http secure-server enable" || /^web-manager security enable/.test(t)) return b.setTrue("management.https_enabled", l);
    if (t === "undo http secure-server enable" || /^undo web-manager security enable/.test(t)) return b.setFalse("management.https_enabled", l);
    if (/^(ftp|tftp) (ipv6 )?server enable/.test(t)) return b.setTrue("management.ftp_enabled", l);
    if (/^undo (ftp|tftp) (ipv6 )?server/.test(t)) return b.setFalse("management.ftp_enabled", l);
    if ((m = t.match(/^super password(?: level \d+)? (irreversible-cipher|cipher|simple)/))) {
      b.setTrue("auth.enable_secret", l);
      if (m[1] === "simple") b.inc("auth.weak_password_hashes", l);
      return;
    }
    if (/^header (login|shell) (information|file)/.test(t)) {
      if (/^header login/.test(t)) b.setTrue("management.login_banner", l);
      else b.mark(l);
      // multi-line header text uses a delimiter char; mark subsequent lines until it closes
      const mm = t.match(/(?:information|file)\s+(\S)(.*)$/);
      if (mm && !mm[2].includes(mm[1])) {
        const start = l.n;
        for (let i = start; i < lines.length; i++) {
          b.mark(lines[i]);
          if (lines[i].raw.includes(mm[1])) break;
        }
      }
      return;
    }
    if (t === "lldp enable") return b.setTrue("services.lldp_enabled", l);
    if (t === "undo lldp enable") return b.setFalse("services.lldp_enabled", l);
    if (/^undo icmp redirect send/.test(t)) return b.setFalse("services.icmp_redirects", l);
    if (/^icmp redirect send/.test(t)) return b.setTrue("services.icmp_redirects", l);
    if ((m = t.match(/^user-interface (vty|con|aux)\s/))) {
      b.mark(l);
      const kind = m[1];
      let auxShell: boolean | undefined;
      for (const c of node.children) {
        const ct = c.line.text;
        let cm: RegExpMatchArray | null;
        if ((cm = ct.match(/^authentication-mode (aaa|password|none)/))) {
          if (kind === "vty") {
            const ok = cm[1] === "aaa";
            if (vtyAaa === undefined || (vtyAaa && !ok)) { vtyAaa = ok; vtyAaaLine = c.line; }
            b.mark(c.line);
          } else b.mark(c.line);
        } else if ((cm = ct.match(/^protocol inbound (ssh|telnet|all)/))) {
          if (cm[1] !== "ssh" && !vtyTelnetLine) vtyTelnetLine = c.line;
          b.mark(c.line);
        } else if ((cm = ct.match(/^idle-timeout\s+(\d+)(?:\s+(\d+))?/))) {
          if (kind === "vty") b.max("management.idle_timeout_minutes", toMinutes(cm[1], cm[2]), c.line);
          else b.max("management.console_timeout_minutes", toMinutes(cm[1], cm[2]), c.line);
        } else if (/^acl\s+\S+\s+inbound/.test(ct)) { if (kind === "vty") b.setTrue("management.mgmt_acl_applied", c.line); else b.mark(c.line); }
        else if (/^set authentication password (cipher|simple)/.test(ct)) { if (/simple/.test(ct)) b.inc("auth.weak_password_hashes", c.line); else b.mark(c.line); }
        else if (/^(undo )?shell$/.test(ct)) { auxShell = !ct.startsWith("undo"); b.mark(c.line); }
        else b.mark(c.line);
      }
      if (kind === "aux") b.set("management.aux_disabled", auxShell === false, l);
      return;
    }
    if (t === "aaa") {
      aaaLine = l;
      b.set("auth.aaa_enabled", true, l);
      const walk = (n: Node) => {
        for (const c of n.children) {
          const ct = c.line.text;
          let cm: RegExpMatchArray | null;
          if ((cm = ct.match(/^local-user (\S+) password (irreversible-cipher|cipher|simple)/))) {
            b.add("auth.local_users", cm[1], c.line);
            if (REVERSIBLE.has(cm[2])) {
              b.inc("auth.weak_password_hashes", c.line);
              b.add("auth.weak_local_users", cm[1], c.line);
              // `simple` is the plaintext form: the password is readable in the config.
              if (cm[2] === "simple") b.set("auth.password_encryption", false, c.line);
            }
            if (cm[2] === "irreversible-cipher" && b.get("auth.password_encryption") !== false) b.setTrue("auth.password_encryption", c.line);
          } else if (/^local-aaa-user password policy/.test(ct) || /^password composition/.test(ct)) { b.setTrue("auth.password_complexity", c.line); }
          else if ((cm = ct.match(/^password (?:min-length|minimum-length|length)\s+(\d+)/))) { b.set("auth.min_password_length", parseInt(cm[1], 10), c.line); }
          else if (/^local-user \S+ (privilege|service-type|user-group|state|ftp-directory|level|idle-timeout|access-limit)/.test(ct)) b.mark(c.line);
          else if (/^authentication-scheme \S+/.test(ct)) b.mark(c.line);
          else if (/^authentication-mode (hwtacacs|radius)/.test(ct)) { b.setTrue("auth.aaa_authentication_login", c.line); }
          else if (/^accounting-mode (hwtacacs|radius)/.test(ct) || /^accounting-scheme/.test(ct)) { if (/hwtacacs|radius/.test(ct)) b.setTrue("auth.aaa_accounting", c.line); else b.mark(c.line); }
          else if (/^(local-aaa-user |local-user )?(wrong-password|user-password)\b/.test(ct)) {
            b.setTrue("auth.login_lockout", c.line);
            const w = ct.match(/retry-time (\d+)/);
            if (w) b.set("auth.max_login_attempts", parseInt(w[1], 10), c.line);
          }
          else b.mark(c.line);
          walk(c);
        }
      };
      walk(node);
      return;
    }
    if ((m = t.match(/^(hwtacacs-server|radius-server) template\s+(\S+)/))) {
      b.mark(l);
      b.setTrue("auth.aaa_enabled", l);
      for (const c of node.children) {
        const cm = c.line.text.match(/^(?:hwtacacs-server|radius-server) (?:authentication|authorization|accounting|shared-key)?\s*(\d{1,3}(?:\.\d{1,3}){3})/);
        if (cm) b.add("auth.remote_auth_servers", cm[1], c.line);
        else b.mark(c.line);
      }
      return;
    }
    if (t === "info-center enable") return b.setTrue("logging.enabled", l);
    if (t === "undo info-center enable") { infoCenterOff = l; return b.setFalse("logging.enabled", l); }
    if ((m = t.match(/^info-center loghost\s+(?:ipv6\s+)?(\S+)(.*)$/))) {
      if (/^(source-ip|source|source-interface)$/.test(m[1])) return b.setTrue("logging.source_interface", l);
      b.add("logging.remote_hosts", m[1], l);
      if (/transport (tcp|dtls)|ssl-policy/.test(m[2])) b.setTrue("logging.remote_secure", l);
      return;
    }
    if (/^info-center timestamp/.test(t)) return b.setTrue("logging.timestamps", l);
    if ((m = t.match(/^info-center source .* level\s+(\S+)/))) return b.set("logging.level", m[1], l);
    if (/^info-center (logbuffer|logfile)/.test(t)) return b.setTrue("logging.buffered", l);
    if (/^undo info-center (logbuffer|logfile)/.test(t)) return b.setFalse("logging.buffered", l);
    if (/^info-center/.test(t)) return b.mark(l);
    if ((m = t.match(/^ntp(?:-service)? (?:ipv6 )?unicast-(server|peer)\s+(\S+)(.*)$/))) { b.add("time.ntp_servers", m[2], l); return; }
    if (/^ntp(-service)? authentication enable$/.test(t)) return b.setTrue("time.ntp_authentication", l);
    if (/^ntp-service/.test(t)) return b.mark(l);
    if (/^clock timezone/.test(t)) return b.setTrue("time.timezone_set", l);
    if (t === "snmp-agent") return b.setTrue("snmp.enabled", l);
    if (t === "undo snmp-agent") return b.setFalse("snmp.enabled", l);
    if ((m = t.match(/^snmp-agent community (read|write)\s+(cipher\s+)?(\S+)(.*)$/))) {
      b.setTrue("snmp.enabled", l);
      // `cipher <blob>` is the saved ciphertext; `cipher public` is somebody typing a default in cleartext.
      const blob = /^%\^%#|^%\$%\$|^\$[\w$]/.test(m[3]) || m[3].length > 20;
      const name = m[2] && blob ? `${m[3].slice(0, 6)}… (cipher)` : m[3];
      b.add("snmp.v1v2c_communities", name, l);
      if (!blob && ["public", "private", "cisco", "admin", "snmp"].includes(m[3].toLowerCase())) {
        b.add("snmp.default_communities", m[3], l);
        // Direction-tagged so remediation can emit `undo snmp-agent community read|write <name>`.
        b.add("snmp.default_community_ids", `${m[1]} ${m[3]}`, l);
      }
      if (m[1] === "write") b.add("snmp.rw_communities", name, l);
      const prev = b.get("snmp.community_acl");
      const acl = /\bacl\s+\S+/.test(m[4]);
      b.set("snmp.community_acl", prev === undefined ? acl : Boolean(prev) && acl, l);
      return;
    }
    if ((m = t.match(/^snmp-agent sys-info version\s+(.*)$/))) {
      b.setTrue("snmp.enabled", l);
      if (/v3|all/.test(m[1])) b.setTrue("snmp.v3_enabled", l);
      return;
    }
    if (/^snmp-agent (usm-user v3 \S+ privacy-mode|group v3 \S+ privacy)/.test(t)) { b.setTrue("snmp.v3_enabled", l); b.setTrue("snmp.v3_priv", l); b.setTrue("snmp.enabled", l); return; }
    if (/^snmp-agent (usm-user v3|group v3)/.test(t)) { b.setTrue("snmp.v3_enabled", l); b.setTrue("snmp.enabled", l); if (!b.has("snmp.v3_priv")) b.set("snmp.v3_priv", false, l); return; }
    if ((m = t.match(/^snmp-agent target-host (?:trap|inform) address udp-domain\s+(\S+)/))) { b.add("snmp.trap_hosts", m[1], l); b.setTrue("snmp.enabled", l); return; }
    if (/^snmp-agent/.test(t)) return b.setTrue("snmp.enabled", l);
    if (/^undo ip source-route|^ip source-route/.test(t)) return b.set("services.ip_source_routing", !t.startsWith("undo"), l);
    if (/^(ftp|tftp) server/.test(t)) return b.mark(l);
    if ((m = t.match(/^interface\s+(\S+)/))) {
      b.mark(l);
      if (/^LoopBack/i.test(m[1])) b.setTrue("identity.loopback_present", l);
      if (/^Tunnel/i.test(m[1])) b.inc("identity.tunnels", l);
      for (const c of node.children) {
        const ct = c.line.text;
        if (/^traffic-filter inbound acl/.test(ct)) b.setTrue("acl.external_ingress_filter", c.line);
        else if (/^arp-proxy( \S+)? enable/.test(ct)) b.setTrue("services.proxy_arp", c.line);
        else if (/^undo arp-proxy/.test(ct)) b.setFalse("services.proxy_arp", c.line);
        else if (ct === "undo icmp redirect send") b.setFalse("services.icmp_redirects", c.line);
        else if (ct === "ip forward-broadcast") b.setTrue("services.directed_broadcast", c.line);
        else if (ct === "undo ip forward-broadcast") b.setFalse("services.directed_broadcast", c.line);
        else if (/^ospf authentication-mode (md5|hmac-md5|hmac-sha256|sha256|keychain)/.test(ct)) b.setTrue("routing.ospf_auth", c.line);
        else if (/^urpf/.test(ct) || /^ip urpf/.test(ct)) b.setTrue("services.unicast_rpf", c.line);
        else b.mark(c.line);
        markBlock(b, c);
      }
      return;
    }
    if ((m = t.match(/^acl (?:ipv6 )?(?:number |name )?(\S+)/))) {
      if (!aclNames.has(m[1])) { aclNames.add(m[1]); b.inc("acl.count", l); } else b.mark(l);
      for (const c of node.children) {
        if (/^rule (\d+ )?deny.*logging/.test(c.line.text)) b.setTrue("acl.explicit_deny_logged", c.line);
        else b.mark(c.line);
      }
      return;
    }
    if ((m = t.match(/^bgp\s+(\S+)/))) {
      b.setTrue("routing.bgp_configured", l);
      b.set("routing.bgp_asn", m[1], l);
      const walk = (n: Node) => {
        for (const c of n.children) {
          const cm = c.line.text.match(/^peer (\S+) password/);
          if (cm) b.setTrue("routing.bgp_auth", c.line);
          else b.mark(c.line);
          walk(c);
        }
      };
      walk(node);
      if (!b.has("routing.bgp_auth")) b.set("routing.bgp_auth", false, l);
      return;
    }
    if (/^ospf\s+\S+/.test(t)) {
      b.setTrue("routing.ospf_configured", l);
      const walk = (n: Node) => {
        for (const c of n.children) {
          const ct = c.line.text;
          if (/^area\s+(\S+)/.test(ct)) b.add("routing.ospf_areas", ct.replace(/^area\s+/, "").trim(), c.line);
          if (/^authentication-mode (md5|hmac-sha256|hmac-md5|sha256|keychain)/.test(ct)) b.setTrue("routing.ospf_auth", c.line);
          else b.mark(c.line);
          walk(c);
        }
      };
      walk(node);
      if (!b.has("routing.ospf_auth")) b.set("routing.ospf_auth", false, l);
      return;
    }
    if ((m = t.match(/^ssl policy\s+\S+/))) {
      b.mark(l);
      for (const c of node.children) {
        const cm = c.line.text.match(/^ssl minimum version tls(\S+)/);
        if (cm) b.set("crypto.tls_min_version", cm[1], c.line);
        else b.mark(c.line);
      }
      return;
    }
    if (/^ike proposal/.test(t)) {
      b.mark(l);
      for (const c of node.children) {
        if (/^(encryption-algorithm (des|3des)|authentication-algorithm md5|dh group[12]\b)/.test(c.line.text)) b.setTrue("crypto.weak_ike", c.line);
        else b.mark(c.line);
      }
      if (!b.has("crypto.weak_ike")) b.set("crypto.weak_ike", false, l);
      return;
    }
    if (/^ipsec proposal/.test(t)) {
      b.mark(l);
      for (const c of node.children) {
        if (/^esp (encryption-algorithm (des|3des)|authentication-algorithm md5)/.test(c.line.text)) b.setTrue("crypto.weak_ike", c.line);
        else b.mark(c.line);
      }
      return;
    }
  };
  for (const node of roots) walkTop(node);

  // Telnet: the listener wins over any single VTY range, and one permissive range is enough.
  if (telnetServer !== undefined) {
    b.set("management.telnet_enabled", telnetServer, telnetServerLine);
    if (telnetServer && vtyTelnetLine) b.set("management.telnet_enabled", true, vtyTelnetLine);
  } else if (vtyTelnetLine) {
    b.set("management.telnet_enabled", true, vtyTelnetLine);
  }
  // The VTY login method decides whether AAA actually guards administrative access.
  if (vtyAaa !== undefined) b.set("auth.aaa_authentication_login", vtyAaa, vtyAaaLine);
  // An `aaa` view with no HWTACACS/RADIUS template means there is no central server —
  // that is an observation, not a gap in the parser.
  if (aaaLine && !b.has("auth.remote_auth_servers")) b.set("auth.remote_auth_servers", [], aaaLine);
  // info-center off ⇒ nothing is shipped anywhere, however the collectors are configured.
  if (infoCenterOff && !b.has("logging.remote_hosts")) b.set("logging.remote_hosts", [], infoCenterOff);

  const nodeByLine = new Map<number, Node>();
  const index = (n: Node) => { nodeByLine.set(n.line.n, n); n.children.forEach(index); };
  roots.forEach(index);
  // Root-level, not "indent 0": some archives indent the whole configuration by one column.
  markKnownPrefixes(b, roots.map((r) => r.line), KNOWN_TOP);
  for (const l of lines) {
    if (isCommentOrBlank(l) || b.recognized.has(l.n)) continue;
    const node = nodeByLine.get(l.n);
    if (node?.parent && b.recognized.has(node.parent.line.n)) {
      for (const p of KNOWN_CHILD) {
        if (typeof p === "string" ? l.text.startsWith(p) : p.test(l.text)) { b.mark(l); break; }
      }
    }
  }
  // Last resort: `display version` output and terminal prompts pasted above the configuration.
  markKnownPrefixes(b, lines, DEVICE_BANNER);

  const meaningful = lines.filter((l) => !isCommentOrBlank(l));
  const unrecognized = b.unrecognized(lines, isCommentOrBlank, (l) => { const n = nodeByLine.get(l.n); return n ? pathOf(n) || undefined : undefined; });
  return {
    vendor: "huawei-vrp",
    identity: id,
    model: b.model(),
    totalLines: lines.length,
    meaningfulLines: meaningful.length,
    recognized: meaningful.length - unrecognized.length,
    unrecognized,
    mappingsApplied: [],
  };
}
