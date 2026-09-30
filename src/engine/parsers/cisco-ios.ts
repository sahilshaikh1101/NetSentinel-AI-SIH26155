import type { ParseResult } from "../types";
import { buildIndentTree, first, hasWeakCipher, IPV4, markKnownPrefixes, ModelBuilder, pathOf, toLines, toMinutes, unquote, type Line, type Node } from "./util";

/**
 * Cisco IOS / IOS-XE parser. Arista EOS shares the grammar and is handled by
 * the same walker with vendor-specific extensions; Cisco NX-OS is a dialect
 * with its own defaults and a few extra command forms.
 */
type IosVendor = "cisco-ios" | "arista-eos" | "cisco-nxos";

const KNOWN_TOP: (string | RegExp)[] = [
  "Building configuration", "Current configuration", "Load for ", "Time source is", "No entries found", "!Command", "!Running configuration", "!Time:",
  "version ", "boot-start-marker", "boot-end-marker", "boot system", "boot nxos", "boot-", "service ", "no service ", "platform ", "license ", "diagnostic ",
  "spanning-tree", "no spanning-tree", "ip security", "vlan ", "memory-size", "memory free", "multilink", "redundancy", "control-plane", "scheduler", "end", "mls ", "system mtu", "vtp ",
  "errdisable", "power ", "ip cef", "no ip cef", "ipv6 cef", "no ipv6 cef", "ip name-server", "ip dhcp", "no ip dhcp", "ip domain lookup", "ip domain-lookup",
  "no ip domain lookup", "no ip domain-lookup", "ip forward-protocol", "ip nat ", "ipv6 unicast-routing", "ip multicast-routing",
  "ip vrf", "vrf definition", "vrf instance", "vrf context", "class-map", "policy-map", "route-map", "ip prefix-list", "ipv6 prefix-list", "track ", "event manager",
  "key chain", "crypto pki", "crypto ca", "certificate", "call-home", "no call-home", "exception ", "file prompt", "hw-module", "device-tracking",
  "mac address-table", "udld", "flow ", "sampler", "ip flow", "parser ", "alias ", "privilege ", "ip tcp", "ip icmp", "ip options", "ipv6 nd",
  "ip dhcp snooping", "ip arp inspection", "storm-control", "ip route", "ipv6 route", "ip default-gateway", "cts ", "dot1x", "lldp ", "no lldp",
  "table-map", "qos", "mls qos", "auto qos", "port-channel", "lacp", "monitor session", "ip sla", "no ip sla", "ip igmp", "ip pim", "no platform",
  "hostname", "ip domain", "no ip domain", "enable", "username", "aaa", "no aaa", "login ", "security ", "ip ssh", "ip http", "no ip http",
  "banner ", "logging", "no logging", "ntp ", "no ntp", "clock ", "snmp-server", "no snmp-server", "cdp ", "no cdp", "ip source-route",
  "no ip source-route", "ip bootp", "no ip bootp", "ip identd", "no ip identd", "ip finger", "no ip finger", "ip domain-name", "ip domain name",
  "archive", "crypto isakmp", "crypto ipsec", "crypto map", "crypto ikev2", "tacacs", "radius", "ip access-list", "ipv6 access-list", "access-list",
  "interface ", "router ", "line ", "ip ftp", "ip tftp", "ip scp", "ip rcmd", "ip radius", "ip tacacs", "vstack", "no vstack", "ip routing",
  "no ip routing", "shutdown vlan", "no shutdown vlan", "ip host ", "ip dns", "ip access-group", "ip verify", "login block-for", "wsma ",
  "transceiver", "daemon", "management ", "dns domain", "service routing", "sflow", "queue-monitor", "mlag", "monitor ", "event-handler",
  "system control-plane", "ip virtual-router", "ip igmp snooping", "hardware ", "load-interval", "no schedule", "mac ", "router-id", "peer-filter",
  "prefix-list", "ip community-list", "ip extcommunity-list", "ip as-path", "vrrp", "queue ", "bfd", "cvx", "traffic-policies", "roles", "role ", "tap ",
  "ptp ", "poe", "arp ", "ip arp", "mac security", "switchport ", "no switchport", "l2-protocol", "ip mroute", "ipv6 ", "system ", "tunnel ", "vxlan",
  "ip dhcp relay", "no ip verify", "no ip icmp", "no ip route", "no ip forward-protocol", "ip subnet-zero", "no ip subnet-zero", "no ip gratuitous-arps",
  "ip gratuitous-arps", "switch ", "snmp ifmib", "password encryption", "object-group", "template ", "access-session", "authentication ", "secure boot",
  "feature ", "no feature", "vdc ", "copp ", "vpc ", "fex ", "install ", "rmon ", "no password strength-check", "password strength-check", "ssh key ",
  "no ip domain-lookup", "cli ", "nv overlay", "fabric ", "spanning-tree", "port-profile", "hardware access-list", "no system ", "rate-limit", "boot ",
  "clock ", "cfs ", "ip pim", "no ip igmp", "evpn", "policy-map", "class-map", "ip community-list", "ip access-list logging", "ip access-list log-update",
];

const KNOWN_CHILD: (string | RegExp)[] = [
  "description", "ip address", "no ip address", "ipv6 address", "switchport", "no switchport", "duplex", "speed", "negotiation", "channel-group",
  "spanning-tree", "ip helper-address", "standby", "vrf ", "mtu", "encapsulation", "tunnel ", "crypto map", "ip nat", "no cdp enable", "cdp enable",
  "no lldp", "lldp", "shutdown", "no shutdown", "ip ospf", "ip pim", "ip igmp", "bandwidth", "delay", "load-interval", "service-policy", "ip flow",
  "storm-control", "no keepalive", "keepalive", "media-type", "power ", "auto qos", "mls qos", "priority-queue", "srr-queue", "queue-set", "wrr-queue",
  "ip dhcp", "no ip dhcp", "ip mtu", "ip tcp", "hold-queue", "no mop", "mop ", "no ip route-cache", "ip route-cache", "cts ", "dot1x", "authentication",
  "mab", "ip device tracking", "ip arp inspection", "ip verify source", "ip access-group", "ipv6 traffic-filter", "ipv6 nd", "logging event",
  "no logging event", "carrier-delay", "dampening", "zone-member", "ip virtual-reassembly", "ip nbar", "ip policy", "ip summary-address", "ip rip",
  "ip authentication", "vrrp", "glbp", "hsrp", "bfd", "isis", "ip router isis", "clns", "mpls", "xconnect", "service instance", "rewrite",
  "bridge-domain", "l2protocol", "ethernet ", "cdp ", "ip proxy-arp", "no ip proxy-arp", "ip redirects", "no ip redirects", "ip unreachables",
  "no ip unreachables", "ip directed-broadcast", "no ip directed-broadcast", "ip mask-reply", "no ip mask-reply", "ip verify unicast",
  "network ", "neighbor ", "bgp ", "address-family", "exit-address-family", "redistribute", "passive-interface", "no passive-interface", "area ",
  "log-adjacency-changes", "router-id", "auto-cost", "default-information", "timers", "distance", "maximum-paths", "no auto-summary", "auto-summary",
  "eigrp ", "metric", "variance", "version", "permit", "deny", "remark", "evaluate", "sequence", "exec-timeout", "no exec-timeout", "transport ",
  "access-class", "login", "no login", "password", "privilege", "logging synchronous", "length", "width", "session-limit", "session-timeout",
  "absolute-timeout", "stopbits", "flowcontrol", "no exec", "exec ", "escape-character", "history", "motd-banner", "exec-banner", "no motd-banner",
  "no exec-banner", "ipv6 access-class", "rotary", "location", "activation-character", "no activation-character", "monitor", "terminal-type",
  "idle-timeout", "no idle-timeout", "authentication mode", "cipher", "key-exchange", "mac ", "hostkey", "login timeout", "connection limit",
  "protocol ", "no protocol", "vrf", "ssl profile", "qos ", "port ", "entropy", "password ", "no password", "ssl ", "server ", "local-interface",
  "source-interface", "log config", "logging enable", "hidekeys", "path ", "maximum ", "write-memory", "time-period", "encryption", "encr ", "hash",
  "group", "lifetime", "authentication", "address ", "key ", "timeout", "single-connection", "server-private", "server name", "ip vrf forwarding",
  "rd ", "route-target", "certificate", "quit", "revocation-check", "rsakeypair", "subject-name", "enrollment", "serial-number", "fqdn", "ip-address",
  "match ", "set ", "class ", "police", "shape", "priority", "queue-limit", "random-detect", "fair-queue", "compress", "ip ", "ipv6 ", "no ip ",
  "no ipv6 ", "auto ", "no auto", "profile ", "contact-email-addr", "destination", "no destination", "active", "no active", "alert-group", "vlan ",
  "name ", "state ", "mode ", "mst ", "instance ", "revision ", "no negotiation", "ip cef", "l2 ", "peer ", "mac-address", "arp ", "logging host",
  "no spanning-tree", "spanning-tree portfast", "no logging", "logging", "session", "sflow", "ip local-proxy-arp", "no ip local-proxy-arp", "tcp ",
  "no tcp", "action", "event ", "monitor-interface", "reachability", "rate-limit", "no rate-limit", "cli ", "no cli", "aaa ", "no aaa",
  "default-router", "dns-server", "domain-name", "lease ", "option ", "key-string", "cryptographic-algorithm", "accept-lifetime", "send-lifetime",
  "client-id-trustpoint", "ciphersuite", "collect ", "exporter ", "cache ", "icmp-echo", "frequency", "key-hash", "username ", "host ", "range ",
  "integrity", "prf ", "proposal", "keyring", "identity", "pre-shared-key", "match identity", "no shut", "vpc ", "allocate ", "limit-resource",
  "cpu-share", "member ", "port-type", "channel-group", "hardware ", "vn-segment", "fabric ", "no negotiate", "medium ", "beacon", "no beacon",
  "template ", "inherit ", "update-source", "ebgp-multihop", "send-community", "soft-reconfiguration", "next-hop-self", "route-reflector-client",
  "transport connection-mode", "no synchronization", "synchronization", "graceful-restart", "log-neighbor-changes", "maximum-prefix", "ao ", "keychain",
  "authentication key-chain", "authentication mode", "af-interface", "topology", "exit-af-interface", "exit-af-topology", "exit-address-family",
  "min-length", "upper-case", "lower-case", "numeric-count", "special-case", "char-changes", "max-length", "lifetime", "no ", "ipv6 router",
  "ospfv3 ", "ipv6 ospf", "ipv6 enable", "ipv6 nd", "ipv6 traffic-filter", "ipv6 verify", "cdp enable", "no cdp enable", "logging trap", "logging source",
  "snmp trap", "snmp ifindex", "no snmp trap", "device-tracking", "ip dhcp snooping", "trust", "no trust", "macro ", "no macro", "stack-", "switch ",
  "peer-switch", "role priority", "peer-keepalive", "peer-gateway", "auto-recovery", "delay restore", "ip arp synchronize", "layer3 peer-router",
  "system-priority", "dual-active", "vpc ", "hsrp ", "priority ", "preempt", "timers ", "track ", "no ip ", "ip forward", "ip dhcp relay", "mtu ",
  "trunk group", "seq ", "domain-id", "peer-address", "peer-link", "reload-delay", "dual-primary", "heartbeat-interval", "client-alive", "connection per-host",
];

const isCommentOrBlank = (l: Line) => !l.text || l.text.startsWith("!");

/** Multi-line banners: mark all banner lines as recognised and exclude from tree. */
function collectBanners(lines: Line[], b: ModelBuilder): Set<number> {
  const inBanner = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].text;
    const m = t.match(/^banner\s+(motd|login|exec|incoming|slip-ppp|prompt-timeout)(?:\s+(\S+)(.*))?$/);
    if (!m) continue;
    const preLogin = m[1] === "motd" || m[1] === "login";
    if (preLogin) b.set("management.login_banner", true, lines[i]);
    else b.mark(lines[i]);
    let delim = m[2] ?? "";
    // EOS style: "banner login" followed by text and "EOF"
    if (!delim || delim === "EOF") {
      let j = i + 1;
      while (j < lines.length && lines[j].text !== "EOF") {
        inBanner.add(lines[j].n);
        b.mark(lines[j]);
        j++;
      }
      if (j < lines.length) {
        inBanner.add(lines[j].n);
        b.mark(lines[j]);
      }
      i = j;
      continue;
    }
    // Delimiter is either a two-character control sequence like ^C or a single character.
    delim = /^\^[A-Za-z]/.test(delim) ? delim.slice(0, 2) : delim.charAt(0);
    const restOfLine = `${(m[2] ?? "").slice(delim.length)}${m[3] ?? ""}`;
    if (restOfLine.includes(delim)) continue; // opened and closed on the same line
    let j = i + 1;
    while (j < lines.length && !lines[j].raw.includes(delim)) {
      inBanner.add(lines[j].n);
      b.mark(lines[j]);
      j++;
    }
    if (j < lines.length) {
      inBanner.add(lines[j].n);
      b.mark(lines[j]);
    }
    i = j;
  }
  return inBanner;
}

interface IfaceInfo {
  name: string;
  l3: boolean;
  shutdown: boolean;
  ip?: string;
  vrf?: string;
  noProxyArp: boolean;
  noRedirects: boolean;
  noLldpTx: boolean;
  noLldpRx: boolean;
  trunk: boolean;
  channel: boolean;
  line: Line;
}

function parseIdentity(raw: string, b: ModelBuilder, vendor: IosVendor): void {
  const id = b.identity;
  id.hostname = first(raw, /^hostname\s+(\S+)/m) ?? first(raw, /^switchname\s+(\S+)/m);
  if (id.hostname) b.set("identity.hostname", id.hostname, undefined);
  if (vendor === "arista-eos") {
    // Header first, then a dotted image version anywhere; a bare "EOS-1" (as in a hostname like EDGE-RTR-EOS-1) never matches.
    id.osVersion =
      first(raw, /^!\s*device:.*\(.*,\s*EOS(?:64)?-(\d+\.[\d.]+\w*)\)/mi) ??
      first(raw, /\bEOS(?:64)?-(\d+\.\d+[\d.]*\w*)/) ??
      first(raw, /Software image version:\s*([\d.]+\w*)/i);
    id.model = first(raw, /^!\s*device:\s*\S+\s*\(([^,]+),/mi) ?? first(raw, /^Hardware\s*(?:version|model)?:?\s*(\S+)/mi);
    id.serial = first(raw, /Serial number:\s*(\S+)/i);
  } else if (vendor === "cisco-nxos") {
    id.os = "NX-OS";
    id.osVersion = first(raw, /^version\s+(\d+\.\d+\(\d+[a-z]?\))/m) ?? first(raw, /^boot nxos \S*nxos\.([\d.]+)\.bin/m) ?? first(raw, /NXOS:\s*version\s+(\S+)/i);
    id.model =
      first(raw, /^!?\s*cisco Nexus\s*(\S+)/mi) ??
      first(raw, /^\s*Hardware\s*\n?\s*cisco\s+(N\S+)/mi) ??
      first(raw, /^license udi pid\s+(\S+)\s+sn\s+\S+/mi) ??
      first(raw, /^!\s*(?:model|platform)\s*[:=]\s*(\S+)/mi);
    id.serial = first(raw, /^license udi pid\s+\S+\s+sn\s+(\S+)/mi) ?? first(raw, /Processor Board ID\s+(\S+)/i) ?? first(raw, /^!\s*serial(?:\s*number)?\s*[:=]\s*(\S+)/mi);
  } else {
    id.osVersion = first(raw, /Cisco IOS.*?Version\s+([\w.()]+)/i) ?? first(raw, /^version\s+([\d.]+)/m);
    id.model =
      first(raw, /^license udi pid\s+(\S+)\s+sn\s+\S+/mi) ??
      first(raw, /^!?\s*PID:\s*(\S+)/m) ??
      first(raw, /^!?\s*[Cc]isco\s+(\S+)\s+\(.*?\)\s+(?:processor|with)/m) ??
      first(raw, /^!?\s*[Cc]isco\s+([A-Z][A-Z0-9/-]+)\s.*(?:with|processor|memory)/m) ??
      first(raw, /^switch\s+\d+\s+provision\s+(\S+)/m) ??
      first(raw, /^!\s*(?:model|platform)\s*[:=]\s*(\S+)/mi);
    id.serial =
      first(raw, /^license udi pid\s+\S+\s+sn\s+(\S+)/mi) ??
      first(raw, /Processor board ID\s+(\S+)/) ??
      first(raw, /System [Ss]erial [Nn]umber\s*:\s*(\S+)/) ??
      first(raw, /\bSN:\s*(\S+)/) ??
      first(raw, /^!\s*serial(?:\s*number)?\s*[:=]\s*(\S+)/mi);
    const xe = /IOS[- ]XE/i.test(raw) || /^version (1[6-9]|2\d)\./m.test(raw) || /^(platform |license boot level|switch \d+ provision)/m.test(raw);
    id.os = xe ? "IOS-XE" : "IOS";
  }
}

function applyDefaults(b: ModelBuilder, vendor: IosVendor, raw: string): void {
  const d = (k: string, v: string | number | boolean | string[], note: string) => b.setDefault(k, v, `Platform default — ${note}`);
  if (vendor === "cisco-ios") {
    const model = b.identity.model ?? "";
    const xeRouter = /^(ISR4|ASR1|CSR1|C8[0-9]{3}|ISR1[0-9]{3}|C11[0-9]{2})/i.test(model) || /^platform qfp/m.test(raw);
    if (xeRouter) d("services.cdp_enabled", false, "IOS-XE routers ship with CDP disabled unless 'cdp run'");
    else if (/^\s+switchport/m.test(raw) || /^switch \d+ provision/m.test(raw)) d("services.cdp_enabled", true, "Catalyst switches run CDP unless 'no cdp run'");
    d("services.ip_source_routing", true, "source routing is on unless 'no ip source-route'");
    d("services.bootp_server", true, "BOOTP server is on unless 'no ip bootp server'");
    d("services.pad", true, "PAD is on unless 'no service pad'");
    d("services.dhcp_server", true, "DHCP service runs unless 'no service dhcp'");
    d("services.identd", false, "identd is off unless enabled");
    d("services.finger", false, "finger is off unless enabled");
    d("services.small_servers", false, "small servers are off on IOS 12.0+");
    d("services.tcp_keepalives", false, "keepalives are off unless configured");
    d("services.directed_broadcast", false, "directed broadcast is off on IOS 12.0+");
    d("management.http_enabled", false, "HTTP server is off unless 'ip http server'");
    d("management.https_enabled", false, "HTTPS server is off unless 'ip http secure-server'");
    d("management.telnet_enabled", true, "vty lines accept Telnet unless 'transport input ssh'");
    d("management.ssh_version", 1, "SSH runs in v1/v2 compatibility mode unless 'ip ssh version 2'");
    d("auth.password_encryption", false, "'service password-encryption' not configured");
    d("auth.aaa_enabled", false, "'aaa new-model' not configured");
    d("auth.login_lockout", false, "no 'login block-for' / 'aaa local authentication attempts max-fail'");
    d("auth.min_password_length", 0, "'security passwords min-length' defaults to 0");
    d("logging.timestamps", false, "'service timestamps log datetime' not configured");
    d("logging.login_events", false, "'login on-failure/on-success log' not configured");
    d("logging.console_restricted", false, "'logging console' defaults to debugging");
    d("logging.source_interface", false, "no 'logging source-interface'");
    d("time.ntp_authentication", false, "'ntp authenticate' not configured");
    d("management.login_banner", false, "no login/motd banner configured");
    d("management.mgmt_acl_applied", false, "no 'access-class' on vty lines");
    d("snmp.enabled", false, "no snmp-server configuration");
    d("management.idle_timeout_minutes", 10, "vty exec-timeout defaults to 10 minutes");
    d("management.console_timeout_minutes", 10, "console exec-timeout defaults to 10 minutes");
    d("logging.enabled", true, "logging is on unless 'no logging on'");
    d("identity.loopback_present", false, "no loopback interface configured");
    d("auth.remote_auth_servers", [], "no tacacs-server/radius-server host configured");
  } else if (vendor === "cisco-nxos") {
    d("management.telnet_enabled", false, "telnet is disabled unless 'feature telnet'");
    d("management.ssh_enabled", true, "SSH is enabled by default");
    d("management.ssh_version", 2, "NX-OS only supports SSH protocol version 2");
    d("management.http_enabled", false, "HTTP server is disabled unless 'feature nxapi' with http");
    d("auth.password_encryption", true, "NX-OS stores passwords as SHA-256 ($5$) hashes");
    d("auth.aaa_enabled", true, "AAA is always active on NX-OS");
    d("auth.password_complexity", true, "password strength checking is on unless 'no password strength-check'");
    d("auth.login_lockout", false, "no 'aaa authentication login ... ' lockout / 'login block-for' equivalent configured");
    d("logging.timestamps", true, "NX-OS syslog messages are timestamped");
    d("logging.enabled", true, "logging is on");
    d("logging.buffered", true, "logfile logging is on by default");
    d("logging.console_restricted", false, "'logging console' defaults to level 2 (critical) — verify");
    d("logging.source_interface", false, "no 'logging source-interface'");
    d("time.ntp_authentication", false, "'ntp authenticate' not configured");
    d("management.login_banner", false, "no banner motd configured");
    d("management.mgmt_acl_applied", false, "no 'access-class' on line vty");
    d("snmp.enabled", false, "no snmp-server community/user configured");
    d("management.idle_timeout_minutes", 10, "vty exec-timeout defaults to 10 minutes");
    d("management.console_timeout_minutes", 10, "console exec-timeout defaults to 10 minutes");
    d("services.cdp_enabled", true, "CDP runs unless 'no cdp enable' globally");
    d("services.ip_source_routing", false, "NX-OS drops source-routed packets");
    d("services.directed_broadcast", false, "directed broadcast forwarding is off");
    d("services.proxy_arp", false, "proxy ARP is off unless 'ip proxy-arp' on an interface");
    d("identity.loopback_present", false, "no loopback interface configured");
    d("crypto.strong_crypto", false, "default SSH cipher list includes CBC modes");
    d("auth.remote_auth_servers", [], "no tacacs-server/radius-server host configured");
  } else {
    d("management.telnet_enabled", false, "'management telnet' is shut down by default");
    d("management.ssh_enabled", true, "'management ssh' is enabled by default");
    d("management.ssh_version", 2, "EOS only supports SSH protocol version 2");
    d("management.http_enabled", false, "eAPI is shut down by default");
    d("management.api_http_enabled", false, "eAPI is shut down by default");
    d("services.lldp_enabled", true, "LLDP runs unless 'no lldp run'");
    d("services.ip_source_routing", false, "EOS drops source-routed packets by default");
    d("services.proxy_arp", false, "proxy ARP is off unless configured");
    d("services.icmp_redirects", true, "ICMP redirects are on unless 'no ip redirects'");
    d("services.directed_broadcast", false, "directed broadcast is off by default");
    d("auth.password_encryption", true, "EOS stores secrets hashed (sha512) by default");
    d("auth.aaa_enabled", true, "EOS AAA framework is always active");
    d("logging.timestamps", true, "EOS syslog messages are timestamped");
    d("time.ntp_authentication", false, "'ntp authenticate' not configured");
    d("management.login_banner", false, "no banner configured");
    d("management.mgmt_acl_applied", false, "no control-plane ACL / vty access-class");
    d("snmp.enabled", false, "no snmp-server configuration");
    // EOS renders none of these when left at their defaults; the defaults themselves are the insecure state.
    d("management.idle_timeout_minutes", 9999, "management ssh idle-timeout defaults to 0 = never");
    d("management.console_timeout_minutes", 9999, "management console idle-timeout defaults to 0 = never");
    d("management.ssh_timeout_seconds", 120, "management ssh login timeout defaults to 120 s");
    d("auth.login_lockout", false, "no 'aaa authentication policy lockout'");
    d("auth.root_login_ssh", false, "'no aaa root' — the root account is disabled unless 'aaa root secret'");
    d("auth.remote_auth_servers", [], "no tacacs-server/radius-server host configured");
    d("logging.login_events", false, "no 'aaa authentication policy on-failure/on-success log'");
    d("logging.enabled", true, "logging is on");
    d("crypto.strong_crypto", false, "default SSH MAC/KEX lists still include hmac-sha1 and diffie-hellman-group14-sha1");
    d("identity.loopback_present", false, "no loopback interface configured");
  }
}

/** strong_crypto is true only while every algorithm line seen is strong. */
function noteCryptoLine(b: ModelBuilder, text: string, l: Line): void {
  const weak = hasWeakCipher(text);
  const seen = b.params["crypto.strong_crypto"]?.source === "parser";
  const cur = seen ? b.get("crypto.strong_crypto") === true : true;
  b.set("crypto.strong_crypto", cur && !weak, l);
}

interface WalkState {
  aclNames: Set<string>;
  ifaces: IfaceInfo[];
  vtyRanges: { telnet: boolean; acl: boolean; line: Line; transportLine?: Line }[];
  ntp: { authenticate: boolean; keys: boolean; servers: number; keyed: number };
  auxSeen: boolean;
  aaaNewModel: boolean | null;
  peerSessionPasswords: Set<string>;
  bgpNeighbors: Map<string, { auth: boolean; line: Line; inherit?: string }>;
  globalProxyArpDisabled: boolean;
  sourceInterfaces: string[];
  aclsWithoutLoggedDeny: string[];
  /** BGP peer-group names ('neighbor NAME peer group' / 'peer-group'): groups, not neighbours. */
  bgpGroups: Set<string>;
  globalIcmpRedirectDisabled: boolean;
  /** EOS 'management ssh' algorithm families that were hardened (cipher / mac / key-exchange). */
  sshAlgoFamilies: Set<string>;
  /** VRF names seen on 'logging vrf X …' lines — fallback for management.mgmt_vrf. */
  mgmtVrfHints: string[];
}

function walkTop(node: Node, b: ModelBuilder, vendor: IosVendor, st: WalkState): void {
  const l = node.line;
  const t = l.text;
  let m: RegExpMatchArray | null;

  const child = (re: RegExp, fn: (mm: RegExpMatchArray, cl: Line) => void) => {
    for (const c of node.children) {
      const cm = c.line.text.match(re);
      if (cm) fn(cm, c.line);
    }
  };
  const markAll = (n: Node) => {
    for (const c of n.children) {
      b.mark(c.line);
      markAll(c);
    }
  };
  const markChildren = () => node.children.forEach((c) => b.mark(c.line));
  const countWeakPassword = (text: string, line: Line, user?: string): boolean => {
    // "password [type] value": reversible/cleartext unless the value is a modern crypt hash ($5$/$6$/$8$/$9$); $1$ (MD5) is weak.
    const pw = ` ${text}`.match(/\spassword\s+(?:(\d)\s+)?(\S+)/);
    let weak = false;
    if (pw && !/\ssecret\s/.test(text)) {
      const type = pw[1];
      const value = pw[2];
      const strongHash = /^\$(5|6|8|9)\$/.test(value);
      weak = !strongHash && (type === undefined || type === "0" || type === "7" || /^\$1\$/.test(value) || (type === "5" && !/^\$\d\$/.test(value)));
      if (type === "5" && /^\$1\$/.test(value)) weak = true;
    }
    const sec = ` ${text}`.match(/\ssecret\s+(?:(\d)\s+)?(\S+)/);
    if (sec && (sec[1] === "5" || sec[1] === "0" || /^\$1\$/.test(sec[2]))) weak = true;
    // EOS 'username … nopassword' / 'aaa root nopassword': an account with no credential at all.
    if (/\snopassword\b/.test(` ${text}`)) weak = true;
    if (weak) {
      b.inc("auth.weak_password_hashes", line);
      if (user) b.add("auth.weak_local_users", user, line);
    }
    return weak;
  };

  if (/^(hostname|switchname)\s+\S+/.test(t)) return b.setTrue("identity.hostname_set", l);
  if (/^(ip domain[- ]name|dns domain)\s+\S+/.test(t)) return b.setTrue("identity.domain_set", l);
  if (t === "service password-encryption") return b.setTrue("auth.password_encryption", l);
  if (t === "no service password-encryption") return b.setFalse("auth.password_encryption", l);
  if (t === "no password strength-check") return b.setFalse("auth.password_complexity", l);
  if (t === "password strength-check") return b.setTrue("auth.password_complexity", l);
  if (t === "feature telnet") return b.setTrue("management.telnet_enabled", l);
  if (t === "no feature telnet") return b.setFalse("management.telnet_enabled", l);
  if (t === "feature ssh") return b.setTrue("management.ssh_enabled", l);
  if (t === "feature nxapi") return b.setTrue("management.api_http_enabled", l);
  if (/^nxapi http\b/.test(t)) return b.setTrue("management.http_enabled", l);
  if (/^nxapi https\b/.test(t)) return b.setTrue("management.https_enabled", l);
  if (/^no nxapi http\b/.test(t)) return b.setFalse("management.http_enabled", l);
  if (/^nxapi\b/.test(t)) return b.mark(l);
  if ((m = t.match(/^ssh key rsa\s+(\d+)/))) return b.set("crypto.rsa_modulus", parseInt(m[1], 10), l);
  if ((m = t.match(/^ssh (login-attempts)\s+(\d+)/))) { b.setTrue("auth.login_lockout", l); b.set("auth.max_login_attempts", parseInt(m[2], 10), l); return; }
  if (/^ssh (ciphers|kex|macs)\s+all/.test(t)) { noteCryptoLine(b, "cbc", l); return; }
  if ((m = t.match(/^ssh (ciphers|kex|macs)\s+(.*)$/))) { noteCryptoLine(b, m[2], l); return; }
  if (/^vrf context management/.test(t)) { b.set("management.mgmt_vrf", "management", l); markAll(node); return; }
  if ((m = t.match(/^enable secret(?: level \d+)?(?: (\d+))?\s+(\S+)/))) {
    b.setTrue("auth.enable_secret", l);
    if (m[1] === "5" || /^\$1\$/.test(m[2])) b.inc("auth.weak_password_hashes", l);
    return;
  }
  if ((m = t.match(/^enable password(?: level \d+)?(?: (\d+|sha512|md5))?\s+(\S+)/))) {
    // EOS renders 'enable password sha512 $6$…' (hashed); 'md5' / type 5 / $1$ are hashed but weak; 0/7/none are reversible.
    const type = m[1];
    const value = m[2];
    if (type === "sha512" || /^\$(5|6|8|9)\$/.test(value)) return b.setTrue("auth.enable_secret", l);
    if (type === "md5" || type === "5" || /^\$1\$/.test(value)) {
      b.setTrue("auth.enable_secret", l);
      b.inc("auth.weak_password_hashes", l);
      return;
    }
    b.inc("auth.weak_password_hashes", l);
    if (!b.has("auth.enable_secret")) b.set("auth.enable_secret", false, l);
    return;
  }
  if ((m = t.match(/^username\s+(\S+)(.*)$/))) {
    b.add("auth.local_users", m[1], l);
    countWeakPassword(m[2], l, m[1]);
    return;
  }
  if (t === "aaa new-model") { st.aaaNewModel = true; return b.setTrue("auth.aaa_enabled", l); }
  if (t === "no aaa new-model") {
    st.aaaNewModel = false;
    b.setFalse("auth.aaa_enabled", l);
    b.setFalse("auth.aaa_authentication_login", l);
    b.setFalse("auth.aaa_accounting", l);
    return;
  }
  if ((m = t.match(/^aaa authentication login\s+(\S+)\s+(.*)$/))) {
    const methods = m[2];
    const central = /\bgroup\s+\S+/.test(methods);
    if (m[1] === "default") {
      if (/^none\b/.test(methods.trim())) b.set("auth.aaa_authentication_login", false, l);
      else if (central) b.set("auth.aaa_authentication_login", true, l);
      else if (!b.has("auth.aaa_authentication_login") || b.params["auth.aaa_authentication_login"].source === "default") b.set("auth.aaa_authentication_login", false, l);
      else b.mark(l);
    } else if (central) b.set("auth.aaa_authentication_login", true, l);
    else b.mark(l);
    return;
  }
  if (/^aaa accounting (commands|exec|connection|system|network|default)/.test(t)) return b.setTrue("auth.aaa_accounting", l);
  if ((m = t.match(/^aaa local authentication attempts max-fail\s+(\d+)/))) {
    b.setTrue("auth.login_lockout", l);
    b.set("auth.max_login_attempts", parseInt(m[1], 10), l);
    return;
  }
  if (/^aaa common-criteria policy\s+\S+/.test(t)) {
    b.mark(l);
    child(/^min-length\s+(\d+)/, (mm, cl) => b.set("auth.min_password_length", parseInt(mm[1], 10), cl));
    if (node.children.some((c) => /^(upper-case|lower-case|numeric-count|special-case)\s+[1-9]/.test(c.line.text))) b.setTrue("auth.password_complexity", l);
    markChildren();
    return;
  }
  // EOS login policies
  if ((m = t.match(/^aaa authentication policy lockout failure\s+(\d+)/))) {
    b.setTrue("auth.login_lockout", l);
    b.set("auth.max_login_attempts", parseInt(m[1], 10), l);
    return;
  }
  if (/^aaa authentication policy on-(failure|success) log/.test(t)) return b.setTrue("logging.login_events", l);
  if (/^aaa authentication policy local allow-nopassword-remote-login/.test(t)) return b.inc("auth.weak_password_hashes", l);
  if (/^aaa root (secret|nopassword)\b/.test(t)) {
    b.setTrue("auth.root_login_ssh", l);
    countWeakPassword(t, l);
    return;
  }
  if (t === "no aaa root") return b.setFalse("auth.root_login_ssh", l);
  if (/^aaa (authentication|authorization|accounting|group|session-id|server|root|local|password)/.test(t)) {
    b.mark(l);
    child(/^server(?:-private)? (?:name )?(\S+)/, (mm, cl) => b.add("auth.remote_auth_servers", mm[1], cl));
    markChildren();
    return;
  }
  if ((m = t.match(/^(tacacs|radius)(?:-server)? (?:server|host)\s+(\S+)/))) {
    b.add("auth.remote_auth_servers", m[2], l);
    child(/^address ipv4\s+(\S+)/, (mm, cl) => b.add("auth.remote_auth_servers", mm[1], cl));
    markChildren();
    return;
  }
  if (/^(tacacs|radius)-server\s/.test(t)) return b.mark(l);
  if ((m = t.match(/^login block-for\s+\d+\s+attempts\s+(\d+)/))) {
    b.setTrue("auth.login_lockout", l);
    b.set("auth.max_login_attempts", parseInt(m[1], 10), l);
    return;
  }
  if (/^login on-(failure|success) log/.test(t)) return b.setTrue("logging.login_events", l);
  if (/^login (delay|quiet-mode)/.test(t)) return b.mark(l);
  if ((m = t.match(/^security passwords min-length\s+(\d+)/))) return b.set("auth.min_password_length", parseInt(m[1], 10), l);
  if (/^security authentication failure rate/.test(t)) return b.setTrue("auth.login_lockout", l);
  if ((m = t.match(/^ip ssh version\s+(\d)/))) {
    b.set("management.ssh_version", parseInt(m[1], 10), l);
    b.setTrue("management.ssh_enabled", l);
    return;
  }
  if ((m = t.match(/^ip ssh time-out\s+(\d+)/))) return b.set("management.ssh_timeout_seconds", parseInt(m[1], 10), l);
  if ((m = t.match(/^ip ssh authentication-retries\s+(\d+)/))) return b.set("management.ssh_auth_retries", parseInt(m[1], 10), l);
  if ((m = t.match(/^ip ssh server algorithm (encryption|mac|kex|hostkey)\s+(.*)$/))) {
    if (m[1] !== "hostkey") noteCryptoLine(b, m[2], l);
    else b.mark(l);
    b.setTrue("management.ssh_enabled", l);
    return;
  }
  if ((m = t.match(/^ip ssh source-interface\s+(\S+)/))) { st.sourceInterfaces.push(m[1]); return b.mark(l); }
  if (/^ip ssh (rsa keypair-name|logging|maxstartups|dh min size|pubkey-chain|client|bulk-mode|port)/.test(t)) { markAll(node); return b.mark(l); }
  if (/^ip ssh\b/.test(t)) return b.setTrue("management.ssh_enabled", l);
  if (/^crypto key generate rsa/.test(t)) {
    const mod = t.match(/modulus\s+(\d+)/);
    if (mod) b.set("crypto.rsa_modulus", parseInt(mod[1], 10), l);
    return b.mark(l);
  }
  if ((m = t.match(/^ip (tacacs|radius) source-interface\s+(\S+)/))) { st.sourceInterfaces.push(m[2]); return b.mark(l); }
  if (t === "ip http server") return b.setTrue("management.http_enabled", l);
  if (t === "no ip http server") return b.setFalse("management.http_enabled", l);
  if (t === "ip http secure-server") return b.setTrue("management.https_enabled", l);
  if (t === "no ip http secure-server") return b.setFalse("management.https_enabled", l);
  if (/^ip http (access-class|authentication|timeout-policy|max-connections|secure-|client|active-session|port|path|server|tls-version)/.test(t)) return b.mark(l);
  if (t === "ip arp proxy disable") { st.globalProxyArpDisabled = true; return b.setFalse("services.proxy_arp", l); }
  if (t === "no ip icmp redirect") { st.globalIcmpRedirectDisabled = true; return b.setFalse("services.icmp_redirects", l); }
  if (t === "ip icmp redirect") return b.setTrue("services.icmp_redirects", l);
  if ((m = t.match(/^line vty(?:\s+(\d+)(?:\s+(\d+))?)?$/))) {
    b.mark(l);
    if (m[2]) b.max("management.vty_max", parseInt(m[2], 10), l);
    else if (m[1]) b.max("management.vty_max", parseInt(m[1], 10), l);
    let transportSeen = false;
    let transportLine: Line | undefined;
    let telnet = vendor === "cisco-nxos" ? (b.get("management.telnet_enabled") === true) : true; // IOS default: transport input all
    let acl = false;
    let timeoutSeen = false;
    for (const c of node.children) {
      const ct = c.line.text;
      let cm: RegExpMatchArray | null;
      if ((cm = ct.match(/^transport input\s+(.*)$/))) {
        transportSeen = true;
        transportLine = c.line;
        const modes = cm[1].split(/\s+/);
        telnet = modes.includes("telnet") || modes.includes("all");
        if (modes.includes("ssh") || modes.includes("all")) b.setTrue("management.ssh_enabled", c.line);
        b.mark(c.line);
      } else if ((cm = ct.match(/^exec-timeout\s+(\d+)(?:\s+(\d+))?/))) {
        timeoutSeen = true;
        b.max("management.idle_timeout_minutes", toMinutes(cm[1], cm[2]), c.line);
      } else if (ct === "no exec-timeout") {
        timeoutSeen = true;
        b.max("management.idle_timeout_minutes", 9999, c.line);
      } else if (/^access-class\s+\S+\s+in/.test(ct)) {
        acl = true;
        b.mark(c.line);
      } else if (/^ipv6 access-class\s+\S+\s+in/.test(ct)) {
        b.mark(c.line);
      } else if (/^password\s+(7\s+|0\s+)?\S+/.test(ct)) {
        countWeakPassword(ct, c.line);
      } else if (/^session-limit\s+\d+/.test(ct)) {
        b.setTrue("management.concurrent_sessions_limited", c.line);
      } else {
        b.mark(c.line);
      }
    }
    st.vtyRanges.push({ telnet, acl, line: l, transportLine });
    if (!transportSeen && vendor !== "cisco-nxos") b.params["management.telnet_enabled"] = { key: "management.telnet_enabled", value: true, evidence: [...(b.params["management.telnet_enabled"]?.evidence.filter((e) => e.line) ?? []), { line: l.n, text: `${t} — no 'transport input' restriction (IOS default: all)` }], source: "parser" };
    if (!timeoutSeen && b.params["management.idle_timeout_minutes"]?.source === "default") {
      b.params["management.idle_timeout_minutes"].evidence = [{ line: l.n, text: `${t} — no exec-timeout configured (default 10 min)` }];
    }
    return;
  }
  if (/^line (con(?:sole)?)(?:\s+0)?$/.test(t)) {
    b.mark(l);
    for (const c of node.children) {
      const cm = c.line.text.match(/^exec-timeout\s+(\d+)(?:\s+(\d+))?/);
      if (cm) b.max("management.console_timeout_minutes", toMinutes(cm[1], cm[2]), c.line);
      else if (c.line.text === "no exec-timeout") b.max("management.console_timeout_minutes", 9999, c.line);
      else if (/^password\s+(7\s+|0\s+)?\S+/.test(c.line.text)) countWeakPassword(c.line.text, c.line);
      else b.mark(c.line);
    }
    return;
  }
  if (/^line aux 0/.test(t)) {
    b.mark(l);
    st.auxSeen = true;
    let noExec = false, noTransport = false;
    for (const c of node.children) {
      if (c.line.text === "no exec") { noExec = true; b.mark(c.line); }
      else if (c.line.text === "transport input none") { noTransport = true; b.mark(c.line); }
      else if (/^password\s+(7\s+|0\s+)?\S+/.test(c.line.text)) countWeakPassword(c.line.text, c.line);
      else b.mark(c.line);
    }
    b.set("management.aux_disabled", noExec && noTransport, noExec && noTransport ? l : { line: l.n, text: `${t} — ${noExec ? "" : "'no exec' missing"}${!noExec && !noTransport ? ", " : ""}${noTransport ? "" : "'transport input none' missing"}` });
    return;
  }
  if (/^line\s/.test(t)) {
    b.mark(l);
    markChildren();
    return;
  }
  if ((m = t.match(/^logging (?:vrf\s+\S+\s+)?(?:host\s+|server\s+)?(?:ipv6\s+)?((?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9a-f]{0,4}:[0-9a-f:]*[0-9a-f])|(?![a-z-]+\b(?:\s|$))[a-zA-Z0-9][a-zA-Z0-9.-]*)(.*)$/i)) && !/^(buffered|trap|console|monitor|source-interface|source|origin-id|facility|on|synchronous|history|persistent|rate-limit|discriminator|count|format|event|level|logfile|timestamp|server-severity|ip|tls-profile|queue-limit|userinfo|alarm|snmp-trap|delimiter|cns-events|esm|exception|message-counter|reload|source-interface|dmvpn|policy-firewall|filter)$/i.test(m[1])) {
    const vrf = t.match(/^logging vrf (\S+)\s/)?.[1];
    if (vrf) st.mgmtVrfHints.push(vrf);
    b.add("logging.remote_hosts", m[1], l);
    b.setTrue("logging.enabled", l);
    if (/transport tls|protocol tls/.test(m[2])) b.setTrue("logging.remote_secure", l);
    else if (!b.has("logging.remote_secure")) b.set("logging.remote_secure", false, l);
    return;
  }
  if (/^logging (buffered|logfile)/.test(t)) return b.setTrue("logging.buffered", l);
  if (t === "no logging buffered") return b.setFalse("logging.buffered", l);
  if ((m = t.match(/^logging trap\s+(\S+)/))) return b.set("logging.level", m[1], l);
  if ((m = t.match(/^logging console\s+(\S+)/))) {
    b.set("logging.console_restricted", ["critical", "alerts", "emergencies", "errors", "0", "1", "2", "3"].includes(m[1]), l);
    return;
  }
  if (t === "no logging console") return b.setTrue("logging.console_restricted", l);
  if ((m = t.match(/^logging (?:vrf\s+\S+\s+)?source-interface\s+(\S+)/))) { st.sourceInterfaces.push(m[1]); return b.setTrue("logging.source_interface", l); }
  if (t === "no logging on") return b.setFalse("logging.enabled", l);
  if (t === "logging on") return b.setTrue("logging.enabled", l);
  if (/^logging (format timestamp|format hostname|timestamp)/.test(t)) return b.setTrue("logging.timestamps", l);
  if (/^logging tls-profile/.test(t)) { markAll(node); return b.mark(l); }
  if (/^logging\b/.test(t)) return b.mark(l);
  if (/^service timestamps log datetime/.test(t)) return b.setTrue("logging.timestamps", l);
  if (/^service timestamps/.test(t)) return b.mark(l);
  if (t === "archive") {
    b.mark(l);
    const walk = (n: Node) => {
      for (const c of n.children) {
        if (c.line.text === "logging enable") b.setTrue("logging.config_changes", c.line);
        else b.mark(c.line);
        walk(c);
      }
    };
    walk(node);
    return;
  }
  if ((m = t.match(/^ntp server(?: vrf \S+)?\s+(\S+)(.*)$/))) {
    b.add("time.ntp_servers", m[1], l);
    st.ntp.servers++;
    if (/\bkey\s+\d+/.test(m[2])) st.ntp.keyed++;
    return;
  }
  if (/^ntp authenticate( servers)?$/.test(t)) { st.ntp.authenticate = true; return b.mark(l); }
  if (/^ntp authentication-key/.test(t)) { st.ntp.keys = true; return b.mark(l); }
  if (/^ntp (trusted-key|source|master|update-calendar|access-group|peer|logging|passive|broadcast|allow)/.test(t)) return b.mark(l);
  if (/^clock timezone\s+\S+/.test(t)) return b.setTrue("time.timezone_set", l);
  if (/^clock\b/.test(t)) return b.mark(l);
  if ((m = t.match(/^snmp-server community\s+(\S+)(.*)$/))) {
    b.setTrue("snmp.enabled", l);
    const name = m[1];
    const rest = m[2];
    b.add("snmp.v1v2c_communities", name, l);
    if (["public", "private"].includes(name.toLowerCase())) b.add("snmp.default_communities", name, l);
    const rw = /\bRW\b/i.test(rest) || /\bgroup\s+network-admin\b/.test(rest);
    if (rw) b.add("snmp.rw_communities", name, l);
    const aclPresent = /\bipv6\s+\S+/.test(rest) || /\buse-ipv[46]acl\s+\S+/.test(rest) || /\b(?:RO|RW)\s+(?!ipv6\b|group\b|use-ipv[46]acl\b)\S+/i.test(rest) || (!/\b(RO|RW|view|group|ipv6|use-ipv[46]acl)\b/i.test(rest) && /\S/.test(rest));
    const prev = b.get("snmp.community_acl");
    b.set("snmp.community_acl", prev === undefined ? aclPresent : Boolean(prev) && aclPresent, l);
    return;
  }
  if ((m = t.match(/^snmp-server group\s+\S+\s+v3\s+(priv|auth|noauth)/))) {
    b.setTrue("snmp.enabled", l);
    b.setTrue("snmp.v3_enabled", l);
    if (m[1] === "priv") b.setTrue("snmp.v3_priv", l);
    else if (!b.has("snmp.v3_priv")) b.set("snmp.v3_priv", false, l);
    return;
  }
  if ((m = t.match(/^snmp-server user\s+\S+\s+\S+\s+v3(.*)$/))) {
    b.setTrue("snmp.enabled", l);
    b.setTrue("snmp.v3_enabled", l);
    if (/\bpriv\b/.test(m[1])) b.setTrue("snmp.v3_priv", l);
    else if (!b.has("snmp.v3_priv")) b.set("snmp.v3_priv", false, l);
    return;
  }
  if ((m = t.match(/^snmp-server host\s+(\S+)/))) {
    b.setTrue("snmp.enabled", l);
    b.add("snmp.trap_hosts", m[1], l);
    return;
  }
  if (t === "no snmp-server") return b.setFalse("snmp.enabled", l);
  if (/^snmp-server\b/.test(t)) return b.setTrue("snmp.enabled", l);
  if (t === "cdp run" || t === "cdp enable") return b.setTrue("services.cdp_enabled", l);
  if (t === "no cdp run" || t === "no cdp enable") return b.setFalse("services.cdp_enabled", l);
  if (t === "lldp run") return b.setTrue("services.lldp_enabled", l);
  if (t === "no lldp run") return b.setFalse("services.lldp_enabled", l);
  if (t === "no ip source-route") return b.setFalse("services.ip_source_routing", l);
  if (t === "ip source-route") return b.setTrue("services.ip_source_routing", l);
  if (t === "no ip bootp server") return b.setFalse("services.bootp_server", l);
  if (t === "ip bootp server") return b.setTrue("services.bootp_server", l);
  if (t === "no service dhcp") return b.setFalse("services.dhcp_server", l);
  if (t === "service dhcp") return b.setTrue("services.dhcp_server", l);
  if (/^ip dhcp pool\s/.test(t)) { b.setTrue("services.dhcp_in_use", l); markAll(node); return; }
  if (t === "no ip identd") return b.setFalse("services.identd", l);
  if (t === "ip identd") return b.setTrue("services.identd", l);
  if (t === "no ip finger" || t === "no service finger") return b.setFalse("services.finger", l);
  if (t === "ip finger" || t === "service finger") return b.setTrue("services.finger", l);
  if (t === "no service pad") return b.setFalse("services.pad", l);
  if (t === "service pad") return b.setTrue("services.pad", l);
  if (/^service tcp-keepalives-(in|out)/.test(t)) return b.setTrue("services.tcp_keepalives", l);
  if (/^no service (tcp|udp)-small-servers/.test(t)) return b.setFalse("services.small_servers", l);
  if (/^service (tcp|udp)-small-servers/.test(t)) return b.setTrue("services.small_servers", l);
  if (/^service (call-home|sequence-numbers|password-recovery|compress-config|timestamps|unsupported-transceiver|linenumber|counters|internal|nagle)/.test(t)) return b.mark(l);
  if (t === "no service call-home") return b.mark(l);
  if ((m = t.match(/^crypto isakmp policy\s+\d+/))) {
    b.mark(l);
    let encSeen = false, groupSeen = false, weak = false;
    for (const c of node.children) {
      const ct = c.line.text;
      if (/^encr(?:yption)?\s+(des|3des)\b/.test(ct)) { weak = true; b.setTrue("crypto.weak_ike", c.line); }
      else if (/^hash\s+md5/.test(ct)) { weak = true; b.setTrue("crypto.weak_ike", c.line); }
      else if (/^group\s+(1|2|5)\b/.test(ct)) { weak = true; b.setTrue("crypto.weak_ike", c.line); }
      else b.mark(c.line);
      if (/^encr/.test(ct)) encSeen = true;
      if (/^group\s/.test(ct)) groupSeen = true;
    }
    if (!encSeen) { weak = true; b.set("crypto.weak_ike", true, { line: l.n, text: `${t} — encryption not set (IOS default DES)` }); }
    if (!groupSeen) { weak = true; b.set("crypto.weak_ike", true, { line: l.n, text: `${t} — DH group not set (IOS default group 1)` }); }
    if (!weak && !b.has("crypto.weak_ike")) b.set("crypto.weak_ike", false, l);
    return;
  }
  if ((m = t.match(/^crypto ikev2 (proposal|policy)\s+\S+/))) {
    b.mark(l);
    let weak = false;
    for (const c of node.children) {
      if (/^(encryption .*\b(3des|des)\b|integrity .*\b(md5|sha1)\b|group .*\b(1|2|5)\b)/.test(c.line.text)) { weak = true; b.setTrue("crypto.weak_ike", c.line); }
      else b.mark(c.line);
    }
    if (!weak && !b.has("crypto.weak_ike")) b.set("crypto.weak_ike", false, l);
    return;
  }
  if ((m = t.match(/^crypto ipsec transform-set\s+\S+\s+(.*)$/))) {
    if (/esp-(des|3des)|esp-md5-hmac/.test(m[1])) b.setTrue("crypto.weak_ike", l);
    else b.mark(l);
    markChildren();
    return;
  }
  if (/^crypto (ikev2|map|pki|ca|keyring|gdoi|engine|ipsec|isakmp|key)/.test(t)) {
    b.mark(l);
    markAll(node);
    return;
  }
  if ((m = t.match(/^interface\s+(\S+)/))) {
    b.mark(l);
    const name = m[1];
    if (/^Loopback/i.test(name)) b.setTrue("identity.loopback_present", l);
    if (/^Tunnel/i.test(name)) b.inc("identity.tunnels", l);
    const info: IfaceInfo = { name, l3: false, shutdown: false, noProxyArp: false, noRedirects: false, noLldpTx: false, noLldpRx: false, trunk: false, channel: false, line: l };
    const mgmtIface = /^(Management|mgmt)\d*$/i.test(name);
    for (const c of node.children) {
      const ct = c.line.text;
      let cm: RegExpMatchArray | null;
      if ((cm = ct.match(/^ip address\s+(\d{1,3}(?:\.\d{1,3}){3})/))) { info.l3 = true; info.ip = info.ip ?? cm[1]; b.mark(c.line); }
      else if (ct === "shutdown") { info.shutdown = true; b.mark(c.line); }
      else if ((cm = ct.match(/^(?:ip )?vrf(?: forwarding| member)?\s+(\S+)$/))) { info.vrf = cm[1]; b.mark(c.line); }
      else if (/^(ip access-group|ipv6 access-group|ipv6 traffic-filter)\s+\S+\s+in\b/.test(ct)) {
        b.setTrue("acl.external_ingress_filter", c.line);
        if (mgmtIface) b.setTrue("management.mgmt_acl_applied", c.line);
      }
      else if (ct === "no lldp transmit") { info.noLldpTx = true; b.mark(c.line); }
      else if (ct === "no lldp receive") { info.noLldpRx = true; b.mark(c.line); }
      else if (/^switchport mode trunk\b/.test(ct)) { info.trunk = true; b.mark(c.line); }
      else if (/^channel-group\s/.test(ct)) { info.channel = true; b.mark(c.line); }
      else if (ct === "no ip proxy-arp") { info.noProxyArp = true; b.mark(c.line); }
      else if (ct === "ip proxy-arp") b.setTrue("services.proxy_arp", c.line);
      else if (ct === "no ip redirects") { info.noRedirects = true; b.mark(c.line); }
      else if (ct === "ip redirects") b.setTrue("services.icmp_redirects", c.line);
      else if (ct === "no ip directed-broadcast") b.setFalse("services.directed_broadcast", c.line);
      else if (/^ip directed-broadcast/.test(ct)) b.setTrue("services.directed_broadcast", c.line);
      else if (/^ip verify unicast (source reachable-via|reverse-path)/.test(ct)) b.setTrue("services.unicast_rpf", c.line);
      else if (/^(ip ospf message-digest-key|ip ospf authentication (message-digest|key-chain)|(ipv6 ospf|ospfv3) authentication (ipsec|key-chain)|ospfv3 \d+ (ipv4|ipv6) authentication)/.test(ct)) b.setTrue("routing.ospf_auth", c.line);
      else if (/^ip authentication mode eigrp/.test(ct)) b.setTrue("routing.eigrp_auth", c.line);
      else if (/^ip helper-address/.test(ct)) { b.setTrue("services.dhcp_in_use", c.line); }
      else b.mark(c.line);
      c.children.forEach((g) => b.mark(g.line));
    }
    st.ifaces.push(info);
    return;
  }
  if ((m = t.match(/^router ospf(?:v3)?\s+\S+/))) {
    b.setTrue("routing.ospf_configured", l);
    const walk = (n: Node) => {
      for (const c of n.children) {
        if (/^area\s+\S+\s+authentication (message-digest|ipsec|key-chain)/.test(c.line.text) || /^authentication (ipsec|key-chain)/.test(c.line.text)) b.setTrue("routing.ospf_auth", c.line);
        else b.mark(c.line);
        walk(c);
      }
    };
    walk(node);
    if (!b.has("routing.ospf_auth")) b.set("routing.ospf_auth", false, l);
    return;
  }
  if ((m = t.match(/^router bgp\s+(\S+)/))) {
    b.setTrue("routing.bgp_configured", l);
    b.set("routing.bgp_asn", m[1], l);
    const walk = (n: Node, ctx: string) => {
      for (const c of n.children) {
        const ct = c.line.text;
        let cm: RegExpMatchArray | null;
        if ((cm = ct.match(/^template peer-session\s+(\S+)/))) {
          const has = c.children.some((g) => /^password\s/.test(g.line.text));
          if (has) st.peerSessionPasswords.add(cm[1]);
          b.mark(c.line);
          markAll(c);
          continue;
        }
        // Peer-group definition (EOS 'neighbor NAME peer group', IOS 'neighbor NAME peer-group'): a group, never a neighbour.
        if ((cm = ct.match(/^neighbor\s+(\S+)\s+peer[- ]group$/))) {
          st.bgpGroups.add(cm[1]);
          if (st.bgpNeighbors.get(cm[1])?.auth) st.peerSessionPasswords.add(cm[1]);
          st.bgpNeighbors.delete(cm[1]);
          b.mark(c.line);
          continue;
        }
        if ((cm = ct.match(/^neighbor\s+(\S+)\s+(password|ao)\b/))) {
          if (st.bgpGroups.has(cm[1])) {
            st.peerSessionPasswords.add(cm[1]);
            b.mark(c.line);
            continue;
          }
          const e = st.bgpNeighbors.get(cm[1]) ?? { auth: false, line: c.line };
          e.auth = true;
          st.bgpNeighbors.set(cm[1], e);
          b.setTrue("routing.bgp_auth", c.line);
          continue;
        }
        // Members inherit the group's password: IOS 'inherit peer-session X', EOS 'peer group X', IOS 'peer-group X'.
        if ((cm = ct.match(/^neighbor\s+(\S+)\s+(?:inherit peer-session|peer[- ]group)\s+(\S+)/))) {
          const e = st.bgpNeighbors.get(cm[1]) ?? { auth: false, line: c.line };
          e.inherit = cm[2];
          st.bgpNeighbors.set(cm[1], e);
          b.mark(c.line);
          continue;
        }
        if ((cm = ct.match(/^neighbor\s+(\S+)\s+remote-as/))) {
          if (!st.bgpGroups.has(cm[1]) && !st.bgpNeighbors.has(cm[1])) st.bgpNeighbors.set(cm[1], { auth: false, line: c.line });
          b.mark(c.line);
          continue;
        }
        if ((cm = ct.match(/^neighbor\s+(\S+)$/))) {
          // NX-OS nested neighbor block
          const e = st.bgpNeighbors.get(cm[1]) ?? { auth: false, line: c.line };
          if (c.children.some((g) => /^password\s/.test(g.line.text))) { e.auth = true; b.setTrue("routing.bgp_auth", c.line); }
          st.bgpNeighbors.set(cm[1], e);
          b.mark(c.line);
          markAll(c);
          continue;
        }
        if (/^password\s/.test(ct) && /^neighbor/.test(ctx)) { b.setTrue("routing.bgp_auth", c.line); continue; }
        b.mark(c.line);
        walk(c, ct);
      }
    };
    walk(node, t);
    return;
  }
  if ((m = t.match(/^router eigrp\s+(\S+)/))) {
    b.setTrue("routing.eigrp_configured", l);
    b.set("routing.eigrp_as", m[1], l);
    b.set("routing.eigrp_named", !/^\d+$/.test(m[1]), l);
    const walk = (n: Node) => {
      for (const c of n.children) {
        if (/authentication mode (md5|hmac)/.test(c.line.text)) b.setTrue("routing.eigrp_auth", c.line);
        else b.mark(c.line);
        walk(c);
      }
    };
    walk(node);
    if (!b.has("routing.eigrp_auth")) b.set("routing.eigrp_auth", false, l);
    return;
  }
  if (/^router\s/.test(t)) {
    b.mark(l);
    markAll(node);
    return;
  }
  if ((m = t.match(/^(?:ip|ipv6) access-list (?:standard |extended |role-based )?(?!logging\b|log-update\b|helper\b|match-local-traffic\b|persistent\b|resequence\b)(\S+)/))) {
    if (!st.aclNames.has(m[1])) {
      st.aclNames.add(m[1]);
      b.inc("acl.count", l);
    } else b.mark(l);
    let logged = false;
    let denyCount = 0;
    for (const c of node.children) {
      const ct = c.line.text;
      if (/^(?:sequence\s+\d+\s+|\d+\s+)?deny\s+(?:(?:ip|ipv6|tcp|udp)\s+)?any(?:\s+any)?\b.*\blog/.test(ct)) { logged = true; b.setTrue("acl.explicit_deny_logged", c.line); }
      else b.mark(c.line);
      if (/^(?:sequence\s+\d+\s+|\d+\s+)?deny\b/.test(ct)) denyCount++;
      c.children.forEach((g) => b.mark(g.line));
    }
    if (!logged && denyCount >= 0 && node.children.length) st.aclsWithoutLoggedDeny.push(m[1]);
    return;
  }
  if (/^(ip|ipv6) access-list (logging|log-update|helper|match-local-traffic|persistent|resequence)/.test(t)) return b.mark(l);
  if ((m = t.match(/^access-list\s+(\S+)\s+(permit|deny|remark)(.*)$/))) {
    if (!st.aclNames.has(m[1])) {
      st.aclNames.add(m[1]);
      b.inc("acl.count", l);
      st.aclsWithoutLoggedDeny.push(m[1]);
    } else b.mark(l);
    if (m[2] === "deny" && /\bany\b.*\blog/.test(m[3])) {
      b.setTrue("acl.explicit_deny_logged", l);
      st.aclsWithoutLoggedDeny = st.aclsWithoutLoggedDeny.filter((x) => x !== m![1]);
    }
    return;
  }
  // ── Arista EOS extensions ────────────────────────────────────────
  if (vendor === "arista-eos") {
    // 'ip access-group NAME [vrf X] in' / 'ipv6 access-group …' — VRF-scoped forms are the norm when management lives in a VRF.
    const MGMT_ACL = /^ip(?:v6)? access-group\s+\S+(?:\s+vrf\s+\S+)?\s+in\b/;
    /** EOS management services are switched on per VRF: 'vrf <name>' → 'no shutdown'. Returns the enabling line. */
    const vrfEnabled = (n: Node): Line | undefined => {
      for (const c of n.children) {
        if (!/^vrf\s+\S+$/.test(c.line.text)) continue;
        const on = c.children.find((g) => g.line.text === "no shutdown");
        if (on) return on.line;
      }
      return undefined;
    };
    if (t === "management ssh") {
      b.mark(l);
      b.setTrue("management.ssh_enabled", l);
      for (const c of node.children) {
        const ct = c.line.text;
        let cm: RegExpMatchArray | null;
        if ((cm = ct.match(/^idle-timeout\s+(\d+)/))) b.set("management.idle_timeout_minutes", parseInt(cm[1], 10) === 0 ? 9999 : parseInt(cm[1], 10), c.line);
        else if (ct === "shutdown") b.setFalse("management.ssh_enabled", c.line);
        else if (ct === "no shutdown") b.setTrue("management.ssh_enabled", c.line);
        else if ((cm = ct.match(/^(cipher|key-exchange|mac)\s+(.*)$/))) { st.sshAlgoFamilies.add(cm[1]); noteCryptoLine(b, cm[2], c.line); }
        else if ((cm = ct.match(/^login timeout\s+(\d+)/))) b.set("management.ssh_timeout_seconds", parseInt(cm[1], 10), c.line);
        else if (/^connection limit\s+\d+/.test(ct)) b.setTrue("management.concurrent_sessions_limited", c.line);
        else if (MGMT_ACL.test(ct)) b.setTrue("management.mgmt_acl_applied", c.line);
        else if (ct === "authentication empty-passwords permit") b.inc("auth.weak_password_hashes", c.line);
        else if (ct === "fips restrictions") b.setTrue("crypto.fips_mode", c.line);
        else b.mark(c.line);
        c.children.forEach((g) => b.mark(g.line));
      }
      const on = vrfEnabled(node);
      if (on) b.setTrue("management.ssh_enabled", on);
      return;
    }
    if (t === "management telnet") {
      b.mark(l);
      for (const c of node.children) {
        if (c.line.text === "no shutdown") b.setTrue("management.telnet_enabled", c.line);
        else if (c.line.text === "shutdown") b.setFalse("management.telnet_enabled", c.line);
        else b.mark(c.line);
        c.children.forEach((g) => b.mark(g.line));
      }
      const on = vrfEnabled(node);
      if (on) b.setTrue("management.telnet_enabled", on);
      return;
    }
    if (t === "management api http-commands") {
      b.mark(l);
      let on = false;
      let httpLine: Line | undefined;
      for (const c of node.children) {
        const ct = c.line.text;
        if (ct === "no shutdown") on = true;
        else if (ct === "shutdown") on = false;
        // 'protocol http [port N]' is network-exposed; 'protocol http localhost …' only listens on the loopback.
        else if (/^protocol http(?:\s+port\s+\d+)?$/.test(ct)) httpLine = c.line;
        else if (/^no protocol http\b/.test(ct)) httpLine = undefined;
        else if (/^protocol https\b/.test(ct)) b.setTrue("management.https_enabled", c.line);
        b.mark(c.line);
        c.children.forEach((g) => b.mark(g.line));
      }
      // A VRF sub-mode enables eAPI regardless of the top-level shutdown state.
      const exposed = (on || Boolean(vrfEnabled(node))) && Boolean(httpLine);
      b.set("management.api_http_enabled", exposed, exposed ? httpLine : l);
      b.set("management.http_enabled", exposed, exposed ? httpLine : l);
      return;
    }
    if (t === "management console") {
      b.mark(l);
      child(/^idle-timeout\s+(\d+)/, (mm, cl) => b.set("management.console_timeout_minutes", parseInt(mm[1], 10) === 0 ? 9999 : parseInt(mm[1], 10), cl));
      markChildren();
      return;
    }
    if (t === "management security") {
      b.mark(l);
      for (const c of node.children) {
        const cm = c.line.text.match(/^password minimum length\s+(\d+)/);
        if (cm) b.set("auth.min_password_length", parseInt(cm[1], 10), c.line);
        else if (/^password policy/.test(c.line.text)) b.setTrue("auth.password_complexity", c.line);
        else b.mark(c.line);
        c.children.forEach((g) => b.mark(g.line));
      }
      return;
    }
    // 'control-plane' is the pre-4.20 name of 'system control-plane'.
    if (/^management\s/.test(t) || t === "system control-plane" || t === "control-plane") {
      b.mark(l);
      const cp = t === "system control-plane" || t === "control-plane";
      const walk = (n: Node) => {
        for (const c of n.children) {
          if (cp && MGMT_ACL.test(c.line.text)) b.setTrue("management.mgmt_acl_applied", c.line);
          else b.mark(c.line);
          walk(c);
        }
      };
      walk(node);
      return;
    }
    // EOS IPsec: 'ip security' → 'ike policy X' / 'sa policy X' / 'profile X'.
    if (t === "ip security") {
      b.mark(l);
      let policies = 0;
      let weak = false;
      const flag = (cl: Line) => { weak = true; b.setTrue("crypto.weak_ike", cl); };
      for (const c of node.children) {
        const ct = c.line.text;
        b.mark(c.line);
        if (/^ike policy\s+\S+/.test(ct)) {
          policies++;
          for (const g of c.children) {
            if (/^(encryption (3des|des)|integrity (md5|sha1)|dh-group (1|2|5))\b/.test(g.line.text)) flag(g.line);
            else b.mark(g.line);
          }
        } else if (/^sa policy\s+\S+/.test(ct)) {
          policies++;
          for (const g of c.children) {
            if (/^(esp encryption (3des|des)|esp integrity (md5|sha1)|pfs dh-group (1|2|5))\b/.test(g.line.text)) flag(g.line);
            else b.mark(g.line);
          }
        } else markAll(c);
      }
      if (policies && !weak && !b.has("crypto.weak_ike")) b.set("crypto.weak_ike", false, l);
      return;
    }
  }
  // Fall through: unknown until prefix table consulted.
}

/** Choose the management address: explicit source interfaces first, then loopback/management, then the first live L3 interface. */
function pickMgmtIp(st: WalkState, vendor: IosVendor): { ip?: string; vrf?: string } {
  const byName = (n: string) => st.ifaces.find((i) => i.name.toLowerCase() === n.toLowerCase());
  // EOS devices are managed through Management1 (usually in a dedicated VRF); loopbacks there are routing anchors.
  if (vendor === "arista-eos") {
    const mgmt = st.ifaces.find((x) => /^Management\d/i.test(x.name) && x.ip);
    if (mgmt) return { ip: mgmt.ip, vrf: mgmt.vrf };
  }
  for (const s of st.sourceInterfaces) {
    const i = byName(s);
    if (i?.ip) return { ip: i.ip, vrf: i.vrf };
  }
  const prefs = [/^Loopback0$/i, /^lo0$/i, /^Vlan1$/i, /^(Management|mgmt)\S*$/i, /^GigabitEthernet0(\/0)?$/i, /^Loopback\d+$/i];
  for (const re of prefs) {
    const i = st.ifaces.find((x) => re.test(x.name) && x.ip);
    if (i) return { ip: i.ip, vrf: i.vrf };
  }
  const live = st.ifaces.find((x) => x.l3 && !x.shutdown && x.ip);
  return live ? { ip: live.ip, vrf: live.vrf } : {};
}

export function parseIosLike(raw: string, vendor: IosVendor): ParseResult {
  const lines = toLines(raw);
  const b = new ModelBuilder(vendor);
  parseIdentity(raw, b, vendor);
  applyDefaults(b, vendor, raw);
  const bannerLines = collectBanners(lines, b);
  const skip = (l: Line) => isCommentOrBlank(l) || bannerLines.has(l.n);
  const roots = buildIndentTree(lines, skip);
  const st: WalkState = {
    aclNames: new Set(),
    ifaces: [],
    vtyRanges: [],
    ntp: { authenticate: false, keys: false, servers: 0, keyed: 0 },
    auxSeen: false,
    aaaNewModel: null,
    peerSessionPasswords: new Set(),
    bgpNeighbors: new Map(),
    globalProxyArpDisabled: false,
    sourceInterfaces: [],
    aclsWithoutLoggedDeny: [],
    bgpGroups: new Set(),
    globalIcmpRedirectDisabled: false,
    sshAlgoFamilies: new Set(),
    mgmtVrfHints: [],
  };
  for (const node of roots) walkTop(node, b, vendor, st);

  // ── Post-walk consolidation ──
  if (st.vtyRanges.length) {
    const telnetRange = st.vtyRanges.find((r) => r.telnet);
    const telnetEv = telnetRange ? (telnetRange.transportLine ? { line: telnetRange.transportLine.n, text: `${telnetRange.line.text}: ${telnetRange.transportLine.text}` } : { line: telnetRange.line.n, text: `${telnetRange.line.text} — no 'transport input' (default: all, accepts Telnet)` }) : undefined;
    b.set("management.telnet_enabled", Boolean(telnetRange), telnetEv ?? (st.vtyRanges[0].transportLine ?? st.vtyRanges[0].line));
    const missingAcl = st.vtyRanges.find((r) => !r.acl);
    b.set("management.mgmt_acl_applied", !missingAcl, missingAcl ? { line: missingAcl.line.n, text: `${missingAcl.line.text} — no access-class` } : st.vtyRanges[0].line);
  }
  if (vendor === "cisco-ios" && !st.auxSeen) b.set("management.aux_disabled", true, { line: 0, text: "No AUX line present on this platform" });
  if (vendor !== "cisco-nxos" || st.ntp.servers) {
    const auth = st.ntp.authenticate && st.ntp.keys && st.ntp.servers > 0 && st.ntp.keyed === st.ntp.servers;
    if (st.ntp.servers > 0 || st.ntp.authenticate) {
      const why = !st.ntp.authenticate ? "'ntp authenticate' missing" : !st.ntp.keys ? "no 'ntp authentication-key'" : st.ntp.keyed < st.ntp.servers ? `${st.ntp.servers - st.ntp.keyed} ntp server(s) without 'key N'` : "authenticate + keys + keyed servers";
      b.set("time.ntp_authentication", auth, { line: 0, text: `NTP authentication: ${why}` });
    }
  }
  // Proxy ARP / redirects: disabled only when disabled on every live L3 interface (or globally).
  const l3 = st.ifaces.filter((i) => i.l3 && !i.shutdown && !/^Loopback/i.test(i.name));
  if (vendor !== "arista-eos") {
    if (st.globalProxyArpDisabled) b.set("services.proxy_arp", false, undefined);
    else if (l3.length) {
      const bad = l3.filter((i) => !i.noProxyArp);
      if (bad.length && b.get("services.proxy_arp") !== true) b.set("services.proxy_arp", vendor === "cisco-nxos" ? false : true, { line: bad[0].line.n, text: `${bad[0].line.text} — proxy ARP not disabled${bad.length > 1 ? ` (+${bad.length - 1} more)` : ""}` });
      else if (!bad.length) b.set("services.proxy_arp", false, { line: l3[0].line.n, text: "no ip proxy-arp on every L3 interface" });
    }
  }
  if (!st.globalIcmpRedirectDisabled && l3.length) {
    const bad = l3.filter((i) => !i.noRedirects);
    if (bad.length && b.get("services.icmp_redirects") !== true) b.set("services.icmp_redirects", true, { line: bad[0].line.n, text: `${bad[0].line.text} — ip redirects not disabled${bad.length > 1 ? ` (+${bad.length - 1} more)` : ""}` });
    else if (!bad.length) b.set("services.icmp_redirects", false, { line: l3[0].line.n, text: "no ip redirects on every L3 interface" });
  }
  // BGP: neighbors inheriting an authenticated peer-session/peer-group count as authenticated; group names are never neighbours.
  for (const g of st.bgpGroups) st.bgpNeighbors.delete(g);
  if (st.bgpNeighbors.size) {
    const unauth: string[] = [];
    for (const [n, e] of st.bgpNeighbors) {
      const ok = e.auth || (e.inherit ? st.peerSessionPasswords.has(e.inherit) : false);
      if (!ok) unauth.push(n);
    }
    b.set("routing.bgp_auth", unauth.length === 0, unauth.length ? { line: st.bgpNeighbors.get(unauth[0])!.line.n, text: `neighbor ${unauth[0]} has no password/TCP-AO${unauth.length > 1 ? ` (+${unauth.length - 1} more)` : ""}` } : undefined);
    if (unauth.length) b.set("routing.bgp_unauth_neighbors", unauth, undefined);
  }
  if (st.aclsWithoutLoggedDeny.length && b.get("acl.explicit_deny_logged") !== true) b.set("acl.explicit_deny_logged", false, { line: 0, text: `ACLs without a logged deny: ${st.aclsWithoutLoggedDeny.slice(0, 5).join(", ")}` });
  const mgmt = pickMgmtIp(st, vendor);
  b.identity.mgmtIp = mgmt.ip;
  if (mgmt.vrf) b.set("management.mgmt_vrf", mgmt.vrf, undefined);
  else if (st.mgmtVrfHints.length) b.set("management.mgmt_vrf", st.mgmtVrfHints[0], undefined);
  // Role heuristic: switchport-heavy configs are switches.
  const switchports = (raw.match(/^\s+switchport/gm) ?? []).length;
  const ipAddrs = (raw.match(/^\s+ip address\s+\d/gm) ?? []).length;
  if (vendor === "cisco-ios") b.identity.role = switchports > ipAddrs || /^switch \d+ provision|^spanning-tree mode/m.test(raw) ? "switch" : "router";
  if (vendor === "cisco-nxos") b.identity.role = switchports > 0 ? "switch" : "router";
  if (vendor === "arista-eos") {
    const routerHints = b.has("identity.tunnels") || /^ip security$/m.test(raw) || !/^\s+switchport/m.test(raw);
    b.identity.role = switchports > ipAddrs ? "switch" : routerHints ? "router" : "switch";
    // LLDP restricted to infrastructure ports: every live access port has both 'no lldp transmit' and 'no lldp receive'.
    if (b.params["services.lldp_enabled"]?.source === "default") {
      const access = st.ifaces.filter((i) => /^Ethernet/i.test(i.name) && !i.shutdown && !i.trunk && !i.channel && !i.l3);
      if (access.length && access.every((i) => i.noLldpTx && i.noLldpRx)) b.set("services.lldp_enabled", false, { line: access[0].line.n, text: `LLDP transmit/receive disabled on every access port (${access.length})` });
    }
    // A single hardened list is not enough: the EOS defaults for the other families still include SHA-1.
    if (b.params["crypto.strong_crypto"]?.source === "parser" && b.get("crypto.strong_crypto") === true) {
      const missing = ["cipher", "mac", "key-exchange"].filter((f) => !st.sshAlgoFamilies.has(f));
      if (missing.length) b.set("crypto.strong_crypto", false, { line: 0, text: `management ssh: no hardened '${missing.join("' / '")}' list (EOS defaults keep hmac-sha1 / diffie-hellman-group14-sha1)` });
    }
  }

  // Understood-but-not-security-relevant syntax
  markKnownPrefixes(b, lines.filter((l) => l.indent === 0 && !skip(l)), KNOWN_TOP);
  const nodeByLine = new Map<number, Node>();
  const index = (n: Node) => {
    nodeByLine.set(n.line.n, n);
    n.children.forEach(index);
  };
  roots.forEach(index);
  for (const l of lines) {
    if (skip(l) || b.recognized.has(l.n) || l.indent === 0) continue;
    const node = nodeByLine.get(l.n);
    const parentKnown = node?.parent ? b.recognized.has(node.parent.line.n) : false;
    if (parentKnown) {
      for (const p of KNOWN_CHILD) {
        if (typeof p === "string" ? l.text.startsWith(p) : p.test(l.text)) {
          b.mark(l);
          break;
        }
      }
    }
  }

  const meaningful = lines.filter((l) => !skip(l));
  const unrecognized = b.unrecognized(lines, skip, (l) => {
    const n = nodeByLine.get(l.n);
    return n ? pathOf(n) || undefined : undefined;
  });
  return {
    vendor,
    identity: b.identity,
    model: b.model(),
    totalLines: lines.length,
    meaningfulLines: meaningful.length,
    recognized: meaningful.length - unrecognized.length,
    unrecognized,
    mappingsApplied: [],
  };
}

export const parseCiscoIos = (raw: string) => parseIosLike(raw, "cisco-ios");
export const parseCiscoNxos = (raw: string) => parseIosLike(raw, "cisco-nxos");
export const parseAristaEos = (raw: string) => parseIosLike(raw, "arista-eos");
export { IPV4, unquote };
