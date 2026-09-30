import type { Mapping, ParamValue, Suggestion, ValueMode, VendorId } from "./types";
import { SBM_INDEX, SBM_PARAMS } from "./sbm";
import { escapeRegex } from "../lib/util";

/**
 * Offline pattern-recognition classifier ("the AI engine" that needs no network).
 *
 * 1. Tokenises an unknown CLI line. Addresses collapse to a single `<ip>` token and
 *    long integers to `<num>` so two lines are not "similar" merely because both
 *    contain 10.x; hyphen/underscore and letter/digit boundaries still split, so
 *    "ssh2" -> ssh, 2 and "protocol-version" -> protocol, version.
 * 2. Scores every SBM parameter by keyword/phrase overlap. A keyword weighs by its
 *    WORD count (not its sub-token count), every single keyword is capped, generic
 *    words weigh less, and repeated hits on the same parameter have diminishing
 *    returns so a parameter with a large synonym list cannot out-shout a single
 *    distinctive match.
 * 3. Adds IDF-weighted k-nearest-neighbour similarity against a cross-vendor corpus
 *    of known commands and against mappings the administrator has already taught
 *    (only when the taught regex really matches the line and its scope applies).
 * 4. Proposes how to extract the value (polarity word, number, IP, host, quoted
 *    string) and a regex that generalises to sibling commands.
 * 5. Reports a confidence built from evidence strength x vocabulary coverage x
 *    margin over the runner-up x extraction validity, so "High" means "safe to
 *    auto-accept at CONFIDENCE_HIGH".
 */

/** The single auto-accept / "High" bar. Training Studio and confidenceLabel share it. */
export const CONFIDENCE_HIGH = 0.72;
export const CONFIDENCE_MEDIUM = 0.45;

const GENERIC_WORDS = new Set([
  "version", "timeout", "service", "log", "user", "admin", "http", "server", "set", "enable", "disable", "configure", "config", "system", "ip",
  "address", "name", "level", "mode", "default", "port", "interface", "add", "no", "yes", "on", "off", "key", "type", "policy", "list", "all",
  "any", "in", "out", "input", "output", "time", "local", "remote", "host", "source", "id", "status", "protocol", "security", "access",
  "management", "console", "trap", "message", "domain", "vlan", "route", "group", "profile", "class", "rule", "action", "match", "filter",
]);

/** Whole-token state words. ACL verbs (deny/drop/reject) are actions, not state. */
const NEG_WORDS = /^(disable|disabled|no|undo|off|false|none|never|shutdown)$/i;
const POS_WORDS = /^(enable|enabled|yes|on|true|permit|allow)$/i;
const KV_STATE = /^([\w-]+)=(yes|no|enable|disable|enabled|disabled|true|false|on|off)$/i;

const IPV4_TOKEN = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:\/\d+)?$/;
const IPV6_TOKEN = /^(?=(?:[^:]*:){2})[0-9a-f:]+(?:\/\d+)?$/i;
/** A hostname value: has a dot, starts with a letter/digit, is not an address. */
const HOST_TOKEN = /^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\.?$/i;
const VERSION_TOKEN = /^v?(\d+(?:\.\d+)?)$/i;

/** Params whose `true` means "the risky feature is OFF" — a negative state word proves them. */
const INVERTED_BOOLEANS = new Set([
  "management.aux_disabled",
  "management.concurrent_sessions_limited",
  "logging.console_restricted",
]);
/** Params where permit/deny words ARE the state (deny => false), not an ACL action. */
const PERMISSION_BOOLEANS = new Set(["auth.root_login_ssh"]);
const DENY_WORDS = /^(deny|denied|prohibit|prohibited|disallow|refuse|never|no)$/i;
const ALLOW_WORDS = /^(permit|permitted|allow|allowed|yes|enable|enabled|on|true)$/i;

/** Only these number params are genuine counters; everything else needs a real number. */
const COUNTER_PARAMS = new Set(["acl.count", "auth.weak_password_hashes", "identity.tunnels"]);

/** Tokens that introduce a value in almost every vendor CLI. */
const VALUE_ANCHORS = new Set([
  "community", "server", "servers", "host", "hosts", "loghost", "address", "ipaddress", "ip-address", "addresses",
  "user", "username", "account", "accounts", "collector", "peer", "neighbor", "neighbour", "target", "target-addr",
  "target-address", "trap-host", "syslog", "remote", "name", "key", "secret",
]);
/** Words that sit between an anchor and the real value ("community readonly public"). */
const VALUE_MODIFIERS = new Set([
  "readonly", "readwrite", "read-only", "read-write", "read", "write", "ro", "rw", "primary", "secondary", "tertiary",
  "add", "create", "set", "auth", "priv", "encrypted", "cipher", "plain", "default",
]);

/** Command words that differ between sibling commands but keep the same meaning. */
const SIBLINGS: string[][] = [
  ["primary", "secondary", "tertiary"],
  ["readonly", "readwrite"],
  ["read-only", "read-write"],
  ["ro", "rw"],
  ["ciphers", "macs"],
  ["lldp", "edp"],
  ["admin", "user"],
  ["enable", "disable"],
  ["enabled", "disabled"],
  ["on", "off"],
  ["yes", "no"],
  ["true", "false"],
];
function siblingsOf(tok: string): string[] | null {
  const low = tok.toLowerCase();
  return SIBLINGS.find((g) => g.includes(low)) ?? null;
}

/** Split a line into tokens, keeping "quoted strings" (which may contain spaces) whole. */
export function splitTokens(text: string): string[] {
  return text.trim().match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
}

const rawSplit = (s: string): string[] => s.toLowerCase().split(/[\s\-_.=:/\\,;()[\]<>|"'`]+/).filter(Boolean);

/** Every token that appears in an SBM keyword — the classifier's vocabulary. */
const KEYWORD_TOKENS = new Set<string>();
for (const p of SBM_PARAMS) for (const kw of p.keywords) for (const t of rawSplit(kw)) KEYWORD_TOKENS.add(t);
/**
 * Words that may stay literal in a generated regex: whole keyword words
 * (including hyphenated ones such as "sntp-client") plus generic CLI verbs.
 * Anything else is instance data and becomes \S+ so sibling commands match too.
 */
const VOCAB = new Set<string>(GENERIC_WORDS);
for (const p of SBM_PARAMS) {
  for (const kw of p.keywords) {
    for (const word of kw.toLowerCase().trim().split(/\s+/)) if (word) VOCAB.add(word);
    for (const t of rawSplit(kw)) VOCAB.add(t);
  }
}
for (const v of ["create", "delete", "undo", "line", "aaa", "banner", "exec", "web", "feature", "nv", "clear", "commit"]) VOCAB.add(v);
/** Acronyms whose trailing "s" is part of the word, not a plural. */
const NO_STEM = new Set(["https", "tls", "dns", "radius", "tacacs", "fips", "status", "class", "access", "address", "ipsec", "ospf", "was", "plus"]);

export function tokenize(text: string): string[] {
  const base = text
    .toLowerCase()
    .replace(/["'`]/g, " ")
    .split(/[\s=:/\\,;(){}[\]<>|]+/)
    .filter(Boolean);
  const out = new Set<string>();
  for (const tok of base) {
    const clean = tok.replace(/^-+|-+$/g, "");
    if (!clean) continue;
    // Addresses and long integers are instance data, not meaning: collapse them.
    if (IPV4_TOKEN.test(clean) || IPV6_TOKEN.test(clean)) { out.add("<ip>"); continue; }
    if (/^\d{3,}$/.test(clean)) { out.add("<num>"); continue; }
    out.add(clean);
    for (const part of clean.split(/[-_.]/)) {
      if (!part) continue;
      out.add(part);
      // letter/digit boundaries: ssh2 -> ssh, 2 ; tls1 -> tls, 1
      const split = part.split(/(?<=[a-z])(?=\d)|(?<=\d)(?=[a-z])/);
      if (split.length > 1) split.forEach((s) => out.add(s));
    }
  }
  // vocabulary-guided plural stemming: "ciphers" also counts as "cipher"
  for (const t of Array.from(out)) {
    if (t.length > 3 && t.endsWith("s") && !NO_STEM.has(t) && KEYWORD_TOKENS.has(t.slice(0, -1))) out.add(t.slice(0, -1));
  }
  return Array.from(out);
}

/** Cross-vendor corpus of commands with known meaning (used for kNN transfer). */
export const KNOWN_COMMANDS: { text: string; param: string; vendor: string }[] = [
  { text: "ip ssh version 2", param: "management.ssh_version", vendor: "Cisco IOS" },
  { text: "set system services ssh protocol-version v2", param: "management.ssh_version", vendor: "Junos" },
  { text: "ssh server compatible-ssh1x disable", param: "management.ssh_version", vendor: "Huawei VRP" },
  { text: "set admin-ssh-v1 disable", param: "management.ssh_version", vendor: "FortiOS" },
  { text: "transport input ssh", param: "management.ssh_enabled", vendor: "Cisco IOS" },
  { text: "stelnet server enable", param: "management.ssh_enabled", vendor: "Huawei VRP" },
  { text: "set system services ssh", param: "management.ssh_enabled", vendor: "Junos" },
  { text: "set ssh disabled=no", param: "management.ssh_enabled", vendor: "RouterOS" },
  { text: "transport input telnet", param: "management.telnet_enabled", vendor: "Cisco IOS" },
  { text: "telnet server enable", param: "management.telnet_enabled", vendor: "Huawei VRP" },
  { text: "set system services telnet", param: "management.telnet_enabled", vendor: "Junos" },
  { text: "set allowaccess ping https ssh telnet", param: "management.telnet_enabled", vendor: "FortiOS" },
  { text: "set deviceconfig system service disable-telnet yes", param: "management.telnet_enabled", vendor: "PAN-OS" },
  { text: "set telnet disabled=yes", param: "management.telnet_enabled", vendor: "RouterOS" },
  { text: "management telnet shutdown", param: "management.telnet_enabled", vendor: "Arista EOS" },
  { text: "no ip http server", param: "management.http_enabled", vendor: "Cisco IOS" },
  { text: "set system services web-management http", param: "management.http_enabled", vendor: "Junos" },
  { text: "undo http server enable", param: "management.http_enabled", vendor: "Huawei VRP" },
  { text: "set www disabled=yes", param: "management.http_enabled", vendor: "RouterOS" },
  { text: "set deviceconfig system service disable-http yes", param: "management.http_enabled", vendor: "PAN-OS" },
  { text: "ip http secure-server", param: "management.https_enabled", vendor: "Cisco IOS" },
  { text: "set system services web-management https system-generated-certificate", param: "management.https_enabled", vendor: "Junos" },
  { text: "http secure-server enable", param: "management.https_enabled", vendor: "Huawei VRP" },
  { text: "set www-ssl disabled=no", param: "management.https_enabled", vendor: "RouterOS" },
  { text: "exec-timeout 10 0", param: "management.idle_timeout_minutes", vendor: "Cisco IOS" },
  { text: "idle-timeout 10 0", param: "management.idle_timeout_minutes", vendor: "Huawei VRP" },
  { text: "set admintimeout 5", param: "management.idle_timeout_minutes", vendor: "FortiOS" },
  { text: "set deviceconfig setting management idle-timeout 10", param: "management.idle_timeout_minutes", vendor: "PAN-OS" },
  { text: "set system login class admin idle-timeout 10", param: "management.idle_timeout_minutes", vendor: "Junos" },
  { text: "management ssh idle-timeout 10", param: "management.idle_timeout_minutes", vendor: "Arista EOS" },
  { text: "ip ssh time-out 60", param: "management.ssh_timeout_seconds", vendor: "Cisco IOS" },
  { text: "ssh server timeout 60", param: "management.ssh_timeout_seconds", vendor: "Huawei VRP" },
  { text: "ip ssh authentication-retries 3", param: "management.ssh_auth_retries", vendor: "Cisco IOS" },
  { text: "ssh server authentication-retries 3", param: "management.ssh_auth_retries", vendor: "Huawei VRP" },
  { text: "access-class 10 in", param: "management.mgmt_acl_applied", vendor: "Cisco IOS" },
  { text: "acl 2000 inbound", param: "management.mgmt_acl_applied", vendor: "Huawei VRP" },
  { text: "set trusthost1 10.1.1.0 255.255.255.0", param: "management.mgmt_acl_applied", vendor: "FortiOS" },
  { text: "set deviceconfig system permitted-ip 10.1.1.0/24", param: "management.mgmt_acl_applied", vendor: "PAN-OS" },
  { text: "banner motd ^C Authorized access only ^C", param: "management.login_banner", vendor: "Cisco IOS" },
  { text: "set system login message Authorized access only", param: "management.login_banner", vendor: "Junos" },
  { text: "header login information Authorized access only", param: "management.login_banner", vendor: "Huawei VRP" },
  { text: "set pre-login-banner enable", param: "management.login_banner", vendor: "FortiOS" },
  { text: "set deviceconfig system login-banner Authorized access only", param: "management.login_banner", vendor: "PAN-OS" },
  { text: "service password-encryption", param: "auth.password_encryption", vendor: "Cisco IOS" },
  { text: "enable secret 9 $9$hash", param: "auth.enable_secret", vendor: "Cisco IOS" },
  { text: "set system root-authentication encrypted-password hash", param: "auth.enable_secret", vendor: "Junos" },
  { text: "aaa new-model", param: "auth.aaa_enabled", vendor: "Cisco IOS" },
  { text: "aaa authentication login default group tacacs+ local", param: "auth.aaa_authentication_login", vendor: "Cisco IOS" },
  { text: "authentication-mode aaa", param: "auth.aaa_authentication_login", vendor: "Huawei VRP" },
  { text: "set system authentication-order tacplus", param: "auth.aaa_authentication_login", vendor: "Junos" },
  { text: "aaa accounting commands 15 default start-stop group tacacs+", param: "auth.aaa_accounting", vendor: "Cisco IOS" },
  { text: "tacacs server ISE address ipv4 10.1.1.10", param: "auth.remote_auth_servers", vendor: "Cisco IOS" },
  { text: "set system tacplus-server 10.1.1.10 secret key", param: "auth.remote_auth_servers", vendor: "Junos" },
  { text: "hwtacacs-server authentication 10.1.1.10", param: "auth.remote_auth_servers", vendor: "Huawei VRP" },
  { text: "radius-server host 10.1.1.11 key secret", param: "auth.remote_auth_servers", vendor: "Cisco IOS" },
  { text: "username admin privilege 15 secret 9 hash", param: "auth.local_users", vendor: "Cisco IOS" },
  { text: "local-user admin password irreversible-cipher hash", param: "auth.local_users", vendor: "Huawei VRP" },
  { text: "set system login user admin class super-user", param: "auth.local_users", vendor: "Junos" },
  { text: "security passwords min-length 12", param: "auth.min_password_length", vendor: "Cisco IOS" },
  { text: "set system login password minimum-length 12", param: "auth.min_password_length", vendor: "Junos" },
  { text: "set minimum-length 12", param: "auth.min_password_length", vendor: "FortiOS" },
  { text: "password minimum length 12", param: "auth.min_password_length", vendor: "Arista EOS" },
  { text: "login block-for 60 attempts 3 within 60", param: "auth.login_lockout", vendor: "Cisco IOS" },
  { text: "set system login retry-options tries-before-disconnect 3", param: "auth.login_lockout", vendor: "Junos" },
  { text: "set admin-lockout-threshold 3", param: "auth.max_login_attempts", vendor: "FortiOS" },
  { text: "set deviceconfig setting management admin-lockout failed-attempts 3", param: "auth.max_login_attempts", vendor: "PAN-OS" },
  { text: "logging host 10.1.1.5", param: "logging.remote_hosts", vendor: "Cisco IOS" },
  { text: "set system syslog host 10.1.1.5 any info", param: "logging.remote_hosts", vendor: "Junos" },
  { text: "info-center loghost 10.1.1.5", param: "logging.remote_hosts", vendor: "Huawei VRP" },
  { text: "set server 10.1.1.5", param: "logging.remote_hosts", vendor: "FortiOS syslogd" },
  { text: "set shared log-settings syslog PROFILE server S1 server 10.1.1.5", param: "logging.remote_hosts", vendor: "PAN-OS" },
  { text: "/system logging action set remote remote=10.1.1.5", param: "logging.remote_hosts", vendor: "RouterOS" },
  { text: "logging buffered 64000 informational", param: "logging.buffered", vendor: "Cisco IOS" },
  { text: "set system syslog file messages any notice", param: "logging.buffered", vendor: "Junos" },
  { text: "logging trap informational", param: "logging.level", vendor: "Cisco IOS" },
  { text: "service timestamps log datetime msec", param: "logging.timestamps", vendor: "Cisco IOS" },
  { text: "info-center timestamp log date", param: "logging.timestamps", vendor: "Huawei VRP" },
  { text: "logging source-interface Loopback0", param: "logging.source_interface", vendor: "Cisco IOS" },
  { text: "login on-failure log", param: "logging.login_events", vendor: "Cisco IOS" },
  { text: "ntp server 10.1.1.2 key 1", param: "time.ntp_servers", vendor: "Cisco IOS" },
  { text: "set system ntp server 10.1.1.2 key 1", param: "time.ntp_servers", vendor: "Junos" },
  { text: "ntp-service unicast-server 10.1.1.2", param: "time.ntp_servers", vendor: "Huawei VRP" },
  { text: "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.1.1.2", param: "time.ntp_servers", vendor: "PAN-OS" },
  { text: "/system ntp client set enabled=yes servers=10.1.1.2", param: "time.ntp_servers", vendor: "RouterOS" },
  { text: "ntp authenticate", param: "time.ntp_authentication", vendor: "Cisco IOS" },
  { text: "ntp-service authentication enable", param: "time.ntp_authentication", vendor: "Huawei VRP" },
  { text: "set system ntp trusted-key 1", param: "time.ntp_authentication", vendor: "Junos" },
  { text: "clock timezone IST 5 30", param: "time.timezone_set", vendor: "Cisco IOS" },
  { text: "set system time-zone Asia/Kolkata", param: "time.timezone_set", vendor: "Junos" },
  { text: "snmp-server community public RO", param: "snmp.v1v2c_communities", vendor: "Cisco IOS" },
  { text: "set snmp community public authorization read-only", param: "snmp.v1v2c_communities", vendor: "Junos" },
  { text: "snmp-agent community read cipher hash", param: "snmp.v1v2c_communities", vendor: "Huawei VRP" },
  { text: "set name public", param: "snmp.v1v2c_communities", vendor: "FortiOS snmp community" },
  { text: "/snmp community set [ find default=yes ] name=public", param: "snmp.v1v2c_communities", vendor: "RouterOS" },
  { text: "snmp-server group SEC v3 priv", param: "snmp.v3_priv", vendor: "Cisco IOS" },
  { text: "snmp-server user secops SEC v3 auth sha key priv aes 128 key", param: "snmp.v3_priv", vendor: "Cisco IOS" },
  { text: "set security-level auth-priv", param: "snmp.v3_priv", vendor: "FortiOS" },
  { text: "snmp-agent usm-user v3 secops group SEC privacy-mode aes128", param: "snmp.v3_priv", vendor: "Huawei VRP" },
  { text: "snmp-server host 10.1.1.6 version 3 priv secops", param: "snmp.trap_hosts", vendor: "Cisco IOS" },
  { text: "no cdp run", param: "services.cdp_enabled", vendor: "Cisco IOS" },
  { text: "no lldp run", param: "services.lldp_enabled", vendor: "Arista EOS" },
  { text: "lldp enable", param: "services.lldp_enabled", vendor: "Huawei VRP" },
  { text: "no ip source-route", param: "services.ip_source_routing", vendor: "Cisco IOS" },
  { text: "no ip proxy-arp", param: "services.proxy_arp", vendor: "Cisco IOS" },
  { text: "no ip directed-broadcast", param: "services.directed_broadcast", vendor: "Cisco IOS" },
  { text: "no ip redirects", param: "services.icmp_redirects", vendor: "Cisco IOS" },
  { text: "no ip bootp server", param: "services.bootp_server", vendor: "Cisco IOS" },
  { text: "no service dhcp", param: "services.dhcp_server", vendor: "Cisco IOS" },
  { text: "no service pad", param: "services.pad", vendor: "Cisco IOS" },
  { text: "no ip finger", param: "services.finger", vendor: "Cisco IOS" },
  { text: "no ip identd", param: "services.identd", vendor: "Cisco IOS" },
  { text: "service tcp-keepalives-in", param: "services.tcp_keepalives", vendor: "Cisco IOS" },
  { text: "no service tcp-small-servers", param: "services.small_servers", vendor: "Cisco IOS" },
  { text: "ip verify unicast source reachable-via rx", param: "services.unicast_rpf", vendor: "Cisco IOS" },
  { text: "neighbor 10.1.1.9 password 7 hash", param: "routing.bgp_auth", vendor: "Cisco IOS" },
  { text: "set protocols bgp group EXT neighbor 10.1.1.9 authentication-key secret", param: "routing.bgp_auth", vendor: "Junos" },
  { text: "peer 10.1.1.9 password cipher hash", param: "routing.bgp_auth", vendor: "Huawei VRP" },
  { text: "ip ospf message-digest-key 1 md5 key", param: "routing.ospf_auth", vendor: "Cisco IOS" },
  { text: "area 0 authentication message-digest", param: "routing.ospf_auth", vendor: "Cisco IOS" },
  { text: "ospf authentication-mode md5 1 cipher hash", param: "routing.ospf_auth", vendor: "Huawei VRP" },
  { text: "ip access-list extended EDGE-IN", param: "acl.count", vendor: "Cisco IOS" },
  { text: "set firewall family inet filter PROTECT-RE term ACCEPT", param: "acl.count", vendor: "Junos" },
  { text: "ip access-group EDGE-IN in", param: "acl.external_ingress_filter", vendor: "Cisco IOS" },
  { text: "traffic-filter inbound acl 3000", param: "acl.external_ingress_filter", vendor: "Huawei VRP" },
  { text: "deny ip any any log", param: "acl.explicit_deny_logged", vendor: "Cisco IOS" },
  { text: "set fwpolicy-implicit-log enable", param: "acl.explicit_deny_logged", vendor: "FortiOS" },
  { text: "set security policies default-policy deny-all", param: "acl.default_deny", vendor: "Junos" },
  { text: "/ip firewall filter add chain=input action=drop", param: "acl.default_deny", vendor: "RouterOS" },
  { text: "crypto key generate rsa modulus 2048", param: "crypto.rsa_modulus", vendor: "Cisco IOS" },
  { text: "set host-key-size 2048", param: "crypto.rsa_modulus", vendor: "RouterOS" },
  { text: "set ssl-min-proto-version TLSv1-2", param: "crypto.tls_min_version", vendor: "FortiOS" },
  { text: "ssl minimum version tls1.2", param: "crypto.tls_min_version", vendor: "Huawei VRP" },
  { text: "set strong-crypto enable", param: "crypto.strong_crypto", vendor: "FortiOS" },
  { text: "ip ssh server algorithm encryption aes256-gcm aes256-ctr", param: "crypto.strong_crypto", vendor: "Cisco IOS" },
  { text: "set system services ssh ciphers aes256-ctr", param: "crypto.strong_crypto", vendor: "Junos" },
  { text: "/ip ssh set strong-crypto=yes", param: "crypto.strong_crypto", vendor: "RouterOS" },
  { text: "crypto isakmp policy 10 encryption 3des", param: "crypto.weak_ike", vendor: "Cisco IOS" },
  { text: "set system fips level 1", param: "crypto.fips_mode", vendor: "Junos" },
  { text: "hostname EDGE-RTR-01", param: "identity.hostname_set", vendor: "Cisco IOS" },
  { text: "set system host-name DC-SRX-01", param: "identity.hostname_set", vendor: "Junos" },
  { text: "sysname CORE-HW-01", param: "identity.hostname_set", vendor: "Huawei VRP" },
  { text: "/system identity set name=CORE-MT-01", param: "identity.hostname_set", vendor: "RouterOS" },
  { text: "ip domain name corp.example.in", param: "identity.domain_set", vendor: "Cisco IOS" },
  { text: "interface Loopback0", param: "identity.loopback_present", vendor: "Cisco IOS" },
  { text: "set system services ssh root-login deny", param: "auth.root_login_ssh", vendor: "Junos" },
  { text: "set two-factor fortitoken", param: "auth.two_factor", vendor: "FortiOS" },
  { text: "set system services ssh connection-limit 5", param: "management.concurrent_sessions_limited", vendor: "Junos" },
  { text: "set admin-concurrent disable", param: "management.concurrent_sessions_limited", vendor: "FortiOS" },
  { text: "no exec", param: "management.aux_disabled", vendor: "Cisco IOS line aux" },
  { text: "set ftp disabled=yes", param: "management.ftp_enabled", vendor: "RouterOS" },
  { text: "set system services ftp", param: "management.ftp_enabled", vendor: "Junos" },
  { text: "management api http-commands protocol http", param: "management.api_http_enabled", vendor: "Arista EOS" },
  { text: "set api disabled=yes", param: "management.api_http_enabled", vendor: "RouterOS" },

  // --- enable/disable-verb CLIs (Extreme EXOS and friends) ---
  { text: "enable ssh2", param: "management.ssh_enabled", vendor: "Extreme EXOS" },
  { text: "disable telnet", param: "management.telnet_enabled", vendor: "Extreme EXOS" },
  { text: "enable web http", param: "management.http_enabled", vendor: "Extreme EXOS" },
  { text: "enable web https", param: "management.https_enabled", vendor: "Extreme EXOS" },
  { text: "configure idletimeout 45", param: "management.idle_timeout_minutes", vendor: "Extreme EXOS" },
  { text: "configure cli max-sessions 4", param: "management.concurrent_sessions_limited", vendor: "Extreme EXOS" },
  { text: "configure banner before-login", param: "management.login_banner", vendor: "Extreme EXOS" },
  { text: "configure ssh2 ciphers aes256-ctr aes128-ctr", param: "crypto.strong_crypto", vendor: "Extreme EXOS" },
  { text: "configure sntp-client primary 10.1.1.2 vr VR-Default", param: "time.ntp_servers", vendor: "Extreme EXOS" },
  { text: "configure syslog add 10.1.1.5:514 vr VR-Default local7", param: "logging.remote_hosts", vendor: "Extreme EXOS" },
  { text: "enable syslog", param: "logging.enabled", vendor: "Extreme EXOS" },
  { text: "configure log target console severity Critical", param: "logging.console_restricted", vendor: "Extreme EXOS" },
  { text: "configure log target memory-buffer severity Debug-Data", param: "logging.buffered", vendor: "Extreme EXOS" },
  { text: "configure snmp add community readonly public", param: "snmp.v1v2c_communities", vendor: "Extreme EXOS" },
  { text: "enable snmp access snmp-v1v2c", param: "snmp.enabled", vendor: "Extreme EXOS" },
  { text: "enable snmp access snmpv3", param: "snmp.v3_enabled", vendor: "Extreme EXOS" },
  { text: "configure snmpv3 add target-addr siem param v3params ipaddress 10.1.1.6 transport-port 162", param: "snmp.trap_hosts", vendor: "Extreme EXOS" },
  { text: "configure account all password-policy lockout-on-login-failures on", param: "auth.login_lockout", vendor: "Extreme EXOS" },
  { text: "configure account all password-policy char-validation all-char-groups", param: "auth.password_complexity", vendor: "Extreme EXOS" },
  { text: "enable radius mgmt-access", param: "auth.aaa_enabled", vendor: "Extreme EXOS" },
  { text: "configure radius mgmt-access primary server 10.1.1.11 1812 client-ip 10.1.1.1 vr VR-Default", param: "auth.remote_auth_servers", vendor: "Extreme EXOS" },
  { text: "configure access-list mgmt-in vlan Mgmt ingress", param: "acl.external_ingress_filter", vendor: "Extreme EXOS" },

  // --- Cisco NX-OS ---
  { text: "feature telnet", param: "management.telnet_enabled", vendor: "Cisco NX-OS" },
  { text: "logging server 10.1.1.5 6 use-vrf management", param: "logging.remote_hosts", vendor: "Cisco NX-OS" },
  { text: "snmp-server user secops network-admin auth sha authkey priv aes-128 privkey", param: "snmp.v3_priv", vendor: "Cisco NX-OS" },
  { text: "ssh key rsa 2048 force", param: "crypto.rsa_modulus", vendor: "Cisco NX-OS" },

  // --- Nokia SR OS ---
  { text: "configure system security ssh version 2", param: "management.ssh_version", vendor: "Nokia SR OS" },
  { text: "configure log syslog 1 address 10.1.1.5", param: "logging.remote_hosts", vendor: "Nokia SR OS" },
  { text: "configure system login-control idle-timeout 10", param: "management.idle_timeout_minutes", vendor: "Nokia SR OS" },
  { text: "configure system security snmp community public r", param: "snmp.v1v2c_communities", vendor: "Nokia SR OS" },

  // --- Aruba AOS-CX ---
  { text: "ssh server vrf mgmt", param: "management.ssh_enabled", vendor: "Aruba AOS-CX" },
  { text: "https-server vrf mgmt", param: "management.https_enabled", vendor: "Aruba AOS-CX" },
  { text: "session-timeout 10", param: "management.idle_timeout_minutes", vendor: "Aruba AOS-CX" },
  { text: "logging 10.1.1.5 vrf mgmt", param: "logging.remote_hosts", vendor: "Aruba AOS-CX" },
  { text: "snmpv3 user secops auth sha auth-pass plaintext secret priv aes priv-pass plaintext secret", param: "snmp.v3_priv", vendor: "Aruba AOS-CX" },

  // --- VyOS ---
  { text: "set service ssh port 22", param: "management.ssh_enabled", vendor: "VyOS" },
  { text: "set system syslog host 10.1.1.5 facility all level info", param: "logging.remote_hosts", vendor: "VyOS" },
  { text: "set system login banner pre-login Authorized access only", param: "management.login_banner", vendor: "VyOS" },
  { text: "set service snmp community public authorization ro", param: "snmp.v1v2c_communities", vendor: "VyOS" },
  { text: "set system ntp server 10.1.1.2", param: "time.ntp_servers", vendor: "VyOS" },

  // --- NVIDIA Cumulus NVUE ---
  { text: "nv set system ssh-server state enabled", param: "management.ssh_enabled", vendor: "Cumulus NVUE" },
  { text: "nv set service syslog default server 10.1.1.5", param: "logging.remote_hosts", vendor: "Cumulus NVUE" },
  { text: "nv set system aaa user admin role system-admin", param: "auth.local_users", vendor: "Cumulus NVUE" },
  { text: "nv set service ntp default server 10.1.1.2", param: "time.ntp_servers", vendor: "Cumulus NVUE" },

  // --- Check Point Gaia clish ---
  { text: "set web session-timeout 10", param: "management.idle_timeout_minutes", vendor: "Gaia clish" },
  { text: "set password-controls min-password-length 14", param: "auth.min_password_length", vendor: "Gaia clish" },
  { text: "add syslog log-remote-address 10.1.1.5 level info", param: "logging.remote_hosts", vendor: "Gaia clish" },
  { text: "set ssh server on", param: "management.ssh_enabled", vendor: "Gaia clish" },
  { text: "set ntp server primary 10.1.1.2 version 4", param: "time.ntp_servers", vendor: "Gaia clish" },

  // --- SonicOS ---
  { text: "administration idle-logout-time 10", param: "management.idle_timeout_minutes", vendor: "SonicOS" },
  { text: "syslog server 10.1.1.5", param: "logging.remote_hosts", vendor: "SonicOS" },
  { text: "administration no http", param: "management.http_enabled", vendor: "SonicOS" },

  // --- Dell OS10 ---
  { text: "ip ssh server enable", param: "management.ssh_enabled", vendor: "Dell OS10" },
  { text: "password-attributes min-length 12", param: "auth.min_password_length", vendor: "Dell OS10" },
  { text: "logging server 10.1.1.5", param: "logging.remote_hosts", vendor: "Dell OS10" },
  { text: "snmp-server user secops group netadmin 3 auth sha authkey priv aes 128 privkey", param: "snmp.v3_priv", vendor: "Dell OS10" },

  // --- HPE Comware / Juniper extras ---
  { text: "line vty 0 63 idle-timeout 10 0", param: "management.idle_timeout_minutes", vendor: "HPE Comware" },
  { text: "info-center loghost 10.1.1.5 facility local7", param: "logging.remote_hosts", vendor: "HPE Comware" },
  { text: "set system services ssh max-sessions-per-connection 2", param: "management.concurrent_sessions_limited", vendor: "Junos" },
];

const CORPUS = KNOWN_COMMANDS.map((c) => ({ ...c, tokens: tokenize(c.text) }));

/** IDF over the corpus so boilerplate ("set", "system", "10") stops dominating similarity. */
const DF = new Map<string, number>();
for (const ex of CORPUS) for (const t of new Set(ex.tokens)) DF.set(t, (DF.get(t) ?? 0) + 1);
const idfOf = (t: string): number => Math.log((CORPUS.length + 1) / ((DF.get(t) ?? 0) + 1)) + 1;

function weightedJaccard(a: Set<string>, b: Set<string>): number {
  let inter = 0;
  let union = 0;
  for (const t of a) { const w = idfOf(t); union += w; if (b.has(t)) inter += w; }
  for (const t of b) if (!a.has(t)) union += idfOf(t);
  return union === 0 ? 0 : inter / union;
}
const CORPUS_SETS = CORPUS.map((c) => new Set(c.tokens));

/** Plain (unweighted) Jaccard, kept for callers that want the raw overlap. */
function jaccard(a: string[], b: string[]): number {
  const A = new Set(a);
  const B = new Set(b);
  let inter = 0;
  for (const x of A) if (B.has(x)) inter++;
  const union = A.size + B.size - inter;
  return union === 0 ? 0 : inter / union;
}

/** Single keyword weight ceiling — stops one hyphenated keyword saturating confidence. */
const KW_CAP = 3.2;

interface KwMeta { kw: string; norm: string; tokens: string[]; weightPhrase: number; weightTokens: number; generic: boolean }
interface ParamMeta { key: string; type: string; kws: KwMeta[]; totalWeight: number; kwTokens: Set<string> }

const PARAM_META: ParamMeta[] = SBM_PARAMS.map((def) => {
  const kws: KwMeta[] = [];
  const kwTokens = new Set<string>();
  let totalWeight = 0;
  for (const kw of def.keywords) {
    const toks = tokenize(kw);
    if (!toks.length) continue;
    const words = kw.trim().split(/\s+/).length;
    const generic = toks.length === 1 && GENERIC_WORDS.has(toks[0]);
    const wp = Math.min(KW_CAP, 1.6 * words) * (generic ? 0.35 : 1);
    const wt = Math.min(KW_CAP, 1.0 * words) * (generic ? 0.35 : 1);
    kws.push({ kw, norm: kw.toLowerCase().replace(/[-_]/g, " "), tokens: toks, weightPhrase: wp, weightTokens: wt, generic });
    if (!generic) totalWeight += wp;
    for (const t of rawSplit(kw)) kwTokens.add(t);
  }
  return { key: def.key, type: def.type, kws, totalWeight, kwTokens };
});
const META_INDEX: Record<string, ParamMeta> = Object.fromEntries(PARAM_META.map((m) => [m.key, m]));

/** Tokenised sample lines of learned mappings, memoised by mapping id. */
const learnedTokens = new Map<string, Set<string>>();
const learnedRegex = new Map<string, RegExp | null>();

export interface ScoredParam {
  param: string;
  score: number;
  /** share of the parameter's non-generic keyword vocabulary that matched (0..1) */
  coverage: number;
  reasons: string[];
}

export function scoreLine(text: string, learned: Mapping[] = [], vendor?: VendorId | "any"): ScoredParam[] {
  const lineTokens = tokenize(text);
  const lineSet = new Set(lineTokens);
  const norm = ` ${text.toLowerCase().replace(/[-_]/g, " ").replace(/\s+/g, " ").trim()} `;
  const results: ScoredParam[] = [];
  for (const meta of PARAM_META) {
    const hits: number[] = [];
    const reasons: string[] = [];
    let matchedWeight = 0;
    for (const kw of meta.kws) {
      let w = 0;
      if (norm.includes(` ${kw.norm} `)) w = kw.weightPhrase;
      else if (kw.tokens.every((t) => lineSet.has(t))) w = kw.weightTokens;
      if (w > 0) {
        hits.push(w);
        if (!kw.generic) matchedWeight += w;
        if (!kw.generic || w >= 1) reasons.push(`keyword “${kw.kw}”`);
      }
    }
    // Diminishing returns: a parameter with many overlapping synonyms cannot
    // out-shout one distinctive match by counting the same words three times.
    hits.sort((a, b) => b - a);
    let score = 0;
    for (let i = 0; i < hits.length; i++) score += hits[i] * Math.pow(0.5, i);
    const coverage = meta.totalWeight > 0 ? Math.min(1, matchedWeight / meta.totalWeight) : 0;

    // kNN against the known-command corpus (IDF weighted)
    let best = 0;
    let bestIdx = -1;
    for (let i = 0; i < CORPUS.length; i++) {
      if (CORPUS[i].param !== meta.key) continue;
      const sim = weightedJaccard(lineSet, CORPUS_SETS[i]);
      if (sim > best) { best = sim; bestIdx = i; }
    }
    if (best >= 0.2 && bestIdx >= 0) {
      score += 3 * best;
      reasons.push(`${Math.round(best * 100)}% similar to ${CORPUS[bestIdx].vendor} “${CORPUS[bestIdx].text}”`);
    }

    // similarity to administrator-taught mappings (scoped, and the regex must fire)
    for (const m of learned) {
      if (m.param !== meta.key || !m.sampleLine) continue;
      if (vendor && m.vendor !== "any" && m.vendor !== vendor) continue;
      let re = learnedRegex.get(m.id);
      if (re === undefined) {
        try { re = new RegExp(m.pattern, (m.flags || "i").replace(/[gy]/g, "")); } catch { re = null; }
        learnedRegex.set(m.id, re);
      }
      if (!re || !re.test(text)) continue;
      let toks = learnedTokens.get(m.id);
      if (!toks) { toks = new Set(tokenize(m.sampleLine)); learnedTokens.set(m.id, toks); }
      const sim = weightedJaccard(lineSet, toks);
      if (sim >= 0.3) {
        score += 2.5 * sim;
        reasons.push(`${Math.round(sim * 100)}% similar to learned “${m.sampleLine}”`);
      }
    }
    if (score > 0) results.push({ param: meta.key, score, coverage, reasons: Array.from(new Set(reasons)).slice(0, 4) });
  }
  results.sort((a, b) => b.score - a.score);
  return results;
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

export interface Extraction {
  valueMode: ValueMode;
  pattern: string;
  constValue?: Suggestion["constValue"];
  captureGroup?: number;
  transform?: Suggestion["transform"];
  extractedValue?: Suggestion["extractedValue"];
  /** false when no real value could be found — the proposal must not be auto-accepted */
  extractionValid: boolean;
}

const esc = (s: string) => escapeRegex(s);
const IP_CLASS = "\\d{1,3}(?:\\.\\d{1,3}){3}";
const CLASS_PARTS = new Set(["\\S+", "\\d+", `"[^"]*"`, IP_CLASS, `(?:${IP_CLASS})`]);
const isClassPart = (p: string) => CLASS_PARTS.has(p);

/** Drop a :port / prefix-length, without eating the tail of an IPv6 address. */
const stripPort = (t: string) => {
  const v4 = t.match(IPV4_TOKEN);
  if (v4) return v4[1];
  return t.replace(/^\[([^\]]+)\](?::\d+)?$/, "$1").replace(/\/\d+$/, "");
};
const unquote = (t: string) => t.replace(/^["']|["']$/g, "");
const isQuoted = (t: string) => /^"[^"]*"$/.test(t) || /^'[^']*'$/.test(t);

/** How a single token should appear in a generated pattern. */
function partFor(tok: string, meta: ParamMeta | undefined): string {
  if (IPV4_TOKEN.test(tok) || IPV6_TOKEN.test(tok)) return "\\S+";
  if (/^\d+$/.test(tok)) return "\\d+";
  if (isQuoted(tok)) return `"[^"]*"`;
  const low = tok.toLowerCase();
  const sib = siblingsOf(low);
  if (sib) return `(?:${sib.map(esc).join("|")})`;
  // Instance names are capitalised (Mgmt, VR-Default, Loopback0, EDGE-IN, Critical).
  if (/[A-Z]/.test(tok)) return "\\S+";
  if (VOCAB.has(low) || (meta?.kwTokens.has(low) ?? false)) return esc(tok);
  if (low.endsWith("s") && VOCAB.has(low.slice(0, -1))) return esc(tok);
  // Everything else is instance data (mgmt-in, local7, VR-Default, dot1w).
  return "\\S+";
}

function isDroppable(tok: string, part: string): boolean {
  return isClassPart(part) || NEG_WORDS.test(tok) || POS_WORDS.test(tok) || tok.toLowerCase() === "all";
}

/**
 * Assemble the pattern, trimming instance-specific tail tokens so siblings match
 * too — but never cutting before the captured value or the last vocabulary word.
 */
function buildPattern(tokens: string[], parts: string[], captureIdx: number): string {
  let end = parts.length - 1;
  while (end > Math.max(captureIdx, 0) && isDroppable(tokens[end], parts[end])) end--;
  const body = parts.slice(0, end + 1).join("\\s+");
  return `^${body}${end === parts.length - 1 ? "$" : "\\b"}`;
}

/** Does this raw token carry any word from the parameter's own keyword list? */
function touchesKeyword(meta: ParamMeta | undefined, token: string | undefined): boolean {
  if (!meta || !token) return false;
  const low = token.toLowerCase();
  if (meta.kwTokens.has(low)) return true;
  return rawSplit(low).some((p) => meta.kwTokens.has(p));
}

interface ValueHit { idx: number; value: string; cls: "ip" | "host" | "quoted" | "word" }

/** Find a real value for a list/string parameter. Returns null when the line has none. */
function findValue(tokens: string[], meta: ParamMeta | undefined): ValueHit | null {
  const addrs: number[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i].replace(/^[\w-]+=/, "");
    if (IPV4_TOKEN.test(t) || IPV6_TOKEN.test(t) || (HOST_TOKEN.test(t) && !/^\d+(\.\d+)*$/.test(t))) addrs.push(i);
  }
  if (addrs.length) {
    const anchored = addrs.find((i) => i > 0 && VALUE_ANCHORS.has(tokens[i - 1].toLowerCase()));
    const idx = anchored ?? addrs[0];
    const raw = tokens[idx].replace(/^[\w-]+=/, "");
    return { idx, value: stripPort(raw), cls: IPV4_TOKEN.test(raw) || IPV6_TOKEN.test(raw) ? "ip" : "host" };
  }
  const q = tokens.findIndex(isQuoted);
  if (q >= 0 && unquote(tokens[q]).trim()) return { idx: q, value: unquote(tokens[q]), cls: "quoted" };
  // the token right after a param keyword (community -> public, user -> admin)
  for (let i = 0; i < tokens.length - 1; i++) {
    const head = tokens[i].toLowerCase();
    if (!VALUE_ANCHORS.has(head) && !meta?.kwTokens.has(head)) continue;
    for (let j = i + 1; j < tokens.length; j++) {
      const cand = tokens[j];
      const low = cand.toLowerCase();
      if (VALUE_MODIFIERS.has(low) || VALUE_ANCHORS.has(low)) continue;
      if (NEG_WORDS.test(cand) || POS_WORDS.test(cand)) break;
      if (!/^[\w.@:-]+$/.test(cand)) break;
      return { idx: j, value: unquote(cand), cls: "word" };
    }
  }
  return null;
}

/** Find the integer/version that belongs to this parameter. */
function findNumber(tokens: string[], meta: ParamMeta | undefined): { idx: number; value: number; whole: boolean; prefix?: string } | null {
  const cands: { idx: number; value: number; whole: boolean; prefix?: string }[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (IPV4_TOKEN.test(t) || IPV6_TOKEN.test(t)) continue;
    const kv = t.match(/^([\w-]+)=(\d+(?:\.\d+)?)$/);
    if (kv) { cands.push({ idx: i, value: Number(kv[2]), whole: false, prefix: `${kv[1]}=` }); continue; }
    const v = t.match(VERSION_TOKEN);
    if (v) { cands.push({ idx: i, value: Number(v[1]), whole: true }); continue; }
    // version-like suffix on a vocabulary word: ssh2 -> 2, tls1.2 -> 1.2
    const suf = t.match(/^([a-z][a-z-]*?)(\d+(?:\.\d+)?)$/i);
    if (suf && (meta?.kwTokens.has(suf[1].toLowerCase()) || KEYWORD_TOKENS.has(suf[1].toLowerCase()))) {
      cands.push({ idx: i, value: Number(suf[2]), whole: false, prefix: suf[1] });
    }
  }
  if (!cands.length) return null;
  const anchored = cands.find((c) => c.idx > 0 && touchesKeyword(meta, tokens[c.idx - 1]));
  return anchored ?? cands[cands.length - 1];
}

/** Locate the polarity word that actually governs this line. */
function findPolarity(tokens: string[], meta: ParamMeta | undefined): { idx: number; negative: boolean; kv?: string } | null {
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const kv = t.match(KV_STATE);
    const isState = NEG_WORDS.test(t) || POS_WORDS.test(t) || Boolean(kv);
    if (!isState) continue;
    // governing when it leads the command or immediately follows a keyword of this param
    const governs = i === 0 || Boolean(kv) || touchesKeyword(meta, tokens[i - 1]);
    if (!governs) continue;
    if (kv) return { idx: i, negative: NEG_WORDS.test(kv[1]) !== NEG_WORDS.test(kv[2]), kv: kv[1] };
    return { idx: i, negative: NEG_WORDS.test(t) };
  }
  return null;
}

/** Build the extraction proposal + regex for a parameter. */
export function proposeExtraction(text: string, param: string): Extraction {
  const def = SBM_INDEX[param];
  const meta = META_INDEX[param];
  const type = def?.type ?? "string";
  const tokens = splitTokens(text);
  if (!tokens.length) return { valueMode: "flag", pattern: `^${esc(text)}$`, constValue: true, extractedValue: true, extractionValid: false };
  const parts = tokens.map((t) => partFor(t, meta));

  if (type === "boolean") {
    if (PERMISSION_BOOLEANS.has(param)) {
      const idx = tokens.findIndex((t) => DENY_WORDS.test(t) || ALLOW_WORDS.test(t));
      if (idx >= 0) {
        const allowed = ALLOW_WORDS.test(tokens[idx]);
        // The state word is pinned literally: a different word means a different constant.
        const p = parts.slice();
        p[idx] = esc(tokens[idx]);
        return { valueMode: "const", pattern: buildPattern(tokens, p, idx), constValue: allowed, extractedValue: allowed, extractionValid: true };
      }
    }
    const pol = findPolarity(tokens, meta);
    if (pol) {
      const tok = tokens[pol.idx];
      const p = parts.slice();
      if (pol.kv) p[pol.idx] = `(${esc(pol.kv)}=\\S+)`;
      else { const sib = siblingsOf(tok); p[pol.idx] = sib ? `(${sib.map(esc).join("|")})` : "(\\S+)"; }
      const value = !pol.negative;
      if (INVERTED_BOOLEANS.has(param)) {
        // "no exec" means the AUX port IS disabled; "admin-concurrent disable" means sessions ARE limited.
        const lit = parts.slice();
        lit[pol.idx] = esc(tok);
        return { valueMode: "const", pattern: buildPattern(tokens, lit, pol.idx), constValue: !value, extractedValue: !value, extractionValid: true };
      }
      return { valueMode: "polarity", pattern: buildPattern(tokens, p, pol.idx), captureGroup: 1, extractedValue: value, extractionValid: true };
    }
    return { valueMode: "flag", pattern: buildPattern(tokens, parts, -1), constValue: true, extractedValue: true, extractionValid: true };
  }

  if (type === "number") {
    const num = findNumber(tokens, meta);
    if (num) {
      const p = parts.slice();
      const digits = Number.isInteger(num.value) && !/\./.test(tokens[num.idx]) ? "(\\d+)" : "(\\d+(?:\\.\\d+)?)";
      p[num.idx] = num.prefix ? `${esc(num.prefix)}${digits}` : /^v/i.test(tokens[num.idx]) ? `v?${digits}` : digits;
      return { valueMode: "capture", pattern: buildPattern(tokens, p, num.idx), captureGroup: 1, transform: "number", extractedValue: num.value, extractionValid: true };
    }
    if (COUNTER_PARAMS.has(param)) {
      return { valueMode: "count", pattern: buildPattern(tokens, parts, -1), extractedValue: 1, extractionValid: true };
    }
    // No number and not a counter: never invent one (an "enable idletimeout" is not a 1-minute timeout).
    return { valueMode: "flag", pattern: buildPattern(tokens, parts, -1), extractedValue: undefined, extractionValid: false };
  }

  if (type === "list") {
    const hit = findValue(tokens, meta);
    if (hit) {
      const p = parts.slice();
      p[hit.idx] = hit.cls === "ip" && IPV4_TOKEN.test(tokens[hit.idx].replace(/^[\w-]+=/, "")) ? `(${IP_CLASS})` : isQuoted(tokens[hit.idx]) ? `"([^"]*)"` : "(\\S+)";
      return { valueMode: "list", pattern: buildPattern(tokens, p, hit.idx), captureGroup: 1, extractedValue: [hit.value], extractionValid: true };
    }
    // Nothing worth listing — never turn the last word of the line into a list item.
    return { valueMode: "flag", pattern: buildPattern(tokens, parts, -1), extractedValue: undefined, extractionValid: false };
  }

  // string
  const hit = findValue(tokens, meta);
  if (hit) {
    const p = parts.slice();
    p[hit.idx] = isQuoted(tokens[hit.idx]) ? `"([^"]*)"` : "(\\S+)";
    return { valueMode: "capture", pattern: buildPattern(tokens, p, hit.idx), captureGroup: 1, transform: "string", extractedValue: hit.value, extractionValid: true };
  }
  const last = tokens.length - 1;
  const prevIsKeyword = last > 0 && ((meta?.kwTokens.has(tokens[last - 1].toLowerCase()) ?? false) || VALUE_ANCHORS.has(tokens[last - 1].toLowerCase()));
  const p = parts.slice();
  p[last] = isQuoted(tokens[last]) ? `"([^"]*)"` : "(\\S+)";
  return { valueMode: "capture", pattern: buildPattern(tokens, p, last), captureGroup: 1, transform: "string", extractedValue: unquote(tokens[last]), extractionValid: prevIsKeyword };
}

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

/** How much the proposal should be trusted given how the value was obtained. */
function extractionFactor(ex: Extraction, type: string): number {
  if (!ex.extractionValid) return 0.35;
  if (ex.valueMode === "flag" && type === "boolean") return 0.88;
  if (ex.valueMode === "count") return 0.85;
  return 1;
}

export function suggestForLine(text: string, learned: Mapping[] = [], limit = 3, vendor?: VendorId | "any"): Suggestion[] {
  const scored = scoreLine(text, learned, vendor);
  if (!scored.length) return [];
  const top = scored[0].score;
  const second = scored[1]?.score ?? 0;
  const margin = top > 0 ? 1 - second / top : 1;
  return scored.slice(0, limit).map((s, i) => {
    const ex = proposeExtraction(text, s.param);
    const type = SBM_INDEX[s.param]?.type ?? "string";
    const strength = 1 - Math.exp(-s.score / 2.2);
    // A parameter that matched only a sliver of its own vocabulary is a weak hit.
    const cover = 0.55 + 0.45 * Math.min(1, s.coverage / 0.3);
    const conf = (i === 0 ? strength * cover * (0.72 + 0.28 * margin) : strength * cover * 0.7) * extractionFactor(ex, type);
    return {
      param: s.param,
      confidence: Math.round(Math.min(0.99, conf) * 100) / 100,
      valueMode: ex.valueMode,
      pattern: ex.pattern,
      constValue: ex.constValue,
      captureGroup: ex.captureGroup,
      transform: ex.transform,
      extractedValue: ex.extractedValue,
      extractionValid: ex.extractionValid,
      reasons: s.reasons,
      source: "classifier",
    };
  });
}

export function confidenceLabel(c: number): "High" | "Medium" | "Low" {
  return c >= CONFIDENCE_HIGH ? "High" : c >= CONFIDENCE_MEDIUM ? "Medium" : "Low";
}

export const vendorHint = (v: VendorId) => v;

/** Exported for tests: the raw overlap helper and the per-parameter vocabulary. */
export const _internals = { jaccard, weightedJaccard, idfOf, partFor, findValue, findNumber, findPolarity, INVERTED_BOOLEANS, COUNTER_PARAMS };

export type { ParamValue };
