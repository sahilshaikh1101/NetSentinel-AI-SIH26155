import type { Mapping } from "../types";

/**
 * A shareable mapping pack for Extreme EXOS — the product of one training
 * session, exportable and importable as data. Loading it makes the EXOS
 * sample fully auditable without any code change.
 */
const m = (id: string, name: string, pattern: string, param: string, valueMode: Mapping["valueMode"], extra: Partial<Mapping> = {}): Mapping => ({
  id,
  name,
  vendor: "any",
  pattern,
  flags: "i",
  param,
  valueMode,
  createdAt: "2026-09-16T14:00:00.000Z",
  createdBy: "seed",
  hits: 0,
  ...extra,
});

export const EXOS_STARTER_PACK: Mapping[] = [
  m("exos-telnet", "EXOS · Telnet", "^(enable|disable)\\s+telnet$", "management.telnet_enabled", "polarity", { sampleLine: "disable telnet" }),
  m("exos-ssh", "EXOS · SSH2", "^(enable|disable)\\s+ssh2$", "management.ssh_enabled", "polarity", { sampleLine: "enable ssh2" }),
  m("exos-ssh-version", "EXOS · SSH protocol v2", "^enable\\s+ssh2$", "management.ssh_version", "const", { constValue: 2, sampleLine: "enable ssh2" }),
  m("exos-http", "EXOS · Web HTTP", "^(enable|disable)\\s+web\\s+http$", "management.http_enabled", "polarity", { sampleLine: "enable web http" }),
  m("exos-https", "EXOS · Web HTTPS", "^(enable|disable)\\s+web\\s+https$", "management.https_enabled", "polarity", { sampleLine: "enable web https" }),
  m("exos-idle", "EXOS · Idle timeout", "^configure\\s+idletimeout\\s+(\\d+)$", "management.idle_timeout_minutes", "capture", { captureGroup: 1, transform: "number", sampleLine: "configure idletimeout 45" }),
  m("exos-sessions", "EXOS · Max sessions", "^configure\\s+cli\\s+max-sessions\\s+(\\d+)$", "management.concurrent_sessions_limited", "flag", { sampleLine: "configure cli max-sessions 4" }),
  m("exos-banner", "EXOS · Login banner", "^configure\\s+banner\\s+before-login", "management.login_banner", "flag", { sampleLine: "configure banner before-login" }),
  m("exos-minlen", "EXOS · Password min length", "^configure\\s+account\\s+all\\s+password-policy\\s+min-length\\s+(\\d+)$", "auth.min_password_length", "capture", { captureGroup: 1, transform: "number", sampleLine: "configure account all password-policy min-length 8" }),
  m("exos-lockout", "EXOS · Login lockout", "^configure\\s+account\\s+all\\s+password-policy\\s+lockout-on-login-failures\\s+(on|off)$", "auth.login_lockout", "polarity", { sampleLine: "configure account all password-policy lockout-on-login-failures on" }),
  m("exos-complexity", "EXOS · Password complexity", "^configure\\s+account\\s+all\\s+password-policy\\s+char-validation", "auth.password_complexity", "flag", { sampleLine: "configure account all password-policy char-validation all-char-groups" }),
  m("exos-radius", "EXOS · RADIUS mgmt auth", "^enable\\s+radius\\s+mgmt-access$", "auth.aaa_authentication_login", "flag", { sampleLine: "enable radius mgmt-access" }),
  m("exos-radius-enabled", "EXOS · AAA enabled", "^enable\\s+radius\\s+mgmt-access$", "auth.aaa_enabled", "flag", { sampleLine: "enable radius mgmt-access" }),
  m("exos-radius-server", "EXOS · RADIUS server", "^configure\\s+radius\\s+mgmt-access\\s+(?:primary|secondary)\\s+server\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})", "auth.remote_auth_servers", "list", { captureGroup: 1, sampleLine: "configure radius mgmt-access primary server 10.10.50.31 1812 client-ip 10.30.99.12 vr VR-Default" }),
  m("exos-account", "EXOS · Local account", "^create\\s+account\\s+(?:admin|user)\\s+\"([^\"]+)\"", "auth.local_users", "list", { captureGroup: 1, sampleLine: "create account admin \"netops\" encrypted \"...\"" }),
  m("exos-syslog", "EXOS · Syslog server", "^configure\\s+syslog\\s+add\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})", "logging.remote_hosts", "list", { captureGroup: 1, sampleLine: "configure syslog add 10.10.50.20:514 vr VR-Default local7" }),
  m("exos-syslog-on", "EXOS · Syslog enabled", "^(enable|disable)\\s+syslog$", "logging.enabled", "polarity", { sampleLine: "enable syslog" }),
  m("exos-logbuffer", "EXOS · Memory log buffer", "^configure\\s+log\\s+target\\s+memory-buffer", "logging.buffered", "flag", { sampleLine: "configure log target memory-buffer severity Debug-Data" }),
  m("exos-loglevel", "EXOS · Syslog severity", "^configure\\s+log\\s+target\\s+syslog\\s+.*severity\\s+(\\S+)$", "logging.level", "capture", { captureGroup: 1, transform: "string", sampleLine: "configure log target syslog 10.10.50.20:514 vr VR-Default local7 severity Info" }),
  m("exos-console", "EXOS · Console log severity", "^configure\\s+log\\s+target\\s+console\\s+severity\\s+(critical|error|emergency|alert)$", "logging.console_restricted", "flag", { sampleLine: "configure log target console severity Critical" }),
  m("exos-sntp", "EXOS · SNTP server", "^configure\\s+sntp-client\\s+(?:primary|secondary)\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})", "time.ntp_servers", "list", { captureGroup: 1, sampleLine: "configure sntp-client primary 10.10.50.10 vr VR-Default" }),
  m("exos-sntp-auth", "EXOS · SNTP without authentication", "^enable\\s+sntp-client$", "time.ntp_authentication", "const", { constValue: false, sampleLine: "enable sntp-client" }),
  m("exos-tz", "EXOS · Timezone", "^configure\\s+timezone\\s+name\\s+", "time.timezone_set", "flag", { sampleLine: "configure timezone name IST 330 autodst off" }),
  m("exos-community", "EXOS · SNMP community", "^configure\\s+snmp\\s+add\\s+community\\s+(?:readonly|readwrite)\\s+(\\S+)$", "snmp.v1v2c_communities", "list", { captureGroup: 1, sampleLine: "configure snmp add community readonly public" }),
  m("exos-community-default", "EXOS · Default community", "^configure\\s+snmp\\s+add\\s+community\\s+(?:readonly|readwrite)\\s+(public|private)$", "snmp.default_communities", "list", { captureGroup: 1, sampleLine: "configure snmp add community readonly public" }),
  m("exos-community-rw", "EXOS · Read-write community", "^configure\\s+snmp\\s+add\\s+community\\s+readwrite\\s+(\\S+)$", "snmp.rw_communities", "list", { captureGroup: 1, sampleLine: "configure snmp add community readwrite private" }),
  m("exos-snmp-on", "EXOS · SNMP v1/v2c access", "^(enable|disable)\\s+snmp\\s+access\\s+snmp-v1v2c$", "snmp.enabled", "polarity", { sampleLine: "enable snmp access snmp-v1v2c" }),
  m("exos-snmpv3", "EXOS · SNMPv3 access", "^(enable|disable)\\s+snmp\\s+access\\s+snmpv3$", "snmp.v3_enabled", "polarity", { sampleLine: "enable snmp access snmpv3" }),
  m("exos-snmpv3-priv", "EXOS · SNMPv3 privacy", "^configure\\s+snmpv3\\s+add\\s+user\\s+.*privacy\\s+(aes|des)", "snmp.v3_priv", "flag", { sampleLine: "configure snmpv3 add user \"secops\" authentication sha \"...\" privacy aes \"...\"" }),
  m("exos-trap", "EXOS · SNMP trap receiver", "^configure\\s+snmpv3\\s+add\\s+target-addr\\s+.*ipaddress\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})", "snmp.trap_hosts", "list", { captureGroup: 1, sampleLine: "configure snmpv3 add target-addr \"siem\" param \"v3params\" ipaddress 10.10.50.40 transport-port 162" }),
  m("exos-ciphers", "EXOS · SSH ciphers", "^configure\\s+ssh2\\s+ciphers\\s+(.+)$", "crypto.strong_crypto", "flag", { sampleLine: "configure ssh2 ciphers aes256-ctr aes128-ctr" }),
  m("exos-lldp", "EXOS · LLDP", "^(enable|disable)\\s+lldp\\s+ports", "services.lldp_enabled", "polarity", { sampleLine: "enable lldp ports all" }),
  m("exos-hostname", "EXOS · sysName", "^configure\\s+snmp\\s+sysName\\s+\"?([^\"]+)\"?$", "identity.hostname_set", "flag", { sampleLine: "configure snmp sysName \"ACCESS-EX-12\"" }),
  m("exos-acl", "EXOS · Access list", "^create\\s+access-list\\s+(\\S+)", "acl.count", "count", { sampleLine: "create access-list mgmt-in \"source-address 10.10.0.0/24;\" \"permit;\"" }),
  m("exos-acl-ingress", "EXOS · Ingress ACL binding", "^configure\\s+access-list\\s+\\S+\\s+vlan\\s+\\S+\\s+ingress$", "acl.external_ingress_filter", "flag", { sampleLine: "configure access-list mgmt-in vlan Mgmt ingress" }),
  m("exos-mgmt-acl", "EXOS · Management ACL", "^configure\\s+access-list\\s+mgmt\\S*\\s+vlan\\s+Mgmt\\s+ingress$", "management.mgmt_acl_applied", "flag", { sampleLine: "configure access-list mgmt-in vlan Mgmt ingress" }),
];
