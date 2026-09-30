import type { ParamValue, VendorId } from "./types";

/**
 * The Security Baseline Model (SBM) catalogue.
 * Every parser, mapping and rule speaks this vocabulary. Keywords feed the
 * pattern-recognition classifier used by the Training Studio.
 */
export type ParamType = "boolean" | "number" | "string" | "list";

export interface ParamDef {
  key: string;
  label: string;
  category: string;
  type: ParamType;
  description: string;
  /** lower-case keywords/synonyms used for NLP classification */
  keywords: string[];
}

export const SBM_CATEGORIES = [
  "Management Plane",
  "Authentication & AAA",
  "Logging & Audit",
  "Time Synchronization",
  "SNMP",
  "Unnecessary Services",
  "Routing Security",
  "Access Control",
  "Cryptography",
  "Device Identity",
] as const;

const P = (
  key: string,
  label: string,
  category: string,
  type: ParamType,
  description: string,
  keywords: string[],
): ParamDef => ({ key, label, category, type, description, keywords });

export const SBM_PARAMS: ParamDef[] = [
  // Management plane
  P("management.ssh_enabled", "SSH management enabled", "Management Plane", "boolean", "Encrypted remote administration (SSH/stelnet) is available.", ["ssh", "stelnet", "secure shell", "sshd", "ssh2", "ssh server"]),
  P("management.ssh_version", "SSH protocol version", "Management Plane", "number", "Only SSH protocol version 2 must be accepted.", ["ssh version", "protocol-version", "ssh v2", "sshv2", "ssh2", "compatible-ssh1x", "ssh-v1", "version"]),
  P("management.telnet_enabled", "Telnet enabled", "Management Plane", "boolean", "Cleartext Telnet management must be disabled.", ["telnet", "transport input telnet", "allowaccess telnet", "disable-telnet", "telnet server"]),
  P("management.http_enabled", "HTTP management enabled", "Management Plane", "boolean", "Plain HTTP web management must be disabled.", ["http server", "ip http", "web http", "disable-http", "www", "http-commands", "web-management http", "http"]),
  P("management.https_enabled", "HTTPS management enabled", "Management Plane", "boolean", "Web management, if used, must be HTTPS only.", ["https", "secure-server", "www-ssl", "web https", "web-management https", "admin-sport", "ip http secure-server", "http secure-server", "https-server"]),
  P("management.idle_timeout_minutes", "Session idle timeout (minutes)", "Management Plane", "number", "Idle administrative sessions must terminate within 10 minutes.", ["exec-timeout", "idle-timeout", "idletimeout", "admintimeout", "idle timeout", "session timeout", "inactivity", "timeout"]),
  P("management.console_timeout_minutes", "Console idle timeout (minutes)", "Management Plane", "number", "Console sessions must time out.", ["console", "exec-timeout", "con 0", "console idle-timeout"]),
  P("management.ssh_timeout_seconds", "SSH negotiation timeout (s)", "Management Plane", "number", "SSH negotiation phase must time out quickly.", ["ssh time-out", "ssh timeout", "login-timeout"]),
  P("management.ssh_auth_retries", "SSH authentication retries", "Management Plane", "number", "SSH authentication retries must be limited (3 or fewer).", ["authentication-retries", "ssh retries", "max-auth-tries", "retries"]),
  P("management.mgmt_acl_applied", "Management ACL applied", "Management Plane", "boolean", "Administrative access must be restricted to trusted sources.", ["access-class", "permitted-ip", "trusthost", "acl inbound", "winbox address", "allowed-address", "management acl", "mgmt acl", "vty acl", "clients"]),
  P("management.login_banner", "Login banner configured", "Management Plane", "boolean", "A legal notice banner must be displayed before login.", ["banner", "motd", "login-banner", "pre-login-banner", "header login", "message", "before-login", "notice"]),
  P("management.aux_disabled", "AUX port disabled", "Management Plane", "boolean", "Unused auxiliary ports must be disabled.", ["aux", "no exec", "line aux", "auxiliary"]),
  P("management.api_http_enabled", "API over plain HTTP", "Management Plane", "boolean", "Management APIs must not be exposed over plain HTTP.", ["api", "http-commands", "rest", "api-ssl", "eapi", "xml-api", "xnm-clear-text"]),
  P("management.ftp_enabled", "FTP/TFTP service enabled", "Management Plane", "boolean", "Cleartext file transfer services must be disabled.", ["ftp", "tftp", "tftp-server", "ftp server"]),
  P("management.concurrent_sessions_limited", "Concurrent sessions limited", "Management Plane", "boolean", "The number of concurrent management sessions must be limited.", ["connection-limit", "session-limit", "admin-concurrent", "max sessions", "concurrent", "max-sessions", "cli max-sessions", "max-sessions-per-connection"]),

  // Authentication & AAA
  P("auth.password_encryption", "Password encryption service", "Authentication & AAA", "boolean", "Stored passwords must not appear in cleartext.", ["password-encryption", "service password", "irreversible-cipher", "encrypted-password", "encrypt", "cipher"]),
  P("auth.enable_secret", "Privileged (enable/root) secret", "Authentication & AAA", "boolean", "Privileged access must be protected with a hashed secret.", ["enable secret", "enable password", "root-authentication", "super password", "enable"]),
  P("auth.weak_password_hashes", "Weak/reversible credentials", "Authentication & AAA", "number", "Number of credentials stored with reversible or weak hashing (type 7/MD5/cleartext).", ["password 7", "type 7", "md5", "cleartext", "plain", "password"]),
  P("auth.aaa_enabled", "AAA model enabled", "Authentication & AAA", "boolean", "Centralised authentication, authorization and accounting must be enabled.", ["aaa new-model", "aaa", "authentication-mode aaa", "aaa enable", "use-radius", "enable radius", "enable tacacs", "enable radius mgmt-access", "aaa mgmt-access"]),
  P("auth.aaa_authentication_login", "AAA login authentication", "Authentication & AAA", "boolean", "Login must be authenticated through AAA method lists.", ["aaa authentication login", "authentication login", "login authentication", "authentication default", "authentication-order", "authentication-profile", "enable radius mgmt-access", "radius mgmt-access authentication"]),
  P("auth.aaa_accounting", "AAA command/exec accounting", "Authentication & AAA", "boolean", "Administrative commands must be accounted for.", ["aaa accounting", "accounting", "command accounting"]),
  P("auth.remote_auth_servers", "Remote AAA servers", "Authentication & AAA", "list", "TACACS+/RADIUS/LDAP servers configured for centralised auth.", ["tacacs", "radius", "tacacs-server", "radius-server", "ldap", "aaa server", "tacplus", "radius server", "tacacs server", "radius shared-secret"]),
  P("auth.local_users", "Local user accounts", "Authentication & AAA", "list", "Local accounts present on the device.", ["username", "local-user", "user add", "admin", "user", "account"]),
  P("auth.min_password_length", "Minimum password length", "Authentication & AAA", "number", "Passwords must be at least 12 (STIG: 15) characters.", ["min-length", "minimum-length", "passwords min-length", "password minimum", "min length", "min-password-length", "password-attributes min-length", "password-policy min-length", "length"]),
  P("auth.password_complexity", "Password complexity enforced", "Authentication & AAA", "boolean", "Password complexity/policy must be enforced.", ["password-policy", "complexity", "min-lower-case", "min-upper-case", "min-number", "min-non-alphanumeric", "strong password", "minimum-categories", "char-validation", "password-policy char-validation"]),
  P("auth.login_lockout", "Login attempt lockout", "Authentication & AAA", "boolean", "Accounts must lock after consecutive failed logins.", ["login block-for", "lockout", "tries-before-disconnect", "admin-lockout", "failed-attempts", "retry-options", "login attempts", "block-for", "lockout-on-login-failures", "login-failures", "lockout-time-period", "lockout-time", "failed-login"]),
  P("auth.max_login_attempts", "Max failed login attempts", "Authentication & AAA", "number", "No more than 3 consecutive failed attempts.", ["attempts", "tries", "lockout-threshold", "failed-attempts"]),
  P("auth.root_login_ssh", "Root/superuser SSH login", "Authentication & AAA", "boolean", "Direct root login over SSH must be denied.", ["root-login", "permit root", "root login", "root"]),
  P("auth.two_factor", "Two-factor authentication", "Authentication & AAA", "boolean", "Administrator accounts should use MFA.", ["two-factor", "mfa", "fortitoken", "otp", "2fa", "multi-factor"]),

  // Logging & audit
  P("logging.enabled", "Logging enabled", "Logging & Audit", "boolean", "System logging must be enabled.", ["logging", "syslog", "info-center", "log", "logging enable", "syslogd"]),
  P("logging.remote_hosts", "Remote syslog hosts", "Logging & Audit", "list", "Logs must be shipped to a central collector.", ["logging host", "syslog host", "loghost", "syslogd server", "log target syslog", "remote", "logging server", "syslog server", "collector", "syslog add", "log-remote-address", "syslog default server"]),
  P("logging.remote_secure", "Encrypted log transport", "Logging & Audit", "boolean", "Remote logging should use TLS.", ["reliable", "tls", "ssl", "transport tcp", "secure syslog", "6514"]),
  P("logging.buffered", "Local log buffer", "Logging & Audit", "boolean", "A local log buffer/file must exist.", ["logging buffered", "buffer", "file messages", "log memory", "log disk", "buffered", "memory-lines", "memory-buffer", "log target memory-buffer"]),
  P("logging.timestamps", "Log timestamps", "Logging & Audit", "boolean", "Log entries must carry date/time stamps.", ["timestamps", "datetime", "msec", "timestamp", "time-stamp", "time-format"]),
  P("logging.level", "Remote logging level", "Logging & Audit", "string", "Trap level should be informational or more verbose.", ["trap", "severity", "level", "informational", "notice", "debug", "warning"]),
  P("logging.source_interface", "Logging source interface", "Logging & Audit", "boolean", "Log messages should originate from a fixed loopback address.", ["source-interface", "source-address", "logging source", "src-address", "source-ip"]),
  P("logging.login_events", "Login success/failure logged", "Logging & Audit", "boolean", "Successful and failed logins must be logged.", ["on-failure", "on-success", "login logging", "log config", "archive", "login events", "audit", "authorization", "interactive-commands"]),
  P("logging.console_restricted", "Console logging restricted", "Logging & Audit", "boolean", "Console logging should be limited to critical.", ["logging console", "console critical", "console", "log target console", "console severity", "logging monitor"]),

  // Time
  P("time.ntp_servers", "NTP servers", "Time Synchronization", "list", "At least two authoritative time sources.", ["ntp server", "ntp-service", "sntp", "ntpserver", "ntp client", "ntp", "time server", "clock server", "sntp-client"]),
  P("time.ntp_authentication", "NTP authentication", "Time Synchronization", "boolean", "Time sources must be cryptographically authenticated.", ["ntp authenticate", "authentication-key", "trusted-key", "ntp key", "authentication-keyid", "ntp auth", "symmetric-key"]),
  P("time.timezone_set", "Timezone configured", "Time Synchronization", "boolean", "A timezone must be configured for accurate correlation.", ["clock timezone", "time-zone", "timezone", "tz"]),

  // SNMP
  P("snmp.enabled", "SNMP agent enabled", "SNMP", "boolean", "SNMP is running.", ["snmp", "snmp-server", "snmp-agent", "snmp enabled", "disable-snmp", "snmp-v1v2c", "snmp access snmp-v1v2c", "snmp-agent enable"]),
  P("snmp.v1v2c_communities", "SNMPv1/v2c communities", "SNMP", "list", "Community strings in use (cleartext protocol versions).", ["community", "snmp-server community", "community read", "trap-community", "snmp-community-string", "add community"]),
  P("snmp.default_communities", "Default community strings", "SNMP", "list", "'public' / 'private' communities must not exist.", ["public", "private", "default community"]),
  P("snmp.rw_communities", "Read-write communities", "SNMP", "list", "No read-write communities on v1/v2c.", ["rw", "read-write", "write", "readwrite"]),
  P("snmp.community_acl", "SNMP community ACL", "SNMP", "boolean", "Communities must be restricted by ACL.", ["snmp acl", "community acl", "hosts", "snmp access-list", "addresses"]),
  P("snmp.v3_enabled", "SNMPv3 configured", "SNMP", "boolean", "SNMPv3 users/groups exist.", ["v3", "snmpv3", "usm-user", "snmp user", "snmp-server group", "snmp v3", "snmp access snmpv3", "snmpv3 add user", "snmpv3 add group"]),
  P("snmp.v3_priv", "SNMPv3 privacy (authPriv)", "SNMP", "boolean", "SNMPv3 must use authentication and privacy.", ["priv", "auth-priv", "privacy", "aes", "priv-proto", "security-level"]),
  P("snmp.trap_hosts", "SNMP trap receivers", "SNMP", "list", "Traps/informs sent to managers.", ["snmp-server host", "trap", "traps", "trap-target", "informs", "trapreceiver", "target-addr", "target-address", "trap-host", "notification", "add target-addr"]),

  // Unnecessary services
  P("services.cdp_enabled", "CDP enabled globally", "Unnecessary Services", "boolean", "Discovery protocols leak topology; disable where not required.", ["cdp run", "cdp enable", "cdp"]),
  P("services.lldp_enabled", "LLDP enabled globally", "Unnecessary Services", "boolean", "LLDP should be disabled on untrusted interfaces.", ["lldp run", "lldp enable", "lldp", "neighbor discovery", "discovery", "edp"]),
  P("services.ip_source_routing", "IP source routing", "Unnecessary Services", "boolean", "Source routing must be disabled.", ["source-route", "source routing", "source-routing"]),
  P("services.proxy_arp", "Proxy ARP", "Unnecessary Services", "boolean", "Proxy ARP should be disabled.", ["proxy-arp", "proxy arp"]),
  P("services.directed_broadcast", "Directed broadcast", "Unnecessary Services", "boolean", "Directed broadcasts must be disabled (Smurf).", ["directed-broadcast", "directed broadcast"]),
  P("services.icmp_redirects", "ICMP redirects", "Unnecessary Services", "boolean", "ICMP redirects should be disabled on external interfaces.", ["ip redirects", "redirects", "icmp redirect"]),
  P("services.bootp_server", "BOOTP server", "Unnecessary Services", "boolean", "BOOTP must be disabled.", ["bootp"]),
  P("services.dhcp_server", "DHCP service", "Unnecessary Services", "boolean", "DHCP service should be disabled when not required.", ["service dhcp", "dhcp server", "dhcp"]),
  P("services.pad", "PAD service", "Unnecessary Services", "boolean", "X.25 PAD must be disabled.", ["pad", "service pad"]),
  P("services.finger", "Finger service", "Unnecessary Services", "boolean", "Finger must be disabled.", ["finger"]),
  P("services.identd", "identd service", "Unnecessary Services", "boolean", "identd must be disabled.", ["identd", "ident"]),
  P("services.tcp_keepalives", "TCP keepalives", "Unnecessary Services", "boolean", "TCP keepalives clean up orphaned sessions.", ["tcp-keepalives", "keepalive", "keepalives"]),
  P("services.small_servers", "TCP/UDP small servers", "Unnecessary Services", "boolean", "Small servers (echo/chargen) must be disabled.", ["small-servers", "small servers", "echo", "chargen"]),
  P("services.unicast_rpf", "Unicast RPF", "Unnecessary Services", "boolean", "uRPF blocks spoofed sources on edge interfaces.", ["verify unicast", "reachable-via", "rpf", "urpf", "unicast reverse", "rp-filter"]),
  P("services.misc_enabled", "Other exposed services", "Unnecessary Services", "list", "Miscellaneous exposed services (upnp, socks, proxy, mac-server, bandwidth-test ...).", ["upnp", "socks", "proxy", "mac-server", "bandwidth-server", "bandwidth-test", "romon", "allow-remote-requests", "service"]),

  // Routing
  P("routing.bgp_configured", "BGP configured", "Routing Security", "boolean", "BGP process present.", ["router bgp", "bgp", "protocols bgp"]),
  P("routing.bgp_auth", "BGP neighbor authentication", "Routing Security", "boolean", "BGP sessions must use MD5/TCP-AO authentication.", ["neighbor password", "bgp password", "authentication-key", "bgp auth", "peer password", "tcp-ao", "tcp-md5-key"]),
  P("routing.ospf_configured", "OSPF configured", "Routing Security", "boolean", "OSPF process present.", ["router ospf", "ospf", "protocols ospf"]),
  P("routing.ospf_auth", "OSPF authentication", "Routing Security", "boolean", "OSPF must use message-digest/SHA authentication.", ["ospf authentication", "message-digest", "ospf md5", "authentication message-digest", "ospf key", "authentication-mode"]),
  P("routing.eigrp_configured", "EIGRP configured", "Routing Security", "boolean", "EIGRP process present.", ["router eigrp", "eigrp"]),
  P("routing.eigrp_auth", "EIGRP authentication", "Routing Security", "boolean", "EIGRP must use authentication.", ["eigrp authentication", "authentication mode md5", "authentication key-chain"]),

  // Access control
  P("acl.count", "Access lists / policies defined", "Access Control", "number", "Number of ACLs / firewall policies.", ["create access-list", "ip access-list", "access-list extended", "acl", "rulebase", "firewall filter", "policy", "firewall policy", "ip filter", "access list"]),
  P("acl.external_ingress_filter", "Ingress filter on interface", "Access Control", "boolean", "External/management interfaces must have an inbound filter.", ["access-group in", "filter input", "ip access-group", "acl inbound", "in filter", "chain=input", "ingress", "traffic-filter inbound", "vlan ingress", "access-list ingress", "apply access-list", "service-policy input"]),
  P("acl.explicit_deny_logged", "Explicit deny with logging", "Access Control", "boolean", "ACLs should end with an explicit logged deny.", ["deny log", "deny any log", "deny ip any any log", "log deny", "drop log", "implicit-log"]),
  P("acl.default_deny", "Default-deny policy", "Access Control", "boolean", "Firewall rulebases must end with a default deny.", ["deny all", "default deny", "implicit deny", "action=drop", "deny any", "default-policy", "interzone-default"]),

  // Cryptography
  P("crypto.rsa_modulus", "SSH RSA key modulus", "Cryptography", "number", "Host keys must be at least 2048 bits.", ["modulus", "key generate rsa", "key size", "rsa", "bits", "host-key-size", "key-length"]),
  P("crypto.tls_min_version", "Minimum TLS version", "Cryptography", "string", "TLS 1.2 or later for management.", ["tls", "ssl version", "tlsv1", "tls-min", "ssl-min-proto", "min-version", "tls1", "ssl-versions"]),
  P("crypto.fips_mode", "FIPS mode", "Cryptography", "boolean", "FIPS-validated cryptography (STIG).", ["fips", "fips-cc", "fips mode"]),
  P("crypto.strong_crypto", "Strong crypto / weak ciphers disabled", "Cryptography", "boolean", "Weak SSH/TLS ciphers (CBC, MD5, SHA1 KEX, 3DES) disabled.", ["strong-crypto", "cipher", "algorithm encryption", "kex", "hmac", "ctr", "gcm", "cbc", "3des", "weak", "ciphers", "macs", "key-exchange", "ssh2 ciphers", "ssh2 macs", "ssh ciphers", "server algorithm", "algorithm mac"]),
  P("crypto.weak_ike", "Weak IKE/IPsec parameters", "Cryptography", "boolean", "IKE must not use DES/3DES/MD5/DH group 1-2.", ["isakmp", "ike", "des", "md5", "group 1", "group 2", "ipsec", "transform-set", "dh-group", "dhgrp", "proposal"]),

  // Device identity
  P("identity.hostname_set", "Hostname configured", "Device Identity", "boolean", "A unique hostname must be set.", ["hostname", "host-name", "sysname", "identity", "system name", "snmp sysname", "snmp name"]),
  P("identity.hostname", "Hostname", "Device Identity", "string", "The configured hostname.", ["hostname", "host-name", "sysname"]),
  P("management.mgmt_vrf", "Management VRF", "Management Plane", "string", "VRF that carries management traffic (affects ACL/logging syntax).", ["vrf forwarding", "management vrf", "mgmt-vrf", "vrf context management", "use-vrf"]),
  P("management.vty_max", "Highest VTY line", "Management Plane", "number", "Highest configured VTY line number (for remediation ranges).", ["line vty"]),
  P("auth.weak_local_users", "Users with weak credentials", "Authentication & AAA", "list", "Local users stored with reversible or cleartext passwords.", ["password 7", "password 0"]),
  P("logging.config_changes", "Configuration change logging", "Logging & Audit", "boolean", "Configuration changes are logged (archive log config / audit).", ["archive", "log config", "logging enable", "config-change", "audit"]),
  P("routing.bgp_asn", "BGP AS number", "Routing Security", "string", "Local BGP autonomous system.", ["router bgp", "bgp", "as-number"]),
  P("routing.eigrp_as", "EIGRP AS / instance", "Routing Security", "string", "EIGRP autonomous system or named instance.", ["router eigrp"]),
  P("routing.eigrp_named", "EIGRP named mode", "Routing Security", "boolean", "EIGRP runs in named (address-family) mode.", ["router eigrp", "address-family"]),
  P("routing.bgp_unauth_neighbors", "Unauthenticated BGP neighbors", "Routing Security", "list", "BGP neighbors without a password/TCP-AO.", ["neighbor", "peer"]),
  P("services.dhcp_in_use", "DHCP server/relay in use", "Unnecessary Services", "boolean", "The device serves DHCP pools or relays requests (remediation must keep the service).", ["ip dhcp pool", "ip helper-address", "dhcp relay", "dhcp server"]),
  P("identity.domain_set", "Domain name configured", "Device Identity", "boolean", "Domain name is required for SSH key generation.", ["domain-name", "domain name", "ip domain", "domain"]),
  P("identity.loopback_present", "Loopback interface present", "Device Identity", "boolean", "A loopback provides a stable management source address.", ["loopback", "lo0", "interface loopback"]),
  P("identity.tunnels", "Tunnel interfaces", "Device Identity", "number", "Tunnel interfaces should be reviewed/absent.", ["interface tunnel", "tunnel", "gre"]),
  P("management.telnet_zones", "Security zones permitting Telnet", "Management Plane", "list", "Junos security zones whose host-inbound-traffic permits Telnet (drives zone-specific remediation).", []),
  P("management.login_classes", "Login classes", "Management Plane", "list", "Custom login classes defined on the device (Junos sets the idle timeout per class).", []),
  P("management.telnet_interfaces", "Interfaces exposing Telnet", "Management Plane", "list", "Interfaces whose management access list permits Telnet (drives per-interface remediation).", []),
  P("management.telnet_interfaces6", "Interfaces exposing Telnet over IPv6", "Management Plane", "list", "Interfaces whose IPv6 management access list permits Telnet.", []),
  P("management.http_interfaces", "Interfaces exposing plain HTTP", "Management Plane", "list", "Interfaces whose management access list permits plain HTTP.", []),
  P("management.http_interfaces6", "Interfaces exposing plain HTTP over IPv6", "Management Plane", "list", "Interfaces whose IPv6 management access list permits plain HTTP.", []),
  P("management.unrestricted_admins", "Administrators without trusted hosts", "Management Plane", "list", "Local administrator accounts that can log in from any source address.", []),
  P("management.unrestricted_api_users", "API users without trusted hosts", "Management Plane", "list", "REST API accounts that can be used from any source address.", []),
  P("routing.bgp_unauth_groups", "Unauthenticated BGP neighbor groups", "Routing Security", "list", "BGP neighbor groups without a password.", []),
  P("routing.ospf_areas", "OSPF areas", "Routing Security", "list", "OSPF areas configured on the device (drives area-level authentication remediation).", []),
  P("routing.ospf_interfaces", "OSPF interfaces", "Routing Security", "list", "Interfaces running OSPF (drives interface-level authentication remediation).", []),
  P("time.unauthenticated_ntp_ids", "Unauthenticated NTP server entries", "Time Synchronization", "list", "NTP server entries configured without authentication.", []),
  P("snmp.default_community_ids", "Default SNMP community entries", "SNMP", "list", "Identifiers of community entries carrying a default or trivial string (drives per-entry deletes).", []),
  P("identity.fortios_7plus", "FortiOS 7.0 or newer", "Device Identity", "boolean", "Software generation flag used to pick the right remediation syntax.", []),
  P("identity.fortios_74plus", "FortiOS 7.4 or newer", "Device Identity", "boolean", "Software generation flag used to pick the right remediation syntax.", []),
  P("management.telnet_profiles", "Management profiles permitting Telnet", "Management Plane", "list", "Interface management profiles bound to an interface that permit Telnet (drives per-profile remediation).", []),
  P("management.http_profiles", "Management profiles permitting plain HTTP", "Management Plane", "list", "Interface management profiles bound to an interface that permit plain HTTP.", []),
  P("crypto.weak_ike_profiles", "Weak IKE crypto profiles", "Cryptography", "list", "IKE crypto profiles offering DES/3DES, MD5/SHA-1 or DH group 1/2/5 (drives per-profile remediation).", []),
  P("crypto.weak_ipsec_profiles", "Weak IPsec crypto profiles", "Cryptography", "list", "IPsec/ESP crypto profiles offering DES/3DES or MD5/SHA-1.", []),
  P("crypto.tls_profiles", "Bound SSL/TLS service profiles", "Cryptography", "list", "SSL/TLS service profiles bound to a management service (drives in-place TLS remediation).", []),
  P("logging.insecure_syslog_targets", "Syslog targets without TLS", "Logging & Audit", "list", "Syslog profile/server pairs whose transport is not encrypted.", []),
  P("routing.bgp_auth_targets", "BGP peers to authenticate", "Routing Security", "list", "Configuration paths of BGP peers without authentication (drives per-peer remediation).", []),
  P("routing.ospf_auth_targets", "OSPF interfaces to authenticate", "Routing Security", "list", "Configuration paths of OSPF area interfaces without authentication.", []),
  P("identity.vrp_r19plus", "VRP V200R019 or newer", "Device Identity", "boolean", "Huawei software generation flag: V200R019+ (and VRP8) accept syslog-over-TLS, GCM SSH ciphers and SHA-2 SNMP/NTP authentication.", []),
  P("identity.routeros_7plus", "RouterOS 7.0 or newer", "Device Identity", "boolean", "MikroTik software generation flag: RouterOS 7 replaced /routing bgp peer with /routing bgp connection and /routing ospf interface with interface-template, and added SHA-2 SNMP authentication.", []),
];

export const SBM_INDEX: Record<string, ParamDef> = Object.fromEntries(SBM_PARAMS.map((p) => [p.key, p]));

export function paramLabel(key: string): string {
  return SBM_INDEX[key]?.label ?? key;
}

export function paramType(key: string): ParamType {
  return SBM_INDEX[key]?.type ?? "string";
}

export function formatValue(v: ParamValue | undefined): string {
  if (v === undefined || v === null) return "not observed";
  if (Array.isArray(v)) return v.length ? v.join(", ") : "none";
  if (typeof v === "boolean") return v ? "enabled" : "disabled";
  return String(v);
}

export interface VendorMeta {
  name: string;
  os: string;
  short: string;
  color: string;
  /** default device role guess */
  role: string;
  /** comment prefix used by the CLI */
  comment: string;
}

export const VENDOR_META: Record<VendorId, VendorMeta> = {
  "cisco-ios": { name: "Cisco", os: "IOS / IOS-XE", short: "Cisco IOS", color: "#2E9BD6", role: "router", comment: "!" },
  "cisco-nxos": { name: "Cisco", os: "NX-OS", short: "Cisco NX-OS", color: "#1F7FB0", role: "switch", comment: "!" },
  "arista-eos": { name: "Arista", os: "EOS", short: "Arista EOS", color: "#F08A3E", role: "switch", comment: "!" },
  "juniper-junos": { name: "Juniper", os: "Junos", short: "Junos", color: "#8BBF4A", role: "firewall", comment: "#" },
  "fortinet-fortios": { name: "Fortinet", os: "FortiOS", short: "FortiOS", color: "#E8483F", role: "firewall", comment: "#" },
  "paloalto-panos": { name: "Palo Alto", os: "PAN-OS", short: "PAN-OS", color: "#F26A3D", role: "firewall", comment: "#" },
  "mikrotik-routeros": { name: "MikroTik", os: "RouterOS", short: "RouterOS", color: "#7A8CA3", role: "router", comment: "#" },
  "huawei-vrp": { name: "Huawei", os: "VRP", short: "Huawei VRP", color: "#D9455F", role: "switch", comment: "#" },
  generic: { name: "Unknown vendor", os: "Generic CLI", short: "Generic", color: "#8A96AB", role: "device", comment: "#" },
};

export const VENDOR_IDS = Object.keys(VENDOR_META) as VendorId[];

/** Short labels for dense chart axes; full names stay in SBM_CATEGORIES. */
export const CATEGORY_SHORT: Record<string, string> = {
  "Management Plane": "Mgmt",
  "Authentication & AAA": "AAA",
  "Logging & Audit": "Logging",
  "Time Synchronization": "Time",
  SNMP: "SNMP",
  "Unnecessary Services": "Services",
  "Routing Security": "Routing",
  "Access Control": "ACL",
  Cryptography: "Crypto",
  "Device Identity": "Identity",
};

/** Remediation template fallback: a vendor without its own template borrows its family's. */
export const VENDOR_FAMILY: Record<VendorId, VendorId> = {
  "cisco-ios": "cisco-ios",
  "cisco-nxos": "cisco-ios",
  "arista-eos": "arista-eos",
  "juniper-junos": "juniper-junos",
  "fortinet-fortios": "fortinet-fortios",
  "paloalto-panos": "paloalto-panos",
  "mikrotik-routeros": "mikrotik-routeros",
  "huawei-vrp": "huawei-vrp",
  generic: "generic",
};
