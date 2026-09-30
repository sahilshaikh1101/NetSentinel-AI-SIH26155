import { describe, expect, it } from "vitest";
import { detectVendor } from "./detect";
import { parseConfig } from "./parsers";
import { panosXmlToSet } from "./parsers/panos";
import { evaluateDevice } from "./rules/evaluate";
import { RULES } from "./rules/library";
import { DEFAULT_REMEDIATION_SETTINGS, renderRemediation } from "./rules/remediation";
import type { ParamValue, SecurityBaselineModel } from "./types";

const settings = DEFAULT_REMEDIATION_SETTINGS;
const frameworks = ["cis", "nist", "stig", "iso"] as const;

/** Parse a set-format (or XML) snippet as PAN-OS. */
function parse(raw: string) {
  const { result } = parseConfig(raw, "paloalto-panos");
  return result;
}
function params(raw: string): Record<string, ParamValue | undefined> {
  const p = parse(raw).model.params;
  return Object.fromEntries(Object.entries(p).map(([k, v]) => [k, v.value]));
}
function source(raw: string, key: string): string | undefined {
  return parse(raw).model.params[key]?.source;
}
function statuses(raw: string): Record<string, string> {
  const result = parse(raw);
  const findings = evaluateDevice("d", result.model, "paloalto-panos", RULES, { frameworks: [...frameworks], settings });
  return Object.fromEntries(findings.map((f) => [f.ruleId, f.status]));
}
function remediationFor(ruleId: string, model: SecurityBaselineModel): string {
  const rule = RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error(`unknown rule ${ruleId}`);
  return renderRemediation(rule, "paloalto-panos", model, settings);
}

// ───────────────────────── SSH service profiles (NS-CRY-001) ─────────────────────────

describe("PAN-OS SSH management profiles", () => {
  const strong = `set deviceconfig system ssh profiles mgmt-profiles server-profiles FIPS-SSH ciphers [ aes256-gcm aes256-ctr ]
set deviceconfig system ssh profiles mgmt-profiles server-profiles FIPS-SSH kex [ ecdh-sha2-nistp384 ecdh-sha2-nistp256 ]
set deviceconfig system ssh profiles mgmt-profiles server-profiles FIPS-SSH mac [ hmac-sha2-256 hmac-sha2-512 ]
set deviceconfig system ssh mgmt server-profile FIPS-SSH`;

  it("accepts the real 10.x/11.x server-profile syntax and can reach strong_crypto = true", () => {
    expect(params(strong)["crypto.strong_crypto"]).toBe(true);
    expect(source(strong, "crypto.strong_crypto")).toBe("parser");
    expect(statuses(strong)["NS-CRY-001"]).toBe("pass");
  });

  it("flags a bound profile that still offers CBC/SHA-1", () => {
    const weak = `set deviceconfig system ssh profiles mgmt-profiles server-profiles LEGACY ciphers [ aes256-cbc aes128-cbc ]
set deviceconfig system ssh profiles mgmt-profiles server-profiles LEGACY mac [ hmac-sha1 ]
set deviceconfig system ssh mgmt server-profile LEGACY`;
    expect(params(weak)["crypto.strong_crypto"]).toBe(false);
    expect(statuses(weak)["NS-CRY-001"]).toBe("fail");
  });

  it("ignores a strong profile that is never bound", () => {
    const unbound = strong.split("\n").slice(0, 3).join("\n");
    expect(params(unbound)["crypto.strong_crypto"]).toBe(false);
    expect(source(unbound, "crypto.strong_crypto")).toBe("default");
  });

  it("understands the PAN-OS 9.x 'ssh <algo> mgmt' form", () => {
    const nine = `set deviceconfig system ssh ciphers mgmt [ aes256-ctr aes256-gcm ]
set deviceconfig system ssh mac mgmt [ hmac-sha2-256 ]`;
    expect(params(nine)["crypto.strong_crypto"]).toBe(true);
    const nineWeak = "set deviceconfig system ssh ciphers mgmt [ aes128-cbc 3des-cbc ]";
    expect(params(nineWeak)["crypto.strong_crypto"]).toBe(false);
  });

  it("renders the profile path, the binding and the service restart", () => {
    const text = remediationFor("NS-CRY-001", parse(strong).model);
    expect(text).toContain("set deviceconfig system ssh profiles mgmt-profiles server-profiles STRONG ciphers");
    expect(text).toContain("set deviceconfig system ssh mgmt server-profile STRONG");
    expect(text).toContain("set ssh service-restart mgmt");
    expect(text).not.toContain("ssh mgmt-profile STRONG\n");
  });
});

// ───────────────────────── interzone-default (NS-ACL-003) ─────────────────────────

describe("PAN-OS default security rules", () => {
  it("detects 'interzone-default action allow'", () => {
    const raw = "set rulebase default-security-rules rules interzone-default action allow";
    expect(params(raw)["acl.default_deny"]).toBe(false);
    expect(source(raw, "acl.default_deny")).toBe("parser");
    expect(statuses(raw)["NS-ACL-003"]).toBe("fail");
  });

  it("keeps the deny/drop/reset actions passing", () => {
    for (const action of ["deny", "drop", "reset-both"]) {
      const raw = `set rulebase default-security-rules rules interzone-default action ${action}`;
      expect(params(raw)["acl.default_deny"]).toBe(true);
      expect(statuses(raw)["NS-ACL-003"]).toBe("pass");
    }
  });

  it("ignores intrazone-default allow (the platform default)", () => {
    const raw = `set rulebase default-security-rules rules intrazone-default action allow
set rulebase default-security-rules rules interzone-default action deny`;
    expect(params(raw)["acl.default_deny"]).toBe(true);
  });

  it("sees an allow in any vsys of a multi-vsys device", () => {
    const raw = `set vsys vsys1 rulebase default-security-rules rules interzone-default action deny
set vsys vsys2 rulebase default-security-rules rules interzone-default action allow`;
    expect(params(raw)["acl.default_deny"]).toBe(false);
    expect(statuses(raw)["NS-ACL-003"]).toBe("fail");
  });
});

// ───────────────────────── XML exports (panosXmlToSet) ─────────────────────────

describe("PAN-OS XML conversion", () => {
  const xml = `<?xml version="1.0"?><response status="success"><result><config version="11.1.4" detail-version="11.1.4-h1" urldb="paloaltonetworks"><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>PA-XML-01</hostname><login-banner>Authorised users only.
All activity &amp; sessions are logged.</login-banner><service><disable-telnet>no</disable-telnet></service><permitted-ip><entry name="10.10.0.0/24"/></permitted-ip></system></deviceconfig><vsys><entry name="vsys1"><rulebase><security><rules><entry name="Branch to HQ"><action>allow</action><application><member>ssl</member><member>web-browsing</member></application></entry></rules></security></rulebase></entry></vsys></entry></devices></config></result></response>`;

  it("drops the API wrapper, the device entry and the vsys1 prefix", () => {
    const set = panosXmlToSet(xml);
    expect(set).toContain("set deviceconfig system hostname PA-XML-01");
    expect(set).toContain("set deviceconfig system service disable-telnet no");
    expect(set).toContain("set deviceconfig system permitted-ip 10.10.0.0/24");
    expect(set).toContain('set rulebase security rules "Branch to HQ" action allow');
    expect(set).not.toContain("response");
    expect(set).not.toContain("localhost.localdomain");
    expect(set).not.toMatch(/\bentry\b/);
  });

  it("collapses <member> lists, unescapes entities and folds multi-line text", () => {
    const set = panosXmlToSet(xml);
    expect(set).toContain('application [ ssl web-browsing ]');
    expect(set).toContain('set deviceconfig system login-banner "Authorised users only. All activity & sessions are logged."');
    expect(set.split("\n").every((l) => l.startsWith("set "))).toBe(true);
  });

  it("parses the converted export with full recognition and keeps the identity", () => {
    const result = parse(xml);
    expect(result.unrecognized).toEqual([]);
    expect(result.recognized).toBe(result.meaningfulLines);
    expect(result.identity.hostname).toBe("PA-XML-01");
    expect(result.identity.osVersion).toBe("11.1.4-h1");
  });

  it("evaluates the XML device from its own configuration, not from defaults", () => {
    const s = statuses(xml);
    expect(params(xml)["management.telnet_enabled"]).toBe(true);
    expect(s["NS-MGMT-001"]).toBe("fail");
    expect(params(xml)["management.login_banner"]).toBe(true);
    expect(params(xml)["management.mgmt_acl_applied"]).toBe(true);
  });

  it("falls back to the config version attribute when detail-version is absent", () => {
    const plain = '<config version="10.2.9" urldb="paloaltonetworks"><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>PA-B</hostname></system></deviceconfig></entry></devices></config>';
    expect(parse(plain).identity.osVersion).toBe("10.2.9");
  });
});

// ───────────────────────── IKE/IPsec crypto profiles (NS-CRY-002) ─────────────────────────

describe("PAN-OS IKE crypto profiles", () => {
  const factory = `set network ike crypto-profiles ike-crypto-profiles default encryption [ aes-128-cbc 3des ]
set network ike crypto-profiles ike-crypto-profiles default hash [ sha1 ]
set network ike crypto-profiles ike-crypto-profiles default dh-group [ group2 ]
set network ike crypto-profiles ipsec-crypto-profiles default esp encryption [ aes-128-cbc 3des ]
set network ike crypto-profiles ipsec-crypto-profiles default esp authentication [ sha1 ]
set network ike crypto-profiles global-protect-app-crypto-profiles default encryption [ aes-128-cbc ]`;

  it("does not fail a device that only carries the factory profiles", () => {
    expect(params(factory)["crypto.weak_ike"]).toBe(false);
    expect(statuses(factory)["NS-CRY-002"]).toBe("pass");
  });

  it("flags a factory profile once a gateway references it", () => {
    const used = `${factory}
set network ike gateway HQ-GW protocol ikev2 ike-crypto-profile default`;
    expect(params(used)["crypto.weak_ike"]).toBe(true);
    expect(params(used)["crypto.weak_ike_profiles"]).toEqual(["default"]);
    expect(statuses(used)["NS-CRY-002"]).toBe("fail");
  });

  it("flags user-defined weak profiles and keeps strong ones clean", () => {
    const mixed = `${factory}
set network ike crypto-profiles ike-crypto-profiles HQ-IKE encryption [ aes-256-cbc ]
set network ike crypto-profiles ike-crypto-profiles HQ-IKE hash [ sha256 ]
set network ike crypto-profiles ike-crypto-profiles HQ-IKE dh-group [ group14 ]
set network ike crypto-profiles ike-crypto-profiles LEGACY-IKE encryption [ 3des ]
set network ike crypto-profiles ipsec-crypto-profiles LEGACY-IPSEC esp authentication [ md5 ]`;
    const p = params(mixed);
    expect(p["crypto.weak_ike"]).toBe(true);
    expect(p["crypto.weak_ike_profiles"]).toEqual(["LEGACY-IKE"]);
    expect(p["crypto.weak_ipsec_profiles"]).toEqual(["LEGACY-IPSEC"]);
  });

  it("rewrites the flagged profiles in place instead of creating an unused STRONG profile", () => {
    const mixed = `set network ike crypto-profiles ike-crypto-profiles LEGACY-IKE encryption [ 3des ]
set network ike crypto-profiles ipsec-crypto-profiles LEGACY-IPSEC esp authentication [ md5 ]`;
    const text = remediationFor("NS-CRY-002", parse(mixed).model);
    expect(text).toContain("set network ike crypto-profiles ike-crypto-profiles LEGACY-IKE encryption [ aes-256-cbc ]");
    expect(text).toContain("set network ike crypto-profiles ipsec-crypto-profiles LEGACY-IPSEC esp encryption [ aes-256-gcm ]");
    expect(text).not.toContain("ike-crypto-profiles STRONG");
  });
});

// ───────────────────────── interface management profiles ─────────────────────────

describe("PAN-OS interface management profiles", () => {
  const unbound = `set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set network profiles interface-management-profile ALLOW-ALL-LAB telnet yes
set network profiles interface-management-profile ALLOW-ALL-LAB http yes
set network profiles interface-management-profile MGMT-STRICT https yes
set network profiles interface-management-profile MGMT-STRICT ssh yes
set network interface ethernet ethernet1/1 layer3 interface-management-profile MGMT-STRICT`;

  it("does not enable telnet/http from a profile that is bound to no interface", () => {
    const p = params(unbound);
    expect(p["management.telnet_enabled"]).toBe(false);
    expect(p["management.http_enabled"]).toBe(false);
    expect(p["management.telnet_profiles"]).toBeUndefined();
    const s = statuses(unbound);
    expect(s["NS-MGMT-001"]).toBe("pass");
    expect(s["NS-MGMT-003"]).toBe("pass");
  });

  it("enables telnet when a bound profile permits it, whatever the line order", () => {
    const bound = `set network profiles interface-management-profile ALLOW-ALL-LAB telnet yes
set network interface aggregate-ethernet ae1 layer3 units ae1.200 interface-management-profile ALLOW-ALL-LAB
set deviceconfig system service disable-telnet yes`;
    const p = params(bound);
    expect(p["management.telnet_enabled"]).toBe(true);
    expect(p["management.telnet_profiles"]).toEqual(["ALLOW-ALL-LAB"]);
    expect(statuses(bound)["NS-MGMT-001"]).toBe("fail");
    const text = remediationFor("NS-MGMT-001", parse(bound).model);
    expect(text).toContain("set network profiles interface-management-profile ALLOW-ALL-LAB telnet no");
    expect(text).not.toContain("*");
  });
});

// ───────────────────────── administrator AAA (NS-AUTH-004/005/008) ─────────────────────────

describe("PAN-OS administrator AAA", () => {
  const gpOnly = `set mgt-config users admin permissions role-based superuser yes
set mgt-config users admin phash $1$abcdefgh$0123456789abcdefghij0
set shared server-profile ldap AD-1 server DC1 address 10.20.0.10
set shared authentication-profile GP-USERS method ldap server-profile AD-1
set shared authentication-profile GP-USERS lockout failed-attempts 3`;

  it("does not count a GlobalProtect/Captive-Portal profile as administrator AAA", () => {
    const p = params(gpOnly);
    expect(p["auth.aaa_enabled"]).toBe(false);
    expect(p["auth.aaa_authentication_login"]).toBe(false);
    expect(p["auth.remote_auth_servers"]).toEqual([]);
    const s = statuses(gpOnly);
    expect(s["NS-AUTH-004"]).toBe("fail");
    expect(s["NS-AUTH-005"]).toBe("fail");
  });

  it("does not borrow the lockout of an unbound profile", () => {
    const p = params(gpOnly);
    expect(p["auth.max_login_attempts"]).toBeUndefined();
    expect(p["auth.login_lockout"]).toBe(false);
    expect(source(gpOnly, "auth.login_lockout")).toBe("default");
    expect(statuses(gpOnly)["NS-AUTH-008"]).toBe("fail");
  });

  it("accepts a profile bound to an administrator or through Authentication Settings", () => {
    const bound = `${gpOnly}
set shared authentication-profile ADMIN-TAC method tacplus server-profile ISE
set shared server-profile tacplus ISE server S1 address 10.10.50.30
set mgt-config users admin authentication-profile ADMIN-TAC`;
    const p = params(bound);
    expect(p["auth.aaa_enabled"]).toBe(true);
    expect(p["auth.aaa_authentication_login"]).toBe(true);
    expect(p["auth.remote_auth_servers"]).toEqual(["10.10.50.30"]);
    const global = `${gpOnly}
set shared authentication-profile ADMIN-TAC method tacplus server-profile ISE
set deviceconfig setting management authentication-profile ADMIN-TAC`;
    expect(params(global)["auth.aaa_enabled"]).toBe(true);
  });

  it("prefers admin-lockout over any authentication-profile lockout", () => {
    const raw = `set deviceconfig setting management admin-lockout failed-attempts 3
set shared authentication-profile GP-USERS lockout failed-attempts 9
set mgt-config users admin authentication-profile GP-USERS`;
    expect(params(raw)["auth.max_login_attempts"]).toBe(3);
    expect(statuses(raw)["NS-AUTH-008"]).toBe("pass");
  });

  it("builds a usable TACACS+ remediation with an allow-list", () => {
    const text = remediationFor("NS-AUTH-004", parse(gpOnly).model);
    expect(text).toContain("set shared authentication-profile TACACS allow-list all");
    expect(text).toContain("set shared server-profile tacplus ISE protocol CHAP");
    expect(text).not.toContain("set mgt-config users admin authentication-profile TACACS");
    expect(text).toMatch(/break-glass/i);
  });
});

// ───────────────────────── multi-vsys and Advanced Routing ─────────────────────────

describe("PAN-OS multi-vsys and Advanced Routing", () => {
  it("counts rules that live under a vsys", () => {
    const raw = `set vsys vsys1 rulebase security rules "Branch to HQ" action allow
set vsys vsys1 rulebase security rules "Branch to HQ" log-end yes
set vsys vsys1 rulebase security rules "Block IoT egress" action drop
set vsys vsys1 rulebase security rules "Block IoT egress" log-end yes`;
    const p = params(raw);
    expect(p["acl.count"]).toBe(2);
    expect(p["acl.explicit_deny_logged"]).toBe(true);
  });

  it("reads BGP peers under a logical-router (PAN-OS 10.2+ Advanced Routing)", () => {
    const raw = `set network logical-router LR-1 vrf default bgp enable yes
set network logical-router LR-1 vrf default bgp peer-group ISP peer ISP-A peer-address ip 203.0.113.2`;
    const p = params(raw);
    expect(p["routing.bgp_configured"]).toBe(true);
    expect(p["routing.bgp_auth"]).toBe(false);
    expect(p["routing.bgp_unauth_neighbors"]).toEqual(["LR-1/ISP/ISP-A"]);
    expect(statuses(raw)["NS-RTG-001"]).toBe("fail");
    const text = remediationFor("NS-RTG-001", parse(raw).model);
    expect(text).toContain("set network logical-router LR-1 vrf default bgp peer-group ISP peer ISP-A connection-options authentication BGP-AUTH");
  });

  it("accepts an authenticated peer configured on its own line", () => {
    const raw = `set network virtual-router default protocol bgp enable yes
set network virtual-router default protocol bgp peer-group ISP peer ISP-A peer-address ip 203.0.113.2
set network virtual-router default protocol bgp peer-group ISP peer ISP-A connection-options authentication BGP-AUTH`;
    expect(params(raw)["routing.bgp_auth"]).toBe(true);
    expect(statuses(raw)["NS-RTG-001"]).toBe("pass");
  });

  it("treats an OSPF auth-profile that is never applied as unauthenticated", () => {
    const raw = `set network virtual-router default protocol ospf enable yes
set network virtual-router default protocol ospf auth-profile OSPF-AUTH md5 1 key -AQ==secret
set network virtual-router default protocol ospf area 0.0.0.0 interface ethernet1/2 enable yes`;
    const p = params(raw);
    expect(p["routing.ospf_auth"]).toBe(false);
    expect(p["routing.ospf_areas"]).toEqual(["0.0.0.0"]);
    expect(statuses(raw)["NS-RTG-002"]).toBe("fail");
    const text = remediationFor("NS-RTG-002", parse(raw).model);
    expect(text).toContain("set network virtual-router default protocol ospf area 0.0.0.0 interface ethernet1/2 authentication OSPF-AUTH");
    expect(text).not.toContain("interface ethernet1/2 auth-profile");
  });

  it("passes once the area interface applies the profile", () => {
    const raw = `set network virtual-router default protocol ospf enable yes
set network virtual-router default protocol ospf area 0.0.0.0 interface ethernet1/2 authentication OSPF-AUTH`;
    expect(params(raw)["routing.ospf_auth"]).toBe(true);
    expect(statuses(raw)["NS-RTG-002"]).toBe("pass");
  });
});

// ───────────────────────── SNMP ─────────────────────────

describe("PAN-OS SNMP", () => {
  const disabled = `set deviceconfig system service disable-snmp yes
set deviceconfig system snmp-setting access-setting version v2c snmp-community-string public
set deviceconfig system snmp-setting snmp-system location "Lab"`;

  it("keeps the agent disabled when the service is off and no profile exposes it", () => {
    const p = params(disabled);
    expect(p["snmp.enabled"]).toBe(false);
    expect(p["snmp.v1v2c_communities"]).toEqual(["public"]);
    const s = statuses(disabled);
    expect(s["NS-SNMP-003"]).toBe("pass");
    expect(s["NS-SNMP-005"]).toBe("pass");
  });

  it("enables the agent from the service or from a bound profile", () => {
    expect(params("set deviceconfig system service disable-snmp no")["snmp.enabled"]).toBe(true);
    const viaProfile = `set network profiles interface-management-profile MP snmp yes
set network interface ethernet ethernet1/1 layer3 interface-management-profile MP`;
    expect(params(viaProfile)["snmp.enabled"]).toBe(true);
  });

  it("derives the community ACL from permitted-ip instead of hard-coding false", () => {
    const restricted = `set deviceconfig system service disable-snmp no
set deviceconfig system permitted-ip 10.10.0.0/24
set deviceconfig system snmp-setting access-setting version v2c snmp-community-string corp-ro`;
    expect(params(restricted)["snmp.community_acl"]).toBe(true);
    expect(statuses(restricted)["NS-SNMP-004"]).toBe("pass");
    const open = restricted.replace("10.10.0.0/24", "0.0.0.0/0");
    expect(params(open)["snmp.community_acl"]).toBe(false);
    expect(statuses(open)["NS-SNMP-004"]).toBe("fail");
  });

  it("reads v2c trap communities and only claims v3 privacy for a real v3 user", () => {
    const traps = `set shared log-settings snmptrap NMS version v2c server NMS-1 manager 10.10.50.40
set shared log-settings snmptrap NMS version v2c server NMS-1 community private`;
    const p = params(traps);
    expect(p["snmp.default_communities"]).toEqual(["private"]);
    expect(p["snmp.trap_hosts"]).toEqual(["10.10.50.40"]);
    const views = "set deviceconfig system snmp-setting access-setting version v3 views VIEW-ALL view all oid 1.3.6.1 option include";
    expect(params(views)["snmp.v3_enabled"]).toBe(true);
    expect(params(views)["snmp.v3_priv"]).toBeUndefined();
    const user = `${views}
set deviceconfig system snmp-setting access-setting version v3 users secops view VIEW-ALL authpwd -AQ==a privpwd -AQ==b`;
    expect(params(user)["snmp.v3_priv"]).toBe(true);
  });
});

// ───────────────────────── management ACL (NS-MGMT-006) ─────────────────────────

describe("PAN-OS management ACL", () => {
  it("rejects permitted-ip 0.0.0.0/0 and ::/0", () => {
    const raw = `set deviceconfig system permitted-ip 0.0.0.0/0
set deviceconfig system permitted-ip ::/0`;
    expect(params(raw)["management.mgmt_acl_applied"]).toBe(false);
    expect(statuses(raw)["NS-MGMT-006"]).toBe("fail");
  });

  it("accepts a real prefix and requires every exposed endpoint to be restricted", () => {
    const ok = "set deviceconfig system permitted-ip 10.10.0.0/24";
    expect(params(ok)["management.mgmt_acl_applied"]).toBe(true);
    expect(statuses(ok)["NS-MGMT-006"]).toBe("pass");
    const dataplaneOpen = `${ok}
set network profiles interface-management-profile MP https yes
set network interface ethernet ethernet1/1 layer3 interface-management-profile MP`;
    expect(params(dataplaneOpen)["management.mgmt_acl_applied"]).toBe(false);
  });
});

// ───────────────────────── rules and quoted names ─────────────────────────

describe("PAN-OS quoted object names", () => {
  it("counts quoted rule names once each", () => {
    const raw = `set rulebase security rules "Branch to HQ" action allow
set rulebase security rules "Branch to Internet" action allow
set rulebase security rules "Block IoT egress" action drop`;
    expect(params(raw)["acl.count"]).toBe(3);
  });

  it("derives the logged deny from separate action/log-end lines", () => {
    const raw = `set rulebase security rules "Block IoT egress" from any to any
set rulebase security rules "Block IoT egress" action drop
set rulebase security rules "Block IoT egress" log-end yes`;
    expect(params(raw)["acl.explicit_deny_logged"]).toBe(true);
    expect(statuses(raw)["NS-ACL-002"]).toBe("pass");
  });

  it("keeps an unlogged deny failing", () => {
    const raw = `set rulebase security rules "Block IoT egress" action deny
set rulebase security rules "Allow web" action allow
set rulebase security rules "Allow web" log-end yes`;
    expect(params(raw)["acl.explicit_deny_logged"]).toBe(false);
  });

  it("reads quoted syslog, match-list and server-profile names", () => {
    const raw = `set shared log-settings syslog "Branch Syslog" server "Collector 1" server 10.10.50.20
set shared log-settings syslog "Branch Syslog" server "Collector 1" transport UDP
set shared log-settings system match-list "Critical only" filter "All Logs"
set shared log-settings system match-list "Critical only" send-syslog "Branch Syslog"
set shared server-profile tacplus "ISE Prod" server "ISE 1" address 10.10.50.30
set shared authentication-profile "Admin TAC" method tacplus server-profile "ISE Prod"
set mgt-config users netops authentication-profile "Admin TAC"`;
    const p = params(raw);
    expect(p["logging.remote_hosts"]).toEqual(["10.10.50.20"]);
    expect(p["logging.remote_secure"]).toBe(false);
    expect(p["logging.login_events"]).toBe(true);
    expect(p["auth.remote_auth_servers"]).toEqual(["10.10.50.30"]);
  });

  it("does not treat a severity-filtered match-list as login logging", () => {
    const raw = `set shared log-settings system match-list ONLY-CRIT filter "(severity eq critical)" send-syslog SIEM`;
    expect(params(raw)["logging.login_events"]).toBe(false);
  });
});

// ───────────────────────── TLS profile binding (NS-CRY-003) ─────────────────────────

describe("PAN-OS SSL/TLS service profiles", () => {
  it("uses the profile bound to the management interface, not the last one defined", () => {
    const raw = `set shared ssl-tls-service-profile MGMT-TLS12 protocol-settings min-version tls1-2
set deviceconfig system ssl-tls-service-profile MGMT-TLS12
set shared ssl-tls-service-profile GP-PORTAL-COMPAT protocol-settings min-version tls1-0`;
    const p = params(raw);
    expect(p["crypto.tls_min_version"]).toBe("1.2");
    expect(p["crypto.tls_profiles"]).toEqual(["MGMT-TLS12"]);
    expect(statuses(raw)["NS-CRY-003"]).toBe("pass");
  });

  it("reports TLS 1.0 as the platform default when nothing is bound", () => {
    const raw = "set shared ssl-tls-service-profile GP-PORTAL-TLS protocol-settings min-version tls1-0";
    expect(params(raw)["crypto.tls_min_version"]).toBe("1.0");
    expect(source(raw, "crypto.tls_min_version")).toBe("default");
  });

  it("remediates the bound profile in place", () => {
    const raw = `set shared ssl-tls-service-profile MGMT-TLS protocol-settings min-version tls1-1
set deviceconfig system ssl-tls-service-profile MGMT-TLS`;
    const text = remediationFor("NS-CRY-003", parse(raw).model);
    expect(text).toContain("set shared ssl-tls-service-profile MGMT-TLS protocol-settings min-version tls1-2");
    const text2 = remediationFor("NS-CRY-003", parse("set deviceconfig system hostname PA-1").model);
    expect(text2).toContain("set shared ssl-tls-service-profile MGMT-TLS certificate");
  });
});

// ───────────────────────── platform defaults ─────────────────────────

describe("PAN-OS platform defaults", () => {
  it("assumes source routing is not dropped without a zone protection profile", () => {
    const raw = "set zone DMZ network layer3 ethernet1/1";
    expect(params(raw)["services.ip_source_routing"]).toBe(true);
    expect(statuses(raw)["NS-SVC-002"]).toBe("fail");
    expect(remediationFor("NS-SVC-002", parse(raw).model)).toContain("discard-strict-source-routing yes");
  });

  it("clears source routing when every layer 3 zone discards it", () => {
    const raw = `set network profiles zone-protection-profile ZPP-EDGE discard-strict-source-routing yes
set network profiles zone-protection-profile ZPP-EDGE discard-loose-source-routing yes
set zone DMZ network layer3 ethernet1/1
set zone DMZ network zone-protection-profile ZPP-EDGE`;
    expect(params(raw)["services.ip_source_routing"]).toBe(false);
    expect(statuses(raw)["NS-SVC-002"]).toBe("pass");
  });

  it("treats max-session-count 0 as unlimited", () => {
    expect(params("set deviceconfig setting management admin-session max-session-count 0")["management.concurrent_sessions_limited"]).toBe(false);
    expect(params("set deviceconfig setting management admin-session max-session-count 4")["management.concurrent_sessions_limited"]).toBe(true);
  });
});

// ───────────────────────── NTP and syslog across all servers ─────────────────────────

describe("PAN-OS whole-file resolution", () => {
  it("requires every NTP server to be authenticated", () => {
    const mixed = `set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.10.50.10
set deviceconfig system ntp-servers primary-ntp-server authentication-type none
set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address 10.10.50.11
set deviceconfig system ntp-servers secondary-ntp-server authentication-type symmetric-key`;
    const p = params(mixed);
    expect(p["time.ntp_authentication"]).toBe(false);
    expect(p["time.unauthenticated_ntp_ids"]).toEqual(["primary-ntp-server"]);
    expect(statuses(mixed)["NS-TIME-002"]).toBe("fail");
    const text = remediationFor("NS-TIME-002", parse(mixed).model);
    expect(text).toContain("set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key");
    expect(text).not.toContain("secondary-ntp-server authentication-type symmetric-key");
  });

  it("passes only when both servers are authenticated", () => {
    const both = `set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key
set deviceconfig system ntp-servers secondary-ntp-server authentication-type autokey`;
    expect(params(both)["time.ntp_authentication"]).toBe(true);
  });

  it("requires every syslog target to use SSL, whatever the order", () => {
    const raw = `set shared log-settings syslog LEGACY-UDP server COLLECTOR-2 server 10.10.50.21
set shared log-settings syslog LEGACY-UDP server COLLECTOR-2 transport UDP
set shared log-settings syslog SIEM-TLS server S1 server 10.10.50.20
set shared log-settings syslog SIEM-TLS server S1 transport SSL`;
    const p = params(raw);
    expect(p["logging.remote_secure"]).toBe(false);
    expect(p["logging.insecure_syslog_targets"]).toEqual(["LEGACY-UDP server COLLECTOR-2"]);
    const text = remediationFor("NS-LOG-008", parse(raw).model);
    expect(text).toContain("set shared log-settings syslog LEGACY-UDP server COLLECTOR-2 transport SSL");
    expect(text).not.toContain("syslog SIEM server S1 transport SSL");
  });

  it("is order-independent for syslog transports", () => {
    const reversed = `set shared log-settings syslog SIEM-TLS server S1 transport SSL
set shared log-settings syslog LEGACY-UDP server COLLECTOR-2 transport UDP`;
    expect(params(reversed)["logging.remote_secure"]).toBe(false);
  });
});

// ───────────────────────── terminal pastes ─────────────────────────

describe("PAN-OS terminal pastes", () => {
  const paste = `admin@BR-PA-3220-01(active)> show system info

hostname: BR-PA-3220-01
ip-address: 192.168.99.5
family: 3200
model: PA-3220
sw-version: 10.1.9
cloud-mode: non-cloud
app-release-date: 2026/09/01 12:00:00 IST
url-db: paloaltonetworks
multi-vsys: off
advanced-routing: off
operational-mode: normal
device-certificate-status: Valid

admin@BR-PA-3220-01(active)> configure
Entering configuration mode
[edit]
admin@BR-PA-3220-01(active)# show
set deviceconfig system hostname BR-PA-3220-01
[edit]`;

  it("recognises prompts, headers and configuration-mode markers", () => {
    const result = parse(paste);
    expect(result.unrecognized).toEqual([]);
    expect(result.identity.hostname).toBe("BR-PA-3220-01");
    expect(result.identity.model).toBe("PA-3220");
    expect(result.identity.osVersion).toBe("10.1.9");
    expect(result.identity.mgmtIp).toBe("192.168.99.5");
  });

  it("turns operational-mode into the FIPS observation", () => {
    expect(params(paste)["crypto.fips_mode"]).toBe(false);
    expect(params(paste.replace("operational-mode: normal", "operational-mode: fips-cc"))["crypto.fips_mode"]).toBe(true);
    expect(statuses(paste.replace("operational-mode: normal", "operational-mode: fips-cc"))["NS-CRY-005"]).toBe("pass");
  });

  it("uses '#' rather than '!' in the FIPS remediation", () => {
    const text = remediationFor("NS-CRY-005", parse(paste).model);
    expect(text.startsWith("#")).toBe(true);
    expect(text).not.toContain("!");
  });
});

// ───────────────────────── password complexity path ─────────────────────────

describe("PAN-OS password complexity", () => {
  it("parses the mgt-config path and remediates with it", () => {
    const raw = `set mgt-config password-complexity enabled yes
set mgt-config password-complexity minimum-length 15`;
    const p = params(raw);
    expect(p["auth.password_complexity"]).toBe(true);
    expect(p["auth.min_password_length"]).toBe(15);
    for (const id of ["NS-AUTH-007", "NS-AUTH-007S", "NS-AUTH-010"]) {
      const text = remediationFor(id, parse("set deviceconfig system hostname PA-1").model);
      expect(text).toContain("set mgt-config password-complexity");
      expect(text).not.toContain("deviceconfig setting management min-password-complexity");
    }
  });
});

// ───────────────────────── vendor detection ─────────────────────────

describe("PAN-OS detection", () => {
  it("detects an XML API fragment without the config header", () => {
    const frag = '<response status="success"><result><system><hostname>PA-X</hostname><service><disable-telnet>no</disable-telnet></service></system><deviceconfig/></result></response>';
    expect(detectVendor(frag).vendor).toBe("paloalto-panos");
  });

  it("detects a Panorama export and marks the role as manager", () => {
    const pano = `set template BRANCH config deviceconfig system hostname BRANCH-FW
set device-group DG-BRANCH pre-rulebase security rules "Allow web" action allow`;
    expect(detectVendor(pano).vendor).toBe("paloalto-panos");
    expect(parse(pano).identity.role).toBe("manager");
  });
});
