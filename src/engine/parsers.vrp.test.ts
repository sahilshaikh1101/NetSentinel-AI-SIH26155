import { describe, expect, it } from "vitest";
import { detectVendor } from "./detect";
import { parseConfig } from "./parsers";
import { evaluateDevice } from "./rules/evaluate";
import { RULES } from "./rules/library";
import { DEFAULT_REMEDIATION_SETTINGS, renderRemediation } from "./rules/remediation";
import { SAMPLE_VRP } from "./samples/vrp";
import type { Finding, ParamValue } from "./types";

const settings = DEFAULT_REMEDIATION_SETTINGS;
/** Every snippet is wrapped in the `#` separators a real `display current-configuration` emits. */
const parse = (raw: string) => parseConfig(raw, "huawei-vrp").result;
const val = (raw: string, key: string): ParamValue | undefined => parse(raw).model.params[key]?.value;
const source = (raw: string, key: string) => parse(raw).model.params[key]?.source;
const ratio = (raw: string) => {
  const r = parse(raw);
  return r.meaningfulLines === 0 ? 1 : r.recognized / r.meaningfulLines;
};
const findings = (raw: string): Record<string, Finding> => {
  const r = parse(raw);
  return Object.fromEntries(
    evaluateDevice("d", r.model, "huawei-vrp", RULES, {
      frameworks: ["cis", "nist", "stig", "iso"],
      settings,
      recognitionRatio: r.meaningfulLines === 0 ? 1 : r.recognized / r.meaningfulLines,
      context: { osVersion: r.identity.osVersion },
    }).map((f) => [f.ruleId, f]),
  );
};
const remediation = (raw: string, ruleId: string) => {
  const r = parse(raw);
  return renderRemediation(RULES.find((x) => x.id === ruleId)!, "huawei-vrp", r.model, settings, { osVersion: r.identity.osVersion });
};

const V21 = "!Software Version V200R021C00SPC600\n#\nsysname DC1\n#\n";
const V10 = "!Software Version V200R010C00SPC600\n#\nsysname SW1\n#\n";

describe("VRP SSH algorithm lists", () => {
  const hardened = `${V21}ssh server cipher aes256_gcm aes128_gcm aes256_ctr aes128_ctr
#
ssh server hmac sha2_256 sha2_512
#
ssh server key-exchange dh_group_exchange_sha256 ecdh_sha2_nistp384
#
`;
  it("reports strong crypto when every algorithm list is modern", () => {
    // Regression: the guard used to read back the platform default `false`, so a hardened
    // device could never clear NS-CRY-001.
    expect(val(hardened, "crypto.strong_crypto")).toBe(true);
    expect(source(hardened, "crypto.strong_crypto")).toBe("parser");
    expect(findings(hardened)["NS-CRY-001"].status).toBe("pass");
  });

  it("one weak list spoils the set whatever its position", () => {
    expect(val(`${hardened}ssh server hmac sha1 sha1_96\n#\n`, "crypto.strong_crypto")).toBe(false);
    expect(val(`${V21}ssh server cipher 3des_cbc aes256_ctr\n#\nssh server hmac sha2_256\n#\n`, "crypto.strong_crypto")).toBe(false);
  });

  it("treats a short DH exchange as weak crypto, not as an SSH host-key size", () => {
    const weakDh = `${V21}ssh server dh-exchange min-len 1024\n#\n`;
    expect(val(weakDh, "crypto.strong_crypto")).toBe(false);
    // `dh-exchange min-len` says nothing about the RSA host key: claiming otherwise passed NS-CRY-004 for free.
    expect(val(`${V21}ssh server dh-exchange min-len 3072\n#\n`, "crypto.rsa_modulus")).toBeUndefined();
    expect(findings(`${V21}ssh server dh-exchange min-len 3072\n#\n`)["NS-CRY-004"].status).toBe("warning");
  });
});

describe("VRP local credentials", () => {
  const cleartext = `${V10}aaa
 local-user admin password irreversible-cipher $1a$Kq2wE4rT6yU8iO0pA2sD$
 local-user admin privilege level 15
 local-user backup password simple Huawei@2019
 local-user backup service-type ftp
 local-user vendor password cipher %^%#Ss7Tt9Uu1Vv3Ww5Xx7Yy9Zz1Aa3Bb5Cc7Dd9%^%#
#
`;
  it("a cleartext `password simple` user disproves password encryption", () => {
    expect(val(cleartext, "auth.password_encryption")).toBe(false);
    expect(findings(cleartext)["NS-AUTH-001"].status).toBe("fail");
  });

  it("counts reversible and cleartext users and names them for remediation", () => {
    expect(val(cleartext, "auth.weak_password_hashes")).toBe(2);
    expect(val(cleartext, "auth.weak_local_users")).toEqual(["backup", "vendor"]);
    expect(val(cleartext, "auth.local_users")).toEqual(["admin", "backup", "vendor"]);
    expect(remediation(cleartext, "NS-AUTH-003")).toContain("local-user backup password irreversible-cipher <new-password>");
    expect(remediation(cleartext, "NS-AUTH-003")).toContain("local-user vendor password irreversible-cipher <new-password>");
  });

  it("keeps password encryption true when every user is hashed", () => {
    const hashed = `${V21}aaa\n local-user netadmin password irreversible-cipher $1c$P0Sk9aN$X7q$\n#\n`;
    expect(val(hashed, "auth.password_encryption")).toBe(true);
  });

  it("reads the lockout policy from `local-aaa-user wrong-password`", () => {
    // Regression: the matcher was anchored at `^wrong-password`, so NS-AUTH-008 was never assessed.
    const locked = `${V21}aaa\n local-aaa-user wrong-password retry-interval 5 retry-time 3 block-time 15\n#\n`;
    expect(val(locked, "auth.login_lockout")).toBe(true);
    expect(val(locked, "auth.max_login_attempts")).toBe(3);
    expect(findings(locked)["NS-AUTH-008"].status).toBe("pass");
    expect(val(`${V21}aaa\n local-aaa-user wrong-password retry-interval 5 retry-time 8 block-time 5\n#\n`, "auth.max_login_attempts")).toBe(8);
  });

  it("reads the password policy sub-view", () => {
    const policy = `${V21}aaa
 local-aaa-user password policy administrator
  password min-length 12
  password composition type-number 4 type-length 2
  password expire 90
#
`;
    expect(val(policy, "auth.min_password_length")).toBe(12);
    expect(val(policy, "auth.password_complexity")).toBe(true);
  });

  it("records a `super password` and flags its cleartext form", () => {
    expect(val(`${V10}super password level 3 cipher %^%#Ab1cD3eF5%^%#\n#\n`, "auth.enable_secret")).toBe(true);
    expect(val(`${V10}super password level 3 simple Huawei123\n#\n`, "auth.weak_password_hashes")).toBe(1);
  });

  it("an aaa view without a server template means there is no central AAA", () => {
    const localOnly = `${V10}aaa\n authentication-scheme default\n local-user admin password irreversible-cipher $1a$xx$\n#\nuser-interface vty 0 4\n authentication-mode password\n#\n`;
    expect(val(localOnly, "auth.remote_auth_servers")).toEqual([]);
    // Without the empty list this reads "not assessed" instead of "no central AAA".
    expect(findings(localOnly)["NS-AUTH-005"].status).toBe("fail");
    const withTacacs = `${V10}hwtacacs-server template T\n hwtacacs-server authentication 10.1.1.1\n#\naaa\n authentication-scheme default\n#\n`;
    expect(val(withTacacs, "auth.remote_auth_servers")).toEqual(["10.1.1.1"]);
  });
});

describe("VRP telnet reachability", () => {
  it("keeps Telnet enabled when the server is up, whatever a single VTY range allows", () => {
    // `protocol inbound ssh` used to overwrite an explicit `telnet server enable` and hide an open TCP/23.
    const open = `${V10}telnet server enable\n#\nuser-interface vty 0 4\n authentication-mode aaa\n protocol inbound ssh\n#\n`;
    expect(val(open, "management.telnet_enabled")).toBe(true);
    expect(findings(open)["NS-MGMT-001"].status).toBe("fail");
  });

  it("an explicit `undo telnet server enable` wins over a permissive VTY range", () => {
    const closed = `${V21}undo telnet server enable\n#\nuser-interface vty 0 4\n protocol inbound all\n#\n`;
    expect(val(closed, "management.telnet_enabled")).toBe(false);
    expect(findings(closed)["NS-MGMT-001"].status).toBe("pass");
  });

  it("falls back to the VTY protocol list when no telnet server command is present", () => {
    expect(val(`${V10}user-interface vty 0 4\n protocol inbound all\n#\n`, "management.telnet_enabled")).toBe(true);
    expect(val(`${V10}user-interface vty 0 4\n protocol inbound ssh\n#\n`, "management.telnet_enabled")).toBe(false);
  });

  it("does not claim SSH is available without a stelnet server", () => {
    expect(val(`${V10}user-interface vty 0 4\n protocol inbound ssh\n#\n`, "management.ssh_enabled")).toBe(false);
    expect(val(`${V21}stelnet server enable\n#\n`, "management.ssh_enabled")).toBe(true);
  });
});

describe("VRP user-interface ranges", () => {
  it("takes the weakest authentication-mode across every VTY range", () => {
    const mixed = `${V21}user-interface vty 0 4
 authentication-mode aaa
#
user-interface vty 16 20
 authentication-mode password
#
`;
    expect(val(mixed, "auth.aaa_authentication_login")).toBe(false);
    const reversed = `${V21}user-interface vty 0 4\n authentication-mode password\n#\nuser-interface vty 16 20\n authentication-mode aaa\n#\n`;
    expect(val(reversed, "auth.aaa_authentication_login")).toBe(false);
  });

  it("takes the longest idle timeout and the management ACL from any range", () => {
    const mixed = `${V21}user-interface vty 0 4\n acl 2999 inbound\n idle-timeout 5 0\n#\nuser-interface vty 16 20\n idle-timeout 30 0\n#\n`;
    expect(val(mixed, "management.idle_timeout_minutes")).toBe(30);
    expect(val(mixed, "management.mgmt_acl_applied")).toBe(true);
  });

  it("treats an AUX block with `undo shell` as disabled and a bare one as live", () => {
    expect(val(`${V10}user-interface aux 0\n undo shell\n#\n`, "management.aux_disabled")).toBe(true);
    expect(val(`${V10}user-interface aux 0\n authentication-mode password\n#\n`, "management.aux_disabled")).toBe(false);
  });
});

describe("VRP platform defaults", () => {
  const bare = `${V21}user-interface vty 0 4\n authentication-mode aaa\n#\n`;
  it("supplies the documented SSH negotiation defaults instead of leaving them unassessed", () => {
    expect(val(bare, "management.ssh_timeout_seconds")).toBe(60);
    expect(val(bare, "management.ssh_auth_retries")).toBe(3);
    expect(findings(bare)["NS-MGMT-012"].status).toBe("pass");
    expect(findings(bare)["NS-MGMT-013"].status).toBe("pass");
  });

  it("treats an absent AUX user-interface as no AUX port", () => {
    expect(val(bare, "management.aux_disabled")).toBe(true);
    expect(source(bare, "management.aux_disabled")).toBe("default");
    expect(findings(bare)["NS-MGMT-008"].status).toBe("pass");
  });

  it("still lets an explicit command override the default", () => {
    expect(val(`${V21}ssh server timeout 120\n#\n`, "management.ssh_timeout_seconds")).toBe(120);
    expect(val(`${V21}ssh server authentication-retries 5\n#\n`, "management.ssh_auth_retries")).toBe(5);
  });
});

describe("VRP services", () => {
  it("detects directed broadcast forwarding on an interface", () => {
    const fwd = `${V10}interface GigabitEthernet0/0/0\n ip address 203.0.113.2 255.255.255.248\n ip forward-broadcast\n#\n`;
    expect(val(fwd, "services.directed_broadcast")).toBe(true);
    expect(findings(fwd)["NS-SVC-004"].status).toBe("fail");
  });

  it("accepts `undo icmp redirect send` in system view as well as interface view", () => {
    expect(val(`${V21}undo icmp redirect send\n#\n`, "services.icmp_redirects")).toBe(false);
    expect(val(`${V21}interface 100GE1/0/1\n undo icmp redirect send\n#\n`, "services.icmp_redirects")).toBe(false);
  });

  it("maps the legacy web-manager commands to the HTTP/HTTPS parameters", () => {
    const web = `${V10}web-manager enable\n#\n`;
    expect(val(web, "management.http_enabled")).toBe(true);
    expect(findings(web)["NS-MGMT-003"].status).toBe("fail");
    expect(val(`${V10}web-manager security enable\n#\n`, "management.https_enabled")).toBe(true);
  });

  it("only counts `header login` as a pre-login legal banner", () => {
    expect(val(`${V10}header shell information "welcome"\n#\n`, "management.login_banner")).toBe(false);
    expect(val(`${V10}header login information "NOTICE"\n#\n`, "management.login_banner")).toBe(true);
  });
});

describe("VRP logging, SNMP and routing", () => {
  it("records no remote collector when info-center is switched off", () => {
    const off = `${V10}undo info-center enable\n#\n`;
    expect(val(off, "logging.enabled")).toBe(false);
    expect(val(off, "logging.remote_hosts")).toEqual([]);
    expect(findings(off)["NS-LOG-001"].status).toBe("fail");
  });

  it("stores the loghost address, not the `ipv6` keyword", () => {
    expect(val(`${V21}info-center loghost ipv6 2001:DB8::20\n#\n`, "logging.remote_hosts")).toEqual(["2001:DB8::20"]);
    expect(val(`${V21}info-center loghost 10.1.1.1 transport tcp ssl-policy P\n#\n`, "logging.remote_secure")).toBe(true);
  });

  it("flags a default community even when it was typed after the `cipher` keyword", () => {
    const pub = `${V10}snmp-agent\n#\nsnmp-agent community read cipher public\n#\nsnmp-agent community write private\n#\n`;
    expect(val(pub, "snmp.default_communities")).toEqual(["public", "private"]);
    expect(val(pub, "snmp.default_community_ids")).toEqual(["read public", "write private"]);
    expect(remediation(pub, "NS-SNMP-001")).toContain("undo snmp-agent community read public");
    expect(remediation(pub, "NS-SNMP-001")).toContain("undo snmp-agent community write private");
  });

  it("captures the BGP AS number so the remediation is not a placeholder", () => {
    const bgp = `${V21}bgp 65001\n router-id 10.0.0.1\n peer 10.0.0.2 as-number 65002\n#\n`;
    expect(val(bgp, "routing.bgp_asn")).toBe("65001");
    expect(val(bgp, "routing.bgp_auth")).toBe(false);
    expect(remediation(bgp, "NS-RTG-001")).toContain("bgp 65001");
  });

  it("lists OSPF areas and rejects cleartext OSPF authentication", () => {
    const ospf = `${V21}ospf 10 router-id 10.0.0.1\n area 0.0.0.0\n  network 10.0.0.0 0.0.0.255\n area 0.0.0.1\n  network 10.0.1.0 0.0.0.255\n#\n`;
    expect(val(ospf, "routing.ospf_areas")).toEqual(["0.0.0.0", "0.0.0.1"]);
    expect(remediation(ospf, "NS-RTG-002")).toContain("area 0.0.0.1");
    const plain = `${V10}interface Vlanif10\n ospf authentication-mode simple plain Huawei123\n#\nospf 1\n area 0.0.0.0\n#\n`;
    expect(val(plain, "routing.ospf_auth")).toBe(false);
  });
});

describe("VRP real-world export formats", () => {
  const withBanner = `<CAMPUS-SW-03>display version
Huawei Versatile Routing Platform Software
VRP (R) software, Version 5.170 (S5700 V200R010C00SPC600)
Copyright (C) 2000-2016 HUAWEI TECH CO., LTD
Quidway S5700-28C-HI Routing Switch uptime is 51 weeks, 3 days, 4 hours
ESN of slot 0: 210235559610G8000456

MPU version information :
1. PCB      Version  : CX22EMGEA REV C
3. Board    Type     : S5700-28C-HI
<CAMPUS-SW-03>display current-configuration
!Software Version V200R010C00SPC600
#
sysname CAMPUS-SW-03
#
vlan batch 10 20
#
interface MEth0/0/1
 ip address 10.20.250.3 255.255.255.0
#
interface Vlanif1
 ip address 192.168.1.1 255.255.255.0
#
return
`;
  it("reads a paste that carries `display version` output above the configuration", () => {
    // A sub-0.9 recognition ratio turns every notExists control into "not assessed".
    expect(ratio(withBanner)).toBe(1);
    expect(parse(withBanner).unrecognized).toEqual([]);
    expect(detectVendor(withBanner).vendor).toBe("huawei-vrp");
  });

  it("extracts identity from the version banner", () => {
    const r = parse(withBanner);
    expect(r.identity.osVersion).toBe("V200R010C00SPC600");
    expect(r.identity.model).toBe("S5700-28C-HI");
    expect(r.identity.serial).toBe("210235559610G8000456");
    expect(r.identity.role).toBe("switch");
  });

  it("prefers the out-of-band management port over whichever SVI came first", () => {
    expect(parse(withBanner).identity.mgmtIp).toBe("10.20.250.3");
  });

  it("derives the release flag used to pick V200R019+ syntax", () => {
    expect(val(withBanner, "identity.vrp_r19plus")).toBe(false);
    expect(val(`${V21}stelnet server enable\n#\n`, "identity.vrp_r19plus")).toBe(true);
    // VRP8 releases on NE/CE hardware carry a higher major number.
    expect(val("!Software Version V800R011C00SPC300\n#\nsysname NE1\n#\n", "identity.vrp_r19plus")).toBe(true);
  });

  it("reads an archive whose top-level commands are indented by one column", () => {
    const indented = "#\n sysname ARCHIVE-SW\n#\n undo telnet server enable\n#\n vlan batch 10 20\n#\n user-interface vty 0 4\n  authentication-mode aaa\n  protocol inbound ssh\n#\nreturn\n";
    expect(ratio(indented)).toBe(1);
    expect(parse(indented).identity.hostname).toBe("ARCHIVE-SW");
    expect(val(indented, "management.telnet_enabled")).toBe(false);
  });

  it("understands stp region blocks and bare feature toggles", () => {
    const misc = `${V10}ipv6
#
stp region-configuration
 region-name CAMPUS
 revision-level 1
 instance 1 vlan 10 20
 active region-configuration
#
`;
    expect(parse(misc).unrecognized).toEqual([]);
  });

  it("extracts the model from a CE board-type line when no banner is pasted", () => {
    const ce = `${V21}device board 1 board-type CE6865-48S8CQ-EI\n#\n`;
    expect(parse(ce).identity.model).toBe("CE6865-48S8CQ-EI");
    expect(parse(ce).identity.role).toBe("switch");
  });
});

describe("VRP remediation syntax", () => {
  const modern = `${V21}stelnet server enable\n#\n`;
  const legacy = `${V10}telnet server enable\n#\n`;

  it("disables SSHv1 with a command that exists on VRP", () => {
    expect(remediation(modern, "NS-MGMT-002")).toBe("system-view\n undo ssh server compatible-ssh1x enable\n quit");
  });

  it("turns the AUX shell off rather than on", () => {
    expect(remediation(modern, "NS-MGMT-008")).toContain("undo shell");
    expect(remediation(modern, "NS-MGMT-008")).not.toMatch(/^\s+shell$/m);
  });

  it("leaves the HWTACACS template view before entering the aaa view", () => {
    const out = remediation(modern, "NS-AUTH-005").split("\n").map((s) => s.trim());
    expect(out.indexOf("quit")).toBeLessThan(out.indexOf("aaa"));
    expect(out).toContain("domain default_admin");
  });

  it("creates SNMPv3 users with one command per attribute", () => {
    const out = remediation(modern, "NS-SNMP-003");
    expect(out).toContain("snmp-agent usm-user v3 secops group SEC-V3\n");
    expect(out).toContain("snmp-agent usm-user v3 secops authentication-mode sha2-256 cipher <auth-pw>");
    expect(out).not.toMatch(/group SEC-V3 authentication-mode/);
  });

  it("names the community it removes", () => {
    const rw = `${V10}snmp-agent community write private\n#\n`;
    expect(remediation(rw, "NS-SNMP-002")).toContain("undo snmp-agent community write private");
  });

  it("does not issue system-view commands from inside an ACL view", () => {
    const acl = remediation(modern, "NS-ACL-001").split("\n").map((s) => s.trim());
    expect(acl.indexOf("quit")).toBeLessThan(acl.indexOf("interface <external-interface>"));
    const snmp = remediation(modern, "NS-SNMP-004").split("\n").map((s) => s.trim());
    expect(snmp.indexOf("quit")).toBeLessThan(snmp.indexOf("snmp-agent community read cipher <community> acl 2001"));
  });

  it("branches SSH, syslog, NTP and OSPF syntax on the VRP release", () => {
    expect(remediation(modern, "NS-CRY-001")).toContain("ssh server key-exchange dh_group_exchange_sha256");
    expect(remediation(legacy, "NS-CRY-001")).not.toContain("key-exchange");
    expect(remediation(legacy, "NS-CRY-001")).toContain("ssh server cipher aes256_ctr aes128_ctr");
    expect(remediation(modern, "NS-LOG-001")).toContain("transport tcp ssl-policy SYSLOG-TLS");
    expect(remediation(legacy, "NS-LOG-001")).toContain("info-center loghost 10.10.50.20\n");
    expect(remediation(legacy, "NS-LOG-008")).not.toContain("ssl-policy");
    expect(remediation(modern, "NS-TIME-002")).toContain("authentication-mode hmac-sha256");
    expect(remediation(legacy, "NS-TIME-002")).toContain("authentication-mode md5");
  });

  it("creates the NTP servers without referencing a key that does not exist yet", () => {
    expect(remediation(modern, "NS-TIME-001")).toBe("system-view\n ntp-service unicast-server 10.10.50.10\n ntp-service unicast-server 10.10.50.11\n quit");
  });

  it("gives the RSA key procedure as a comment, not as a command", () => {
    const out = remediation(modern, "NS-CRY-004");
    expect(out).toContain("rsa local-key-pair create");
    expect(out).not.toContain("(choose 2048 or larger)");
    expect(out.split("\n").filter((l) => !l.trim().startsWith("#")).every((l) => !l.includes("("))).toBe(true);
  });
});

describe("VRP bundled sample", () => {
  const r = parse(SAMPLE_VRP);
  it("stays fully recognised and gains model/role identity", () => {
    expect(r.unrecognized).toEqual([]);
    expect(r.identity.model).toBe("S6730-H48X6C");
    expect(r.identity.role).toBe("switch");
    expect(r.identity.serial).toBe("2102353VTX10N4000123");
  });
  it("now credits the sample's modern SSH algorithm lists", () => {
    expect(r.model.params["crypto.strong_crypto"].value).toBe(true);
    expect(r.model.params["identity.vrp_r19plus"].value).toBe(true);
    expect(r.model.params["routing.bgp_asn"].value).toBe("64513");
  });
});
