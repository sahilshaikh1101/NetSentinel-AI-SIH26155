import { describe, expect, it } from "vitest";
import { detectVendor, parseConfig } from "./parsers";
import { flattenJunos } from "./parsers/junos";
import { toLines } from "./parsers/util";
import { evaluateDevice } from "./rules/evaluate";
import { RULES } from "./rules/library";
import { DEFAULT_REMEDIATION_SETTINGS, renderRemediation } from "./rules/remediation";
import { SAMPLE_INDEX } from "./samples";
import type { FrameworkId, VendorId } from "./types";

/** Regression tests for the adversarial parser reviews (Arista EOS and Junos). */
const settings = DEFAULT_REMEDIATION_SETTINGS;
const frameworks: FrameworkId[] = ["cis", "nist", "stig", "iso"];
const parse = (raw: string, vendor: VendorId) => parseConfig(raw, vendor).result;
const params = (raw: string, vendor: VendorId) => parse(raw, vendor).model.params;
const statuses = (raw: string, vendor: VendorId) => Object.fromEntries(evaluateDevice("t", parse(raw, vendor).model, vendor, RULES, { frameworks, settings }).map((f) => [f.ruleId, f.status]));
const rule = (id: string) => RULES.find((r) => r.id === id)!;
const eos = (raw: string) => params(raw, "arista-eos");
const junos = (raw: string) => params(raw, "juniper-junos");
const HASH = "$6$Qh1mZ4dK9eL2fT7u$Y3xN8vB1rW5oP0cS6aZ2jD4fH9nQ7kM1lG3tV5yE8wR2uI6bA0";

describe("Arista EOS parser — review fixes", () => {
  it("treats 'enable password sha512 <hash>' as a hashed enable secret, md5/type-5 as hashed-but-weak, 7/0 as cleartext", () => {
    const sha = eos(`hostname SW\nenable password sha512 ${HASH}\n`);
    expect(sha["auth.enable_secret"].value).toBe(true);
    expect(sha["auth.weak_password_hashes"]).toBeUndefined();
    const md5 = eos("enable password 5 $1$abc$defghijklmnop\n");
    expect(md5["auth.enable_secret"].value).toBe(true);
    expect(md5["auth.weak_password_hashes"].value).toBe(1);
    const t7 = params("enable password 7 0822455D0A16\n", "cisco-ios");
    expect(t7["auth.enable_secret"].value).toBe(false);
    expect(t7["auth.weak_password_hashes"].value).toBe(1);
    expect(rule("NS-AUTH-002").remediation["arista-eos"]).not.toContain("sha512");
  });

  it("detects Telnet and SSH enabled inside a VRF sub-mode", () => {
    const telnet = "management telnet\n   shutdown\n   !\n   vrf MGMT\n      no shutdown\n";
    expect(eos(telnet)["management.telnet_enabled"].value).toBe(true);
    expect(statuses(telnet, "arista-eos")["NS-MGMT-001"]).toBe("fail");
    expect(eos("management telnet\n   shutdown\n")["management.telnet_enabled"].value).toBe(false);
    expect(eos("management ssh\n   shutdown\n   vrf MGMT\n      no shutdown\n")["management.ssh_enabled"].value).toBe(true);
  });

  it("detects plain-HTTP eAPI with a port or enabled only in a VRF; localhost-only HTTP is not exposed", () => {
    const vrf = eos("management api http-commands\n   protocol http port 8080\n   !\n   vrf MGMT\n      no shutdown\n");
    expect(vrf["management.api_http_enabled"].value).toBe(true);
    expect(vrf["management.http_enabled"].value).toBe(true);
    const https = eos("management api http-commands\n   protocol https port 8443\n   protocol https ssl profile X\n   no shutdown\n");
    expect(https["management.api_http_enabled"].value).toBe(false);
    expect(https["management.https_enabled"].value).toBe(true);
    expect(eos("management api http-commands\n   protocol http localhost port 8080\n   no shutdown\n")["management.api_http_enabled"].value).toBe(false);
    expect(eos("management api http-commands\n   protocol http\n   shutdown\n")["management.api_http_enabled"].value).toBe(false);
  });

  it("recognises 'logging vrf X host …' and 'logging vrf X source-interface …'", () => {
    const p = eos("logging vrf MGMT host 10.10.50.20 6514 protocol tls\nlogging vrf MGMT host 2001:db8:50::20 6514 protocol tls\nlogging vrf MGMT source-interface Management1\n");
    expect(p["logging.remote_hosts"].value).toEqual(["10.10.50.20", "2001:db8:50::20"]);
    expect(p["logging.remote_secure"].value).toBe(true);
    expect(p["logging.source_interface"].value).toBe(true);
    expect(p["management.mgmt_vrf"].value).toBe("MGMT");
  });

  it("accepts VRF-scoped and IPv6 management ACLs under management ssh, (system) control-plane and Management interfaces", () => {
    expect(eos("management ssh\n   ip access-group MGMT-ACL vrf MGMT in\n")["management.mgmt_acl_applied"].value).toBe(true);
    expect(eos("system control-plane\n   ipv6 access-group MGMT6-ACL vrf MGMT in\n")["management.mgmt_acl_applied"].value).toBe(true);
    expect(eos("control-plane\n   ip access-group MGMT-ACL in\n")["management.mgmt_acl_applied"].value).toBe(true);
    const mgmt = parse("interface Management1\n   vrf MGMT\n   ip address 10.10.0.19/24\n   ip access-group MGMT-IN in\ninterface Loopback0\n   ip address 10.14.255.9/32\n", "arista-eos");
    expect(mgmt.model.params["management.mgmt_acl_applied"].value).toBe(true);
    expect(mgmt.model.params["acl.external_ingress_filter"].value).toBe(true);
    expect(mgmt.model.params["management.mgmt_vrf"].value).toBe("MGMT");
    expect(mgmt.identity.mgmtIp).toBe("10.10.0.19");
    expect(eos("interface Ethernet1\n   no switchport\n   ipv6 access-group EDGE6 in\n")["acl.external_ingress_filter"].value).toBe(true);
    expect(eos("hostname SW\n")["management.mgmt_acl_applied"].value).toBe(false);
  });

  it("lets BGP neighbours inherit the peer-group password and never lists the group itself as a neighbour", () => {
    const base = "router bgp 65001\n   neighbor EVPN peer group\n   neighbor EVPN password 7 0822455D0A16\n   neighbor EVPN remote-as 65000\n   neighbor 10.0.0.1 peer group EVPN\n   neighbor 10.0.0.1 remote-as 65000\n   neighbor 10.0.0.2 peer group EVPN\n";
    const ok = eos(base);
    expect(ok["routing.bgp_auth"].value).toBe(true);
    expect(ok["routing.bgp_unauth_neighbors"]).toBeUndefined();
    const mixed = eos(`${base}   neighbor 203.0.113.1 remote-as 64496\n`);
    expect(mixed["routing.bgp_auth"].value).toBe(false);
    expect(mixed["routing.bgp_unauth_neighbors"].value).toEqual(["203.0.113.1"]);
    const ios = params("router bgp 65001\n neighbor ISP peer-group\n neighbor ISP password 7 0822455D0A16\n neighbor 10.0.0.1 peer-group ISP\n neighbor 10.0.0.1 remote-as 64496\n", "cisco-ios");
    expect(ios["routing.bgp_auth"].value).toBe(true);
  });

  it("uses the insecure EOS defaults (never-expiring sessions, 120 s login timeout) when the management blocks are absent", () => {
    const p = eos("hostname SW\n");
    expect(p["management.idle_timeout_minutes"].value).toBe(9999);
    expect(p["management.console_timeout_minutes"].value).toBe(9999);
    expect(p["management.ssh_timeout_seconds"].value).toBe(120);
    const s = statuses("hostname SW\n", "arista-eos");
    expect(s["NS-MGMT-004"]).toBe("fail");
    expect(s["NS-MGMT-005"]).toBe("fail");
    expect(s["NS-MGMT-012"]).toBe("fail");
    expect(s["NS-AUTH-008"]).toBe("fail");
    expect(s["NS-LOG-005"]).toBe("fail");
    expect(eos("management ssh\n   idle-timeout 10\n")["management.idle_timeout_minutes"].value).toBe(10);
  });

  it("counts password-less accounts, empty-password permits and 'aaa root' as weak credentials", () => {
    const p = eos("username backup-op privilege 15 nopassword\naaa authentication policy local allow-nopassword-remote-login\naaa root nopassword\nmanagement ssh\n   authentication empty-passwords permit\n");
    expect(p["auth.weak_password_hashes"].value).toBe(4);
    expect(p["auth.weak_local_users"].value).toEqual(["backup-op"]);
    expect(p["auth.root_login_ssh"].value).toBe(true);
    const s = statuses("username backup-op privilege 15 nopassword\naaa root nopassword\n", "arista-eos");
    expect(s["NS-AUTH-003"]).toBe("fail");
    expect(s["NS-AUTH-009"]).toBe("fail");
    expect(eos("no aaa root\n")["auth.root_login_ssh"].value).toBe(false);
    const secret = eos(`aaa root secret sha512 ${HASH}\n`);
    expect(secret["auth.root_login_ssh"].value).toBe(true);
    expect(secret["auth.weak_password_hashes"]).toBeUndefined();
    expect(eos("username jdoe privilege 15 secret 0 Winter2026!\n")["auth.weak_password_hashes"].value).toBe(1);
  });

  it("reads the OS version from the header or image name, never from a hostname such as EDGE-RTR-EOS-1", () => {
    const hdr = parse("! device: EDGE-RTR-EOS-1 (DCS-7280SR3-48YC8, EOS-4.28.3M)\nhostname EDGE-RTR-EOS-1\n", "arista-eos");
    expect(hdr.identity.osVersion).toBe("4.28.3M");
    expect(hdr.identity.model).toBe("DCS-7280SR3-48YC8");
    expect(parse("hostname LEAF-EOS-01\nboot system flash:/EOS64-4.31.1F.swi\n", "arista-eos").identity.osVersion).toBe("4.31.1F");
    expect(parse("hostname vEOS-1\n", "arista-eos").identity.osVersion).toBeUndefined();
  });

  const HEADERLESS = `no aaa root
!
username admin privilege 15 secret sha512 ${HASH}
username backup-op privilege 15 nopassword
!
hostname ACC-SW-17
ip domain-name campus.example.in
!
enable password sha512 ${HASH}
!
spanning-tree mode mstp
!
vlan 10
   name USERS
!
aaa authentication login default local
!
snmp-server community public ro
!
interface Ethernet1
   switchport access vlan 10
!
interface Vlan10
   ip address 10.1.10.2/24
!
interface Loopback0
   ip address 10.1.255.17/32
!
ip routing
!
end
`;
  it("detects a comment-less EOS config without management blocks as Arista, not Cisco IOS", () => {
    const d = detectVendor(HEADERLESS);
    expect(d.vendor).toBe("arista-eos");
    expect(d.confidence).toBeGreaterThan(0.5);
    expect(d.scores["arista-eos"]!).toBeGreaterThan(d.scores["cisco-ios"]! * 2);
    // local-only AAA with no servers is a FAIL, not "not observed"
    expect(statuses(HEADERLESS, "arista-eos")["NS-AUTH-005"]).toBe("fail");
    expect(detectVendor(SAMPLE_INDEX.cisco.raw).vendor).toBe("cisco-ios");
    expect(detectVendor(SAMPLE_INDEX.nxos.raw).vendor).toBe("cisco-nxos");
  });

  it("understands MLAG, trunk group, prefix-list seq, 'no spanning-tree vlan-id' and the ip security block", () => {
    const cfg = "mlag configuration\n   domain-id DC1\n   local-interface Vlan4094\n   peer-address 10.255.252.1\n   peer-link Port-Channel1\n   reload-delay mlag 300\n   dual-primary detection delay 10 action errdisable all-interfaces\n!\nvlan 4093\n   name MLAG-PEER\n   trunk group MLAG\n!\nno spanning-tree vlan-id 4093-4094\n!\nip prefix-list PL-LOOPBACKS\n   seq 10 permit 10.14.255.0/24 eq 32\n!\nip security\n   ike policy IKE-LEGACY\n      encryption 3des\n      integrity md5\n      dh-group 2\n   !\n   sa policy SA-LEGACY\n      esp encryption 3des\n      esp integrity md5\n      pfs dh-group 2\n   !\n   profile VPN\n      ike-policy IKE-LEGACY\n      sa-policy SA-LEGACY\n      shared-key 7 0A1B2C\n";
    const r = parse(cfg, "arista-eos");
    expect(r.unrecognized).toEqual([]);
    expect(r.model.params["crypto.weak_ike"].value).toBe(true);
    expect(statuses(cfg, "arista-eos")["NS-CRY-002"]).toBe("fail");
    const strong = eos("ip security\n   ike policy IKE-OK\n      encryption aes256\n      integrity sha256\n      dh-group 14\n   sa policy SA-OK\n      esp encryption aes256gcm128\n      pfs dh-group 14\n");
    expect(strong["crypto.weak_ike"].value).toBe(false);
    expect(rule("NS-CRY-002").remediation["arista-eos"]).toContain("ip security");
  });

  it("accepts 'ntp authenticate servers' as NTP authentication", () => {
    const p = eos("ntp authentication-key 1 sha1 7 0A1B2C\nntp trusted-key 1\nntp authenticate servers\nntp server vrf MGMT 10.10.50.10 key 1 prefer\nntp server vrf MGMT 10.10.50.11 key 1\n");
    expect(p["time.ntp_authentication"].value).toBe(true);
    expect(p["time.ntp_servers"].value).toEqual(["10.10.50.10", "10.10.50.11"]);
  });

  it("extracts EOS lockout and login-event policies and 'dns domain'", () => {
    const cfg = "aaa authentication policy lockout failure 3 window 900 duration 1800\naaa authentication policy on-failure log\naaa authentication policy on-success log\ndns domain corp.example.in\n";
    const p = eos(cfg);
    expect(p["auth.login_lockout"].value).toBe(true);
    expect(p["auth.max_login_attempts"].value).toBe(3);
    expect(p["logging.login_events"].value).toBe(true);
    expect(p["identity.domain_set"].value).toBe(true);
    const s = statuses(cfg, "arista-eos");
    expect(s["NS-AUTH-008"]).toBe("pass");
    expect(s["NS-LOG-005"]).toBe("pass");
    expect(s["NS-ID-002"]).toBe("pass");
    expect(rule("NS-ID-002").remediation["arista-eos"]).toContain("dns domain");
  });

  it("treats LLDP as restricted only when every live access port disables transmit and receive", () => {
    const off = "interface Ethernet1\n   switchport access vlan 10\n   no lldp transmit\n   no lldp receive\ninterface Ethernet49\n   switchport mode trunk\n";
    expect(eos(off)["services.lldp_enabled"].value).toBe(false);
    expect(eos("interface Ethernet1\n   switchport access vlan 10\ninterface Ethernet49\n   switchport mode trunk\n")["services.lldp_enabled"].value).toBe(true);
    expect(rule("NS-SVC-011").remediation["arista-eos"]).not.toContain("no lldp run");
  });

  it("requires cipher, MAC and key-exchange lists before calling EOS SSH crypto strong", () => {
    expect(eos("management ssh\n   cipher aes256-gcm@openssh.com aes256-ctr\n")["crypto.strong_crypto"].value).toBe(false);
    const all = "management ssh\n   cipher aes256-gcm@openssh.com\n   mac hmac-sha2-512\n   key-exchange ecdh-sha2-nistp384\n   fips restrictions\n";
    expect(eos(all)["crypto.strong_crypto"].value).toBe(true);
    expect(eos(all)["crypto.fips_mode"].value).toBe(true);
    expect(statuses(all, "arista-eos")["NS-CRY-005"]).toBe("pass");
  });

  it("honours the global 'no ip icmp redirect' and derives the EOS role from the interface mix", () => {
    const p = parse("no ip icmp redirect\ninterface Vlan10\n   ip address 10.1.10.1/24\ninterface Tunnel1\n   ip address 172.16.0.1/30\n", "arista-eos");
    expect(p.model.params["services.icmp_redirects"].value).toBe(false);
    expect(p.identity.role).toBe("router");
    expect(parse(SAMPLE_INDEX.arista.raw, "arista-eos").identity.role).toBe("switch");
    expect(parse(SAMPLE_INDEX.arista.raw, "arista-eos").identity.mgmtIp).toBe("10.10.0.12");
  });
});

describe("Junos parser — review fixes", () => {
  it("drops deactivated/deleted set statements and honours a later 'activate'", () => {
    const off = "set system services ssh\nset system services telnet\ndeactivate system services telnet\n";
    const r = parse(off, "juniper-junos");
    expect(r.model.params["management.telnet_enabled"].value).toBe(false);
    expect(r.unrecognized).toEqual([]);
    expect(junos("set system services telnet\ndelete system services telnet\n")["management.telnet_enabled"].value).toBe(false);
    expect(junos("set system services telnet\ndeactivate system services telnet\nactivate system services telnet\n")["management.telnet_enabled"].value).toBe(true);
  });

  it("skips 'inactive:' leaves and stanzas in brace format", () => {
    const cfg = "system {\n    services {\n        ssh;\n        inactive: telnet;\n        web-management {\n            inactive: http {\n                interface irb.10;\n            }\n            https {\n                system-generated-certificate;\n            }\n        }\n    }\n}\n";
    const r = parse(cfg, "juniper-junos");
    expect(r.model.params["management.telnet_enabled"].value).toBe(false);
    expect(r.model.params["management.http_enabled"].value).toBe(false);
    expect(r.model.params["management.https_enabled"].value).toBe(true);
    expect(r.unrecognized).toEqual([]);
    expect(flattenJunos(toLines("system {\n    replace: services {\n        ssh;\n    }\n}\n")).entries.map((e) => e.path)).toContain("system services ssh");
  });

  it("folds applied groups (and re0/re1/node0/node1) into the main hierarchy, ignoring unapplied groups", () => {
    const cfg = "groups {\n    node0 {\n        system {\n            host-name FW-A;\n        }\n        interfaces {\n            fxp0 {\n                unit 0 {\n                    family inet {\n                        filter {\n                            input MGMT-ONLY;\n                        }\n                        address 10.20.0.11/24;\n                    }\n                }\n            }\n        }\n    }\n    GLOBAL {\n        system {\n            login {\n                message \"AUTHORISED USE ONLY\";\n            }\n        }\n    }\n    UNUSED {\n        system {\n            services {\n                telnet;\n            }\n        }\n    }\n}\napply-groups [ \"${node}\" GLOBAL ];\nsystem {\n    services {\n        ssh;\n    }\n}\n";
    const r = parse(cfg, "juniper-junos");
    expect(r.identity.hostname).toBe("FW-A");
    expect(r.identity.mgmtIp).toBe("10.20.0.11");
    expect(r.model.params["identity.hostname_set"].value).toBe(true);
    expect(r.model.params["management.login_banner"].value).toBe(true);
    expect(r.model.params["management.mgmt_acl_applied"].value).toBe(true);
    expect(r.model.params["management.telnet_enabled"].value).toBe(false);
    expect(r.unrecognized).toEqual([]);
  });

  it("only counts zone host-inbound-traffic when the matching system service exists, and records the zones for remediation", () => {
    const zones = "security {\n    zones {\n        security-zone TRUST {\n            host-inbound-traffic {\n                system-services {\n                    all;\n                }\n            }\n        }\n    }\n}\n";
    const off = junos(`system {\n    services {\n        ssh;\n    }\n}\n${zones}`);
    expect(off["management.telnet_enabled"].value).toBe(false);
    expect(off["management.telnet_zones"].value).toEqual(["TRUST"]);
    expect(off["management.ssh_enabled"].evidence.some((e) => e.text.includes("security-zone TRUST permits ssh"))).toBe(true);
    const on = parse(`system {\n    services {\n        telnet;\n    }\n}\n${zones}`, "juniper-junos");
    expect(on.model.params["management.telnet_enabled"].value).toBe(true);
    expect(on.model.params["management.telnet_enabled"].evidence.some((e) => e.text.includes("TRUST"))).toBe(true);
    expect(renderRemediation(rule("NS-MGMT-001"), "juniper-junos", on.model, settings)).toContain("delete security zones security-zone TRUST host-inbound-traffic system-services telnet");
    const except = junos("security {\n    zones {\n        security-zone TRUST {\n            host-inbound-traffic {\n                system-services {\n                    all;\n                    telnet {\n                        except;\n                    }\n                }\n            }\n        }\n    }\n}\n");
    expect(except["management.telnet_zones"]).toBeUndefined();
  });

  it("can set crypto.strong_crypto to true, and keeps it false once any weak algorithm list was seen", () => {
    expect(junos("set system services ssh ciphers [ aes256-gcm@openssh.com aes256-ctr ]\n")["crypto.strong_crypto"].value).toBe(true);
    expect(junos("set system services ssh ciphers [ aes256-gcm@openssh.com aes256-ctr ]\nset system services ssh macs [ hmac-sha1 hmac-sha2-256 ]\n")["crypto.strong_crypto"].value).toBe(false);
    expect(junos("set system services ssh macs [ hmac-sha1 hmac-sha2-256 ]\nset system services ssh ciphers [ aes256-gcm@openssh.com ]\n")["crypto.strong_crypto"].value).toBe(false);
    expect(statuses(SAMPLE_INDEX.junos.raw, "juniper-junos")["NS-CRY-001"]).toBe("pass");
  });

  it("reports SSH version 1 when v1 is listed in any form", () => {
    expect(junos("system {\n    services {\n        ssh {\n            protocol-version [ v1 v2 ];\n        }\n    }\n}\n")["management.ssh_version"].value).toBe(1);
    expect(junos("set system services ssh protocol-version v1\nset system services ssh protocol-version v2\n")["management.ssh_version"].value).toBe(1);
    expect(junos("set system services ssh protocol-version v2\n")["management.ssh_version"].value).toBe(2);
    expect(rule("NS-MGMT-002").remediation["juniper-junos"]).toContain("delete system services ssh protocol-version");
  });

  it("evaluates the SRX default policy: permit-all fails, absence on a firewall is the deny-all default, routers stay unobserved", () => {
    const policy = "security {\n    policies {\n        from-zone TRUST to-zone UNTRUST {\n            policy BLOCK-SMB {\n                match {\n                    source-address any;\n                    destination-address any;\n                    application junos-smb;\n                }\n                then {\n                    deny;\n                    log {\n                        session-init;\n                    }\n                }\n            }\n        }\n";
    const permit = `${policy}        default-policy {\n            permit-all;\n        }\n    }\n}\n`;
    expect(junos(permit)["acl.default_deny"].value).toBe(false);
    expect(statuses(permit, "juniper-junos")["NS-ACL-003"]).toBe("fail");
    expect(junos(permit)["acl.explicit_deny_logged"].value).toBe(true);
    const implicit = junos(`${policy}    }\n}\n`);
    expect(implicit["acl.default_deny"].value).toBe(true);
    expect(implicit["acl.default_deny"].source).toBe("default");
    expect(junos("set system host-name R\n")["acl.default_deny"]).toBeUndefined();
  });

  it("flags proposal-sets, aggressive mode and IKEv1-only gateways as weak IKE", () => {
    const cfg = "security {\n    ike {\n        policy P {\n            mode aggressive;\n            proposal-set standard;\n        }\n        gateway G {\n            ike-policy P;\n            version v1-only;\n        }\n    }\n}\n";
    expect(junos(cfg)["crypto.weak_ike"].value).toBe(true);
    expect(statuses(cfg, "juniper-junos")["NS-CRY-002"]).toBe("fail");
    expect(junos("set security ipsec policy X proposal-set basic\n")["crypto.weak_ike"].value).toBe(true);
    expect(junos("set security ike gateway G version v1-only\n")["crypto.weak_ike"].value).toBe(true);
    const tmpl = rule("NS-CRY-002").remediation["juniper-junos"]!;
    expect(tmpl).toContain("authentication-method pre-shared-keys");
    expect(tmpl).not.toContain("gcm");
  });

  it("tracks BGP authentication per group/neighbour, including routing-instance protocols", () => {
    const cfg = "set protocols bgp group IBGP type internal\nset protocols bgp group IBGP authentication-key-chain BGP-KC\nset protocols bgp group IBGP neighbor 10.0.255.1\nset protocols bgp group EBGP type external\nset protocols bgp group EBGP peer-as 64496\nset protocols bgp group EBGP neighbor 203.0.113.1\nset routing-instances ACME protocols bgp group CE neighbor 172.16.100.2\n";
    const p = junos(cfg);
    expect(p["routing.bgp_auth"].value).toBe(false);
    expect(p["routing.bgp_unauth_neighbors"].value).toEqual(["203.0.113.1", "172.16.100.2"]);
    expect(statuses(cfg, "juniper-junos")["NS-RTG-001"]).toBe("fail");
    const fixed = junos(`${cfg}set protocols bgp group EBGP neighbor 203.0.113.1 authentication-key "$9$x"\nset routing-instances ACME protocols bgp group CE authentication-key "$9$y"\n`);
    expect(fixed["routing.bgp_auth"].value).toBe(true);
    expect(fixed["routing.bgp_unauth_neighbors"]).toBeUndefined();
  });

  it("does not accept OSPF simple-password as authentication and sees routing-instance OSPF", () => {
    expect(junos("protocols {\n    ospf {\n        area 0.0.0.0 {\n            interface irb.10 {\n                authentication {\n                    simple-password \"$9$x\";\n                }\n            }\n            interface lo0.0 {\n                passive;\n            }\n        }\n    }\n}\n")["routing.ospf_auth"].value).toBe(false);
    expect(junos("set protocols ospf area 0.0.0.0 interface irb.10 authentication md5 1 key \"$9$x\"\n")["routing.ospf_auth"].value).toBe(true);
    expect(junos("set protocols ospf area 0.0.0.0 interface lo0.0 passive\n")["routing.ospf_auth"].value).toBe(true);
    const vrf = junos("set routing-instances ACME protocols ospf area 0.0.0.0 interface ge-0/0/1.100\n");
    expect(vrf["routing.ospf_configured"].value).toBe(true);
    expect(vrf["routing.ospf_auth"].value).toBe(false);
  });

  it("counts $1$ (MD5-crypt) hashes as weak credentials", () => {
    const cfg = "set system root-authentication encrypted-password \"$1$p3Vx9k2d$Q1wE4rT7yU0iO3pA6sD9fG.\"\nset system login user noc authentication encrypted-password \"$1$Zq8mN2vB$lK4jH6gF8dS0aP2oI4uY1t.\"\nset system login user ok authentication encrypted-password \"$6$abc$def\"\n";
    expect(junos(cfg)["auth.weak_password_hashes"].value).toBe(2);
    expect(statuses(cfg, "juniper-junos")["NS-AUTH-003"]).toBe("fail");
  });

  it("derives AAA from authentication-order, ignoring server stanzas the order does not reference", () => {
    const stale = "set system authentication-order password\nset system tacplus-server 10.10.50.30 secret \"$9$x\"\n";
    const p = junos(stale);
    expect(p["auth.aaa_enabled"].value).toBe(false);
    expect(p["auth.remote_auth_servers"].value).toEqual([]);
    const s = statuses(stale, "juniper-junos");
    expect(s["NS-AUTH-004"]).toBe("fail");
    expect(s["NS-AUTH-005"]).toBe("fail");
    const live = junos("set system authentication-order tacplus\nset system authentication-order password\nset system tacplus-server 10.10.50.30 secret \"$9$x\"\n");
    expect(live["auth.aaa_authentication_login"].value).toBe(true);
    expect(live["auth.remote_auth_servers"].value).toEqual(["10.10.50.30"]);
    const none = junos("set system host-name R\n");
    expect(none["auth.aaa_enabled"].value).toBe(false);
    expect(none["auth.aaa_enabled"].source).toBe("default");
  });

  it("does not lose the rest of the configuration after a bracket inside a quoted string", () => {
    const r = parse("interfaces {\n    ge-0/0/0 {\n        description \"Uplink [primary\";\n        unit 0 {\n            family inet {\n                address 192.0.2.1/30;\n            }\n        }\n    }\n}\nsnmp {\n    community public;\n}\n", "juniper-junos");
    expect(r.model.params["snmp.default_communities"].value).toEqual(["public"]);
    expect(r.identity.mgmtIp).toBe("192.0.2.1");
    expect(r.unrecognized).toEqual([]);
  });

  it("extracts identity from set format, management ports, virtual-chassis members and 'Chassis' headers only", () => {
    const set = parse("set version 20.4R3-S4.1\nset system host-name R\nset interfaces vme unit 0 family inet filter input MGMT-IN\nset interfaces vme unit 0 family inet address 10.10.0.107/24\nset interfaces lo0 unit 0 family inet address 10.0.255.107/32\n", "juniper-junos");
    expect(set.identity.osVersion).toBe("20.4R3-S4.1");
    expect(set.identity.mgmtIp).toBe("10.10.0.107");
    expect(set.model.params["management.mgmt_acl_applied"].value).toBe(true);
    expect(parse(SAMPLE_INDEX.junos.raw, "juniper-junos").identity.mgmtIp).toBe("10.10.0.14");
    const vc = parse("virtual-chassis {\n    member 0 {\n        serial-number PE3716120123;\n    }\n    member 1 {\n        serial-number PE3716120456;\n    }\n}\n", "juniper-junos");
    expect(vc.identity.serial).toBe("PE3716120123");
    expect(vc.identity.extra?.vc_members).toBe("PE3716120123, PE3716120456");
    const cluster = parse("Chassis cluster status\nset system host-name R\n", "juniper-junos");
    expect(cluster.identity.serial).toBeUndefined();
    expect(cluster.identity.model).toBeUndefined();
  });

  it("classifies the role from zones/policies, ethernet-switching or vlans — not from authentication-key-chains", () => {
    expect(parse("set security authentication-key-chains key-chain K key 0 secret \"$9$x\"\nset system host-name R\n", "juniper-junos").identity.role).toBe("router");
    expect(parse("set vlans USERS vlan-id 10\n", "juniper-junos").identity.role).toBe("switch");
    expect(parse("set security zones security-zone TRUST interfaces ge-0/0/1.0\n", "juniper-junos").identity.role).toBe("firewall");
  });

  it("detects explicit logged denies split across term lines in brace and set format", () => {
    expect(junos("firewall {\n    family inet {\n        filter MGMT-IN {\n            term DENY-LOG {\n                then {\n                    log;\n                    discard;\n                }\n            }\n        }\n    }\n}\n")["acl.explicit_deny_logged"].value).toBe(true);
    expect(junos("set firewall family inet filter F term D then syslog\nset firewall family inet filter F term D then discard\n")["acl.explicit_deny_logged"].value).toBe(true);
    expect(junos("set firewall family inet filter F term A then accept\n")["acl.explicit_deny_logged"].value).toBe(false);
    expect(junos("firewall {\n    family ethernet-switching {\n        filter BLOCK {\n            term T then discard;\n        }\n    }\n}\n")["acl.count"].value).toBe(1);
  });

  it("requires keyed servers for NTP authentication, not just a trusted-key", () => {
    const keys = "set system ntp authentication-key 10 type md5 value \"$9$x\"\nset system ntp trusted-key 10\n";
    expect(junos(`${keys}set system ntp server 10.10.50.10 prefer\n`)["time.ntp_authentication"].value).toBe(false);
    expect(junos(`${keys}set system ntp server 10.10.50.10 key 10\nset system ntp server 10.10.50.10 prefer\n`)["time.ntp_authentication"].value).toBe(true);
  });

  it("reads SNMPv3 privacy, login banners, lockout and retry semantics precisely", () => {
    expect(junos("set snmp v3 usm local-engine user m privacy-none\n")["snmp.v3_priv"].value).toBe(false);
    expect(junos("set snmp v3 usm local-engine user m privacy-aes128 privacy-key \"$9$x\"\n")["snmp.v3_priv"].value).toBe(true);
    expect(junos("set system login announcement \"Welcome\"\n")["management.login_banner"].value).toBe(false);
    expect(junos("set system login message \"AUTHORISED USE ONLY\"\n")["management.login_banner"].value).toBe(true);
    const backoff = junos("set system login retry-options backoff-threshold 3\nset system login retry-options backoff-factor 10\n");
    expect(backoff["auth.login_lockout"].value).toBe(false);
    expect(backoff["auth.login_lockout"].source).toBe("default");
    expect(junos("set system login retry-options lockout-period 15\n")["auth.login_lockout"].value).toBe(true);
    const retries = junos("set system services ssh rate-limit 150\nset system login retry-options tries-before-disconnect 3\n");
    expect(retries["management.ssh_auth_retries"].value).toBe(3);
    expect(retries["management.concurrent_sessions_limited"].value).toBe(true);
  });

  it("handles syslog hosts: UDP is unencrypted, the most verbose severity wins, 'any any' logs logins", () => {
    const cfg = "set system syslog host 10.10.50.20 any any\nset system syslog host 2001:db8:50::20 any notice\n";
    const p = junos(cfg);
    expect(p["logging.level"].value).toBe("any");
    expect(p["logging.login_events"].value).toBe(true);
    expect(p["logging.remote_secure"].value).toBe(false);
    const s = statuses(cfg, "juniper-junos");
    expect(s["NS-LOG-004"]).toBe("pass");
    expect(s["NS-LOG-008"]).toBe("fail");
    const stream = junos("security {\n    log {\n        stream SIEM {\n            host {\n                10.10.50.21;\n                port 6514;\n            }\n            transport {\n                protocol tls;\n            }\n        }\n    }\n}\n");
    expect(stream["logging.remote_hosts"].value).toEqual(["10.10.50.21"]);
    expect(stream["logging.remote_secure"]).toBeUndefined();
  });

  it("treats a community without a restrictive clients list as unfiltered", () => {
    expect(junos("set snmp community public authorization read-only\n")["snmp.community_acl"].value).toBe(false);
    expect(junos("set snmp community c clients 0.0.0.0/0\n")["snmp.community_acl"].value).toBe(false);
    expect(junos("set snmp community c clients 10.10.50.0/24\nset snmp community c clients 0.0.0.0/0 restrict\n")["snmp.community_acl"].value).toBe(true);
    expect(statuses("set snmp community public authorization read-only\n", "juniper-junos")["NS-SNMP-004"]).toBe("fail");
  });

  it("sees per-unit proxy-arp, no-redirects and targeted-broadcast", () => {
    expect(junos("set interfaces ge-0/0/1 unit 100 proxy-arp restricted\n")["services.proxy_arp"].value).toBe(true);
    const redirects = "set interfaces ge-0/0/0 unit 0 family inet no-redirects\nset interfaces ge-0/0/0 unit 0 family inet address 203.0.113.2/30\nset interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24\n";
    expect(junos(redirects)["services.icmp_redirects"].value).toBe(true);
    expect(junos(`${redirects}set interfaces ge-0/0/1 unit 0 family inet no-redirects\n`)["services.icmp_redirects"].value).toBe(false);
    expect(junos("set interfaces ge-0/0/1 unit 0 family inet targeted-broadcast\n")["services.directed_broadcast"].value).toBe(true);
  });

  it("applies Junos platform defaults: no AUX port on branch/EX platforms, no plain-HTTP API/FTP, quiet console, no uRPF", () => {
    const p = junos("set system host-name R\n");
    expect(p["management.aux_disabled"].value).toBe(true);
    expect(p["management.api_http_enabled"].value).toBe(false);
    expect(p["management.ftp_enabled"].value).toBe(false);
    expect(p["logging.console_restricted"].value).toBe(true);
    expect(p["services.unicast_rpf"].value).toBe(false);
    expect(statuses(SAMPLE_INDEX.junos.raw, "juniper-junos")["NS-MGMT-008"]).toBe("pass");
    expect(junos("## Chassis   JN1234ABCD   MX204\nset system host-name R\n")["management.aux_disabled"].value).toBe(false);
    expect(junos("set chassis redundancy graceful-switchover\n")["management.aux_disabled"].value).toBe(false);
    expect(junos("set chassis redundancy graceful-switchover\nset system ports auxiliary disable\n")["management.aux_disabled"].value).toBe(true);
  });

  it("reports 'never' when a login class has no idle-timeout or a user sits in a built-in class", () => {
    expect(junos("set system login class NETADMIN permissions all\nset system login class HELPDESK idle-timeout 30\n")["management.idle_timeout_minutes"].value).toBe(9999);
    expect(junos("set system login class A idle-timeout 10\nset system login user admin class super-user\n")["management.idle_timeout_minutes"].value).toBe(9999);
    const ok = junos("set system login class A idle-timeout 10\nset system login user u class A\n");
    expect(ok["management.idle_timeout_minutes"].value).toBe(10);
    expect(ok["management.login_classes"].value).toEqual(["A"]);
    expect(renderRemediation(rule("NS-MGMT-004"), "juniper-junos", parse("set system login class A permissions all\n", "juniper-junos").model, settings)).toContain("set system login class A idle-timeout 10");
  });

  it("detects set-format subtrees, templates and '## Last changed' exports as Junos", () => {
    expect(detectVendor("set groups GLOBAL system login message \"hi\"\nset apply-groups GLOBAL\nset routing-instances ACME instance-type vrf\n").vendor).toBe("juniper-junos");
    expect(detectVendor("## Last changed: 2025-11-03 14:22:51 IST\nset system host-name R\n").scores["juniper-junos"]!).toBeGreaterThanOrEqual(11);
  });

  it("renders syntactically valid Junos remediation", () => {
    const m006 = rule("NS-MGMT-006").remediation["juniper-junos"]!;
    expect(m006).not.toContain("then log discard");
    expect(m006).toContain("term DENY-MGMT then log\n");
    expect(m006).toContain("term DENY-MGMT then discard");
    expect(m006).toContain("term ICMP");
    expect(rule("NS-MGMT-001").remediation["juniper-junos"]).not.toContain("security-zone *");
    expect(rule("NS-AUTH-006").remediation["juniper-junos"]).toContain("secret <secret>");
    expect(rule("NS-SNMP-001").remediation["juniper-junos"]).toContain("vacm");
    expect(rule("NS-SNMP-003").remediation["juniper-junos"]).toContain("vacm");
    // the empty-list fallback uses the vendor's comment marker, never Cisco's '!'
    const noZones = parse("set system services telnet\n", "juniper-junos").model;
    const rendered = renderRemediation(rule("NS-MGMT-001"), "juniper-junos", noZones, settings);
    expect(rendered).toContain("\n# (no telnet zones");
    expect(rendered).not.toContain("!");
  });
});
