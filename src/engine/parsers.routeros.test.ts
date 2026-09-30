import { describe, expect, it } from "vitest";
import { detectVendor } from "./detect";
import { parseConfig } from "./parsers";
import { SAMPLE_INDEX } from "./samples";
import { RULE_INDEX } from "./rules/library";
import { DEFAULT_REMEDIATION_SETTINGS, renderRemediation } from "./rules/remediation";
import { evalCheck } from "./rules/evaluate";
import type { ParamValue, SecurityBaselineModel } from "./types";

const parse = (raw: string) => parseConfig(raw, "mikrotik-routeros").result;
const params = (raw: string) => parse(raw).model.params;
const value = (raw: string, key: string): ParamValue | undefined => params(raw)[key]?.value;
const HEADER6 = "# feb/11/2025 09:41:02 by RouterOS 6.49.13\n# software id = 7N4X-2LQD\n";
const HEADER7 = "# 2026-03-04 07:22:10 by RouterOS 7.16.2\n# software id = QJ4M-8TPV\n";
const render = (ruleId: string, model: SecurityBaselineModel) => renderRemediation(RULE_INDEX[ruleId], "mikrotik-routeros", model, DEFAULT_REMEDIATION_SETTINGS);

describe("RouterOS tokenizer", () => {
  it("keeps a quoted value whole instead of letting it inject a key/value pair", () => {
    // "disabled=yes" inside the comment used to disable the rule for the parser.
    const p = params('/ip firewall filter\nadd action=drop chain=input comment="deny all, was disabled=yes until 2025"\n');
    expect(p["acl.default_deny"].value).toBe(true);
    expect(p["acl.count"].value).toBe(1);
  });

  it("does not split a quoted value on spaces", () => {
    const p = params('/system identity\nset name="BR 07 EDGE"\n');
    expect(p["identity.hostname"].value).toBe("BR 07 EDGE");
  });

  it("joins backslash continuations carrying quoted comments", () => {
    const raw = '/ip firewall filter\nadd action=drop chain=input comment="default deny input" \\\n    log=yes log-prefix="INPUT-DROP"\n';
    const r = parse(raw);
    expect(r.model.params["acl.explicit_deny_logged"].value).toBe(true);
    expect(r.unrecognized).toHaveLength(0);
  });
});

describe("RouterOS /ip service", () => {
  it("resolves a '[ find name=… ]' selector to the service", () => {
    expect(value("/ip service\nset [ find name=telnet ] disabled=yes\n", "management.telnet_enabled")).toBe(false);
  });

  it("honours the enable/disable verbs", () => {
    expect(value("/ip service disable telnet\n", "management.telnet_enabled")).toBe(false);
    expect(value("/ip service enable ftp\n", "management.ftp_enabled")).toBe(true);
  });

  it("keeps www-ssl disabled when a set line does not enable it", () => {
    // www-ssl is the one /ip service item that ships disabled.
    expect(value("/ip service\nset www-ssl certificate=mgmt-cert\n", "management.https_enabled")).toBe(false);
    expect(value("/ip service\nset www-ssl certificate=mgmt-cert disabled=no\n", "management.https_enabled")).toBe(true);
  });

  it("does not call management restricted while a core service stays open", () => {
    const raw = "/ip service\nset telnet disabled=yes\nset ssh port=22\nset winbox address=10.9.9.0/24\n";
    expect(value(raw, "management.mgmt_acl_applied")).toBe(false);
  });

  it("calls management restricted only when every enabled core service carries address=", () => {
    const raw = "/ip service\nset telnet disabled=yes\nset www disabled=yes\nset api disabled=yes\nset ssh address=10.10.0.0/24\nset winbox address=10.10.0.0/24\nset api-ssl address=10.10.0.0/24 disabled=no\n";
    expect(value(raw, "management.mgmt_acl_applied")).toBe(true);
  });

  it("treats address=0.0.0.0/0 as no restriction at all", () => {
    expect(value("/ip service\nset ssh address=0.0.0.0/0\n", "management.mgmt_acl_applied")).toBe(false);
  });
});

describe("RouterOS local users", () => {
  it("counts a passwordless and a cleartext account as weak credentials", () => {
    const p = params('/user\nadd group=full name=admin password=""\nadd group=full name=support password=branch123\n');
    expect(p["auth.weak_password_hashes"].value).toBe(2);
    expect(p["auth.weak_local_users"].value).toEqual(["admin", "support"]);
    // the critical control used to pass on exactly this device
    expect(evalCheck(RULE_INDEX["NS-AUTH-003"].check, { params: p }).status).toBe("fail");
  });

  it("lists accounts that may log in from anywhere and skips restricted or disabled ones", () => {
    const p = params("/user\nadd group=full name=netops address=10.10.0.0/24\nadd group=read name=noc\nadd group=full name=legacy disabled=yes\n");
    expect(p["management.unrestricted_admins"].value).toEqual(["noc"]);
    expect(p["auth.local_users"].value).toEqual(["netops", "noc", "legacy"]);
  });
});

describe("RouterOS firewall", () => {
  it("does not read 'drop invalid' as the terminating deny", () => {
    const p = params("/ip firewall filter\nadd action=accept chain=input connection-state=established,related\nadd action=drop chain=input connection-state=invalid\n");
    expect(p["acl.default_deny"].value).toBe(false);
    expect(p["acl.default_deny"].source).toBe("default");
    expect(p["acl.external_ingress_filter"].value).toBe(true);
  });

  it("accepts an interface-scoped catch-all drop as the terminating deny", () => {
    expect(value('/ip firewall filter\nadd action=drop chain=input in-interface-list=WAN log=yes comment="deny wan"\n', "acl.default_deny")).toBe(true);
  });

  it("ignores disabled rules", () => {
    const p = params("/ip firewall filter\nadd action=drop chain=input disabled=yes\nadd action=accept chain=input src-address=10.0.0.0/8\n");
    expect(p["acl.default_deny"].value).toBe(false);
    expect(p["acl.count"].value).toBe(1);
  });

  it("reports an empty rulebase as no default deny rather than leaving it unassessed", () => {
    const p = params("/ip service\nset telnet disabled=no\n");
    expect(p["acl.default_deny"].value).toBe(false);
    expect(p["acl.external_ingress_filter"].value).toBe(false);
  });

  it("recognises the staged address-list brute-force guard as a lockout control", () => {
    const raw = "/ip firewall filter\nadd action=add-src-to-address-list address-list=ssh-stage1 address-list-timeout=1m chain=input connection-state=new dst-port=22 protocol=tcp\n";
    expect(value(raw, "auth.login_lockout")).toBe(true);
  });
});

describe("RouterOS routing protocols", () => {
  it("fails BGP authentication when any peer is missing a key and names it", () => {
    const raw = "/routing bgp peer\nadd name=upstream-a remote-address=203.0.113.17 remote-as=64500 tcp-md5-key=secret\nadd name=upstream-b remote-address=198.51.100.2 remote-as=64501\n";
    const p = params(raw);
    expect(p["routing.bgp_auth"].value).toBe(false);
    expect(p["routing.bgp_unauth_neighbors"].value).toEqual(["upstream-b"]);
  });

  it("passes BGP authentication when every peer has a key", () => {
    expect(value("/routing bgp connection\nadd name=peer-core remote.address=10.255.0.1 remote.as=65000 tcp-md5-key=k\n", "routing.bgp_auth")).toBe(true);
  });

  it("fails OSPF authentication when any interface template is unauthenticated", () => {
    const raw = "/routing ospf interface-template\nadd area=backbone auth=sha256 auth-id=1 auth-key=k interfaces=ether1\nadd area=backbone interfaces=ether2\n";
    expect(value(raw, "routing.ospf_auth")).toBe(false);
  });

  it("reads the RouterOS 6 per-interface OSPF authentication form", () => {
    const raw = "/routing ospf interface\nadd interface=ether1 authentication=md5 authentication-key=k authentication-key-id=1\n";
    const p = params(raw);
    expect(p["routing.ospf_auth"].value).toBe(true);
    expect(p["routing.ospf_interfaces"].value).toEqual(["ether1"]);
  });
});

describe("RouterOS SNMP", () => {
  it("does not count an SNMPv3 USM entry as a v1/v2c community", () => {
    const raw = "/snmp\nset enabled=yes\n/snmp community\nset [ find default=yes ] addresses=10.10.0.0/24 authentication-protocol=SHA256 encryption-protocol=AES name=nsops security=private\n";
    const p = params(raw);
    expect(p["snmp.v1v2c_communities"]).toBeUndefined();
    expect(p["snmp.v3_priv"].value).toBe(true);
    expect(evalCheck(RULE_INDEX["NS-SNMP-003"].check, { params: p }).status).toBe("pass");
  });

  it("drops to authNoPriv when a USM entry has no encryption", () => {
    const raw = "/snmp community\nadd name=ro-user security=authorized authentication-protocol=SHA1\n";
    const p = params(raw);
    expect(p["snmp.v3_enabled"].value).toBe(true);
    expect(p["snmp.v3_priv"].value).toBe(false);
  });

  it("fails the community ACL when any community is left open", () => {
    const raw = "/snmp community\nset [ find default=yes ] addresses=10.9.9.0/24 name=public\nadd addresses=0.0.0.0/0 name=nocpoll\n";
    expect(value(raw, "snmp.community_acl")).toBe(false);
  });

  it("flags a default trap community and ignores a null trap target", () => {
    const p = params("/snmp\nset enabled=yes trap-community=public trap-target=0.0.0.0 trap-version=2\n");
    expect(p["snmp.default_communities"].value).toEqual(["public"]);
    expect(p["snmp.default_community_ids"].value).toEqual(["public"]);
    expect(p["snmp.trap_hosts"]).toBeUndefined();
  });
});

describe("RouterOS time, services and crypto", () => {
  it("does not list NTP servers while the client is disabled", () => {
    expect(value("/system ntp client\nset enabled=no primary-ntp=10.9.9.10 secondary-ntp=10.9.9.11\n", "time.ntp_servers")).toEqual([]);
  });

  it("reads the RouterOS 6 SNTP client menu", () => {
    const r = parse("/system sntp client\nset enabled=yes primary-ntp=10.9.9.10\n");
    expect(r.model.params["time.ntp_servers"].value).toEqual(["10.9.9.10"]);
    expect(r.unrecognized).toHaveLength(0);
  });

  it("tracks per-server NTP authentication on RouterOS 7", () => {
    const authed = params("/system ntp client\nset enabled=yes\n/system ntp client servers\nadd address=10.10.50.10 auth-key=1\n");
    expect(authed["time.ntp_authentication"].value).toBe(true);
    const plain = params("/system ntp client\nset enabled=yes\n/system ntp client servers\nadd address=10.10.50.10\n");
    expect(plain["time.unauthenticated_ntp_ids"].value).toEqual(["10.10.50.10"]);
  });

  it("treats a named neighbor-discovery interface list as a restriction", () => {
    expect(value("/ip neighbor discovery-settings\nset discover-interface-list=MGMT\n", "services.lldp_enabled")).toBe(false);
    expect(value("/ip neighbor discovery-settings\nset discover-interface-list=all\n", "services.lldp_enabled")).toBe(true);
    expect(value("/ip neighbor discovery-settings\nset discover-interface-list=none\n", "services.lldp_enabled")).toBe(false);
  });

  it("assumes the services a factory RouterOS exposes when /export prints nothing about them", () => {
    const p = params("/ip service\nset telnet disabled=yes\n");
    expect(p["services.misc_enabled"].value).toEqual(["mac-server", "mac-winbox", "bandwidth-server"]);
    expect(p["services.misc_enabled"].source).toBe("default");
  });

  it("keeps the remaining defaults when only one tool is turned off", () => {
    const p = params("/tool mac-server\nset allowed-interface-list=none\n");
    expect(p["services.misc_enabled"].value).toEqual(["mac-winbox", "bandwidth-server"]);
    expect(p["services.misc_enabled"].source).toBe("parser");
  });

  it("flags the SMB server and MikroTik cloud DDNS", () => {
    const p = params("/ip smb\nset enabled=yes\n/ip cloud\nset ddns-enabled=yes\n/tool mac-server\nset allowed-interface-list=none\n/tool mac-server mac-winbox\nset allowed-interface-list=none\n/tool bandwidth-server\nset enabled=no\n");
    expect(p["services.misc_enabled"].value).toEqual(["smb", "cloud-ddns"]);
  });

  it("reads source routing and the SSH none-cipher from their own knobs", () => {
    expect(value("/ip settings\nset accept-source-route=yes\n", "services.ip_source_routing")).toBe(true);
    expect(value("/ip ssh\nset strong-crypto=yes allow-none-crypto=yes\n", "crypto.strong_crypto")).toBe(false);
  });

  it("counts only a RADIUS server that serves login as an administrator AAA source", () => {
    expect(value("/radius\nadd address=10.10.50.30 service=ppp,hotspot secret=x\n", "auth.remote_auth_servers")).toBeUndefined();
    expect(value("/radius\nadd address=10.10.50.30 service=login secret=x\n", "auth.remote_auth_servers")).toEqual(["10.10.50.30"]);
  });

  it("does not claim a banner when the note is hidden at login", () => {
    expect(value('/system note\nset note="Authorised access only." show-at-login=no\n', "management.login_banner")).toBe(false);
    expect(value('/system note\nset note="Authorised access only."\n', "management.login_banner")).toBe(true);
  });
});

describe("RouterOS identity", () => {
  it("prefers the address an operator marked as management", () => {
    const raw = "/ip address\nadd address=192.168.88.1/24 comment=\"lan gateway\" interface=bridge1 network=192.168.88.0\nadd address=203.0.113.18/29 comment=\"wan\" interface=ether1-wan network=203.0.113.16\nadd address=10.9.9.18/24 comment=\"management\" interface=ether2-lan network=10.9.9.0\n";
    expect(parse(raw).identity.mgmtIp).toBe("10.9.9.18");
  });

  it("skips a public uplink address when nothing is marked", () => {
    expect(parse("/ip address\nadd address=203.0.113.18/29 interface=ether1\nadd address=10.22.9.1/24 interface=bridge\n").identity.mgmtIp).toBe("10.22.9.1");
  });

  it("does not treat the factory identity as a configured hostname", () => {
    const p = params("/system identity\nset name=MikroTik\n");
    expect(p["identity.hostname_set"].value).toBe(false);
    expect(params("/system identity\nset name=PUNE-BR-01\n")["identity.hostname_set"].value).toBe(true);
  });

  it("flags the software generation and the device role", () => {
    expect(value(`${HEADER6}/system identity\nset name=A\n`, "identity.routeros_7plus")).toBe(false);
    expect(value(`${HEADER7}/system identity\nset name=A\n`, "identity.routeros_7plus")).toBe(true);
    expect(parse(`${HEADER7}# model = CRS354-48G-4S+\n`).identity.role).toBe("switch");
    expect(parse(`${HEADER7}/interface wireless security-profiles\nset [ find default=yes ] mode=none\n`).identity.role).toBe("wireless router");
  });
});

describe("RouterOS input formats", () => {
  it("parses the RouterOS 7 slash-separated CLI form", () => {
    const raw = "/ip/service/set telnet disabled=yes\n/ip/service/set ssh address=10.10.0.0/24\n/system/identity/set name=DC1-MT\n";
    const r = parse(raw);
    expect(r.model.params["management.telnet_enabled"].value).toBe(false);
    expect(r.identity.hostname).toBe("DC1-MT");
    expect(r.unrecognized).toHaveLength(0);
    expect(detectVendor(raw).vendor).toBe("mikrotik-routeros");
  });

  it("detects a compact export whose only block headers are bare menus", () => {
    expect(detectVendor("/user\nadd group=full name=netops\n/interface\nprint\n/tool romon\nset enabled=no\n").vendor).toBe("mikrotik-routeros");
  });

  it("keeps the bundled sample fully recognised", () => {
    const r = parse(SAMPLE_INDEX.routeros.raw);
    expect(r.unrecognized).toHaveLength(0);
    expect(r.recognized).toBe(r.meaningfulLines);
  });
});

describe("RouterOS remediation syntax", () => {
  const model = (extra: Record<string, ParamValue>): SecurityBaselineModel => ({
    params: Object.fromEntries(Object.entries(extra).map(([key, value]) => [key, { key, value, evidence: [], source: "parser" as const }])),
  });

  it("uses /routing bgp peer on RouterOS 6 and /routing bgp connection on RouterOS 7", () => {
    const v6 = render("NS-RTG-001", model({ "identity.routeros_7plus": false, "routing.bgp_unauth_neighbors": ["upstream-b"] }));
    expect(v6).toContain("/routing bgp peer set [ find name=upstream-b ] tcp-md5-key=");
    expect(v6).not.toContain("/routing bgp connection set");
    const v7 = render("NS-RTG-001", model({ "identity.routeros_7plus": true, "routing.bgp_unauth_neighbors": ["peer-core"] }));
    expect(v7).toContain("/routing bgp connection set [ find name=peer-core ] tcp-md5-key=");
    expect(v7).not.toContain("/routing bgp peer set");
  });

  it("uses the OSPF menu that exists in each generation", () => {
    expect(render("NS-RTG-002", model({ "identity.routeros_7plus": false }))).toContain("/routing ospf interface set [ find ] authentication=md5");
    expect(render("NS-RTG-002", model({ "identity.routeros_7plus": true }))).toContain("/routing ospf interface-template set [ find ] auth=sha256");
  });

  it("uses primary-ntp on RouterOS 6, which has no servers= property", () => {
    const v6 = render("NS-TIME-001", model({ "identity.routeros_7plus": false }));
    expect(v6).toContain("/system ntp client set enabled=yes primary-ntp=10.10.50.10 secondary-ntp=10.10.50.11");
    expect(v6).not.toContain("servers add address=");
    expect(render("NS-TIME-001", model({ "identity.routeros_7plus": true }))).toContain("/system ntp client servers add address=10.10.50.10");
  });

  it("appends the default deny instead of asking for a place-before that has no value", () => {
    const out = render("NS-ACL-003", model({}));
    expect(out).not.toContain("place-before=<last>");
    expect(out).toContain("/ip firewall filter add chain=input action=drop");
  });

  it("selects logging actions and SNMP communities with an unambiguous find", () => {
    expect(render("NS-LOG-002", model({}))).toContain("/system logging action set [ find name=memory ]");
    expect(render("NS-LOG-006", model({}))).toContain("/system logging action set [ find name=siem ]");
    expect(render("NS-SNMP-002", model({ "snmp.rw_communities": ["private"] }))).toContain("/snmp community set [ find name=private ] write-access=no");
  });

  it("picks the SNMPv3 authentication protocol the generation supports", () => {
    expect(render("NS-SNMP-001", model({ "identity.routeros_7plus": false, "snmp.default_community_ids": ["public"] }))).toContain("authentication-protocol=SHA1");
    expect(render("NS-SNMP-001", model({ "identity.routeros_7plus": true, "snmp.default_community_ids": ["public"] }))).toContain("authentication-protocol=SHA256");
  });

  it("restricts every account the parser found unrestricted", () => {
    const out = render("NS-MGMT-006", model({ "management.unrestricted_admins": ["admin", "support"] }));
    expect(out).toContain("/user set [ find name=admin ] address=10.10.0.0/24");
    expect(out).toContain("/user set [ find name=support ] address=10.10.0.0/24");
    expect(out).toContain("/ip service set api-ssl address=10.10.0.0/24");
  });

  it("keeps every RouterOS template free of other vendors' comment markers", () => {
    for (const rule of Object.values(RULE_INDEX)) {
      const template = rule.remediation["mikrotik-routeros"];
      if (!template) continue;
      for (const line of template.split("\n")) {
        expect(line.trimStart().startsWith("!"), `${rule.id}: '!' is not a RouterOS comment`).toBe(false);
      }
    }
  });
});
