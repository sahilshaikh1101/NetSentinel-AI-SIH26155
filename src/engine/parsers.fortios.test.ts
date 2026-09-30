import { describe, expect, it } from "vitest";
import { parseConfig } from "./parsers";
import { fortiProduct } from "./parsers/fortios";
import { evaluateDevice } from "./rules/evaluate";
import { RULES } from "./rules/library";
import { DEFAULT_REMEDIATION_SETTINGS, renderRemediation } from "./rules/remediation";
import { SAMPLE_FORTIOS } from "./samples/fortios";
import type { Finding, ParamValue } from "./types";

const settings = DEFAULT_REMEDIATION_SETTINGS;
const HEADER_74 = "#config-version=FGT60F-7.4.2-FW-build2571-240304:opmode=0:vdom=0:user=admin\n";
const HEADER_64 = "#config-version=FWF60E-6.4.15-FW-build2201-231211:opmode=0:vdom=0:user=admin\n";

const parse = (raw: string, header = HEADER_74) => parseConfig(header + raw, "fortinet-fortios").result;
const val = (raw: string, key: string, header = HEADER_74): ParamValue | undefined => parse(raw, header).model.params[key]?.value;
const source = (raw: string, key: string) => parse(raw).model.params[key]?.source;
const findings = (raw: string, header = HEADER_74): Record<string, Finding> => {
  const r = parse(raw, header);
  return Object.fromEntries(evaluateDevice("d", r.model, "fortinet-fortios", RULES, { frameworks: ["cis", "nist", "stig", "iso"], settings, context: { osVersion: r.identity.osVersion } }).map((f) => [f.ruleId, f]));
};
const remediation = (raw: string, ruleId: string, header = HEADER_74) => renderRemediation(RULES.find((r) => r.id === ruleId)!, "fortinet-fortios", parse(raw, header).model, settings, { osVersion: parse(raw, header).identity.osVersion });

const GLOBAL_TELNET_ENABLE = "config system global\n    set admin-telnet enable\n    set hostname \"FW\"\nend\n";
const IFACE = (name: string, allow: string, extra = "") => `config system interface\n    edit "${name}"\n        set ip 10.0.0.1 255.255.255.0\n        set allowaccess ${allow}\n${extra}    next\nend\n`;
const ADMIN = (name: string, body: string) => `    edit "${name}"\n${body}        set accprofile "super_admin"\n        set password ENC SH2abc\n    next\n`;

describe("FortiOS multi-VDOM structure", () => {
  const multi = `#config-version=FG100F-7.0.12-FW-build0523-230704:opmode=1:vdom=1:user=admin
config vdom
edit root
next
edit DMZ
next
end
config global
config system global
    set admin-telnet enable
    set hostname "FW-CORE-01"
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.1.1.1 255.255.255.0
        set allowaccess ping https ssh telnet
    next
end
end
config vdom
edit root
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
end
next
edit DMZ
config firewall policy
    edit 1
        set srcintf "port3"
        set dstintf "port4"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
end
config system foo-bar
    set something odd
end
next
end
`;
  const r = parseConfig(multi, "fortinet-fortios").result;
  const p = r.model.params;
  it("treats config global / config vdom > edit as transparent scopes", () => {
    expect(r.identity.hostname).toBe("FW-CORE-01");
    expect(p["identity.hostname_set"].value).toBe(true);
    expect(p["management.telnet_enabled"].value).toBe(true);
    expect(p["management.telnet_enabled"].source).toBe("parser");
    expect(p["acl.count"].value).toBe(2); // policy 1 exists in both VDOMs
    expect(r.identity.extra).toMatchObject({ vdom_mode: "multi-vdom", opmode: "transparent", vdoms: "root, DMZ", product: "FortiGate-100F" });
  });
  it("leaves unknown sections unrecognised instead of hiding them behind the root name", () => {
    expect(r.unrecognized.map((u) => u.text)).toEqual(["set something odd"]);
    expect(r.unrecognized[0].context).toBe("config system foo-bar [vdom DMZ]");
  });
});

describe("FortiOS Telnet / HTTP detection", () => {
  it("does not flag Telnet on the default 'admin-telnet enable' alone", () => {
    expect(val(GLOBAL_TELNET_ENABLE + IFACE("port1", "ping https ssh"), "management.telnet_enabled")).toBe(false);
    expect(source(GLOBAL_TELNET_ENABLE + IFACE("port1", "ping https ssh"), "management.telnet_enabled")).toBe("default");
    expect(findings(GLOBAL_TELNET_ENABLE)["NS-MGMT-001"].status).toBe("pass");
  });
  it("lets 'admin-telnet disable' override an interface that still lists telnet", () => {
    const raw = "config system global\n    set admin-telnet disable\nend\n" + IFACE("wan1", "ping https telnet");
    expect(val(raw, "management.telnet_enabled")).toBe(false);
  });
  it("detects Telnet and HTTP over IPv6 (ip6-allowaccess)", () => {
    const raw = IFACE("port1", "ping", "        config ipv6\n            set ip6-allowaccess ping https ssh telnet http\n        end\n");
    expect(val(raw, "management.telnet_enabled")).toBe(true);
    expect(val(raw, "management.http_enabled")).toBe(true);
    expect(val(raw, "management.telnet_interfaces6")).toEqual(["port1"]);
    expect(val(raw, "management.telnet_interfaces")).toBeUndefined();
    const fix = remediation(raw, "NS-MGMT-001");
    expect(fix).toContain('edit "port1"');
    expect(fix).toContain("unselect ip6-allowaccess telnet");
    expect(fix).toContain("set admin-telnet disable");
  });
  it("renders per-interface 'unselect' fixes that keep fgfm/capwap", () => {
    const raw = IFACE("internal", "ping https ssh http fgfm capwap") + IFACE("wan1", "ping https ssh telnet http");
    const telnet = remediation(raw, "NS-MGMT-001");
    expect(telnet).toContain('edit "wan1"\n        unselect allowaccess telnet');
    expect(telnet).not.toContain('edit "internal"');
    expect(telnet).not.toContain("<interface>");
    expect(telnet).not.toContain("set allowaccess");
    const http = remediation(raw, "NS-MGMT-003");
    expect(http).toContain('edit "internal"\n        unselect allowaccess http');
    expect(http).toContain('edit "wan1"\n        unselect allowaccess http');
  });
});

describe("FortiOS management ACL (trusthost / local-in-policy)", () => {
  const ANY = "        set trusthost1 0.0.0.0 0.0.0.0\n        set trusthost2 0.0.0.0 0.0.0.0\n        set ip6-trusthost1 ::/0\n";
  it("ignores the default any-trusthosts of a full-configuration dump", () => {
    const raw = `config system admin\n${ADMIN("admin", ANY)}end\n`;
    expect(val(raw, "management.mgmt_acl_applied")).toBe(false);
    expect(val(raw, "management.unrestricted_admins")).toEqual(["admin"]);
    expect(findings(raw)["NS-MGMT-006"].status).toBe("fail");
  });
  it("requires every local admin to be restricted, skipping wildcard remote accounts", () => {
    const one = `config system admin\n${ADMIN("netops", "        set trusthost1 10.10.0.0 255.255.255.0\n")}${ADMIN("helpdesk", "")}end\n`;
    expect(val(one, "management.mgmt_acl_applied")).toBe(false);
    expect(val(one, "management.unrestricted_admins")).toEqual(["helpdesk"]);
    expect(remediation(one, "NS-MGMT-006")).toContain('edit "helpdesk"\n        set trusthost1 10.10.0.0 255.255.255.0');
    expect(remediation(one, "NS-MGMT-006")).not.toContain('edit "admin"');
    const all = `config system admin\n${ADMIN("netops", "        set trusthost1 10.10.0.0 255.255.255.0\n")}${ADMIN("secops", "        set ip6-trusthost1 2001:db8:10::/64\n")}    edit "tac-wild"\n        set remote-auth enable\n        set wildcard enable\n        set remote-group "ADMINS"\n    next\nend\n`;
    expect(val(all, "management.mgmt_acl_applied")).toBe(true);
    expect(findings(all)["NS-MGMT-006"].status).toBe("pass");
  });
  it("covers API users through config trusthost", () => {
    const raw = `config system admin\n${ADMIN("netops", "        set trusthost1 10.10.0.0 255.255.255.0\n")}end\nconfig system api-user\n    edit "ansible"\n        set api-key ENC x\n        set accprofile "api-ro"\n    next\n    edit "backup"\n        set api-key ENC y\n        config trusthost\n            edit 1\n                set ipv4-trusthost 10.10.0.0 255.255.255.0\n            next\n        end\n    next\nend\n`;
    expect(val(raw, "management.mgmt_acl_applied")).toBe(false);
    expect(val(raw, "management.unrestricted_api_users")).toEqual(["ansible"]);
    expect(remediation(raw, "NS-MGMT-006")).toContain('config system api-user\n    edit "ansible"');
  });
  it("accepts a local-in-policy fence that covers every management interface", () => {
    const admins = `config system admin\n${ADMIN("admin", "")}end\n`;
    const policy = (intf: string) => `config firewall local-in-policy\n    edit 1\n        set intf "port3"\n        set srcaddr "ADMIN-NET"\n        set dstaddr "all"\n        set action accept\n        set service "HTTPS" "SSH"\n        set schedule "always"\n    next\n    edit 2\n        set intf "${intf}"\n        set srcaddr "all"\n        set dstaddr "all"\n        set action deny\n        set service "HTTPS" "SSH"\n        set schedule "always"\n    next\nend\n`;
    const ifaces = IFACE("port3", "https ssh") + IFACE("mgmt", "https ssh");
    expect(val(admins + ifaces + policy("any"), "management.mgmt_acl_applied")).toBe(true);
    expect(val(admins + ifaces + policy("port3"), "management.mgmt_acl_applied")).toBe(false);
  });
  it("still passes the bundled sample only when every admin is restricted", () => {
    const { result } = parseConfig(SAMPLE_FORTIOS, "fortinet-fortios");
    expect(result.model.params["management.mgmt_acl_applied"].value).toBe(false);
    expect(result.model.params["management.unrestricted_admins"].value).toEqual(["helpdesk"]);
    expect(result.unrecognized.length).toBe(0);
  });
  it("evaluates the bundled sample to the expected verdicts", () => {
    const f = findings(SAMPLE_FORTIOS, "");
    const expected: Record<string, Finding["status"]> = {
      "NS-MGMT-001": "fail", "NS-MGMT-003": "fail", "NS-MGMT-004": "fail", "NS-MGMT-006": "fail", "NS-AUTH-004": "fail", "NS-AUTH-005": "fail",
      "NS-AUTH-007": "fail", "NS-AUTH-010": "fail", "NS-LOG-001": "pass", "NS-LOG-002": "pass", "NS-LOG-005": "pass", "NS-LOG-008": "fail",
      "NS-TIME-001": "pass", "NS-TIME-002": "fail", "NS-TIME-003": "pass", "NS-SNMP-001": "fail", "NS-SNMP-004": "pass", "NS-RTG-001": "pass",
      "NS-RTG-002": "pass", "NS-ACL-002": "fail", "NS-ACL-003": "pass", "NS-CRY-001": "fail", "NS-CRY-002": "fail", "NS-CRY-003": "pass",
    };
    expect(Object.fromEntries(Object.keys(expected).map((k) => [k, f[k].status]))).toEqual(expected);
  });
});

describe("FortiOS remote administrator authentication", () => {
  const RADIUS = "config user radius\n    edit \"GUEST-RADIUS\"\n        set server \"192.168.12.60\"\n        set secret ENC x\n    next\nend\nconfig user tacacs+\n    edit \"ISE\"\n        set server \"10.10.50.30\"\n        set secondary-server \"10.10.51.30\"\n        set key ENC y\n    next\nend\nconfig user group\n    edit \"GUEST-WIFI\"\n        set member \"GUEST-RADIUS\"\n    next\n    edit \"NOC-ADMINS\"\n        set member \"ISE\"\n    next\nend\n";
  it("does not treat user servers as admin AAA unless an admin is bound to them", () => {
    const raw = `config system admin\n${ADMIN("admin", "")}end\n` + RADIUS;
    expect(val(raw, "auth.aaa_enabled")).toBe(false);
    expect(val(raw, "auth.remote_auth_servers")).toEqual([]);
    const f = findings(raw);
    expect(f["NS-AUTH-004"].status).toBe("fail");
    expect(f["NS-AUTH-005"].status).toBe("fail");
    expect(remediation(raw, "NS-AUTH-004")).toContain('edit "admin"\n        set remote-auth enable\n        set remote-group "ADMIN-TACACS"');
    expect(remediation(raw, "NS-AUTH-004")).toContain('config user group\n    edit "ADMIN-TACACS"');
  });
  it("resolves the servers of the admin's remote-group only", () => {
    const raw = `config system admin\n    edit "noc"\n        set remote-auth enable\n        set remote-group "NOC-ADMINS"\n        set accprofile "super_admin"\n    next\nend\n` + RADIUS;
    expect(val(raw, "auth.aaa_enabled")).toBe(true);
    expect(val(raw, "auth.aaa_authentication_login")).toBe(true);
    expect(val(raw, "auth.remote_auth_servers")).toEqual(["10.10.50.30", "10.10.51.30"]);
    expect(findings(raw)["NS-AUTH-005"].status).toBe("pass");
  });
  it("counts SAML SSO for administrators", () => {
    expect(val("config system saml\n    set status enable\n    set idp-entity-id \"https://idp\"\nend\n", "auth.aaa_enabled")).toBe(true);
  });
});

describe("FortiOS logging destinations", () => {
  const SYSLOG = "config log syslogd setting\n    set status enable\n    set server \"10.1.1.1\"\n    set mode udp\nend\n";
  it("keeps status per syslogd instance: syslogd2 'status disable' never wipes the list", () => {
    const off = "config log syslogd2 setting\n    set status disable\nend\nconfig log syslogd3 setting\n    set status disable\nend\n";
    expect(val(SYSLOG + off, "logging.remote_hosts")).toEqual(["10.1.1.1"]);
    expect(val(off + SYSLOG, "logging.remote_hosts")).toEqual(["10.1.1.1"]);
    expect(val("config log syslogd2 setting\n    set status disable\n    set server \"10.9.9.9\"\nend\n" + SYSLOG, "logging.remote_hosts")).toEqual(["10.1.1.1"]);
    expect(findings(SYSLOG + off)["NS-LOG-001"].status).toBe("pass");
  });
  it("models FortiAnalyzer, FortiCloud and per-VDOM override destinations", () => {
    const faz = "config log fortianalyzer setting\n    set status enable\n    set server \"10.10.50.70\"\n    set reliable enable\n    set enc-algorithm high\nend\n";
    expect(val(faz, "logging.remote_hosts")).toEqual(["10.10.50.70 (FortiAnalyzer)"]);
    expect(val(faz, "logging.remote_secure")).toBe(true);
    expect(val(faz.replace("enc-algorithm high", "enc-algorithm disable"), "logging.remote_secure")).toBe(false);
    expect(val("config log fortiguard setting\n    set status enable\n    set upload-option realtime\nend\n", "logging.remote_hosts")).toEqual(["FortiGate Cloud (fortiguard)"]);
    const override = (on: string) => `config log syslogd override-setting\n    set override ${on}\n    set status enable\n    set server "172.16.20.250"\n    set mode udp\nend\n`;
    expect(val(override("enable"), "logging.remote_hosts")).toEqual(["172.16.20.250"]);
    expect(val(override("disable"), "logging.remote_hosts")).toBeUndefined();
  });
  it("treats 'mode reliable' as encrypted only with an enc-algorithm", () => {
    const tcp = "config log syslogd setting\n    set status enable\n    set server \"10.1.1.1\"\n    set mode reliable\n    set enc-algorithm disable\nend\n";
    expect(val(tcp, "logging.remote_secure")).toBe(false);
    expect(val(tcp.replace("    set enc-algorithm disable\n", ""), "logging.remote_secure")).toBe(false);
    expect(val(tcp.replace("enc-algorithm disable", "enc-algorithm high"), "logging.remote_secure")).toBe(true);
    expect(val(SYSLOG, "logging.remote_secure")).toBe(false);
    expect(val(SYSLOG + tcp.replace("enc-algorithm disable", "enc-algorithm high").replace("syslogd setting", "syslogd2 setting"), "logging.remote_secure")).toBe(false);
  });
  it("recognises 7.0+ source binding via interface-select-method / interface", () => {
    expect(val(SYSLOG.replace("    set mode udp\n", "    set interface-select-method specify\n    set interface \"port3\"\n"), "logging.source_interface")).toBe(true);
    expect(val(SYSLOG, "logging.source_interface")).toBeUndefined();
  });
  it("uses last-wins no more for local buffers and defaults memory logging to enabled", () => {
    const diskless = "config log memory setting\n    set status enable\nend\nconfig log disk setting\n    set status disable\nend\n";
    expect(val(diskless, "logging.buffered")).toBe(true);
    expect(findings(diskless)["NS-LOG-002"].status).toBe("pass");
    expect(val(diskless.replace("status enable", "status disable"), "logging.buffered")).toBe(false);
    expect(val("", "logging.buffered")).toBe(true);
    expect(source("", "logging.buffered")).toBe("default");
  });
  it("treats 'event disable' as the eventfilter master switch and maps cli-audit-log to config-change logging", () => {
    expect(val("config log eventfilter\n    set event disable\n    set system enable\n    set user enable\nend\n", "logging.login_events")).toBe(false);
    expect(val("config log eventfilter\n    set event enable\n    set system disable\nend\n", "logging.login_events")).toBe(true);
    expect(val("", "logging.login_events")).toBe(true);
    const audit = "config system global\n    set cli-audit-log disable\nend\n";
    expect(val(audit, "logging.config_changes")).toBe(false);
    expect(val(audit, "logging.login_events")).toBe(true);
  });
});

describe("FortiOS routing protocols", () => {
  const BGP = (neighbors: string) => `config router bgp\n    set as 65000\n    set router-id 10.0.0.1\n    config neighbor-group\n        edit "UPSTREAM"\n            set remote-as 65001\n            set password ENC grp\n        next\n    end\n${neighbors}end\n`;
  it("ignores the full-configuration BGP/OSPF placeholders (as 0, router-id 0.0.0.0)", () => {
    const raw = "config router bgp\n    set as 0\n    set router-id 0.0.0.0\n    config redistribute \"connected\"\n        set status disable\n    end\nend\nconfig router ospf\n    set router-id 0.0.0.0\n    config redistribute \"connected\"\n        set status disable\n    end\nend\n";
    expect(val(raw, "routing.bgp_configured")).toBe(false);
    expect(val(raw, "routing.ospf_configured")).toBe(false);
    const f = findings(raw);
    expect(f["NS-RTG-001"].status).toBe("pass");
    expect(f["NS-RTG-002"].status).toBe("pass");
  });
  it("requires every BGP neighbor to authenticate, honouring neighbor-group passwords", () => {
    const inherited = BGP("    config neighbor\n        edit \"10.60.1.1\"\n            set remote-as 65001\n            set neighbor-group \"UPSTREAM\"\n        next\n    end\n");
    expect(val(inherited, "routing.bgp_auth")).toBe(true);
    expect(val(inherited, "routing.bgp_asn")).toBe("65000");
    const mixed = BGP("    config neighbor\n        edit \"10.60.1.1\"\n            set remote-as 65001\n            set password ENC own\n        next\n        edit \"10.60.1.2\"\n            set remote-as 65001\n        next\n    end\n");
    expect(val(mixed, "routing.bgp_auth")).toBe(false);
    expect(val(mixed, "routing.bgp_unauth_neighbors")).toEqual(["10.60.1.2"]);
    expect(findings(mixed)["NS-RTG-001"].status).toBe("fail");
    const fix = remediation(mixed, "NS-RTG-001");
    expect(fix).toContain('edit "10.60.1.2"\n            set password <shared-secret>');
    expect(fix).not.toContain("<peer>");
  });
  it("accepts area-level message-digest, rejects text authentication and renders 7.x syntax", () => {
    const OSPF = (auth: string) => `config router ospf\n    set router-id 10.0.0.1\n    config area\n        edit 0.0.0.0\n            set authentication ${auth}\n        next\n    end\n    config ospf-interface\n        edit "ospf-port2"\n            set interface "port2"\n            config md5-keys\n                edit 1\n                    set key-string ENC k\n                next\n            end\n        next\n    end\n    config network\n        edit 1\n            set prefix 10.60.2.0 255.255.255.0\n        next\n    end\nend\n`;
    expect(val(OSPF("message-digest"), "routing.ospf_configured")).toBe(true);
    expect(val(OSPF("message-digest"), "routing.ospf_auth")).toBe(true);
    expect(val(OSPF("text"), "routing.ospf_auth")).toBe(false);
    expect(val(OSPF("none"), "routing.ospf_auth")).toBe(false);
    expect(findings(OSPF("text"))["NS-RTG-002"].status).toBe("fail");
    const fix = remediation(OSPF("text"), "NS-RTG-002");
    expect(fix).toContain('edit "ospf-port2"\n            set authentication message-digest\n            config md5-keys');
    expect(fix).toContain("edit 0.0.0.0\n            set authentication message-digest");
    expect(fix).not.toMatch(/^\s+set (md5-key|authentication md5)/m); // legacy 6.2 form only appears in a comment
  });
});

describe("FortiOS cryptography", () => {
  it("keeps the weakest TLS version across the admin GUI, system default and SSL-VPN", () => {
    const gui = "config system global\n    set admin-https-ssl-versions tlsv1-1 tlsv1-2 tlsv1-3\n    set ssl-min-proto-version TLSv1-2\nend\nconfig vpn ssl settings\n    set ssl-min-proto-ver tls1-2\nend\n";
    expect(val(gui, "crypto.tls_min_version")).toBe("1.1");
    expect(findings(gui)["NS-CRY-003"].status).toBe("fail");
    const vpn = "config system global\n    set ssl-min-proto-version TLSv1-2\n    set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend\nconfig vpn ssl settings\n    set ssl-min-proto-ver tls1-1\nend\n";
    expect(val(vpn, "crypto.tls_min_version")).toBe("1.1");
    expect(val("config system global\n    set admin-https-ssl-versions tlsv1-2 tlsv1-3\n    set ssl-min-proto-version TLSv1-2\nend\n", "crypto.tls_min_version")).toBe("1.2");
  });
  it("flags explicit weak SSH algorithm lists even when strong-crypto is enabled afterwards", () => {
    const mac = "config system global\n    set ssh-mac-algo hmac-sha1 hmac-sha2-256-etm@openssh.com\n    set strong-crypto enable\nend\n";
    expect(val(mac, "crypto.strong_crypto")).toBe(false);
    expect(findings(mac)["NS-CRY-001"].status).toBe("fail");
    expect(val("config system ssh-config\n    set ssh-enc-algo aes128-cbc aes256-gcm@openssh.com\nend\n", "crypto.strong_crypto")).toBe(false);
    expect(val("config system global\n    set ssh-kex-algo diffie-hellman-group1-sha1\nend\n", "crypto.strong_crypto")).toBe(false);
    expect(val("config system global\n    set strong-crypto enable\n    set ssh-enc-algo aes256-gcm@openssh.com chacha20-poly1305@openssh.com\n    set ssh-mac-algo hmac-sha2-256-etm@openssh.com hmac-sha2-512\n    set ssh-kex-algo curve25519-sha256@libssh.org diffie-hellman-group14-sha256\n    set ssh-hostkey-algo ssh-ed25519 rsa-sha2-512\nend\n", "crypto.strong_crypto")).toBe(true);
    expect(val("config vpn ssl settings\n    set algorithm low\nend\n", "crypto.strong_crypto")).toBe(false);
  });
  it("lists weak IPsec tunnels per table for the remediation", () => {
    const raw = "config vpn ipsec phase1\n    edit \"LEGACY-P1\"\n        set ike-version 1\n        set proposal 3des-sha1 aes128-md5\n        set dhgrp 2 5\n    next\nend\nconfig vpn ipsec phase2\n    edit \"LEGACY-P2\"\n        set phase1name \"LEGACY-P1\"\n        set proposal 3des-sha1\n    next\nend\nconfig vpn ipsec phase1-interface\n    edit \"DC2\"\n        set ike-version 2\n        set proposal aes256gcm-prfsha384\n        set dhgrp 21\n    next\nend\n";
    expect(val(raw, "crypto.weak_ike")).toBe(true);
    expect(val(raw, "crypto.weak_ike_phase1_policy")).toEqual(["LEGACY-P1"]);
    expect(val(raw, "crypto.weak_ike_phase2_policy")).toEqual(["LEGACY-P2"]);
    expect(val(raw, "crypto.weak_ike_phase1")).toBeUndefined();
    const fix = remediation(raw, "NS-CRY-002");
    expect(fix).toContain('config vpn ipsec phase1\n    edit "LEGACY-P1"\n        set proposal aes256-sha256');
    expect(fix).toContain('config vpn ipsec phase2\n    edit "LEGACY-P2"');
    expect(fix).not.toContain("phase1-interface");
    expect(fix).not.toContain("<vpn>");
  });
});

describe("FortiOS NTP", () => {
  const NTP = (servers: string, sync = "enable") => `config system ntp\n    set ntpsync ${sync}\n    set type custom\n    config ntpserver\n${servers}    end\nend\n`;
  const SRV = (id: number, host: string, auth?: string) => `        edit ${id}\n            set server "${host}"\n${auth ? `            set authentication ${auth}\n` : ""}        next\n`;
  it("drops servers when ntpsync is disabled and models the FortiGuard default", () => {
    expect(val(NTP(SRV(1, "10.1.1.5"), "disable"), "time.ntp_servers")).toEqual([]);
    expect(findings(NTP(SRV(1, "10.1.1.5"), "disable"))["NS-TIME-001"].status).toBe("fail");
    expect(val("", "time.ntp_servers")).toEqual(["ntp.fortiguard.com (FortiGuard default)"]);
    expect(source("", "time.ntp_servers")).toBe("default");
    expect(val("config system ntp\n    set ntpsync enable\n    set type fortiguard\nend\n", "time.ntp_servers")).toEqual(["fortiguard (ntp.fortiguard.com)"]);
    expect(val(NTP(""), "time.ntp_servers")).toEqual([]);
  });
  it("requires every ntpserver entry to be authenticated", () => {
    const mixed = NTP(SRV(1, "in.pool.ntp.org") + SRV(2, "192.168.12.60", "enable"));
    expect(val(mixed, "time.ntp_servers")).toEqual(["in.pool.ntp.org", "192.168.12.60"]);
    expect(val(mixed, "time.ntp_authentication")).toBe(false);
    expect(val(mixed, "time.unauthenticated_ntp_ids")).toEqual(["1"]);
    expect(remediation(mixed, "NS-TIME-002")).toContain("edit 1\n            set authentication enable");
    expect(remediation(mixed, "NS-TIME-002")).not.toContain("edit 2");
    expect(val(NTP(SRV(1, "10.1.1.5", "enable") + SRV(2, "10.1.1.6", "enable")), "time.ntp_authentication")).toBe(true);
  });
  it("branches the timezone fix on the FortiOS generation", () => {
    expect(remediation("", "NS-TIME-003")).toContain('set timezone "Asia/Kolkata"');
    expect(remediation("", "NS-TIME-003", HEADER_64)).toContain("set timezone <index>");
    expect(remediation("", "NS-TIME-003", HEADER_64)).not.toContain("Asia/Kolkata\"");
  });
});

describe("FortiOS SNMP", () => {
  const COMMUNITY = (id: number, name: string, body = "") => `    edit ${id}\n        set name "${name}"\n${body}    next\n`;
  const HOSTS = (ip: string) => `        config hosts\n            edit 1\n                set ip ${ip}\n            next\n        end\n`;
  it("requires an ACL on every enabled community", () => {
    const raw = `config system snmp sysinfo\n    set status enable\nend\nconfig system snmp community\n${COMMUNITY(1, "public")}${COMMUNITY(2, "monitor", HOSTS("192.168.12.50 255.255.255.255"))}end\n`;
    expect(val(raw, "snmp.community_acl")).toBe(false);
    expect(findings(raw)["NS-SNMP-004"].status).toBe("fail");
    expect(val(`config system snmp community\n${COMMUNITY(1, "netmon", HOSTS("10.10.50.40 255.255.255.255"))}end\n`, "snmp.community_acl")).toBe(true);
    expect(val(`config system snmp community\n${COMMUNITY(1, "netmon", HOSTS("0.0.0.0 0.0.0.0"))}end\n`, "snmp.community_acl")).toBe(false);
  });
  it("skips status-disabled communities and renders id-based deletes with version-specific SNMPv3 algorithms", () => {
    const disabled = `config system snmp community\n${COMMUNITY(1, "netmon", HOSTS("10.10.50.40 255.255.255.255"))}${COMMUNITY(2, "public", "        set status disable\n")}end\n`;
    expect(val(disabled, "snmp.default_communities")).toBeUndefined();
    expect(val(disabled, "snmp.v1v2c_communities")).toEqual(["netmon"]);
    expect(findings(disabled)["NS-SNMP-001"].status).toBe("pass");
    const live = `config system snmp community\n${COMMUNITY(3, "public")}end\n`;
    expect(val(live, "snmp.default_communities")).toEqual(["public"]);
    expect(val(live, "snmp.default_community_ids")).toEqual(["3"]);
    expect(remediation(live, "NS-SNMP-001")).toContain("config system snmp community\n    delete 3\nend");
    expect(remediation(live, "NS-SNMP-001")).toContain("set auth-proto sha256\n        set auth-pwd <auth-pw>\n        set priv-proto aes256\n        set priv-pwd <priv-pw>\n        set notify-hosts 10.10.50.40");
    expect(remediation(live, "NS-SNMP-001", HEADER_64)).toContain("set auth-proto sha\n        set auth-pwd <auth-pw>\n        set priv-proto aes\n");
    expect(remediation(live, "NS-SNMP-001")).not.toContain("purge");
  });
});

describe("FortiOS password policy and firewall policy semantics", () => {
  it("counts complexity only with a character-class requirement applied to admin passwords", () => {
    const POLICY = (body: string) => `config system password-policy\n    set status enable\n${body}end\n`;
    const weak = POLICY("    set apply-to admin-password\n    set minimum-length 8\n    set min-lower-case-letter 0\n    set min-upper-case-letter 0\n    set min-non-alphanumeric 0\n    set min-number 0\n");
    expect(val(weak, "auth.password_complexity")).toBe(false);
    expect(val(weak, "auth.min_password_length")).toBe(8);
    expect(findings(weak)["NS-AUTH-010"].status).toBe("fail");
    expect(val(POLICY("    set minimum-length 15\n    set min-number 1\n"), "auth.password_complexity")).toBe(true);
    expect(val(POLICY("    set apply-to ipsec-preshared-key\n    set min-number 1\n"), "auth.password_complexity")).toBe(false);
    expect(val("", "auth.password_complexity")).toBe(false);
    expect(source("", "auth.password_complexity")).toBe("default");
    expect(val("config system password-policy\n    set status disable\n    set minimum-length 12\nend\n", "auth.min_password_length")).toBe(0);
  });
  it("credits a logged catch-all deny and detects permit-any rules from WAN", () => {
    const POLICY = (id: number, body: string) => `    edit ${id}\n${body}    next\n`;
    const catchAll = `config firewall policy\n${POLICY(1, "        set srcintf \"any\"\n        set dstintf \"any\"\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set action deny\n        set service \"ALL\"\n        set logtraffic all\n")}end\n`;
    expect(val(catchAll, "acl.explicit_deny_logged")).toBe(true);
    const partial = `config log setting\n    set fwpolicy-implicit-log disable\nend\nconfig firewall policy\n${POLICY(1, "        set srcintf \"dmz\"\n        set dstintf \"internal\"\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set action deny\n        set service \"ALL\"\n        set logtraffic all\n")}end\n`;
    expect(val(partial, "acl.explicit_deny_logged")).toBe(false);
    const wanAny = IFACE("wan1", "ping", "        set role wan\n") + `config firewall policy\n${POLICY(2, "        set srcintf \"wan1\"\n        set dstintf \"internal\"\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set action accept\n        set service \"ALL\"\n")}end\n`;
    expect(val(wanAny, "acl.default_deny")).toBe(false);
    expect(findings(wanAny)["NS-ACL-003"].status).toBe("fail");
    expect(val(wanAny.replace('set srcintf "wan1"', 'set srcintf "internal"').replace('set dstintf "internal"', 'set dstintf "wan1"'), "acl.default_deny")).toBe(true);
  });
});

describe("FortiOS identity", () => {
  it("prefers the dedicated management interface over port1 and never leaks other sections' addresses", () => {
    const raw = "config system interface\n    edit \"port1\"\n        set mode dhcp\n        set allowaccess ping https\n    next\n    edit \"port3\"\n        set dedicated-to management\n        set ip 10.10.0.60 255.255.255.0\n        set allowaccess https ssh\n    next\nend\nconfig system snmp community\n    edit 1\n        set name \"x\"\n        config hosts\n            edit 1\n                set ip 10.10.50.40 255.255.255.255\n            next\n        end\n    next\nend\n";
    const r = parse(raw);
    expect(r.identity.mgmtIp).toBe("10.10.0.60");
    expect(r.identity.extra?.mgmt_interface).toBe("port3");
    const ha = "config system interface\n    edit \"port1\"\n        set ip 10.60.1.10 255.255.255.0\n        set allowaccess https ssh\n    next\n    edit \"port5\"\n        set ip 10.10.0.5 255.255.255.0\n        set allowaccess https\n    next\nend\nconfig system ha\n    config ha-mgmt-interfaces\n        edit 1\n            set interface \"port5\"\n        next\n    end\nend\n";
    expect(parse(ha).identity.mgmtIp).toBe("10.10.0.5");
    expect(parseConfig(SAMPLE_FORTIOS, "fortinet-fortios").result.identity.mgmtIp).toBe("10.22.7.1"); // internal (lan) beats wan1
    expect(parse("config system snmp community\n    edit 1\n        config hosts\n            edit 1\n                set ip 10.10.50.40 255.255.255.255\n            next\n        end\n    next\nend\n").identity.mgmtIp).toBeUndefined();
  });
  it("derives the product line from the header and skips firewall defaults on a FortiSwitch", () => {
    const sw = parseConfig("#config-version=FS1E48-7.2.4-FW-build0427-230607:opmode=0:vdom=0:user=admin\nconfig system global\n    set hostname \"FSW\"\nend\nconfig switch vlan\n    edit 10\n        set description \"USERS\"\n    next\nend\n", "fortinet-fortios").result;
    expect(sw.identity.os).toBe("FortiSwitchOS");
    expect(sw.identity.role).toBe("switch");
    expect(sw.identity.extra?.product).toBe("FortiSwitch-1E48");
    expect(sw.model.params["acl.default_deny"]).toBeUndefined();
    expect(sw.unrecognized.length).toBe(0);
    expect(fortiProduct("FGVM64")?.model).toBe("FortiGate-VM64");
    expect(fortiProduct("FWF60E")?.model).toBe("FortiWiFi-60E");
    expect(fortiProduct("S124EN")?.model).toBe("FortiSwitch-124EN");
    expect(fortiProduct("FAZ-VM64")).toMatchObject({ family: "appliance", model: "FortiAnalyzer-VM64" });
    const fg = parse("");
    expect(fg.identity.role).toBe("firewall");
    expect(fg.identity.extra).toMatchObject({ product: "FortiGate-60F", opmode: "nat", vdom_mode: "single" });
    expect(fg.model.params["identity.fortios_74plus"].value).toBe(true);
    expect(parse("", HEADER_64).model.params["identity.fortios_7plus"].value).toBe(false);
  });
  it("survives a UTF-8 BOM in front of the header", () => {
    const r = parseConfig("﻿" + HEADER_74 + "config system global\n    set hostname \"BOM\"\nend\n", "fortinet-fortios").result;
    expect(r.identity.model).toBe("FGT60F");
    expect(r.identity.osVersion).toBe("7.4.2 build 2571");
    expect(r.identity.hostname).toBe("BOM");
  });
});
