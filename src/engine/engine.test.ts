import { describe, expect, it } from "vitest";
import { detectVendor } from "./detect";
import { parseConfig, detectAndParse } from "./parsers";
import { SAMPLES, SAMPLE_INDEX } from "./samples";
import { evaluateDevice, summarize } from "./rules/evaluate";
import { RULES } from "./rules/library";
import { DEFAULT_REMEDIATION_SETTINGS, renderRemediation } from "./rules/remediation";
import { applyMappings, polarityOf } from "./mappings";
import { suggestForLine, tokenize } from "./classifier";
import { flattenJunos } from "./parsers/junos";
import { panosXmlToSet } from "./parsers/panos";
import { toLines } from "./parsers/util";
import type { Mapping } from "./types";

const settings = DEFAULT_REMEDIATION_SETTINGS;
const allFrameworks = ["cis", "nist", "stig", "iso"] as const;

describe("vendor detection", () => {
  for (const s of SAMPLES) {
    it(`detects ${s.label} as ${s.expectedVendor}`, () => {
      const d = detectVendor(s.raw);
      expect(d.vendor).toBe(s.expectedVendor);
      if (s.expectedVendor !== "generic") expect(d.confidence).toBeGreaterThan(0.5);
    });
  }
});

describe("Cisco IOS parser", () => {
  const { result } = parseConfig(SAMPLE_INDEX.cisco.raw, "cisco-ios");
  const p = result.model.params;
  it("extracts identity", () => {
    expect(result.identity.hostname).toBe("EDGE-RTR-01");
    expect(result.identity.serial).toBe("FGL2331L0A7");
    expect(result.identity.model).toBe("ISR4451-X/K9");
    expect(result.identity.osVersion).toContain("17.09.04a");
  });
  it("finds telnet on vty and SNMP public", () => {
    expect(p["management.telnet_enabled"].value).toBe(true);
    expect(p["snmp.default_communities"].value).toEqual(["public"]);
    expect(p["management.ssh_version"].value).toBe(2);
    expect(p["management.mgmt_acl_applied"].value).toBe(true);
    expect(p["management.idle_timeout_minutes"].value).toBe(30);
    expect(p["auth.weak_password_hashes"].value).toBeGreaterThanOrEqual(2);
    expect(p["crypto.weak_ike"].value).toBe(true);
    expect(p["routing.bgp_auth"].value).toBe(true);
    expect(p["routing.ospf_auth"].value).toBe(true);
    expect(p["management.aux_disabled"].value).toBe(false);
    expect(p["logging.remote_hosts"].value).toEqual(["10.10.50.20"]);
    expect(p["time.ntp_authentication"].value).toBe(false);
    expect(p["management.login_banner"].value).toBe(true);
    expect(p["acl.explicit_deny_logged"].value).toBe(true);
  });
  it("understands almost every line", () => {
    expect(result.unrecognized.length).toBeLessThanOrEqual(3);
  });
});

describe("Arista EOS parser", () => {
  const { result } = parseConfig(SAMPLE_INDEX.arista.raw, "arista-eos");
  const p = result.model.params;
  it("extracts identity and management state", () => {
    expect(result.identity.model).toBe("DCS-7050SX3-48YC8");
    expect(result.identity.osVersion).toBe("4.30.2F");
    expect(p["management.idle_timeout_minutes"].value).toBe(9999);
    expect(p["management.telnet_enabled"].value).toBe(false);
    expect(p["management.api_http_enabled"].value).toBe(false);
    expect(p["auth.min_password_length"].value).toBe(8);
    expect(p["management.login_banner"].value).toBe(true);
    expect(result.unrecognized.length).toBeLessThanOrEqual(3);
  });
});

describe("Junos parser", () => {
  const { result } = parseConfig(SAMPLE_INDEX.junos.raw, "juniper-junos");
  const p = result.model.params;
  it("flattens braces to set paths", () => {
    const { entries } = flattenJunos(toLines("system {\n    host-name X;\n    services {\n        ssh {\n            root-login deny;\n        }\n    }\n}\n"));
    expect(entries.map((e) => e.path)).toContain("system services ssh root-login deny");
  });
  it("extracts security state", () => {
    expect(result.identity.hostname).toBe("DC-SRX-01");
    expect(result.identity.serial).toBe("CV4620AF0018");
    expect(result.identity.model).toBe("SRX345");
    expect(p["auth.root_login_ssh"].value).toBe(false);
    expect(p["management.ssh_version"].value).toBe(2);
    expect(p["auth.min_password_length"].value).toBe(14);
    expect(p["time.ntp_authentication"].value).toBe(true);
    expect(p["logging.remote_secure"].value).toBe(true);
    expect(p["acl.default_deny"].value).toBe(true);
    expect(p["crypto.weak_ike"].value).toBe(true);
    expect(p["management.mgmt_acl_applied"].value).toBe(true);
    expect(result.unrecognized.length).toBeLessThanOrEqual(2);
  });
});

describe("FortiOS parser", () => {
  const { result } = parseConfig(SAMPLE_INDEX.fortios.raw, "fortinet-fortios");
  const p = result.model.params;
  it("extracts identity from the config header", () => {
    expect(result.identity.model).toBe("FGT60F");
    expect(result.identity.osVersion).toContain("7.4.2");
    expect(result.identity.hostname).toBe("BRANCH-FW-07");
    expect(result.identity.serial).toBe("FGT60FTK22011234");
  });
  it("finds exposed services and weak settings", () => {
    expect(p["management.telnet_enabled"].value).toBe(true);
    expect(p["management.http_enabled"].value).toBe(true);
    expect(p["management.idle_timeout_minutes"].value).toBe(30);
    expect(p["crypto.strong_crypto"].value).toBe(false);
    expect(p["snmp.default_communities"].value).toEqual(["public"]);
    expect(p["time.ntp_authentication"].value).toBe(false);
    expect(p["acl.explicit_deny_logged"].value).toBe(false);
    expect(p["crypto.weak_ike"].value).toBe(true);
    expect(p["crypto.tls_min_version"].value).toBe("1.2");
    expect(p["acl.count"].value).toBe(3);
    expect(result.unrecognized.length).toBe(0);
  });
});

describe("PAN-OS parser", () => {
  const { result } = parseConfig(SAMPLE_INDEX.panos.raw, "paloalto-panos");
  const p = result.model.params;
  it("extracts identity from show system info", () => {
    expect(result.identity.serial).toBe("015351000098765");
    expect(result.identity.model).toBe("PA-440");
    expect(result.identity.osVersion).toBe("11.1.2");
  });
  it("finds findings", () => {
    expect(p["management.telnet_enabled"].value).toBe(true);
    expect(p["management.http_enabled"].value).toBe(false);
    expect(p["auth.min_password_length"].value).toBe(8);
    expect(p["snmp.default_communities"].value).toEqual(["public"]);
    expect(p["logging.remote_secure"].value).toBe(true);
    expect(p["crypto.tls_min_version"].value).toBe("1.1");
    expect(p["crypto.weak_ike"].value).toBe(true);
    expect(p["acl.explicit_deny_logged"].value).toBe(true);
    expect(p["auth.aaa_authentication_login"].value).toBe(true);
    expect(result.unrecognized.length).toBe(0);
  });
  it("converts XML exports to set format", () => {
    const set = panosXmlToSet('<config version="11.1.0" urldb="paloaltonetworks"><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>PA-X</hostname><service><disable-telnet>yes</disable-telnet></service></system></deviceconfig></entry></devices></config>');
    expect(set).toContain("set deviceconfig system hostname PA-X");
    expect(set).toContain("set deviceconfig system service disable-telnet yes");
  });
});

describe("RouterOS parser", () => {
  const { result } = parseConfig(SAMPLE_INDEX.routeros.raw, "mikrotik-routeros");
  const p = result.model.params;
  it("extracts identity from the export header", () => {
    expect(result.identity.model).toBe("RB4011iGS+");
    expect(result.identity.serial).toBe("HD3M0A9F1QP");
    expect(result.identity.osVersion).toBe("7.14.3");
    expect(result.identity.hostname).toBe("BRANCH-MT-09");
  });
  it("evaluates services", () => {
    expect(p["management.telnet_enabled"].value).toBe(false);
    expect(p["management.http_enabled"].value).toBe(true);
    expect(p["management.api_http_enabled"].value).toBe(true);
    expect(p["management.mgmt_acl_applied"].value).toBe(true);
    expect(p["crypto.strong_crypto"].value).toBe(true);
    expect(p["snmp.default_communities"].value).toContain("public");
    expect(p["services.misc_enabled"].value).toEqual(expect.arrayContaining(["dns-remote-requests", "bandwidth-server", "mac-server"]));
    expect(p["acl.default_deny"].value).toBe(true);
    expect(p["auth.min_password_length"].value).toBe(8);
    expect(result.unrecognized.length).toBe(0);
  });
});

describe("Huawei VRP parser", () => {
  const { result } = parseConfig(SAMPLE_INDEX.vrp.raw, "huawei-vrp");
  const p = result.model.params;
  it("extracts identity", () => {
    expect(result.identity.hostname).toBe("CORE-HW-01");
    expect(result.identity.serial).toBe("2102353VTX10N4000123");
    expect(result.identity.osVersion).toContain("V200R022C00SPC500");
  });
  it("finds findings", () => {
    expect(p["management.telnet_enabled"].value).toBe(true);
    expect(p["management.ssh_version"].value).toBe(1);
    expect(p["management.http_enabled"].value).toBe(true);
    expect(p["auth.weak_password_hashes"].value).toBe(1);
    expect(p["time.ntp_authentication"].value).toBe(true);
    expect(p["crypto.tls_min_version"].value).toBe("1.1");
    expect(p["crypto.weak_ike"].value).toBe(true);
    expect(p["routing.ospf_auth"].value).toBe(true);
    expect(p["snmp.v3_priv"].value).toBe(true);
    expect(p["management.idle_timeout_minutes"].value).toBe(5);
    expect(result.unrecognized.length).toBeLessThanOrEqual(2);
  });
});

describe("generic parser + training loop", () => {
  const exos = SAMPLE_INDEX.exos.raw;
  it("routes the unknown vendor to generic with all lines unrecognized", () => {
    const { detection, result } = detectAndParse(exos);
    expect(detection.vendor).toBe("generic");
    expect(result.identity.hostname).toBe("ACCESS-EX-12");
    expect(result.unrecognized.length).toBeGreaterThan(30);
    expect(Object.keys(result.model.params).length).toBe(0);
  });
  it("classifier proposes sensible parameters", () => {
    const telnet = suggestForLine("disable telnet");
    expect(telnet[0].param).toBe("management.telnet_enabled");
    expect(telnet[0].valueMode).toBe("polarity");
    const idle = suggestForLine("configure idletimeout 45");
    expect(idle[0].param).toBe("management.idle_timeout_minutes");
    expect(idle[0].valueMode).toBe("capture");
    expect(idle[0].extractedValue).toBe(45);
    const syslog = suggestForLine("configure syslog add 10.10.50.20:514 vr VR-Default local7");
    expect(syslog[0].param).toBe("logging.remote_hosts");
    const sntp = suggestForLine("configure sntp-client primary 10.10.50.10 vr VR-Default");
    expect(sntp[0].param).toBe("time.ntp_servers");
    const community = suggestForLine("configure snmp add community readonly public");
    expect(["snmp.v1v2c_communities", "snmp.default_communities"]).toContain(community[0].param);
    const minlen = suggestForLine("configure account all password-policy min-length 8");
    expect(minlen[0].param).toBe("auth.min_password_length");
  });
  it("learned mappings turn unknown lines into observations", () => {
    const mappings: Mapping[] = [
      { id: "m1", name: "EXOS telnet", vendor: "any", pattern: "^(\\S+)\\s+telnet$", param: "management.telnet_enabled", valueMode: "polarity", createdAt: "", createdBy: "admin", hits: 0 },
      { id: "m2", name: "EXOS idle", vendor: "any", pattern: "^configure\\s+idletimeout\\s+(\\d+)$", param: "management.idle_timeout_minutes", valueMode: "capture", captureGroup: 1, transform: "number", createdAt: "", createdBy: "admin", hits: 0 },
      { id: "m3", name: "EXOS syslog", vendor: "any", pattern: "^configure\\s+syslog\\s+add\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})", param: "logging.remote_hosts", valueMode: "list", captureGroup: 1, createdAt: "", createdBy: "admin", hits: 0 },
    ];
    const base = parseConfig(exos, "generic").result;
    const { result, hits } = applyMappings(base, mappings);
    expect(result.model.params["management.telnet_enabled"].value).toBe(false);
    expect(result.model.params["management.idle_timeout_minutes"].value).toBe(45);
    expect(result.model.params["logging.remote_hosts"].value).toEqual(["10.10.50.20"]);
    expect(hits.m1).toBe(1);
    expect(result.unrecognized.length).toBe(base.unrecognized.length - 3);
  });
  it("derives polarity from negation words", () => {
    expect(polarityOf("no shutdown")).toBe(true);
    expect(polarityOf("shutdown")).toBe(false);
    expect(polarityOf("set telnet disabled=yes")).toBe(false);
    expect(polarityOf("set telnet disabled=no")).toBe(true);
    expect(tokenize("configure ssh2 ciphers aes256-ctr")).toEqual(expect.arrayContaining(["ssh", "2", "ciphers", "aes256-ctr", "aes", "256", "ctr"]));
  });
  it("flattens JSON exports", () => {
    const { result } = detectAndParse(SAMPLE_INDEX.aws.raw);
    expect(result.vendor).toBe("generic");
    expect(result.unrecognized.some((u) => u.text.includes("CidrIp = 0.0.0.0/0"))).toBe(true);
  });
});

describe("compliance engine", () => {
  it("evaluates the Cisco sample with expected statuses", () => {
    const { result } = parseConfig(SAMPLE_INDEX.cisco.raw, "cisco-ios");
    const findings = evaluateDevice("d1", result.model, "cisco-ios", RULES, { frameworks: [...allFrameworks], settings });
    const byRule = Object.fromEntries(findings.map((f) => [f.ruleId, f]));
    expect(byRule["NS-MGMT-001"].status).toBe("fail");
    expect(byRule["NS-MGMT-002"].status).toBe("pass");
    expect(byRule["NS-SNMP-001"].status).toBe("fail");
    expect(byRule["NS-AUTH-004"].status).toBe("pass");
    expect(byRule["NS-RTG-001"].status).toBe("pass");
    expect(byRule["NS-CRY-002"].status).toBe("fail");
    expect(byRule["NS-MGMT-008"].status).toBe("fail");
    expect(byRule["NS-MGMT-001"].evidence.some((e) => e.text.includes("transport input telnet ssh"))).toBe(true);
    const s = summarize(findings);
    expect(s.score).toBeGreaterThan(30);
    expect(s.score).toBeLessThan(90);
  });
  it("marks rules not applicable to the platform", () => {
    const { result } = parseConfig(SAMPLE_INDEX.fortios.raw, "fortinet-fortios");
    const findings = evaluateDevice("d2", result.model, "fortinet-fortios", RULES, { frameworks: ["cis"], settings });
    expect(findings.find((f) => f.ruleId === "NS-SVC-001")?.status).toBe("na");
    expect(findings.every((f) => f.frameworks.includes("cis"))).toBe(true);
  });
  it("renders device-specific remediation", () => {
    const { result } = parseConfig(SAMPLE_INDEX.cisco.raw, "cisco-ios");
    const rule = RULES.find((r) => r.id === "NS-SNMP-001")!;
    const text = renderRemediation(rule, "cisco-ios", result.model, settings);
    expect(text).toContain("no snmp-server community public");
    const acl = RULES.find((r) => r.id === "NS-MGMT-006")!;
    expect(renderRemediation(acl, "cisco-ios", result.model, settings)).toContain("permit 10.10.0.0 0.0.0.255");
  });
  it("every rule references at least two frameworks (framework-specific variants one) and has generic remediation", () => {
    for (const r of RULES) {
      expect(new Set(r.refs.map((x) => x.framework)).size).toBeGreaterThanOrEqual(/S$/.test(r.id) ? 1 : 2);
      expect(r.remediation.generic).toBeTruthy();
    }
    expect(RULES.find((r) => r.id === "NS-AUTH-007S")?.refs.every((x) => x.framework === "stig")).toBe(true);
  });
  it("scores the untrained device as not assessable and the NX-OS sample with expected findings", () => {
    const exos = parseConfig(SAMPLE_INDEX.exos.raw, "generic").result;
    expect(summarize(evaluateDevice("x", exos.model, "generic", RULES, { frameworks: [...allFrameworks], settings, assessable: false })).assessable).toBe(false);
    const { detection, result } = detectAndParse(SAMPLE_INDEX.nxos.raw);
    expect(detection.vendor).toBe("cisco-nxos");
    expect(result.identity.serial).toBe("FDO23110ABC");
    expect(result.identity.model).toBe("N9K-C93180YC-FX");
    const f = Object.fromEntries(evaluateDevice("n", result.model, "cisco-nxos", RULES, { frameworks: [...allFrameworks], settings }).map((x) => [x.ruleId, x.status]));
    expect(f["NS-MGMT-001"]).toBe("fail"); // feature telnet
    expect(f["NS-SNMP-002"]).toBe("fail"); // group network-admin community
    expect(f["NS-RTG-001"]).toBe("fail"); // one neighbor without password
    expect(f["NS-MGMT-006"]).toBe("pass"); // access-class on line vty
    expect(f["NS-AUTH-003"]).toBe("pass"); // $5$ hashes are strong
    expect(f["NS-AUTH-010"]).toBe("fail"); // no password strength-check
    expect(result.unrecognized.length).toBeLessThanOrEqual(2);
  });
  it("returns warnings, not failures, for the untrained EXOS device", () => {
    const { result } = parseConfig(SAMPLE_INDEX.exos.raw, "generic");
    const findings = evaluateDevice("d3", result.model, "generic", RULES, { frameworks: [...allFrameworks], settings });
    expect(findings.filter((f) => f.status === "fail").length).toBe(0);
    expect(findings.filter((f) => f.status === "warning").length).toBeGreaterThan(10);
  });
});
