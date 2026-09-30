import { describe, expect, it } from "vitest";
import { RULES } from "./rules/library";
import { DEFAULT_REMEDIATION_SETTINGS, cidrToParts, renderRemediation } from "./rules/remediation";
import { evalCheck, evaluateDevice, scoreLabel, summarize } from "./rules/evaluate";
import { VENDOR_IDS } from "./sbm";
import { parseConfig } from "./parsers";
import { SAMPLE_INDEX } from "./samples";
import type { ParamObservation, SecurityBaselineModel, Severity } from "./types";

const FRAMEWORKS = ["cis", "nist", "stig", "iso"] as const;
const obs = (value: ParamObservation["value"], source: ParamObservation["source"] = "parser"): ParamObservation => ({ key: "k", value, evidence: [], source });
const model = (params: Record<string, ParamObservation>): SecurityBaselineModel => ({ params });
const sev = (p: Partial<Record<Severity, number>> = {}): Record<Severity, number> => ({ critical: 0, high: 0, medium: 0, low: 0, ...p });

describe("remediation templates", () => {
  it("renders every control for every vendor without leaving template syntax behind", () => {
    const cisco = parseConfig(SAMPLE_INDEX.cisco.raw, "cisco-ios").result;
    const bad: string[] = [];
    for (const rule of RULES) {
      for (const vendor of VENDOR_IDS) {
        const diagnostics: string[] = [];
        renderRemediation(rule, vendor, cisco.model, DEFAULT_REMEDIATION_SETTINGS, { osVersion: cisco.identity.osVersion, hostname: cisco.identity.hostname }, diagnostics);
        if (diagnostics.length) bad.push(`${rule.id}/${vendor}: ${Array.from(new Set(diagnostics)).join(", ")}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it("resolves nested conditionals against the device state", () => {
    const rule = { ...RULES[0], remediation: { "cisco-ios": "logging host {{syslog_host}}{{#if iosxe}}{{#if mgmt_vrf}} vrf {{mgmt_vrf}}{{else}} transport tcp{{/if}} sequence-num{{else}} legacy{{/if}}" } };
    const withVrf = model({ "management.mgmt_vrf": obs("Mgmt-vrf") });
    expect(renderRemediation(rule, "cisco-ios", withVrf, DEFAULT_REMEDIATION_SETTINGS, { osVersion: "17.09.04a" })).toBe("logging host 10.10.50.20 vrf Mgmt-vrf sequence-num");
    expect(renderRemediation(rule, "cisco-ios", model({}), DEFAULT_REMEDIATION_SETTINGS, { osVersion: "17.09.04a" })).toBe("logging host 10.10.50.20 transport tcp sequence-num");
    expect(renderRemediation(rule, "cisco-ios", withVrf, DEFAULT_REMEDIATION_SETTINGS, { osVersion: "15.2(4)M" })).toBe("logging host 10.10.50.20 legacy");
  });

  it("never widens a management prefix and refuses invalid input", () => {
    expect(cidrToParts("10.10.0.0/24")).toMatchObject({ network: "10.10.0.0", wildcard: "0.0.0.255", bits: 24, valid: true });
    // a bare address is one host, not a /24
    expect(cidrToParts("10.10.0.5")).toMatchObject({ network: "10.10.0.5", mask: "255.255.255.255", bits: 32, valid: true });
    for (const bad of ["10.10.0.5/abc", "10.10.0", "300.1.1.1/24", "2001:db8::/32", ""]) expect(cidrToParts(bad).valid).toBe(false);
    const rule = { ...RULES[0], remediation: { "cisco-ios": "access-list 99 permit {{mgmt_subnet}}\naccess-list 99 deny any log" } };
    const out = renderRemediation(rule, "cisco-ios", model({}), { ...DEFAULT_REMEDIATION_SETTINGS, mgmtSubnetCidr: "10.10.0.5/abc" });
    expect(out).toContain("<mgmt-subnet>");
    expect(out.split("\n")[0]).toMatch(/^! Set a valid management prefix/);
    expect(out).not.toContain("0.0.0.255");
  });

  it("uses the parser's interface list for per-interface fixes", () => {
    const rule = { ...RULES[0], remediation: { "fortinet-fortios": "{{#each ifaces_telnet}}edit \"{{item}}\"\n{{/each}}" } };
    const m = model({ "management.telnet_enabled": obs(true), "management.telnet_interfaces": obs(["wan1", "internal"]) });
    expect(renderRemediation(rule, "fortinet-fortios", m, DEFAULT_REMEDIATION_SETTINGS)).toBe('edit "wan1"\nedit "internal"');
  });
});

describe("evaluation honesty", () => {
  it("does not treat an absent command as evidence when the parser read little of the file", () => {
    const check = { param: "snmp.default_communities", op: "notExists" as const };
    const empty = model({});
    expect(evalCheck(check, empty, { assessable: true, thorough: true }).status).toBe("pass");
    expect(evalCheck(check, empty, { assessable: true, thorough: false }).status).toBe("warning");
    // …unless something else in the same family was observed
    expect(evalCheck(check, model({ "snmp.enabled": obs(true) }), { assessable: true, thorough: false }).status).toBe("pass");
    expect(evalCheck(check, model({ "snmp.default_communities": obs(["public"]) }), { assessable: true, thorough: false }).status).toBe("fail");
  });

  it("keeps a barely-parsed device out of pass/fail verdicts entirely", () => {
    const exos = parseConfig(SAMPLE_INDEX.exos.raw, "generic").result;
    const findings = evaluateDevice("d", exos.model, "generic", RULES, { frameworks: [...FRAMEWORKS], settings: DEFAULT_REMEDIATION_SETTINGS, assessable: false, recognitionRatio: exos.recognized / exos.meaningfulLines });
    expect(findings.filter((f) => f.status === "pass" || f.status === "fail")).toHaveLength(0);
    expect(summarize(findings, false).assessable).toBe(false);
  });

  it("evaluates vendor-scoped controls on a trained unknown vendor instead of marking them N/A", () => {
    const scoped = RULES.filter((r) => r.appliesTo && !r.appliesTo.includes("generic"));
    expect(scoped.length).toBeGreaterThan(10);
    const m = model({ "management.telnet_enabled": obs(true), "services.lldp_enabled": obs(true, "mapping") });
    const findings = evaluateDevice("d", m, "generic", scoped, { frameworks: [...FRAMEWORKS], settings: DEFAULT_REMEDIATION_SETTINGS, assessable: true });
    expect(findings.some((f) => f.status === "fail")).toBe(true);
    expect(findings.every((f) => f.status !== "na")).toBe(true);
    // a known vendor outside the list stays not-applicable
    const cisco = evaluateDevice("d", m, "cisco-ios", scoped.filter((r) => !r.appliesTo!.includes("cisco-ios")), { frameworks: [...FRAMEWORKS], settings: DEFAULT_REMEDIATION_SETTINGS, assessable: true });
    expect(cisco.every((f) => f.status === "na")).toBe(true);
  });

  it("marks remediation for an unassessed control as a verification step", () => {
    const findings = evaluateDevice("d", model({}), "cisco-ios", RULES, { frameworks: [...FRAMEWORKS], settings: DEFAULT_REMEDIATION_SETTINGS, assessable: false });
    const warned = findings.find((f) => f.status === "warning" && f.remediation);
    expect(warned?.remediation.split("\n")[0]).toMatch(/^! VERIFY FIRST/);
  });

  it("does not let a boolean satisfy a list condition", () => {
    // a polarity mapping stored on a list parameter used to pass "has a remote syslog host"
    expect(evalCheck({ param: "logging.remote_hosts", op: "notEmpty" }, model({ "logging.remote_hosts": obs(false) })).status).toBe("fail");
    expect(evalCheck({ param: "logging.remote_hosts", op: "notEmpty" }, model({ "logging.remote_hosts": obs(0) })).status).toBe("fail");
    expect(evalCheck({ param: "logging.remote_hosts", op: "notEmpty" }, model({ "logging.remote_hosts": obs(["10.0.0.1"]) })).status).toBe("pass");
    expect(evalCheck({ param: "auth.min_password_length", op: "countGte", value: 2 }, model({ "auth.min_password_length": obs(true) })).status).toBe("warning");
  });

  it("compares strings case-insensitively both ways and matches lists with in/notIn", () => {
    expect(evalCheck({ param: "p", op: "neq", value: "none" }, model({ p: obs("None") })).status).toBe("fail");
    expect(evalCheck({ param: "p", op: "in", value: ["aes", "sha256"] }, model({ p: obs(["AES", "rsa"]) })).status).toBe("pass");
    expect(evalCheck({ param: "p", op: "notIn", value: ["des"] }, model({ p: obs(["AES"]) })).status).toBe("pass");
  });

  it("never labels a partially assessed device or one with an open critical as hardened", () => {
    expect(scoreLabel(100, false)).toMatchObject({ label: "Not assessed" });
    expect(scoreLabel(100, true, { coverage: 12 })).toMatchObject({ label: "Partially assessed", tone: "warn" });
    expect(scoreLabel(91, true, { coverage: 90, bySeverity: sev({ critical: 1 }) })).toMatchObject({ label: "Needs attention", tone: "warn" });
    expect(scoreLabel(92, true, { coverage: 90, bySeverity: sev({ high: 2 }) })).toMatchObject({ label: "Needs attention" });
    expect(scoreLabel(92, true, { coverage: 90, bySeverity: sev() })).toMatchObject({ label: "Hardened", tone: "good" });
    expect(scoreLabel(40, true, { coverage: 90, bySeverity: sev({ critical: 3 }) })).toMatchObject({ label: "At risk", tone: "bad" });
  });
});
