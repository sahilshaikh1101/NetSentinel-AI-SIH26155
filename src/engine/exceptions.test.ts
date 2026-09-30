import { describe, expect, it } from "vitest";
import { applyTriage, findingKey, isActive, summarizeTriaged } from "./exceptions";
import { parseConfig } from "./parsers";
import { SAMPLE_INDEX } from "./samples";
import { evaluateDevice } from "./rules/evaluate";
import { RULES } from "./rules/library";
import { DEFAULT_REMEDIATION_SETTINGS } from "./rules/remediation";

describe("risk acceptance", () => {
  const p = parseConfig(SAMPLE_INDEX.cisco.raw, "cisco-ios").result;
  const findings = evaluateDevice("d", p.model, "cisco-ios", RULES, { frameworks: ["cis", "nist", "stig", "iso"], settings: DEFAULT_REMEDIATION_SETTINGS });
  it("accepted risks are excluded from the adjusted score but still counted as failed", () => {
    const key = findingKey("EDGE-RTR-01", "NS-MGMT-001");
    const triaged = applyTriage(findings, "EDGE-RTR-01", { [key]: { key, ruleId: "NS-MGMT-001", deviceKey: "EDGE-RTR-01", reason: "Telnet needed for legacy OOB console until Q4", by: "netops", at: "2026-09-01T00:00:00Z" } }, {});
    const s = summarizeTriaged(triaged);
    expect(s.accepted).toBe(1);
    expect(s.fail).toBeGreaterThan(0);
    expect(s.adjustedScore).toBeGreaterThan(s.score);
    expect(triaged.find((f) => f.ruleId === "NS-MGMT-001")?.exception?.reason).toContain("Telnet");
  });
  it("expired exceptions are inactive", () => {
    expect(isActive({ key: "k", ruleId: "r", deviceKey: "d", reason: "", by: "", at: "", expires: "2000-01-01T00:00:00Z" })).toBe(false);
    expect(isActive({ key: "k", ruleId: "r", deviceKey: "d", reason: "", by: "", at: "" })).toBe(true);
  });
});

describe("non-assessable devices", () => {
  it("does not turn platform defaults into verdicts when the parser understood too little", async () => {
    const { evaluateDevice } = await import("./rules/evaluate");
    const { RULES } = await import("./rules/library");
    const { DEFAULT_REMEDIATION_SETTINGS } = await import("./rules/remediation");
    const model = { params: { "management.telnet_enabled": { key: "management.telnet_enabled", value: true, evidence: [], source: "default" as const } } };
    const strict = evaluateDevice("x", model, "cisco-ios", RULES, { frameworks: ["cis", "nist", "stig", "iso"], settings: DEFAULT_REMEDIATION_SETTINGS, assessable: false });
    expect(strict.find((f) => f.ruleId === "NS-MGMT-001")?.status).toBe("warning");
    const normal = evaluateDevice("x", model, "cisco-ios", RULES, { frameworks: ["cis", "nist", "stig", "iso"], settings: DEFAULT_REMEDIATION_SETTINGS, assessable: true });
    expect(normal.find((f) => f.ruleId === "NS-MGMT-001")?.status).toBe("fail");
  });
});
