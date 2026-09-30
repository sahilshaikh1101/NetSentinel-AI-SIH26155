import { describe, expect, it } from "vitest";
import { diffFindings, diffLines, diffModels, diffStats } from "./diff";
import { parseConfig } from "./parsers";
import { SAMPLE_INDEX } from "./samples";
import { evaluateDevice } from "./rules/evaluate";
import { RULES } from "./rules/library";
import { DEFAULT_REMEDIATION_SETTINGS } from "./rules/remediation";

describe("configuration drift", () => {
  it("diffs lines with LCS and keeps line numbers", () => {
    const ops = diffLines("a\nb\nc\nd", "a\nc\nd\ne");
    expect(diffStats(ops)).toEqual({ added: 1, removed: 1, unchanged: 3 });
    expect(ops.find((o) => o.kind === "del")?.a).toBe(2);
    expect(ops.find((o) => o.kind === "add")?.b).toBe(4);
  });
  it("reports semantic deltas and regressions between two versions of a device", () => {
    const before = SAMPLE_INDEX.cisco.raw;
    const after = before.replace("transport input telnet ssh", "transport input ssh").replace("snmp-server community public RO\n", "").replace("no ip source-route", "ip source-route");
    const pb = parseConfig(before, "cisco-ios").result;
    const pa = parseConfig(after, "cisco-ios").result;
    const deltas = diffModels(pb.model, pa.model);
    expect(deltas.find((d) => d.key === "management.telnet_enabled")?.after).toBe("disabled");
    expect(deltas.find((d) => d.key === "services.ip_source_routing")?.after).toBe("enabled");
    const opts = { frameworks: ["cis", "nist", "stig", "iso"] as const, settings: DEFAULT_REMEDIATION_SETTINGS };
    const fd = diffFindings(evaluateDevice("d", pb.model, "cisco-ios", RULES, { ...opts, frameworks: [...opts.frameworks] }), evaluateDevice("d", pa.model, "cisco-ios", RULES, { ...opts, frameworks: [...opts.frameworks] }));
    expect(fd.find((d) => d.ruleId === "NS-MGMT-001")?.kind).toBe("fixed");
    expect(fd.find((d) => d.ruleId === "NS-SNMP-001")?.kind).toBe("fixed");
    expect(fd.find((d) => d.ruleId === "NS-SVC-002")?.kind).toBe("regressed");
  });
});
