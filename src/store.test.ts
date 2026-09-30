import { describe, expect, it } from "vitest";
import { useStore } from "./store";
import { buildFleet } from "./engine/fleet";
import { RULES } from "./engine/rules/library";
import { diffFindings, diffLines, diffStats } from "./engine/diff";
import { sha256Sync } from "./lib/hash";

describe("workspace store", () => {
  it("archives the previous version when the same hostname is uploaded again and skips duplicates", () => {
    useStore.getState().resetToSamples();
    const before = useStore.getState().devices.find((d) => d.fileName === "edge-rtr-01.cfg");
    expect(before).toBeDefined();
    const raw2 = `${before!.raw.trimEnd()}\nntp server 10.10.50.99\n`;
    const out = useStore.getState().addDevices([{ fileName: "edge-rtr-01-v2.cfg", raw: raw2, sha256: sha256Sync(raw2) }]);
    expect(out.replaced).toHaveLength(1);
    expect(out.added).toHaveLength(0);
    const st = useStore.getState();
    const after = st.devices.find((d) => d.id === before!.id);
    expect(after?.raw).toBe(raw2);
    expect(after?.fileName).toBe("edge-rtr-01-v2.cfg");
    expect(st.history[before!.id]?.[0].sha256).toBe(before!.sha256);
    const ops = diffLines(st.history[before!.id][0].raw, raw2);
    expect(diffStats(ops).added).toBe(1);
    const dup = useStore.getState().addDevices([{ fileName: "again.cfg", raw: raw2, sha256: sha256Sync(raw2) }]);
    expect(dup.skipped).toHaveLength(1);
    expect(dup.added).toHaveLength(0);
  });

  it("removes and restores a device together with its history", () => {
    const st = useStore.getState();
    const target = st.devices.find((d) => d.fileName === "edge-rtr-01-v2.cfg")!;
    const versions = st.history[target.id];
    const removed = st.removeDevice(target.id);
    expect(removed?.id).toBe(target.id);
    expect(useStore.getState().devices.some((d) => d.id === target.id)).toBe(false);
    expect(useStore.getState().history[target.id]).toBeUndefined();
    useStore.getState().restoreDevice(removed!, versions);
    expect(useStore.getState().devices.some((d) => d.id === target.id)).toBe(true);
    expect(useStore.getState().history[target.id]).toHaveLength(1);
  });

  it("risk acceptance leaves the adjusted score but not the raw score", () => {
    const st = useStore.getState();
    const settings = st.settings.remediation;
    const base = buildFleet(st.devices, [], RULES, st.frameworks, settings);
    const dev = base.devices.find((d) => d.name === "EDGE-RTR-01")!;
    const failed = dev.findings.find((f) => f.status === "fail")!;
    st.acceptRisk(dev.key, failed.ruleId, { reason: "Legacy console server until Q4", ticket: "CHG-1" });
    const next = useStore.getState();
    const fleet = buildFleet(next.devices, [], RULES, next.frameworks, settings, { exceptions: next.exceptions, triage: next.triage });
    const dev2 = fleet.devices.find((d) => d.name === "EDGE-RTR-01")!;
    expect(dev2.summary.accepted).toBe(1);
    expect(dev2.summary.score).toBe(dev.summary.score);
    expect(dev2.summary.adjustedScore).toBeGreaterThan(dev.summary.score);
    expect(dev2.findings.find((f) => f.ruleId === failed.ruleId)?.exception?.reason).toContain("console server");
    expect(dev2.findings.find((f) => f.ruleId === failed.ruleId)?.triage?.state).toBe("accepted");
    next.revokeException(`${dev.key}::${failed.ruleId}`);
    expect(useStore.getState().triage[`${dev.key}::${failed.ruleId}`]?.state).toBe("open");
    const noDelta = diffFindings(dev.findings, dev2.findings);
    expect(noDelta).toHaveLength(0);
  });

  it("rejects duplicate custom control ids and invalid mapping patterns", () => {
    const st = useStore.getState();
    expect(st.addCustomRule({ ...RULES[0], id: RULES[0].id, custom: true })).toBe(false);
    expect(st.addCustomRule({ ...RULES[0], id: "NS-CUSTOM-TEST", custom: true })).toBe(true);
    expect(useStore.getState().customRules.some((r) => r.id === "NS-CUSTOM-TEST")).toBe(true);
    const r = st.importMappings([
      { id: "ok-1", name: "ok", vendor: "any", pattern: "^foo$", param: "management.telnet_enabled", valueMode: "flag", createdAt: "", createdBy: "admin", hits: 0 },
      { id: "bad-1", name: "bad", vendor: "any", pattern: "^(foo$", param: "management.telnet_enabled", valueMode: "flag", createdAt: "", createdBy: "admin", hits: 0 },
    ]);
    expect(r).toEqual({ imported: 1, skipped: 1 });
  });
});
