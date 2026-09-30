import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { RULES } from "./engine/rules/library";
import { SBM_PARAMS, VENDOR_IDS } from "./engine/sbm";
import { KNOWN_COMMANDS } from "./engine/classifier";

const read = (p: string) => readFileSync(resolve(process.cwd(), p), "utf8");

/**
 * The pitch documents quote counts; keep them honest against the code.
 * If this fails after you added a control or a baseline parameter, the fix is
 * to update the number in README.md / docs/*.md, not to change the engine.
 */
describe("documentation", () => {
  const readme = read("README.md");
  const architecture = read("docs/ARCHITECTURE.md");
  const demo = read("docs/DEMO-SCRIPT.md");

  it("states the real number of baseline parameters", () => {
    for (const [name, text] of [["README", readme], ["ARCHITECTURE", architecture], ["DEMO-SCRIPT", demo]] as const) {
      const claims = [...text.matchAll(/(?<![-\w])(\d+)\s+(?:vendor-neutral\s+)?(?:SBM\s+)?param(?:eter)?s/g)].map((m) => Number(m[1]));
      expect(claims.length, `${name} should quote the parameter count`).toBeGreaterThan(0);
      for (const c of claims) expect(c, `${name} parameter count`).toBe(SBM_PARAMS.length);
    }
  });

  it("states the real number of controls", () => {
    for (const [name, text] of [["README", readme], ["ARCHITECTURE", architecture], ["DEMO-SCRIPT", demo]] as const) {
      const claims = [...text.matchAll(/(?<![-\w])(\d+)\s+controls/g)].map((m) => Number(m[1]));
      expect(claims.length, `${name} should quote the control count`).toBeGreaterThan(0);
      for (const c of claims) expect(c, `${name} control count`).toBe(RULES.length);
    }
  });

  it("states the real classifier corpus size", () => {
    for (const text of [readme, architecture]) {
      const claims = [...text.matchAll(/(\d+)-command/g)].map((m) => Number(m[1]));
      for (const c of claims) expect(c).toBe(KNOWN_COMMANDS.length);
    }
  });

  it("names every vendor parser that ships", () => {
    for (const v of VENDOR_IDS.filter((x) => x !== "generic")) {
      const family = v.split("-")[1];
      expect(readme.toLowerCase(), `README should mention ${v}`).toContain(family.slice(0, 5));
    }
  });
});
