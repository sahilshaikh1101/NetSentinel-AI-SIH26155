import { detectAndParse } from "../src/engine/parsers";
import { SAMPLES } from "../src/engine/samples";
for (const s of SAMPLES) {
  const { detection, result } = detectAndParse(s.raw);
  console.log(`\n=== ${s.label} -> ${detection.vendor} (${detection.confidence}) recognized ${result.recognized}/${result.meaningfulLines}`);
  console.log("identity:", JSON.stringify(result.identity));
  if (s.expectedVendor !== "generic") for (const u of result.unrecognized) console.log(`  ? L${u.line}: ${u.text}   [${u.context ?? ""}]`);
}
