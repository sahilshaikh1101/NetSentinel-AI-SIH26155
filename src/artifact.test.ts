import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const file = resolve(process.cwd(), "dist-artifact/netsentinel.html");

/**
 * A published page that embeds an image, font or media file cannot be reviewed
 * for sharing, so the artifact must carry no `data:` payloads at all. Runtime
 * string literals inside bundled libraries are fine; an actual encoded file is not.
 */
describe("artifact bundle", () => {
  it("embeds no files", () => {
    if (!existsSync(file)) return; // only meaningful after npm run build:single
    const html = readFileSync(file, "utf8");
    const embedded = [...html.matchAll(/data:(image|font|audio|video|application\/(?:octet-stream|font[\w-]*))\/?[\w.+-]*[;,][^"'\s)]{40,}/g)].map((m) => m[0].slice(0, 60));
    expect(embedded).toEqual([]);
    expect([...html.matchAll(/base64,[A-Za-z0-9+/=]{200,}/g)]).toHaveLength(0);
  });
});
