/**
 * Converts the single-file Vite build (dist-single/index.html) into an
 * artifact fragment: <title> first, then fonts, styles, root element and the
 * inlined application script. The artifact host supplies the document
 * skeleton, so no <html>/<head>/<body> wrappers are emitted.
 *
 * The application script is sliced by position (first module <script> to the
 * last </script>) so that "<style>"/"<script>" strings inside the JS bundle
 * are never mistaken for markup.
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";

const html = readFileSync(resolve("dist-single/index.html"), "utf8");

const sStart = html.indexOf('<script type="module"');
const sEnd = html.lastIndexOf("</script>") + "</script>".length;
if (sStart < 0 || sEnd < sStart) throw new Error("inlined module script not found");
const script = html.slice(sStart, sEnd);
const rest = html.slice(0, sStart) + html.slice(sEnd);

const pick = (re) => Array.from(rest.matchAll(re)).map((m) => m[0]);
const title = (rest.match(/<title>[\s\S]*?<\/title>/) ?? ["<title>NetSentinel AI</title>"])[0];
const links = pick(/<link[^>]+rel="(?:preconnect|stylesheet)"[^>]*>/g).filter((l) => /fonts\.g(oogleapis|static)\.com/.test(l));
const styles = pick(/<style[^>]*>[\s\S]*?<\/style>/g);
const meta = `<meta name="description" content="NetSentinel AI — AI-driven multi-vendor network security compliance auditor (SIH26155). Runs entirely in the browser.">`;

const out = [title, meta, ...links, ...styles, `<div id="root"></div>`, `<noscript>NetSentinel AI needs JavaScript.</noscript>`, script].join("\n");

mkdirSync("dist-artifact", { recursive: true });
writeFileSync(resolve("dist-artifact/netsentinel.html"), out);
console.log(`artifact written: dist-artifact/netsentinel.html (${(out.length / 1024 / 1024).toFixed(2)} MB, ${styles.length} style blocks, script ${(script.length / 1024).toFixed(0)} kB)`);
