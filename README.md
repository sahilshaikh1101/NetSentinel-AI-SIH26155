# NetSentinel AI — AI-Driven Multi-Vendor Network Security Compliance Auditor

**Smart India Hackathon 2026 · Problem Statement SIH26155 · NTRO · Blockchain & Cybersecurity**

NetSentinel AI ingests raw configuration files from *any* network device, normalises them into a vendor-neutral **Security Baseline Model (SBM)**, audits the model against **CIS, NIST SP 800-53, DISA STIG and ISO/IEC 27001**, and produces a **PDF report per device** with identification details, pass/fail findings, severity, evidence line numbers and **device-specific remediation CLI**. When it meets syntax it has never seen, the **Training Studio** proposes mappings with an offline pattern-recognition classifier (optionally an LLM) and the administrator confirms them in a low-code editor — the engine learns without a redeploy.

The whole engine runs in the browser: no server, no database, no configuration ever leaves the machine.

## What it does (mapped to the problem statement)

| PS requirement | Implementation |
|---|---|
| **R1 Unified ingestion** — single or bulk upload, any vendor | Drag-and-drop files, folders and ZIP archives; paste text; JSON/XML exports flattened. Weighted syntax signatures detect the vendor (`src/engine/detect.ts`) with a confidence score and reasons; manual parser override per device. Files are SHA-256 hashed and deduplicated; a second upload for a known hostname becomes a new **version** and the previous one is archived for drift analysis. |
| **R2 Normalisation** — vendor-neutral Security Baseline Model | 118 parameters across 10 control families (`src/engine/sbm.ts`). Parsers for Cisco IOS/IOS-XE, Cisco NX-OS, Arista EOS, Juniper Junos (brace + set format), FortiOS, PAN-OS (set + XML), MikroTik RouterOS, Huawei VRP, plus a generic parser. Every observation carries **evidence line numbers** and a source (parser / platform default / learned mapping / LLM). |
| **R3 Multi-framework engine** | One control library (`src/engine/rules/library.ts`, 68 controls) cross-referenced to CIS, NIST 800-53 r5, DISA NDM/Router SRG and ISO 27001:2022. Selecting frameworks scopes the audit; controls are data, not code. Custom controls are added in the UI. |
| **R4 Deviation analysis** — Pass/Fail with risk severity | Every control evaluates to PASS / FAIL / NOT ASSESSED (no evidence) / N/A with critical–high–medium–low severity; the compliance score is severity-weighted. A device whose configuration was barely understood is reported as **Not assessed** instead of a misleading score, and a **coverage** figure says how much of the library had evidence. Failed controls carry triage state and time-boxed, documented **risk acceptance**, which produces an adjusted score. |
| **R5 AI training loop** — interactive low-code GUI | The Training Studio groups unrecognised lines by configuration block, proposes an SBM parameter + extraction rule (polarity / capture / list / count / flag / constant), shows a live regex test across all pending lines, and persists the mapping. Mappings apply fleet-wide on the next parse, can be edited, and are exported/imported as **mapping packs**. |
| **R6 AI/NLP component** | Offline classifier (`src/engine/classifier.ts`): tokenisation with letter/digit and hyphen splitting, keyword/phrase scoring against the SBM ontology, nearest-neighbour similarity against a 212-command cross-vendor corpus and against previously learned mappings, confidence with margin adjustment. Optional **LLM assist** via the Anthropic API with the operator's own key, kept for the tab session only (`src/engine/llm.ts`). |
| **R7 PDF report per device** | jsPDF report (`src/engine/report/pdf.ts`): identification (hostname, vendor/OS, version, model, serial, management IP, SHA-256 of the config), findings table, remediation paths with evidence and vendor CLI, accepted risks, normalised baseline model. Also: fleet summary PDF, CSV and JSON, a reviewable **remediation script** per device and a ZIP **evidence bundle** with a SHA-256 manifest. |
| **R8 Vendor-agnostic scalability** | New vendor = signature entries + parser module (or just learned mappings); new framework = references on existing controls; new control = data. Configuration **drift** between versions is shown as a line diff plus the baseline-parameter and control deltas. |

## Quick start

```bash
npm install
npm run dev            # http://localhost:5173
npm test               # engine, parser, store, drift and exception tests
npm run build          # static site in dist/
npm run build:single   # one self-contained HTML file in dist-artifact/
```

Node 22 or newer. No environment variables are required.

## Deploying for free

**GitHub Pages:** push this folder to a repository and enable *Settings → Pages → Source: GitHub Actions*. The included workflow (`.github/workflows/deploy.yml`) tests, builds and publishes on every push to `main`. The site works at `https://<user>.github.io/<repo>/` because the build uses relative asset paths and hash routing.

**Any static host** (Netlify, Vercel, Cloudflare Pages): deploy the `dist/` folder.

**Single file:** `npm run build:single` produces `dist-artifact/netsentinel.html`, which can be opened directly or published as a Claude artifact.

## Demo flow (2 minutes)

1. **Overview** — the numbered pipeline shows 9 sample devices, 8 vendor families plus one unknown vendor, the baseline parameters extracted, the control checks and failures. The fleet gauge, the severity bars and the "devices needing attention first" list are computed from the files. The heatmap shows failed/assessed controls per family and device.
2. **Devices → EDGE-RTR-01** — identification pulled from the IOS-XE configuration (model, serial, version). Open a failed control: evidence line (click to jump into the configuration), rationale, remediation CLI ready to review. Triage it, or accept the risk with a reason and ticket: the stamp changes and the adjusted score moves.
3. **Training Studio** — ACCESS-EX-12 (Extreme EXOS) has 57 unparsed lines. Pick a line: the classifier proposes a parameter with confidence and reasons; the regex is generated and tested live. *Accept high-confidence*, or *Load EXOS starter pack*. Back on the device it is now assessable — no code changed.
4. **Devices → Drift** — paste a newer configuration for the same hostname: the previous version is archived, and the Drift tab shows the line diff, the baseline parameters that moved and the controls that regressed or were fixed.
5. **Reports** — download the device PDF, the fleet summary, the fleet remediation plan or the evidence bundle (its `MANIFEST.sha256` verifies with `sha256sum -c`).
6. **Frameworks** — toggle STIG off and on; the scope re-labels instantly. Add a custom control in the low-code form.
7. **Ctrl+K** jumps to any page, device or control; the **Methodology** page explains scoring, coverage and the training loop.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the pipeline, data model, training loop and extensibility design.

```
src/engine/
  detect.ts              vendor signatures (data)
  sbm.ts                 Security Baseline Model catalogue (118 parameters)
  parsers/               cisco-ios (+nxos, eos), junos, fortios, panos, routeros, vrp, generic
  mappings.ts            learned-mapping application (polarity / capture / list / count / flag / const)
  classifier.ts          offline NLP classifier + cross-vendor corpus
  llm.ts                 optional LLM assist (Anthropic SDK, browser-direct)
  rules/library.ts       68 controls × 4 frameworks, remediation templates per vendor
  rules/evaluate.ts      evaluation, assessability, severity-weighted scoring
  rules/remediation.ts   device-specific CLI rendering ({{placeholders}}, {{#each}}, {{#if}})
  fleet.ts               device and fleet views (coverage, adjusted score)
  exceptions.ts          risk acceptance and triage
  diff.ts                configuration drift (line diff, parameter and finding deltas)
  report/                jsPDF reports, CSV/JSON, remediation script, evidence bundle
  samples/               9 realistic configurations + EXOS starter mapping pack
src/pages/               Overview, Ingest, Devices, Findings, Frameworks, Training, Reports, Help, Settings
src/components/          design system (ui.tsx), shell with command palette, finding drawer
```

## Adding a vendor without touching code

1. Ingest the configuration; it routes to the generic parser.
2. In the Training Studio accept or edit the proposed mappings.
3. Export the mapping pack (`*.json`) and share it — importing it on another workstation makes the vendor auditable there too.

Adding a full parser (for very hierarchical syntaxes) is one module in `src/engine/parsers/` plus a signature block in `detect.ts`.

## Security notes

- Configurations are processed and stored only in the browser (local storage), hashed with SHA-256 for evidence integrity.
- The optional LLM key lives in the tab's session storage only and is used for browser-to-API calls you trigger; only unrecognised lines are sent.
- Framework reference IDs are seeded from public benchmark documents and should be validated against the licensed benchmark edition before formal audits.
- Generated remediation CLI is for review in a change window, never for blind execution.

## Roadmap

- Collector service (Netmiko / NAPALM) to pull running configurations over SSH on a schedule.
- Server mode with a shared mapping-pack registry and role-based access.
- Signed evidence bundles (hash chain of report + configuration) anchored in a ledger.
- Additional parsers: Check Point Gaia, SonicOS, HPE Aruba AOS-CX, SONiC config_db, cloud security groups.

## Licence

MIT.
