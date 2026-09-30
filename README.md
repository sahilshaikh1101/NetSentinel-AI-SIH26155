# NetSentinel AI

### AI-Driven Multi-Vendor Network Security Compliance Auditor

> Developed for **Smart India Hackathon 2026** | Problem Statement **SIH26155** | National Technical Research Organisation (NTRO)

---

## Problem Statement

| Field                    | Details                                                    |
|--------------------------|------------------------------------------------------------|
| **Problem Statement ID** | SIH26155                                                   |
| **Title**                | AI-Driven Multi-Vendor Network Security Compliance Auditor |
| **Organization**         | National Technical Research Organisation (NTRO)            |
| **Department**           | National Technical Research Organisation (NTRO)            |
| **Category**             | Software                                                   |
| **Theme**                | Blockchain & Cybersecurity                                 |

**Problem Description:**
Modern enterprise networks are inherently heterogeneous, consisting of hardware from diverse vendors. Organizations are mandated to align these devices with rigorous security frameworks including CIS Benchmarks, NIST SP 800-53, DISA STIGs, and ISO/IEC 27001. Administrators managing hybrid networks lack a centralized, vendor-agnostic solution for compliance auditing. The challenge lies in syntactic diversity across vendor CLIs and the need for scalable adaptation as new vendors, firmware versions, and device types are introduced.

NetSentinel AI addresses this gap by providing an AI-augmented, vendor-agnostic Compliance Engine that interprets configuration files through pattern recognition and NLP, rather than relying on hard-coded vendor-specific parsers that become obsolete with firmware updates.

---

---

## Overview

NetSentinel AI ingests raw configuration files from any network device, normalises them into a vendor-neutral **Security Baseline Model (SBM)**, audits the model against **CIS, NIST SP 800-53, DISA STIG, and ISO/IEC 27001**, and produces a comprehensive **PDF report per device** containing device identification, pass/fail findings with severity ratings, evidence line numbers, and device-specific remediation CLI commands.

When the engine encounters syntax it has not been trained on, the **Training Studio** proposes mappings using an offline pattern-recognition classifier (with optional LLM assistance). The administrator confirms or adjusts these mappings through a low-code interface — the engine learns without requiring a redeployment.

The entire application runs in the browser. No server, no database, and no configuration data ever leaves the user's machine.

---

## Key Features (Mapped to Problem Statement Requirements)

| Requirement | Implementation |
|-------------|----------------|
| **R1 — Unified Ingestion Engine** | Drag-and-drop support for files, folders, and ZIP archives. Paste-based text input. JSON/XML exports are flattened automatically. Weighted syntax signatures detect the vendor with a confidence score. Files are SHA-256 hashed and deduplicated. Re-uploading a configuration for a known hostname creates a new version with the previous one archived for drift analysis. |
| **R2 — Normalisation** | 118 parameters across 10 control families in the Security Baseline Model. Dedicated parsers for Cisco IOS/IOS-XE, Cisco NX-OS, Arista EOS, Juniper Junos (brace and set formats), FortiOS, PAN-OS (set and XML), MikroTik RouterOS, Huawei VRP, plus a generic parser for unseen vendors. Every observation carries evidence line numbers and a source attribution (parser, platform default, learned mapping, or LLM). |
| **R3 — Multi-Framework Compliance Engine** | A single control library of 68 controls cross-referenced to CIS, NIST 800-53 r5, DISA NDM/Router SRG, and ISO 27001:2022. Selecting frameworks scopes the audit dynamically. Controls are defined as data, not code. Custom controls can be added through the UI. |
| **R4 — Deviation Analysis** | Every control evaluates to PASS, FAIL, NOT ASSESSED, or N/A with critical, high, medium, and low severity levels. Compliance scores are severity-weighted. Devices with insufficient parsed data are reported as "Not Assessed" with a coverage figure. Failed controls support triage states and time-boxed, documented risk acceptance with adjusted scoring. |
| **R5 — AI Training Loop** | The Training Studio groups unrecognised configuration lines by block, proposes SBM parameter mappings with extraction rules (polarity, capture, list, count, flag, constant), provides live regex testing, and persists mappings. Mappings apply fleet-wide on the next parse and can be exported/imported as mapping packs. |
| **R6 — AI/NLP Component** | Offline classifier with tokenisation, keyword/phrase scoring against the SBM ontology, nearest-neighbour similarity against a 212-command cross-vendor corpus and previously learned mappings. Optional LLM assist via the Anthropic API using the operator's own key (session-scoped, never persisted). |
| **R7 — PDF Reporting** | Per-device PDF reports include device identification (hostname, vendor/OS, version, model, serial, management IP, SHA-256 hash), findings table, remediation paths with evidence and vendor CLI, accepted risks, and the normalised baseline model. Additional exports include fleet summary PDF, CSV, JSON, per-device remediation scripts, and ZIP evidence bundles with SHA-256 manifests. |
| **R8 — Vendor-Agnostic Scalability** | Adding a new vendor requires only signature entries and a parser module (or just learned mappings). Adding a new framework requires only references on existing controls. Adding a new control requires only data. Configuration drift between versions is displayed as a line diff with baseline-parameter and control deltas. |

---

## Technology Stack

| Layer           | Technology                                                |
|-----------------|-----------------------------------------------------------|
| **Frontend**    | React 19, TypeScript, Vite                                |
| **State**       | Zustand (client-side store with local storage persistence) |
| **Routing**     | Wouter (hash-based routing)                               |
| **PDF Engine**  | jsPDF, jsPDF-AutoTable                                    |
| **Archive**     | JSZip (evidence bundles, mapping pack import/export)      |
| **Icons**       | Lucide React                                              |
| **AI/NLP**      | Custom offline classifier, optional Anthropic LLM assist  |
| **Testing**     | Vitest                                                    |
| **Build**       | Vite, vite-plugin-singlefile (single-file artifact build) |

---

## Getting Started

### Prerequisites

- Node.js 22 or newer
- npm (bundled with Node.js)
- No environment variables are required

### Installation

```bash
git clone https://github.com/<your-username>/NetSentinel-AI-SIH26155.git
cd NetSentinel-AI-SIH26155
npm install
```

### Running the Application

```bash
npm run dev            # Development server at http://localhost:5173
```

### Testing

```bash
npm test               # Runs engine, parser, store, drift, and exception tests
```

### Production Build

```bash
npm run build          # Static site output in dist/
npm run build:single   # Single self-contained HTML file in dist-artifact/
```

---

## Deployment

**GitHub Pages:** Enable *Settings > Pages > Source: GitHub Actions*. The included workflow tests, builds, and publishes on every push to `main`. The site works at `https://<user>.github.io/<repo>/` using relative asset paths and hash routing.

**Static Hosting (Netlify, Vercel, Cloudflare Pages):** Deploy the `dist/` folder after running `npm run build`.

**Single File:** `npm run build:single` produces `dist-artifact/netsentinel.html`, a fully self-contained HTML file that can be opened directly in any modern browser.

---

## Project Architecture

For the complete architecture document, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
src/
  engine/
    detect.ts                 Vendor detection via weighted syntax signatures
    sbm.ts                    Security Baseline Model (118 parameters, 10 families)
    parsers/
      cisco-ios.ts            Cisco IOS, IOS-XE, NX-OS, Arista EOS
      junos.ts                Juniper Junos (brace and set formats)
      fortios.ts              Fortinet FortiOS
      panos.ts                Palo Alto PAN-OS (set and XML)
      routeros.ts             MikroTik RouterOS
      vrp.ts                  Huawei VRP
      generic.ts              Generic fallback parser
    mappings.ts               Learned mapping application
    classifier.ts             Offline NLP classifier with cross-vendor corpus
    llm.ts                    Optional LLM assist (Anthropic SDK, browser-direct)
    rules/
      library.ts              68 controls across 4 frameworks
      evaluate.ts             Evaluation logic, severity-weighted scoring
      remediation.ts          Device-specific CLI remediation rendering
    fleet.ts                  Fleet-wide views, coverage, adjusted scoring
    exceptions.ts             Risk acceptance and triage management
    diff.ts                   Configuration drift detection
    report/
      pdf.ts                  Per-device and fleet PDF generation
      exports.ts              CSV, JSON export
      evidence-bundle.ts      ZIP evidence bundle with SHA-256 manifest
      remediation-bundle.ts   Reviewable remediation script generation
    samples/                  9 sample configurations across 8 vendor families
  pages/                      Overview, Ingest, Devices, Findings, Frameworks,
                              Training, Reports, Help, Settings
  components/                 Design system, shell with command palette, finding drawer
```

---

## Demo Flow (2 Minutes)

1. **Overview** — The pipeline displays 9 sample devices across 8 vendor families plus one unknown vendor. The fleet compliance gauge, severity distribution bars, and prioritised device list are computed from the ingested files. A heatmap shows failed versus assessed controls per family and device.

2. **Device Inspection** — Select a device (e.g., EDGE-RTR-01) to view identification details extracted from the IOS-XE configuration. Open a failed control to see the evidence line, rationale, and remediation CLI. Triage the finding or accept the risk with a documented reason.

3. **Training Studio** — For an unsupported vendor (e.g., Extreme EXOS with 57 unparsed lines), the classifier proposes parameter mappings with confidence scores. Regex patterns are generated and tested live. Accept high-confidence suggestions or load a starter mapping pack. The device becomes assessable without any code changes.

4. **Configuration Drift** — Upload a newer configuration for the same hostname. The previous version is archived. The Drift tab shows a line-level diff alongside baseline parameter and control finding deltas.

5. **Reports** — Download per-device PDF reports, fleet summary reports, fleet remediation plans, or evidence bundles (verifiable via `sha256sum -c MANIFEST.sha256`).

6. **Frameworks** — Toggle frameworks (CIS, NIST, STIG, ISO) on and off; the audit scope updates instantly. Add custom controls through the low-code form.

---

## Adding a New Vendor (Without Code Changes)

1. Ingest the device configuration file; it will be routed to the generic parser.
2. Open the Training Studio and accept or edit the proposed mappings.
3. Export the mapping pack (`.json`) and distribute it to other workstations for immediate vendor support.

For vendors with highly hierarchical syntax, a dedicated parser module can be added in `src/engine/parsers/` with a corresponding signature block in `detect.ts`.

---

## Security Considerations

- All configuration data is processed and stored exclusively in the browser via local storage. No data is transmitted to any server.
- Configuration files are hashed with SHA-256 for evidence integrity and auditability.
- The optional LLM API key is stored only in the browser tab's session storage and is used for direct browser-to-API calls. Only unrecognised configuration lines are transmitted to the LLM endpoint.
- Framework reference IDs are seeded from publicly available benchmark documents and should be validated against the licensed benchmark edition before formal audits.
- Generated remediation CLI commands are intended for review in a controlled change window, not for blind execution.

---

## Roadmap

- **Collector Service:** SSH-based configuration collection using Netmiko / NAPALM on a scheduled basis.
- **Server Mode:** Shared mapping-pack registry with role-based access control for enterprise deployments.
- **Signed Evidence Bundles:** Hash chain of report and configuration data anchored in a distributed ledger.
- **Additional Parsers:** Check Point Gaia, SonicOS, HPE Aruba AOS-CX, SONiC config_db, cloud security groups (AWS, Azure, GCP).

---

## Deliverables (as per SIH Requirements)

| Deliverable                              | Status    |
|------------------------------------------|-----------|
| Source Code (GitHub Repository)          | Provided  |
| README with Setup Instructions           | Provided  |
| Architecture Document (Max 2 Pages)      | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Demo Video (Max 2 Minutes)               | Pending   |
| Technical Presentation (Max 5 Slides)    | Pending   |

---

## License

MIT. See [LICENSE](LICENSE) for details.
