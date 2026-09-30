# Demo script (≤ 2 minutes) and 5-slide outline

## Video script

| Time | Screen | Say |
|---|---|---|
| 0:00 | Overview | "NetSentinel AI audits any network device configuration against CIS, NIST, STIG and ISO. Nine devices from eight vendor families are loaded; every number here is computed from the files, in the browser, with nothing sent anywhere." |
| 0:12 | Overview pipeline | "The pipeline: ingest, detect the vendor from syntax signatures, normalise into a vendor-neutral Security Baseline Model, evaluate one control library across four frameworks, and report. The gauge is severity-weighted; a device the parser did not understand is reported as *not assessed*, never as a fake 100." |
| 0:28 | Devices → EDGE-RTR-01 | "This IOS-XE edge router: model, serial and version extracted from the configuration. Telnet is open on the VTY lines — here is the evidence line, why it matters, and the exact CLI to fix it. I can triage it to an owner, or accept the risk with a reason and a ticket: the adjusted score moves and the acceptance is printed in the report." |
| 0:50 | Findings → By control | "Fleet-wide view by control: which weaknesses repeat across devices, with pass, fail and not-assessed counts per control." |
| 1:02 | Training Studio | "The hard part of the problem statement: an Extreme switch no parser knows. The offline classifier proposes a baseline parameter for each unknown line with confidence and reasons; the regex is generated and tested live. Accept the high-confidence proposals…" |
| 1:22 | Devices → ACCESS-EX-12 | "…and the device is now assessable: score, findings, remediation. No code changed, and the mapping pack can be exported for the whole organisation." |
| 1:36 | Devices → Drift tab | "Upload a newer configuration for a device and NetSentinel keeps the previous version: line diff, which baseline parameters changed, which controls regressed or were fixed." |
| 1:48 | Reports | "One PDF per device — identification with serial and model, pass/fail with severity, step-by-step CLI remediation, the normalised model as evidence. Plus fleet summaries, CSV, JSON, a remediation script and a tamper-evident evidence bundle with a SHA-256 manifest." |

## Technical presentation (5 slides)

1. **Problem & approach** — heterogeneous networks, bifurcated auditing; our answer: normalise first, evaluate once, learn continuously, and never claim what the evidence does not show.
2. **Architecture** — pipeline diagram (detect → parse → learned mappings → SBM → evaluate → report) and the training loop; everything vendor-specific is data.
3. **AI engine** — offline classifier (tokenisation, ontology scoring, cross-vendor kNN, learned-mapping similarity, confidence with margin) + optional LLM assist; human-in-the-loop confirmation; mapping packs.
4. **Compliance & reporting** — 118 SBM parameters, 68 controls × CIS/NIST/STIG/ISO, assessability and coverage, severity-weighted and adjusted scores, evidence line numbers, device-specific remediation templates, drift, triage and risk acceptance, single PDF per device, evidence bundle.
5. **Validation & roadmap** — eight vendor parsers at 100% recognised lines on the sample corpus, adversarial parser reviews folded back into the tests, automated test suite, static/free hosting; roadmap: SSH collector (Netmiko/NAPALM), pack registry, ledger-anchored evidence bundles.
