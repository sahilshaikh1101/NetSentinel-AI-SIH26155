import { Link } from "wouter";
import { Page, Section, StatusLine } from "../components/ui";
import { RULES, FRAMEWORKS } from "../engine/rules/library";
import { SBM_PARAMS, VENDOR_IDS, VENDOR_META } from "../engine/sbm";
import { KNOWN_COMMANDS } from "../engine/classifier";
import { SEVERITY_WEIGHT } from "../engine/rules/evaluate";
import type { FrameworkId } from "../engine/types";

export default function Help() {
  const parsers = VENDOR_IDS.filter((v) => v !== "generic").map((v) => VENDOR_META[v].short);
  return (
    <Page title="Methodology" status={<StatusLine items={["How NetSentinel turns a raw configuration into an auditable verdict", "Every number in the app is reproducible from the text you upload"]} />}>
      <div className="grid">
        <Section className="span-8" id="m-pipeline" num="01" title="The pipeline">
          <ol className="stack" style={{ margin: 0, paddingLeft: 20, gap: 10 }}>
            <li><strong>Ingest.</strong> Files, folders, ZIP archives or pasted text. Each file is hashed with SHA-256 for evidence integrity and deduplicated. A second upload for the same hostname becomes a new <em>version</em>; the previous one is archived for drift analysis.</li>
            <li><strong>Detect.</strong> Weighted syntax signatures score every vendor family ({parsers.join(", ")}). The winner and its confidence are shown on the Ingest page; you can override the parser per device.</li>
            <li><strong>Normalise.</strong> The vendor parser walks the configuration and fills the <em>Security Baseline Model</em> — {SBM_PARAMS.length} vendor-neutral parameters such as <span className="mono">management.telnet_enabled</span> or <span className="mono">auth.min_password_length</span>. Every value keeps the line numbers that produced it. Platform defaults are recorded as defaults, never as observations. Lines the parser does not understand are queued for the Training Studio.</li>
            <li><strong>Evaluate.</strong> {RULES.length} controls, each a declarative check against the model (equals, at least, list includes, exists…), cross-referenced to CIS, NIST SP 800-53, DISA STIG and ISO/IEC 27001. A control passes, fails, is not applicable to the vendor, or is <em>not assessed</em> when the model has no evidence either way.</li>
            <li><strong>Report.</strong> Device-specific remediation CLI is rendered from templates with the device's own values (ACL names, VTY ranges, BGP neighbours). Everything exports as PDF, CSV, JSON, a remediation script and a tamper-evident evidence bundle.</li>
          </ol>
        </Section>
        <Section className="span-4" id="m-privacy" title="Privacy" box>
          <p className="small">Nothing leaves the browser. Parsing, evaluation and PDF generation run locally; the workspace persists in this browser's storage. The optional LLM assist sends only the <em>unrecognised lines</em> of a device to the Anthropic API with a key you provide, kept for the current tab session only.</p>
        </Section>
      </div>

      <div className="grid">
        <Section className="span-6" id="m-score" num="02" title="Scoring" box>
          <p className="small">The score is the severity-weighted share of passed controls among the controls that were assessed:</p>
          <pre className="cli" style={{ margin: "10px 0" }}>{`score = Σ weight(passed) / Σ weight(passed + failed) × 100`}</pre>
          <table className="table table--ground small">
            <thead><tr><th>Severity</th><th className="right">Weight</th><th>Typical example</th></tr></thead>
            <tbody>
              <tr><td className="sev sev--critical"><i />Critical</td><td className="right num">{SEVERITY_WEIGHT.critical}</td><td>Telnet enabled, default SNMP community, no AAA</td></tr>
              <tr><td className="sev sev--high"><i />High</td><td className="right num">{SEVERITY_WEIGHT.high}</td><td>No remote logging, unauthenticated routing peers</td></tr>
              <tr><td className="sev sev--medium"><i />Medium</td><td className="right num">{SEVERITY_WEIGHT.medium}</td><td>Idle timeout too long, single NTP server</td></tr>
              <tr><td className="sev sev--low"><i />Low</td><td className="right num">{SEVERITY_WEIGHT.low}</td><td>Missing login banner, no domain name</td></tr>
            </tbody>
          </table>
          <p className="small" style={{ marginTop: 10 }}>Thresholds: <strong>85 and above</strong> is hardened, <strong>65 to 84</strong> needs attention, below 65 is at risk. The label is stricter than the number, because a high score computed from a handful of controls is not a safe device: a device is never called <em>Hardened</em> while a critical or high finding is open, and one whose coverage is below half reads <em>Partially assessed</em> whatever it scores. The <em>adjusted score</em> additionally excludes failed controls with an active, documented risk acceptance. The fleet score is the mean of device scores weighted by how many controls each device had assessed.</p>
        </Section>
        <Section className="span-6" id="m-coverage" num="03" title="Assessable devices and coverage" box>
          <p className="small">A score only means something when the parser understood the file. A device is <strong>assessable</strong> when at least a quarter of its meaningful lines were recognised and at least three parameters were observed (eight for the generic parser). Devices below that bar show <em>Not assessed</em> instead of a misleading 100, are excluded from the fleet score, and cannot fail "absence" controls — a parser that saw nothing cannot claim a setting is missing.</p>
          <p className="small" style={{ marginTop: 10 }}><strong>Coverage</strong> is the share of applicable controls that had evidence either way. It rises as you train the parser; the Training Studio shows the unrecognised lines that keep it down.</p>
          <dl className="kv small" style={{ marginTop: 12 }}>
            <dt><span className="stamp stamp--pass">Pass</span></dt><dd>Evidence confirms the hardened state.</dd>
            <dt><span className="stamp stamp--fail">Fail</span></dt><dd>Evidence shows the insecure state; remediation CLI is rendered.</dd>
            <dt><span className="stamp stamp--warning">Not assessed</span></dt><dd>No evidence either way. Train the parser or verify on the device.</dd>
            <dt><span className="stamp stamp--na">N/A</span></dt><dd>The control does not apply to this vendor or role.</dd>
            <dt><span className="stamp stamp--accepted">Accepted</span></dt><dd>Failed, but a documented risk acceptance is active.</dd>
          </dl>
        </Section>
      </div>

      <div className="grid">
        <Section className="span-6" id="m-training" num="04" title="Training loop" box>
          <p className="small">When a line is not understood, the offline classifier normalises it (addresses and long numbers become placeholders so the shape is compared, not the values), scores it against parameter keywords and a corpus of {KNOWN_COMMANDS.length} labelled commands from other vendors weighted by how distinctive each token is, and proposes a parameter plus a value-extraction rule (flag, polarity, capture, list, count or constant). The generated regular expression is generalised so sibling commands share one mapping: teach it the primary NTP server and the secondary one is understood too. Confidence combines evidence strength, how much of the parameter's vocabulary the line covers, the margin over the runner-up, and whether a real value could be extracted, so a line that looks relevant but yields nothing to store cannot reach the auto-accept bar.</p>
          <p className="small" style={{ marginTop: 10 }}>Accepting a proposal stores a <em>mapping</em>: a vendor-scoped regular expression. Mappings apply to every device on the next parse, can be edited, exported as a pack and shared. No redeploy, no code. The test suite pins the accuracy on the bundled Extreme EXOS switch and on a held-out set of commands from vendors that are not in the corpus at all.</p>
          <p className="small" style={{ marginTop: 10 }}>Try it: the sample fleet includes an Extreme EXOS switch that no built-in parser understands. Open the <Link href="/training">Training Studio</Link>, accept the high-confidence proposals, and watch the device become assessable.</p>
        </Section>
        <Section className="span-6" id="m-frameworks" num="05" title="Frameworks" box>
          <table className="table table--ground small">
            <thead><tr><th>Framework</th><th>Edition</th><th className="right">Controls</th></tr></thead>
            <tbody>
              {(Object.keys(FRAMEWORKS) as FrameworkId[]).map((f) => (
                <tr key={f}><td><span className={`tag tag--${f}`}>{FRAMEWORKS[f].short}</span> {FRAMEWORKS[f].name}</td><td className="muted">{FRAMEWORKS[f].edition}</td><td className="right num">{RULES.filter((r) => r.refs.some((x) => x.framework === f)).length}</td></tr>
              ))}
            </tbody>
          </table>
          <p className="small" style={{ marginTop: 10 }}>Selecting frameworks in the top bar scopes the audit to controls mapped to at least one of them. Custom controls added on the Frameworks page are evaluated exactly like built-in ones.</p>
        </Section>
      </div>

      <div className="grid">
        <Section className="span-6" id="m-drift" num="06" title="Drift, triage and exceptions" box>
          <p className="small">Upload a newer configuration for a device that is already in the fleet and NetSentinel keeps the previous version. The device's <em>Drift</em> tab shows the line diff, which baseline parameters changed, and which controls regressed or were fixed. Findings carry triage state (open, in progress, remediated) with owner and due date, and failed controls can receive a time-boxed risk acceptance with a reason and ticket — printed in the report and logged in the activity trail.</p>
        </Section>
        <Section className="span-6" id="m-keys" num="07" title="Keyboard" box>
          <dl className="kv small">
            <dt><kbd>Ctrl</kbd> <kbd>K</kbd> or <kbd>/</kbd></dt><dd>Search pages, devices and controls</dd>
            <dt><kbd>Esc</kbd></dt><dd>Close a drawer or dialog</dd>
            <dt><kbd>←</kbd> <kbd>→</kbd></dt><dd>Move between tabs when a tab is focused</dd>
            <dt><kbd>Tab</kbd></dt><dd>Every row link, filter and action is reachable without a mouse</dd>
          </dl>
        </Section>
      </div>

      <Section id="m-limits" num="08" title="Known limits" box>
        <ul className="small stack" style={{ margin: 0, paddingLeft: 18, gap: 6 }}>
          <li>Parsers cover common syntax of eight vendor families; unusual constructs land in the training queue rather than being guessed.</li>
          <li>A configuration cannot prove everything: hardware inventory, running software vulnerabilities and live reachability are out of scope. Paste <span className="mono">show version</span> output at the top of a file to enrich identity.</li>
          <li>Remediation CLI is generated for review, not for blind execution. Apply it in a change window and re-audit the saved configuration.</li>
          <li>Browser storage holds roughly five megabytes per origin; export the evidence bundle before ingesting very large fleets.</li>
        </ul>
      </Section>
    </Page>
  );
}
