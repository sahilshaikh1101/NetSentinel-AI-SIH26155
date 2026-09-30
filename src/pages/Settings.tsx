import { useState } from "react";
import { Database, KeyRound, RotateCcw, Trash2 } from "lucide-react";
import { useStore } from "../store";
import { Confirm, Page, Section, StatusLine, toast } from "../components/ui";
import { RULES } from "../engine/rules/library";
import { SBM_PARAMS, VENDOR_IDS, VENDOR_META } from "../engine/sbm";
import { DEFAULT_LLM_MODEL } from "../engine/llm";
import { KNOWN_COMMANDS } from "../engine/classifier";
import { fmtDateTime } from "../lib/util";

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const HOST = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;
const CIDR = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/;
const hostOk = (v: string) => IPV4.test(v) || HOST.test(v) || /^[0-9a-f:]+$/i.test(v);

export default function Settings() {
  const settings = useStore((s) => s.settings);
  const update = useStore((s) => s.updateSettings);
  const activity = useStore((s) => s.activity);
  const resetToSamples = useStore((s) => s.resetToSamples);
  const clearAll = useStore((s) => s.clearAll);
  const [rem, setRem] = useState(settings.remediation);
  const [profile, setProfile] = useState({ organisation: settings.organisation, operator: settings.operator });
  const [llm, setLlm] = useState(settings.llm);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const saveRem = () => {
    const e: Record<string, string> = {};
    for (const k of ["syslogHost", "ntpServer", "ntpServer2", "tacacsServer", "snmpManager"] as const) if (rem[k].trim() && !hostOk(rem[k].trim())) e[k] = "Enter an IPv4/IPv6 address or a host name.";
    if (!CIDR.test(rem.mgmtSubnetCidr.trim())) e.mgmtSubnetCidr = "Use CIDR notation, e.g. 10.10.0.0/24.";
    if (rem.domain.trim() && !HOST.test(rem.domain.trim())) e.domain = "Enter a DNS domain name.";
    setErrors(e);
    if (Object.keys(e).length) return toast.err("Check the highlighted fields");
    update({ remediation: rem });
    toast.ok("Remediation defaults saved", "Every remediation snippet now uses these values.");
  };
  const saveProfile = () => {
    if (!profile.organisation.trim() || !profile.operator.trim()) return toast.err("Organisation and operator are required", "Both are printed on every report.");
    update({ organisation: profile.organisation.trim(), operator: profile.operator.trim() });
    toast.ok("Report identity saved");
  };
  const saveLlm = () => {
    update({ llm: { apiKey: llm.apiKey.trim(), model: llm.model.trim() || DEFAULT_LLM_MODEL } });
    toast.ok(llm.apiKey.trim() ? "LLM assist enabled for this session" : "LLM assist disabled", llm.apiKey.trim() ? "The key lives in this tab's session storage and is gone when the tab closes." : undefined);
  };

  return (
    <Page title="Settings" status={<StatusLine items={["Report identity, remediation defaults, optional LLM assist and workspace data", "Everything is stored in this browser only"]} />}>
      <div className="grid">
        <Section className="span-6" id="st-identity" title="Report identity" sub="Printed in the header of every PDF and the evidence manifest" box>
          <div className="stack" style={{ gap: 12 }}>
            <div className="field"><label htmlFor="s-org">Organisation</label><input id="s-org" className="input" value={profile.organisation} onChange={(e) => setProfile({ ...profile, organisation: e.target.value })} /></div>
            <div className="field"><label htmlFor="s-op">Operator</label><input id="s-op" className="input" value={profile.operator} onChange={(e) => setProfile({ ...profile, operator: e.target.value })} /><span className="hint">Also recorded as the author of risk acceptances.</span></div>
            <div className="field"><label htmlFor="s-theme">Theme</label><select id="s-theme" className="select" value={settings.theme} onChange={(e) => update({ theme: e.target.value as "light" | "dark" })}><option value="light">Light</option><option value="dark">Dark</option></select></div>
            <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" className="btn btn--primary" onClick={saveProfile}>Save identity</button></div>
          </div>
        </Section>
        <Section className="span-6" id="st-llm" title="LLM assist" sub="Optional. Model-generated mapping proposals in the Training Studio; the offline classifier works without it" box>
          <div className="stack" style={{ gap: 12 }}>
            <div className="field"><label htmlFor="s-key">Anthropic API key</label><input id="s-key" className="input" type="password" autoComplete="off" value={llm.apiKey} onChange={(e) => setLlm({ ...llm, apiKey: e.target.value })} placeholder="sk-ant-…" /><span className="hint"><KeyRound size={11} style={{ verticalAlign: -1 }} aria-hidden="true" /> Session-scoped: kept in this tab's session storage, never written to disk or logs. Only the unrecognised lines of the selected device are sent, straight from the browser to api.anthropic.com. Hosted viewers with a strict content policy block that request; run locally to use it.</span></div>
            <div className="field"><label htmlFor="s-model">Model</label><input id="s-model" className="input mono" value={llm.model} onChange={(e) => setLlm({ ...llm, model: e.target.value })} placeholder={DEFAULT_LLM_MODEL} /></div>
            <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" className="btn btn--primary" onClick={saveLlm}>Save</button></div>
          </div>
        </Section>
      </div>

      <Section id="st-rem" title="Remediation defaults" sub="Placeholders in remediation templates are filled from these values so the generated CLI is ready to review" box>
        <div className="grid grid--3" style={{ gap: 12 }}>
          {([
            ["syslogHost", "Syslog / SIEM collector"],
            ["ntpServer", "Primary NTP server"],
            ["ntpServer2", "Secondary NTP server"],
            ["mgmtSubnetCidr", "Management subnet (CIDR)"],
            ["tacacsServer", "TACACS+ / RADIUS server"],
            ["snmpManager", "SNMP manager"],
            ["domain", "Domain name"],
          ] as const).map(([k, label]) => (
            <div key={k} className="field"><label htmlFor={`rem-${k}`}>{label}</label><input id={`rem-${k}`} className="input mono" value={rem[k]} onChange={(e) => setRem({ ...rem, [k]: e.target.value })} aria-invalid={Boolean(errors[k])} />{errors[k] && <span className="error">{errors[k]}</span>}</div>
          ))}
          <div className="field" style={{ gridColumn: "span 2" }}><label htmlFor="rem-banner">Login banner text</label><textarea id="rem-banner" className="textarea" style={{ minHeight: 60, fontFamily: "var(--font-body)" }} value={rem.banner} onChange={(e) => setRem({ ...rem, banner: e.target.value })} /></div>
        </div>
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 12 }}><button type="button" className="btn btn--primary" onClick={saveRem}>Save defaults</button></div>
      </Section>

      <div className="grid">
        <Section className="span-6" id="st-data" title="Workspace" sub="Devices, versions, mappings, custom controls, exceptions and the activity trail persist in this browser" box>
          <div className="row">
            <Confirm label="Reset to sample fleet" armedLabel="Discard my work and reset?" icon={<RotateCcw />} small={false} onConfirm={() => { resetToSamples(); toast.ok("Sample fleet restored", "Uploaded devices, mappings, exceptions and history were discarded."); }} />
            <Confirm label="Clear everything" armedLabel="Really clear the workspace?" danger small={false} icon={<Trash2 />} onConfirm={() => { clearAll(); toast.info("Workspace cleared"); }} />
          </div>
          <div className="small muted" style={{ marginTop: 12 }}><Database size={12} style={{ verticalAlign: -2 }} aria-hidden="true" /> Uploads are hashed with SHA-256 for evidence integrity. Browser storage holds about five megabytes per site; export an evidence bundle before ingesting very large fleets.</div>
        </Section>
        <Section className="span-6" id="st-engine" title="Engine" sub="What ships in this build" box>
          <dl className="kv">
            <dt>Vendor parsers</dt><dd>{VENDOR_IDS.filter((v) => v !== "generic").map((v) => VENDOR_META[v].short).join(", ")} + generic (learned mappings, JSON/XML flattening)</dd>
            <dt>Baseline parameters</dt><dd>{SBM_PARAMS.length} vendor-neutral parameters in ten control families</dd>
            <dt>Control library</dt><dd>{RULES.length} controls cross-referenced to CIS, NIST SP 800-53 r5, DISA NDM SRG and ISO/IEC 27001:2022</dd>
            <dt>Classifier corpus</dt><dd>{KNOWN_COMMANDS.length} labelled commands across vendors for nearest-neighbour transfer</dd>
            <dt>Reporting</dt><dd>Per-device and fleet PDFs, CSV, JSON, remediation scripts, evidence bundles, mapping packs</dd>
          </dl>
        </Section>
      </div>

      <Section id="st-activity" title="Activity log" sub="Immutable trail of administrator and engine actions" box flush>
        <div className="table-wrap" style={{ maxHeight: 480, overflowY: "auto" }}>
          <table className="table">
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
            <tbody>
              {activity.map((a) => <tr key={a.id}><td className="nowrap dim small">{fmtDateTime(a.at)}</td><td><span className={`pill ${a.actor === "admin" ? "pill--accent" : a.actor === "engine" ? "pill--info" : "pill--ai"}`}>{a.actor}</span></td><td><strong>{a.action}</strong></td><td className="small">{a.target}</td><td className="small muted">{a.detail}</td></tr>)}
              {!activity.length && <tr><td colSpan={5} className="muted" style={{ textAlign: "center", padding: 30 }}>No activity yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </Section>
    </Page>
  );
}
