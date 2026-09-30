import { useEffect, useState } from "react";
import { Link } from "wouter";
import { ClipboardCheck, ShieldCheck, Undo2 } from "lucide-react";
import { useStore } from "../store";
import type { DeviceView } from "../engine/fleet";
import type { TriagedFinding, TriageState } from "../engine/exceptions";
import { CopyButton, Drawer, EvidenceList, FwTag, Sev, Stamp, Vendor, toast } from "./ui";
import { fmtDate, fmtDateTime } from "../lib/util";

const TRIAGE: { id: Exclude<TriageState, "accepted">; label: string }[] = [
  { id: "open", label: "Open" },
  { id: "in-progress", label: "In progress" },
  { id: "remediated", label: "Remediated — awaiting re-audit" },
];

export function FindingDrawer({ finding, view, onClose, onJump }: { finding: TriagedFinding | null; view?: DeviceView; onClose: () => void; onJump?: (line: number) => void }) {
  const acceptRisk = useStore((s) => s.acceptRisk);
  const revokeException = useStore((s) => s.revokeException);
  const setTriage = useStore((s) => s.setTriage);
  const [mode, setMode] = useState<"triage" | "accept">("triage");
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState("");
  const [ticket, setTicket] = useState("");
  const [state, setState] = useState<TriageState>("open");
  const [owner, setOwner] = useState("");
  const [due, setDue] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setMode("triage");
    setReason("");
    setExpires("");
    setTicket("");
    setError(null);
    setState(finding?.triage?.state ?? "open");
    setOwner(finding?.triage?.owner ?? "");
    setDue(finding?.triage?.due ?? "");
    setNote(finding?.triage?.note ?? "");
  }, [finding?.id, finding?.triage]);

  const key = view?.key;
  const saveTriage = () => {
    if (!finding || !key) return;
    setTriage(key, finding.ruleId, { state: state === "accepted" ? "open" : state, owner: owner.trim() || undefined, due: due || undefined, note: note.trim() || undefined });
    toast.ok("Finding triaged", `${finding.ruleId} on ${view?.name}: ${TRIAGE.find((t) => t.id === state)?.label ?? state}.`);
  };
  const accept = () => {
    if (!finding || !key) return;
    if (reason.trim().length < 8) { setError("Give a reason of at least eight characters — it is printed in the report and the audit trail."); return; }
    if (expires && new Date(expires).getTime() < Date.now()) { setError("The expiry date is in the past."); return; }
    acceptRisk(key, finding.ruleId, { reason: reason.trim(), expires: expires || undefined, ticket: ticket.trim() || undefined });
    setMode("triage");
    toast.ok("Risk accepted", `${finding.ruleId} on ${view?.name} no longer lowers the adjusted score${expires ? ` until ${fmtDate(expires)}` : ""}.`);
  };

  return (
    <Drawer
      open={Boolean(finding)}
      onClose={onClose}
      title={finding ? `${finding.ruleId} — ${finding.title}` : ""}
      sub={
        finding && (
          <span className="row">
            <Stamp status={finding.status} accepted={Boolean(finding.exception)} />
            <Sev severity={finding.severity} />
            <span className="muted">{finding.category}</span>
            {view && <Link href={`/devices/${view.record.id}`} className="row" style={{ gap: 6 }}><Vendor vendor={view.vendor} label={view.name} /></Link>}
          </span>
        )
      }
    >
      {finding && (
        <>
          <dl className="kv">
            <dt>Observed</dt><dd>{finding.observed}</dd>
            <dt>Expected</dt><dd>{finding.expected}</dd>
          </dl>
          <div>
            <div className="eyebrow" style={{ marginBottom: 6 }}>Why it matters</div>
            <p>{finding.rationale}</p>
          </div>
          <div>
            <div className="eyebrow" style={{ marginBottom: 6 }}>Evidence in the configuration</div>
            <EvidenceList evidence={finding.evidence} onJump={onJump} />
          </div>
          {finding.status === "warning" && (
            <div className="callout callout--warn small">
              This control could not be assessed: the parser found no evidence either way. Teach it the relevant syntax in the <Link href="/training">Training Studio</Link>, or verify the control on the device and record the outcome below.
            </div>
          )}
          {(finding.status === "fail" || finding.status === "warning") && (
            <div>
              <div className="row between" style={{ marginBottom: 6 }}>
                <span className="eyebrow">Remediation · device-specific CLI</span>
                <CopyButton text={finding.remediation} />
              </div>
              <pre className="cli">{finding.remediation}</pre>
              {finding.remediationNote && <div className="small muted" style={{ marginTop: 6 }}>{finding.remediationNote}</div>}
            </div>
          )}
          <div>
            <div className="eyebrow" style={{ marginBottom: 6 }}>Framework references</div>
            <div className="stack" style={{ gap: 4 }}>
              {finding.refs.map((r, i) => (
                <div key={i} className="row"><FwTag framework={r.framework} id={r.id} /><span className="small muted">{r.title}</span></div>
              ))}
            </div>
          </div>

          {finding.status === "fail" && view && (
            <div className="box box--pad stack" style={{ gap: 12 }}>
              {finding.exception ? (
                <>
                  <div className="row between">
                    <strong className="row" style={{ gap: 6 }}><ShieldCheck size={16} color="var(--info)" aria-hidden="true" /> Risk accepted</strong>
                    <button type="button" className="btn btn--sm" onClick={() => { revokeException(finding.exception!.key); toast.info("Acceptance revoked", `${finding.ruleId} counts against the score again.`); }}><Undo2 /> Revoke</button>
                  </div>
                  <dl className="kv">
                    <dt>Reason</dt><dd>{finding.exception.reason}</dd>
                    <dt>Accepted by</dt><dd>{finding.exception.by} · {fmtDateTime(finding.exception.at)}</dd>
                    <dt>Expires</dt><dd>{finding.exception.expires ? fmtDate(finding.exception.expires) : "no expiry"}</dd>
                    {finding.exception.ticket && <><dt>Ticket</dt><dd className="mono">{finding.exception.ticket}</dd></>}
                  </dl>
                  <div className="small muted">Accepted risks are excluded from the adjusted score and listed separately in reports. The raw score still counts them.</div>
                </>
              ) : mode === "accept" ? (
                <>
                  <strong>Accept this risk</strong>
                  <div className="field">
                    <label htmlFor="ex-reason">Business justification</label>
                    <textarea id="ex-reason" className="textarea" style={{ minHeight: 70, fontFamily: "var(--font-body)" }} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Telnet is required by the legacy OOB console server until its replacement in Q4; access is limited to the management VRF." aria-invalid={Boolean(error && reason.trim().length < 8)} />
                  </div>
                  <div className="grid grid--2">
                    <div className="field"><label htmlFor="ex-exp">Expires (optional)</label><input id="ex-exp" type="date" className="input" value={expires} onChange={(e) => setExpires(e.target.value)} /></div>
                    <div className="field"><label htmlFor="ex-ticket">Change / risk ticket</label><input id="ex-ticket" className="input" value={ticket} onChange={(e) => setTicket(e.target.value)} placeholder="CHG0012345" /></div>
                  </div>
                  {error && <div className="error" role="alert">{error}</div>}
                  <div className="row" style={{ justifyContent: "flex-end" }}>
                    <button type="button" className="btn" onClick={() => { setMode("triage"); setError(null); }}>Cancel</button>
                    <button type="button" className="btn btn--primary" onClick={accept}><ShieldCheck /> Accept risk</button>
                  </div>
                </>
              ) : (
                <>
                  <div className="row between">
                    <strong className="row" style={{ gap: 6 }}><ClipboardCheck size={16} aria-hidden="true" /> Triage</strong>
                    <button type="button" className="btn btn--sm" onClick={() => setMode("accept")}>Accept risk…</button>
                  </div>
                  <div className="grid grid--2">
                    <div className="field"><label htmlFor="tr-state">State</label>
                      <select id="tr-state" className="select" value={state} onChange={(e) => setState(e.target.value as TriageState)}>
                        {TRIAGE.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
                      </select>
                    </div>
                    <div className="field"><label htmlFor="tr-owner">Owner</label><input id="tr-owner" className="input" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="name or team" /></div>
                    <div className="field"><label htmlFor="tr-due">Due</label><input id="tr-due" type="date" className="input" value={due} onChange={(e) => setDue(e.target.value)} /></div>
                    <div className="field"><label htmlFor="tr-note">Note</label><input id="tr-note" className="input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="planned change window, blockers…" /></div>
                  </div>
                  <div className="row between">
                    <span className="small muted">{finding.triage?.updatedAt ? `Last updated ${fmtDateTime(finding.triage.updatedAt)}` : "Not triaged yet"}</span>
                    <button type="button" className="btn btn--primary btn--sm" onClick={saveTriage}>Save triage</button>
                  </div>
                </>
              )}
            </div>
          )}
        </>
      )}
    </Drawer>
  );
}
