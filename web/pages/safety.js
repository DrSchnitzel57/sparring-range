import { useEffect, useState } from "react";
import { api } from "../lib/api";

// Operator safety panel (plan 13 phase 7): BOTH latch states side by side —
// the supervisor killswitch latch and the broker's independent cessation
// authority — plus live deploy executors and the authorized recovery
// procedure. Read-only by design: release authority is NOT moved into the
// browser; the panel links the exact authorized endpoints instead.
function isOperator() {
  return typeof window !== "undefined"
    && localStorage.getItem("sr_role") === "operator";
}

export default function Safety() {
  const [panel, setPanel] = useState(null);
  const [stages, setStages] = useState(null);
  const [qual, setQual] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = () => {
    api("/safety/panel").then(setPanel).catch(e => setErr(String(e.message || e)));
    api("/stages").then(setStages).catch(() => {});
    api("/safety/qualification").then(setQual).catch(() => {});
  };
  useEffect(load, []);

  if (!isOperator()) return <p className="bad">operator only</p>;
  if (err && !panel) return <p className="bad">{err}</p>;
  if (!panel) return <p className="dim">loading…</p>;

  const latched = !!panel.supervisor_latch?.latched;
  const engage = async () => {
    if (!confirm("Engage the killswitch? Stops workers, latches the range, cancels remote operations.")) return;
    setBusy(true); setErr(null);
    try { await api("/safety/killswitch", { method: "POST" }); load(); }
    catch (e) { setErr(String(e.message || e)); }
    setBusy(false);
  };

  return (
    <>
      <h2>operator safety</h2>
      {err && <p className="bad">{err}</p>}
      <div className="grid">
        <div>
          <div className="panel" data-testid="qualification">
            <h3>practice eligibility</h3>
            {qual ? (<>
              <p data-testid="begin-allowed" className={qual.begin_allowed ? "ok" : "bad"}>
                begin: {qual.begin_allowed ? "eligible" : "refused"}
              </p>
              <table>
                <thead><tr><th>qualification</th><th>state</th><th>provenance</th><th>age (advisory)</th></tr></thead>
                <tbody>
                  {(qual.qualifications || []).map(q => (
                    <tr key={q.kind} data-testid={`qual-${q.kind}`}
                        data-usable={q.usable ? "yes" : "no"}>
                      <td>{q.kind}</td>
                      <td>{q.usable ? "valid for this configuration"
                                    : (q.problems || []).join("; ")}</td>
                      <td>{q.provenance}</td>
                      <td>{q.age_h === null || q.age_h === undefined ? "—"
                          : `${q.age_h}h`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="dim">qualification is commissioning evidence bound
                to the current configuration: its age is shown, never silently
                treated as a failed test. It is invalidated by configuration
                changes, failed checks or safety transitions — then the exact
                operator re-collection flow is listed above.</p>
              {(qual.advisories || []).map((a, i) => (
                <p key={i} className="dim" data-testid="qual-advisory">ℹ {a}</p>))}
              <h3>automatic admission checks (non-destructive)</h3>
              <ul>
                {(qual.admission?.checks || []).map(c => (
                  <li key={c.check} data-testid={`admission-${c.check}`}
                      data-ok={c.ok ? "yes" : "no"}>
                    {c.ok ? "○" : "●"} {c.check}: {c.detail}
                  </li>))}
              </ul>
              {(qual.begin_blockers || []).length > 0 && (<>
                <h3>what blocks Begin right now</h3>
                <ul>{qual.begin_blockers.map((r, i) => (
                  <li key={i} className="bad" data-testid="begin-blocker">{r}</li>))}
                </ul></>)}
            </>) : <p className="dim">loading…</p>}
          </div>
          <div className="panel">
            <h3>supervisor latch {latched ? <span className="bad">● LATCHED</span> : <span className="ok">○ clear</span>}</h3>
            <p className="dim">{panel.supervisor_latch?.reason || "no engagement recorded"}</p>
            <button onClick={engage} disabled={busy || latched}>
              {busy ? "engaging…" : "engage killswitch"}</button>
            <p className="dim">release: POST /safety/killswitch-release only after
              the recovery procedure below is confirmed — the panel never
              releases by itself.</p>
          </div>
          <div className="panel">
            <h3>broker cessation authority</h3>
            <pre className="dim">{JSON.stringify(panel.broker_cessation, null, 1)}</pre>
            <p className="dim">remote-command cessation lives behind the
              broker's own endpoint; this panel reports it, never moves it.</p>
          </div>
        </div>
        <div>
          <div className="panel">
            <h3>release stages</h3>
            {stages ? (<ul>
              <li>install-ready: {stages.install_ready ? "yes" : "NO"}</li>
              <li>lab-ready: {stages.lab_ready ? "yes" : "NO"}</li>
              <li>attack-authorized: {stages.attack_authorized ? "yes" : "NO"}</li>
              <li data-testid="stage-begin" data-allowed={stages.safety?.begin_allowed ? "yes" : "no"}>
                begin-eligible: {stages.safety?.begin_allowed ? "yes" : "NO"}
                {(stages.safety?.begin_blockers || []).length > 0
                  ? ` — ${stages.safety.begin_blockers.join("; ")}` : ""}
              </li>
            </ul>) : <p className="dim">loading…</p>}
            {(panel.live_deploy_executors || []).length > 0 &&
              <p className="bad">live deploy executors: {panel.live_deploy_executors.join(", ")}</p>}
          </div>
          <div className="panel">
            <h3>authorized recovery procedure</h3>
            <ol>{(panel.recovery_procedure || []).map((s, i) => <li key={i}>{s}</li>)}</ol>
          </div>
        </div>
      </div>
    </>
  );
}
