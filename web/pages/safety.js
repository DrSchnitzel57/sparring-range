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
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = () => {
    api("/safety/panel").then(setPanel).catch(e => setErr(String(e.message || e)));
    api("/stages").then(setStages).catch(() => {});
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
