import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import { api, getConnections, saveConnections } from "../../lib/api";

export default function LiveSession() {
  const router = useRouter();
  const id = router.query.id;
  const [sess, setSess] = useState(null);
  const [live, setLive] = useState(null);
  const [conns, setConns] = useState(null);
  const [hint, setHint] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [seconds, setSeconds] = useState(0);
  const startRef = useRef(null);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    api(`/sessions/${id}`).then(s => {
      if (stop) return;
      setSess(s);
      setConns(getConnections(id));
    }).catch(e => setErr(String(e.message || e)));
    const tick = async () => {
      try {
        const d = await api(`/sessions/${id}/live`);
        if (stop) return;
        setLive(d);
        if (!startRef.current && d.started_at) startRef.current = new Date(d.started_at).getTime();
        if (startRef.current) setSeconds(Math.max(0, Math.floor((Date.now() - startRef.current) / 1000)));
      } catch (e) { /* transient */ }
    };
    tick();
    const t = setInterval(tick, 2000);
    const tc = setInterval(() => { if (startRef.current) setSeconds(s => s + 1); }, 1000);
    return () => { stop = true; clearInterval(t); clearInterval(tc); };
  }, [id]);

  async function act(fn, label) {
    setBusy(true); setErr(null);
    try { await fn(); } catch (e) { setErr(`${label}: ${e.message || e}`); }
    setBusy(false);
    router.replace(router.asPath, undefined, { scroll: false });
  }
  const startRed = () => act(async () => {
    await api(`/run/${sess.scenario_id}`, { method: "POST", body: { session_id: id } });
    setSess(await api(`/sessions/${id}`));
  }, "start red");
  const stopRed = () => act(async () => {
    await api(`/runs/${sess.active_run}/stop`, { method: "POST" });
    setSess(await api(`/sessions/${id}`));
  }, "stop red");
  const endSession = () => {
    if (!confirm("End session? Stops red, takes a trusted final score, revokes tokens.")) return;
    act(async () => {
      const r = await api(`/sessions/${id}/end`, { method: "POST" });
      setSess({ ...sess, status: r.status, outcome: r.outcome });
    }, "end");
  };
  const redeploy = () => act(async () => {
    const out = await api(`/sessions/${id}/launch`, { method: "POST" });
    saveConnections(id, out.connections); setConns(out.connections);
  }, "redeploy");
  const askHint = () => act(async () => {
    const r = await api(`/sessions/${id}/hint`, { method: "POST", body: { question: "" } });
    setHint(r.hint);
  }, "hint");

  if (err && !sess) return <p className="bad">{err}</p>;
  if (!sess) return <p className="dim">loading…</p>;
  const mm = String(Math.floor(seconds / 60)).padStart(2, "0"), ss = String(seconds % 60).padStart(2, "0");
  const running = sess.status === "running" || sess.status === "stopping";

  return (
    <div className="grid">
      <div>
        <div className="panel">
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <h2>{sess.scenario_id} — <span className="phase">{live?.red_phase || sess.status}</span></h2>
            {running && <span style={{ fontSize: 24 }}>{mm}:{ss}</span>}
          </div>
          <p className="dim">status: {sess.status} {sess.outcome && `(${sess.outcome})`}
            {sess.active_run && ` · red run ${sess.active_run.slice(0, 8)}`} ·
            phases advance only when verifiers pass</p>
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            {!running && sess.status !== "complete" && sess.status !== "failed" &&
              <button onClick={startRed} disabled={busy}>▶ start red</button>}
            {sess.active_run && <button onClick={stopRed} disabled={busy}>■ stop red</button>}
            {sess.status !== "complete" && <button className="danger" onClick={endSession} disabled={busy}>end session</button>}
          </div>
          {err && <p className="bad">{err}</p>}
        </div>
        <div className="panel">
          <h3>connections</h3>
          {conns ? (
            <ul>{conns.map(c => (
              <li key={c.host}><code>{c.ssh}</code></li>))}</ul>
          ) : (
            <p className="dim">instructions not in this browser tab —{" "}
              <a href="#" onClick={e => { e.preventDefault(); redeploy(); }}>re-issue</a>
            </p>
          )}
          <p className="dim">Defend: SSH through the bastion with the token login; every keystroke
            is recorded and replayable.</p>
        </div>
        <div className="panel">
          <h3>detections</h3>
          {(!live || live.detections.length === 0) && <p className="dim">nothing verified yet</p>}
          <ul>{live?.detections.map(d => (
            <li key={d.event_id}>
              {d.passed ? <span className="bad">● objective {d.objective} CONFIRMED</span>
                : <span className="dim">○ {d.objective} not yet</span>}{" "}
              <span className="dim">{new Date(d.ts).toLocaleTimeString()}</span>
            </li>))}
          </ul>
        </div>
        <div className="panel">
          <h3>recent log</h3>
          <table><tbody>
            {live?.recent.map(e => (
              <tr key={e.event_id}>
                <td className="dim">{new Date(e.ts).toLocaleTimeString()}</td>
                <td>{e.actor}</td><td>{e.action_type}</td><td>{e.phase || ""}</td>
              </tr>))}
          </tbody></table>
        </div>
      </div>
      <div>
        <div className="panel">
          <h3>coach</h3>
          <button onClick={askHint} disabled={busy}>{busy ? "thinking…" : "request hint"}</button>
          {hint && <p style={{ marginTop: 12 }}>{hint}</p>}
        </div>
        <div className="panel">
          <h3>after action</h3>
          <Link href={`/session/${id}/report`}>graded AAR →</Link><br />
          <Link href={`/session/${id}/replay`}>replay ↔ timeline →</Link>
        </div>
      </div>
    </div>
  );
}
