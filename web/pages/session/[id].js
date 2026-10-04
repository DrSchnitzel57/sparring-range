import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import { api } from "../../lib/api";

export default function LiveSession() {
  const router = useRouter();
  const id = router.query.id;
  const [live, setLive] = useState(null);
  const [hint, setHint] = useState("");
  const [hintBusy, setHintBusy] = useState(false);
  const [seconds, setSeconds] = useState(0);
  const startRef = useRef(null);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    const tick = async () => {
      try {
        const d = await api(`/sessions/${id}/live`);
        if (stop) return;
        setLive(d);
        if (!startRef.current) { startRef.current = new Date(d.started_at).getTime(); }
        setSeconds(Math.max(0, Math.floor((Date.now() - startRef.current) / 1000)));
      } catch (e) { /* transient */ }
    };
    tick();
    const t = setInterval(tick, 2000);
    return () => { stop = true; clearInterval(t); };
  }, [id]);

  async function askHint() {
    setHintBusy(true);
    try {
      const r = await api(`/sessions/${id}/hint`, { method: "POST", body: { question: "" } });
      setHint(r.hint);
    } catch (e) { setHint(String(e)); }
    setHintBusy(false);
  }

  if (!live) return <p className="dim">connecting…</p>;
  const mm = String(Math.floor(seconds / 60)).padStart(2, "0"), ss = String(seconds % 60).padStart(2, "0");
  return (
    <div className="grid">
      <div>
        <div className="panel">
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <h2>live — <span className="phase">{live.red_phase || "not started"}</span></h2>
            <span style={{ fontSize: 24 }}>{mm}:{ss}</span>
          </div>
          <p className="dim">status: {live.status} · red phase advances only when verifiers pass</p>
        </div>
        <div className="panel">
          <h3>detections</h3>
          {live.detections.length === 0 && <p className="dim">nothing verified yet</p>}
          <ul>{live.detections.map(d => (
            <li key={d.event_id}>
              {d.passed ? <span className="bad">● objective {d.objective} CONFIRMED</span>
                        : <span className="dim">○ {d.objective} not yet</span>} <span className="dim">{new Date(d.ts).toLocaleTimeString()}</span>
            </li>))}
          </ul>
        </div>
        <div className="panel">
          <h3>recent log</h3>
          <table><tbody>
            {live.recent.map(e => (
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
          <button onClick={askHint} disabled={hintBusy}>{hintBusy ? "thinking…" : "request hint"}</button>
          {hint && <p style={{ marginTop: 12 }}>{hint}</p>}
        </div>
        <div className="panel">
          <h3>defend</h3>
          <p className="dim">SSH in via the bastion with your token login (copy-paste works like any terminal):</p>
          <pre>ssh drew@bastion -l tok_web01</pre>
          <p className="dim">Everything you do is recorded and replayable.</p>
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
