import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import { api } from "../lib/api";

export default function Library() {
  const [rows, setRows] = useState([]);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);
  const [fDiff, setFDiff] = useState("");
  const [fFocus, setFFocus] = useState("");
  // attack pace is SNAPSHOTTED into the match at creation (pilot step 4)
  const [pace, setPace] = useState(30);
  // plan 13 phase 6/7 control builder: every bounded match choice is picked
  // HERE and frozen into the creation snapshot — never re-read mid-match.
  const [mode, setMode] = useState("practice");
  const [duration, setDuration] = useState(30);
  const [startCond, setStartCond] = useState("manual");
  const [injects, setInjects] = useState(true);
  const router = useRouter();

  useEffect(() => { api("/scenarios").then(setRows).catch(e => setErr(String(e.message || e))); }, []);

  const focuses = useMemo(() => [...new Set(rows.flatMap(s => s.focus || []))].sort(), [rows]);
  const shown = rows.filter(s => s._valid !== false
    && (!fDiff || String(s.difficulty) === fDiff)
    && (!fFocus || (s.focus || []).includes(fFocus)));

  // ONE shared backend workflow: create session → launch (lease + deploy +
  // per-host SSH instructions). Identical to rangectl launch.
  async function launch(id) {
    setBusy(id); setErr(null);
    try {
      const s = await api("/sessions", { method: "POST",
                                         body: { scenario_id: id,
                                                 pace_seconds: pace,
                                                 mode, duration_minutes: duration,
                                                 start_condition: startCond,
                                                 injects_enabled: injects } });
      await api(`/sessions/${s.session_id}/launch`, { method: "POST" });
      // connection instructions are fetched from the API on the session page
      // (pilot step 4) — nothing secret is kept in browser storage
      router.push(`/session/${s.session_id}`);
    } catch (e) {
      setErr(e.status === 409
        ? `range busy: ${e.message}` : e.status === 422
        ? `invalid match setup: ${e.message}` : String(e.message || e));
      setBusy(null);
    }
  }

  return (
    <>
      <h2>scenario library</h2>
      {err && <p className="bad">{err}</p>}
      <div className="panel">
        <h3>match controls — frozen into the creation snapshot</h3>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <label>mode{" "}
            <select value={mode} onChange={e => setMode(e.target.value)}>
              <option value="practice">practice</option>
              <option value="competition">competition</option>
            </select></label>
          <label>duration (min){" "}
            <input type="number" min={1} max={480} value={duration}
              onChange={e => setDuration(Number(e.target.value))} style={{ width: 70 }} /></label>
          <label>attack pace (s/action){" "}
            <select value={pace} onChange={e => setPace(Number(e.target.value))}>
              <option value={60}>60 (slow)</option>
              <option value={30}>30 (standard)</option>
              <option value={15}>15 (fast)</option>
              <option value={0}>0 (no-delay fixture)</option>
            </select></label>
          <label>start condition{" "}
            <select value={startCond} onChange={e => setStartCond(e.target.value)}>
              <option value="manual">manual Begin</option>
              <option value="auto-on-ready">auto on ready</option>
            </select></label>
          <label><input type="checkbox" checked={injects}
            onChange={e => setInjects(e.target.checked)} /> injects</label>
        </div>
        <p className="dim">pace 0 is the explicit no-delay fixture mode, never an
          operator default; these choices are validated server-side (422) and
          snapshotted — history is never re-scored against later edits.</p>
      </div>
      <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
        <select value={fDiff} onChange={e => setFDiff(e.target.value)}>
          <option value="">any difficulty</option>
          {[1, 2, 3, 4, 5].map(d => <option key={d} value={d}>difficulty {d}</option>)}
        </select>
        <select value={fFocus} onChange={e => setFFocus(e.target.value)}>
          <option value="">any focus</option>
          {focuses.map(f => <option key={f} value={f}>{f}</option>)}
        </select>
      </div>
      <div className="panel">
        <table>
          <thead><tr><th>scenario</th><th>difficulty</th><th>focus</th><th>est.</th><th>techniques</th><th /></tr></thead>
          <tbody>{shown.map(s => (
            <tr key={s.id}>
              <td><Link href={`/scenario/${s.id}`}>{s.name}</Link><div className="dim">{s.id}</div></td>
              <td>d{s.difficulty}</td>
              <td>{(s.focus || []).join(", ")}</td>
              <td>{s.est_minutes}m</td>
              <td className="dim">{(s.techniques || []).join(" ")}</td>
              <td><button disabled={!!busy} onClick={() => launch(s.id)}>
                {busy === s.id ? "deploying…" : "launch"}</button></td>
            </tr>))}
          </tbody>
        </table>
        {shown.length === 0 && <p className="dim">no scenarios match (or the library has invalid entries — check CLI)</p>}
      </div>
    </>
  );
}
