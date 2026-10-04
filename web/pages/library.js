import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import { api, saveConnections } from "../lib/api";

export default function Library() {
  const [rows, setRows] = useState([]);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);
  const [fDiff, setFDiff] = useState("");
  const [fFocus, setFFocus] = useState("");
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
      const s = await api("/sessions", { method: "POST", body: { scenario_id: id } });
      const out = await api(`/sessions/${s.session_id}/launch`, { method: "POST" });
      saveConnections(s.session_id, out.connections);
      router.push(`/session/${s.session_id}`);
    } catch (e) {
      setErr(e.status === 409
        ? `range busy: ${e.message}` : String(e.message || e));
      setBusy(null);
    }
  }

  return (
    <>
      <h2>scenario library</h2>
      {err && <p className="bad">{err}</p>}
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
