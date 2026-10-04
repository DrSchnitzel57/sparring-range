import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import { api, currentUser } from "../lib/api";

export default function Library() {
  const [rows, setRows] = useState([]);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);
  const router = useRouter();

  useEffect(() => { if (!currentUser()) router.replace("/"); api("/scenarios").then(setRows).catch(e => setErr(String(e))); }, []);

  async function launch(id) {
    setBusy(id); setErr(null);
    try {
      await api(`/deploy/${id}`, { method: "POST" });                       // same path as rangectl
      const s = await api("/sessions", { method: "POST", body: { scenario_id: id, username: currentUser() } });
      await api(`/run/${id}`, { method: "POST", body: { session_id: s.session_id } });
      router.push(`/session/${s.session_id}`);
    } catch (e) { setErr(String(e)); setBusy(null); }
  }

  return (
    <>
      <h2>scenario library</h2>
      {err && <p className="bad">{err}</p>}
      <div className="panel">
        <table>
          <thead><tr><th>scenario</th><th>difficulty</th><th>focus</th><th>est.</th><th>techniques</th><th /></tr></thead>
          <tbody>{rows.map(s => (
            <tr key={s.id}>
              <td><Link href={`/scenario/${s.id}`}>{s.name}</Link><div className="dim">{s.id}</div></td>
              <td>d{s.difficulty}</td>
              <td>{(s.focus || []).join(", ")}</td>
              <td>{s.est_minutes}m</td>
              <td className="dim">{(s.techniques || []).join(" ")}</td>
              <td><button disabled={busy === s.id} onClick={() => launch(s.id)}>{busy === s.id ? "spinning up…" : "launch"}</button></td>
            </tr>))}
          </tbody>
        </table>
      </div>
    </>
  );
}
