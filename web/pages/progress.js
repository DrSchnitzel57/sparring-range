import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { api, currentUser } from "../lib/api";

export default function Progress() {
  const router = useRouter();
  const [prog, setProg] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => {
    if (!currentUser()) return router.replace("/");
    api(`/users/${currentUser()}/progress`).then(setProg).catch(e => setErr(String(e)));
  }, []);
  if (err) return <p className="bad">{err}</p>;
  if (!prog) return <p className="dim">loading…</p>;
  return (
    <div>
      <h2>progress — {prog.username}</h2>
      <div className="panel">
        <h3>by domain <span className="dim">(lagging: {prog.lagging_domains.join(", ") || "none"})</span></h3>
        {Object.entries(prog.by_domain).map(([d, m]) => (
          <div key={d} style={{ marginBottom: 10 }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span>{d}</span><span className="dim">{m.avg_pct}% over {m.sessions} session(s)</span>
            </div>
            <div className="bar"><div style={{ width: `${m.avg_pct || 0}%` }} /></div>
          </div>
        ))}
      </div>
      <div className="panel">
        <h3>every session</h3>
        <table>
          <thead><tr><th>scored</th><th>scenario</th><th>score</th><th /></tr></thead>
          <tbody>{prog.sessions.map(s => (
            <tr key={s.session_id}>
              <td className="dim">{s.scored_at.slice(0, 10)}</td>
              <td>{s.scenario_id}</td>
              <td className={s.pct >= 70 ? "ok" : "bad"}>{s.earned}/{s.total} ({s.pct}%)</td>
              <td><a href={`/session/${s.session_id}/report`}>AAR</a></td>
            </tr>))}
          </tbody>
        </table>
      </div>
      <p className="dim">This page is a query over the append-only event log (v_session_scores) — no separate tracking store exists to drift.</p>
    </div>
  );
}
