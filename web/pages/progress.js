import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { api, currentUser } from "../lib/api";

export default function Progress() {
  const router = useRouter();
  const [prog, setProg] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => {
    const u = currentUser();
    if (!u) return router.replace("/");
    api(`/users/${u}/progress`).then(setProg).catch(e => setErr(String(e.message || e)));
  }, []);
  if (err) return <p className="bad">{err}</p>;
  if (!prog) return <p className="dim">loading…</p>;
  return (
    <div>
      <h2>progress — {prog.username}</h2>
      <div className="panel">
        <h3>by domain <span className="dim">(lagging: {prog.lagging_domains.join(", ") || "none"})</span></h3>
        {Object.keys(prog.by_domain).length === 0 && <p className="dim">no scored sessions yet</p>}
        {Object.entries(prog.by_domain).map(([d, m]) => (
          <div key={d} style={{ marginBottom: 10 }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span>{d}</span>
              <span className="dim">
                {m.avg_pct ?? "?"}% over {m.sessions} session(s)
                {m.trend != null && <span className={m.trend >= 0 ? "ok" : "bad"}> ({m.trend >= 0 ? "+" : ""}{m.trend})</span>}
              </span>
            </div>
            <div className="bar"><div style={{ width: `${m.avg_pct || 0}%` }} /></div>
          </div>
        ))}
      </div>
      <div className="panel">
        <h3>scored sessions</h3>
        <table>
          <thead><tr><th>scored</th><th>scenario</th><th>score</th><th>status</th><th /></tr></thead>
          <tbody>{prog.sessions.map(s => (
            <tr key={s.session_id}>
              <td className="dim">{s.scored_at.slice(0, 10)}</td>
              <td>{s.scenario_id}</td>
              <td className={s.pct >= 70 ? "ok" : "bad"}>{s.earned}/{s.total} ({s.pct}%)</td>
              <td className={s.status === "partial" ? "bad" : "dim"}>{s.status}</td>
              <td><a href={`/session/${s.session_id}/report`}>AAR</a></td>
            </tr>))}
          </tbody>
        </table>
      </div>
      <p className="dim">{prog.unscored_note} This page reads trusted score snapshots
        (v_score_items) from the append-only log — no separate tracking store exists to drift.</p>
    </div>
  );
}
