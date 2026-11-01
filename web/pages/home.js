import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { api, getRole } from "../lib/api";

const PAGE = 12;

function flagBadges(s) {
  return (
    <>
      {s.interrupted && <span className="badge bad" title="worker failure, canceled, or unconfirmed stop">interrupted</span>}{" "}
      {s.unscored && <span className="badge warn" title="finished without a trusted scorecard">unscored</span>}{" "}
      {s.cleanup_pending && <span className="badge bad" title="an operation's cessation is unresolved — range may still be reserved">cleanup pending</span>}
    </>
  );
}

export default function Dashboard() {
  const [active, setActive] = useState(null);
  const [hist, setHist] = useState(null);
  const [page, setPage] = useState(0);
  const [allMine, setAllMine] = useState(true);
  const [err, setErr] = useState(null);
  const isOp = getRole() === "operator";

  const load = useCallback(async () => {
    try {
      const [a, h] = await Promise.all([
        api(`/sessions?view=active&limit=50${allMine ? "" : "&mine=false"}`),
        api(`/sessions?view=history&limit=${PAGE}&offset=${page * PAGE}${allMine ? "" : "&mine=false"}`),
      ]);
      setActive(a); setHist(h); setErr(null);
    } catch (e) { setErr(String(e.message || e)); }
  }, [page, allMine]);
  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, [load]);

  const sessionsRow = (s) => (
    <tr key={s.session_id}>
      <td><Link href={`/session/${s.session_id}`}>{s.scenario_id}</Link>
        <div className="dim mono" style={{ fontSize: ".75rem" }}>{s.session_id.slice(0, 8)}</div></td>
      <td><span className="phase">{s.status}</span>{s.outcome && <span className="dim"> {s.outcome}</span>}
        <div style={{ marginTop: 3 }}>{flagBadges(s)}</div></td>
      <td className="dim">{s.started_at ? new Date(s.started_at).toLocaleString() : "—"}</td>
      <td className="dim">{s.ended_at ? new Date(s.ended_at).toLocaleString() : ""}</td>
    </tr>
  );

  return (
    <>
      <div className="row" style={{ marginBottom: 14 }}>
        <h2 style={{ margin: 0 }}>dashboard</h2>
        <span className="spacer" />
        {isOp && (
          <label className="dim"><input type="checkbox" checked={!allMine}
            onChange={() => { setAllMine(allMine); setPage(0); }} /> all sessions (operator)</label>
        )}
        <button className="ghost" onClick={load}>refresh</button>
        <Link href="/library"><button>launch new scenario</button></Link>
      </div>
      {err && <p className="bad" role="alert">could not load sessions: {err}</p>}

      <div className="panel">
        <h3>active sessions</h3>
        {!active ? <p className="dim">loading…</p>
          : active.sessions.length === 0 ? <p className="dim">nothing running —
            start from the <Link href="/library">scenario library</Link>.</p> : (
            <div className="cards">
              {active.sessions.map(s => (
                <div className="card" key={s.session_id}>
                  <h3><Link href={`/session/${s.session_id}`}>{s.scenario_id}</Link></h3>
                  <div><span className="phase">{s.status}</span> {flagBadges(s)}</div>
                  <div className="meta">started {s.started_at ? new Date(s.started_at).toLocaleString() : "—"}</div>
                  <div><Link href={`/session/${s.session_id}`}>open →</Link></div>
                </div>
              ))}
            </div>)}
        {active && active.sessions.length > 0 &&
          active.total > active.sessions.length &&
          <p className="dim">{active.total - active.sessions.length} more active sessions
            {" "}({active.sessions.length} shown)</p>}
      </div>

      <div className="panel">
        <h3>history</h3>
        {!hist ? <p className="dim">loading…</p> : (
          <>
            {hist.sessions.length === 0 && page === 0 && <p className="dim">no finished sessions yet.</p>}
            <table>
              <thead><tr><th>scenario</th><th>state</th><th>started</th><th>ended</th></tr></thead>
              <tbody>{hist.sessions.map(sessionsRow)}</tbody>
            </table>
            <div className="pager">
              <button className="ghost" disabled={page === 0} onClick={() => setPage(p => p - 1)}>← newer</button>
              <span className="dim">page {page + 1} · {hist.total} sessions total</span>
              <button className="ghost" disabled={!hist.has_more} onClick={() => setPage(p => p + 1)}>older →</button>
            </div>
          </>)}
      </div>
    </>
  );
}
