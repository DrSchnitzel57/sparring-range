import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { api } from "../../lib/api";

export default function Scenario() {
  const router = useRouter();
  const [spec, setSpec] = useState(null);
  useEffect(() => {
    if (router.query.id) api("/scenarios").then(rs => setSpec(rs.find(s => s.id === router.query.id))).catch(() => {});
  }, [router.query.id]);
  if (!spec) return <p className="dim">loading…</p>;
  return (
    <div className="panel">
      <h2>{spec.name}</h2>
      <p className="dim">{spec.id} · difficulty {spec.difficulty} · ~{spec.est_minutes} min · focus: {(spec.focus || []).join(", ")}</p>
      <h4>Red objectives (verifier-confirmed only)</h4>
      <ul>{(spec.red?.objectives || []).map(o => <li key={o.id}><code>{o.id}</code> → <code>{o.verifier}</code> <span className="dim">{JSON.stringify(o.args || {})}</span></li>)}</ul>
      <h4>Blue scorecard</h4>
      <ul>{(spec.scoring?.blue_checks || []).map((b, i) => <li key={i}><code>{b.verifier}</code> on <code>{b.host}</code> — {b.points} pts</li>)}</ul>
      <p className="dim">MITRE: {(spec.techniques || []).join(", ")}</p>
    </div>
  );
}
