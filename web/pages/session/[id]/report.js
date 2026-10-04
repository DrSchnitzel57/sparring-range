import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { api } from "../../../lib/api";

export default function Report() {
  const router = useRouter();
  const [aar, setAar] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  function load() {
    api(`/sessions/${router.query.id}/aar`)
      .then(setAar)
      .catch(e => setErr(String(e.message || e)));
  }
  useEffect(() => { if (router.query.id) load(); }, [router.query.id]);

  async function generate(regenerate) {
    setBusy(true); setErr(null);
    try { setAar(await api(`/sessions/${router.query.id}/aar`,
      { method: "POST", body: { regenerate, narrative: true } })); }
    catch (e) { setErr(String(e.message || e)); }
    setBusy(false);
  }

  if (err) return <p className="bad">{err}</p>;
  if (!aar) return <p className="dim">loading report…</p>;
  if (aar.status === "no-report")
    return (
      <div className="panel">
        <h2>After-Action Review</h2>
        <p className="dim">No report generated for this session yet.</p>
        <button onClick={() => generate(false)} disabled={busy}>{busy ? "generating…" : "generate AAR"}</button>
        <p className="dim">Loading this page never spends model tokens — generation is explicit.</p>
      </div>
    );
  const unscored = aar.score_status === "unscored";
  return (
    <div>
      <h2>After-Action Review {aar.version && <span className="phase">v{aar.version}</span>}
        {unscored
          ? <span className="bad" title="no trusted scorecard — no letter grade"> · UNSCORED</span>
          : <span className={aar.pct >= 70 ? "ok" : "bad"}> · {aar.grade} ({aar.earned}/{aar.total})</span>}
      </h2>
      {unscored && <p className="bad">Honesty notice: scoring evidence was unavailable, so there is
        no grade and there will be no silent F. Fix telemetry/verifiers, end the session again, then
        regenerate.</p>}
      {aar.telemetry_gaps?.length > 0 && (
        <p className="bad">telemetry gaps: {aar.telemetry_gaps.length} (see below)</p>
      )}
      <pre style={{ whiteSpace: "pre-wrap", fontFamily: "inherit" }}>{aar.markdown}</pre>
      <p>
        <button onClick={() => generate(true)} disabled={busy}>{busy ? "regenerating…" : "regenerate (new version)"}</button>
        <span className="dim"> prior versions stay in the append-only log (evidence cutoff{" "}
          #{aar.evidence_cutoff_event_id}, rubric v{aar.rubric_version})</span>
      </p>
    </div>
  );
}
