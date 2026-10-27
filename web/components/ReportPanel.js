import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { Md } from "../lib/md";

// Versioned AAR. The page NEVER generates on load (model tokens are
// explicit); regeneration appends a new version with cutoff/rubric
// provenance. Rendered as safe markdown (links to authorized evidence),
// not a preformatted dump — and the UNSCORED honesty notice stays.
export default function ReportPanel({ sid }) {
  const [aar, setAar] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  function load() {
    api(`/sessions/${sid}/aar`).then(setAar).catch(e => setErr(String(e.message || e)));
  }
  useEffect(() => { setAar(null); load(); }, [sid]);  // eslint-disable-line react-hooks/exhaustive-deps

  async function generate(regenerate) {
    setBusy(true); setErr(null);
    try { setAar(await api(`/sessions/${sid}/aar`,
      { method: "POST", body: { regenerate, narrative: true } })); }
    catch (e) { setErr(String(e.message || e)); }
    setBusy(false);
  }

  if (err) return <p className="bad" role="alert">{err}</p>;
  if (!aar) return <p className="dim">loading report…</p>;
  if (aar.status === "no-report")
    return (
      <div className="panel">
        <h3>After-Action Review</h3>
        <p className="dim">No report generated for this session yet.</p>
        <button onClick={() => generate(false)} disabled={busy}>{busy ? "generating…" : "generate AAR"}</button>
        <p className="dim">Loading this page never spends model tokens — generation is explicit.</p>
      </div>
    );
  const unscored = aar.score_status === "unscored";
  return (
    <div className="panel">
      <h3>After-Action Review {aar.version && <span className="phase">v{aar.version}</span>}
        {unscored
          ? <span className="bad" title="no trusted scorecard — no letter grade"> · UNSCORED</span>
          : <span className={aar.pct >= 70 ? "ok" : "bad"}> · {aar.grade} ({aar.earned}/{aar.total})</span>}
      </h3>
      {unscored && <p className="bad">Honesty notice: scoring evidence was unavailable, so there is
        no grade and there will be no silent F. Fix telemetry/verifiers, end the session again, then
        regenerate.</p>}
      {aar.telemetry_gaps?.length > 0 && (
        <p className="bad">telemetry gaps: {aar.telemetry_gaps.length} (detailed below)</p>
      )}
      <Md text={aar.markdown} citations={aar.approved_citation_ids || []} />
      <p className="row" style={{ marginTop: 14 }}>
        <button onClick={() => generate(true)} disabled={busy}>{busy ? "regenerating…" : "regenerate (new version)"}</button>
        <span className="dim"> prior versions stay in the append-only log (evidence cutoff{" "}
          #{aar.evidence_cutoff_event_id}, rubric v{aar.rubric_version})</span>
      </p>
    </div>
  );
}
