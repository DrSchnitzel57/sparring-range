import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { api } from "../../../lib/api";

export default function Report() {
  const router = useRouter();
  const [aar, setAar] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => {
    if (router.query.id)
      api(`/sessions/${router.query.id}/aar`, { method: "POST", body: { narrative: true } })
        .then(setAar).catch(e => setErr(String(e)));
  }, [router.query.id]);
  if (err) return <p className="bad">{err}</p>;
  if (!aar) return <p className="dim">generating graded review from the event log…</p>;
  return (
    <div>
      <h2>After-Action Review</h2>
      <pre style={{ whiteSpace: "pre-wrap", fontFamily: "inherit" }}>{aar.markdown}</pre>
    </div>
  );
}
