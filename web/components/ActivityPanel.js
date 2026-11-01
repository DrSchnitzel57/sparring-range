import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";

// Authorized activity log: server-side cursor paging (never a head-window
// truncation), actor/kind filters applied BEFORE fetching, expandable raw
// payload, and deep-link support (?event=<id>) for coach/report citations.
// Competition redaction is the API's job — this renders what it allows.
const KINDS = ["action_intent", "action_result", "verifier", "detection",
  "hint", "agent_note", "telemetry_capture_verified", "score_snapshot",
  "coach_message"];

export default function ActivityPanel({ sid, focusEvent }) {
  const [events, setEvents] = useState([]);
  const [cursor, setCursor] = useState(0);
  const [done, setDone] = useState(false);
  const [kind, setKind] = useState("");
  const [err, setErr] = useState(null);
  const [loading, setLoading] = useState(false);
  const focusRef = useRef(null);

  const load = useCallback(async (after, replace) => {
    setLoading(true);
    try {
      const q = new URLSearchParams({ session_id: sid, limit: "50", after_event_id: String(after) });
      if (kind) q.set("action_type", kind);
      const page = await api(`/events?${q.toString()}`);
      setEvents(prev => replace ? page : prev.concat(page));
      if (page.length) setCursor(page[page.length - 1].event_id);
      if (page.length < 50) setDone(true);
      setErr(null);
    } catch (e) { setErr(String(e.message || e)); }
    setLoading(false);
  }, [sid, kind]);

  useEffect(() => { setEvents([]); setCursor(0); setDone(false); load(0, true); }, [load]);

  // citation deep link: keep fetching until the target event is visible
  useEffect(() => {
    if (!focusEvent) return;
    const id = Number(focusEvent);
    if (!Number.isFinite(id)) return;
    if (events.length && id > cursor && !done) load(cursor, false);
  }, [focusEvent, events, cursor, done, load]);
  useEffect(() => { focusRef.current?.scrollIntoView({ block: "center" }); }, [events, focusEvent]);

  return (
    <div className="panel">
      <h3>activity</h3>
      <div className="row" style={{ marginBottom: 10 }}>
        <label className="dim">kind{" "}
          <select aria-label="Event kind filter" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">all kinds</option>
            {KINDS.map(k => <option key={k} value={k}>{k}</option>)}
          </select></label>
        <span className="spacer" />
        <button className="ghost" onClick={() => load(cursor, false)} disabled={loading || done}>
          {done ? "end of log" : "next 50 →"}</button>
      </div>
      {err && <p className="bad" role="alert">{err}</p>}
      {events.length === 0 && !loading && <p className="dim">no matching events yet.</p>}
      <table><tbody>
        {events.map(e => (
          <tr key={e.event_id} ref={String(e.event_id) === String(focusEvent) ? focusRef : null}
              style={String(e.event_id) === String(focusEvent) ? { background: "#21313f" } : undefined}>
            <td className="dim mono" style={{ whiteSpace: "nowrap", fontSize: ".8rem" }}>
              {new Date(e.ts).toLocaleTimeString()}</td>
            <td className={e.actor === "red" ? "bad" : e.actor === "system" ? "dim" : "ok"}>{e.actor}</td>
            <td>{e.action_type}{e.phase ? <span className="dim"> · {e.phase}</span> : null}</td>
            <td><details>
              <summary className="dim">details #{e.event_id}</summary>
              <pre className="md-pre">{JSON.stringify(e.payload, null, 2)}</pre>
            </details></td>
          </tr>))}
      </tbody></table>
      <p className="dim" style={{ fontSize: ".8rem" }}>events arrive in durable ingestion order;
        sealed competition content is already redacted by the API.</p>
    </div>
  );
}
