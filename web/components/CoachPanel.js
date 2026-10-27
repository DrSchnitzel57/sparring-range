import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { Md } from "../lib/md";

// Persistent coach conversation (plan 20): hints-first guidance through a
// durable job. Reload always shows pending answers (from the job row);
// unavailable/fallback answers are visibly the honest ones. Citations link
// to the authorized Activity evidence. The coach NEVER executes anything.
export default function CoachPanel({ sid }) {
  const [msgs, setMsgs] = useState([]);
  const [pending, setPending] = useState([]);
  const [sealed, setSealed] = useState(false);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [hint, setHint] = useState("");
  const endRef = useRef(null);
  const lastIdRef = useRef(0);

  async function askHint() {
    setBusy(true); setErr(null);
    try {
      const r = await api(`/sessions/${sid}/hint`, { method: "POST", body: { question: "" } });
      const payload = r || {};
      const shown = (payload.hint || "").trim() || payload.redacted;
      setHint(shown || "The last model hint was empty. No usable hint was generated.");
    } catch (e) { setErr(String(e.message || e)); }
    setBusy(false);
  }

  const load = useCallback(async (initial) => {
    try {
      const q = initial || lastIdRef.current === 0
        ? "" : `?after_id=${lastIdRef.current}`;
      const d = await api(`/sessions/${sid}/coach/messages${q}`);
      setSealed(!!d.sealed);
      setPending(d.pending || []);
      setMsgs((prev) => {
        if (initial || lastIdRef.current === 0) {
          if (d.messages.length) lastIdRef.current = d.messages[d.messages.length - 1].message_id;
          return d.messages;
        }
        if (!d.messages.length) return prev;
        lastIdRef.current = d.messages[d.messages.length - 1].message_id;
        const seen = new Set(prev.map(m => m.message_id));
        return prev.concat(d.messages.filter(m => !seen.has(m.message_id)));
      });
      setErr(null);
    } catch (e) { setErr(String(e.message || e)); }
  }, [sid]);

  useEffect(() => { lastIdRef.current = 0; setMsgs([]); load(true); }, [load]);
  useEffect(() => {
    // the LATEST hint event stays visible across reloads: an empty stored
    // hint must surface as an honest failure, not as silent absence (18/19
    // regression kept from the old coach panel)
    if (!sid) return;
    let stop = false;
    api(`/events?session_id=${sid}&action_type=hint&tail=1`).then((events) => {
      if (stop || !events.length) return;
      const payload = events[0].payload || {};
      setHint(payload.redacted || (payload.hint || "").trim() ||
        "The last model hint was empty. No usable hint was generated.");
    }).catch(() => {});
    return () => { stop = true; };
  }, [sid]);
  useEffect(() => {
    const t = setInterval(() => load(false), 4000);
    return () => clearInterval(t);
  }, [load]);
  useEffect(() => { endRef.current?.scrollIntoView({ block: "nearest" }); }, [msgs, pending]);

  async function send(e) {
    e.preventDefault();
    const t = text.trim();
    if (!t || busy) return;
    setBusy(true); setErr(null);
    try {
      await api(`/sessions/${sid}/coach/messages`, { method: "POST", body: { text: t } });
      setText("");
      await load(false);
    } catch (e2) { setErr(String(e2.message || e2)); }
    setBusy(false);
  }

  return (
    <div className="panel">
      <h3>practice coach</h3>
      <p className="dim" style={{ fontSize: ".85rem" }}>
        Hints and guidance only — the coach never runs commands and never
        awards points. {sealed && "This match is sealed: answers use only the evidence you are allowed to see."}
      </p>
      <div className="row" style={{ marginBottom: 10 }}>
        <button className="ghost" onClick={askHint} disabled={busy || !!pending.length}>
          request a hint</button>
        {hint && <span className="dim" style={{ flex: 1 }}>{hint}</span>}
      </div>
      {err && <p className="bad" role="alert">{err}</p>}
      <div className="chat" aria-live="polite">
        {msgs.length === 0 && !pending.length &&
          <p className="dim">no conversation yet — ask where to look next.</p>}
        {msgs.map(m => (
          <div key={m.message_id} className={`msg ${m.role}`} data-role={m.role}
               data-model-ok={m.model_ok === null ? "" : String(m.model_ok)}>
            <div className="who">{m.role === "user" ? "you" : m.model_ok === false ? "coach (no model answer — honest fallback)" : "coach"}</div>
            <Md text={m.body} />
            {m.citations?.length > 0 && (
              <div className="citations">evidence:{" "}
                {m.citations.map(id => <a key={id} href={`?tab=activity&event=${id}`} className="md-cite">#{id}</a>)}
              </div>)}
          </div>))}
        {pending.map(j => (
          <div key={j.job_id} className="msg coach" data-pending={j.state}>
            <div className="who">coach — {j.state === "running" ? "answering…" : "queued…"}</div>
            <p className="dim">working through the evidence so far (this survives a reload).</p>
          </div>))}
        <div ref={endRef} />
      </div>
      <form onSubmit={send}>
        <input aria-label="Ask the coach" placeholder="ask the coach… (it will not run anything)"
               value={text} onChange={(e) => setText(e.target.value)} maxLength={4000} />
        <button type="submit" disabled={busy || !text.trim()}>send</button>
      </form>
    </div>
  );
}
