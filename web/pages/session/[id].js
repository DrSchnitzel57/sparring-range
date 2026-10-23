import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import { api } from "../../lib/api";

export default function LiveSession() {
  const router = useRouter();
  const id = router.query.id;
  const [sess, setSess] = useState(null);
  const [live, setLive] = useState(null);
  const [conns, setConns] = useState(null);
  const [hint, setHint] = useState("");
  const [logKind, setLogKind] = useState("");
  const [logEvents, setLogEvents] = useState([]);
  const [logError, setLogError] = useState(null);
  const [injects, setInjects] = useState(null);
  const [injectDraft, setInjectDraft] = useState({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [opNote, setOpNote] = useState(null);
  const [seconds, setSeconds] = useState(0);
  const startRef = useRef(null);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    api(`/sessions/${id}`).then(s => {
      if (stop) return;
      setSess(s);
    }).catch(e => setErr(String(e.message || e)));
    // connection instructions are SERVED BY THE API (pilot step 4): they
    // survive refreshes and other devices — no browser-session secret.
    // After a 202 launch the executor provisions in the background, which
    // takes longer than any fixed retry budget: follow the durable
    // operation to its terminal state, THEN load connections. A failed
    // operation surfaces its (redacted) error instead of an empty panel.
    // Follows the durable operation to its terminal state: provisioning
    // outlasts any fixed retry budget, so this polls the full server-side
    // operation deadline (900s). Transient poll failures NEVER abort the
    // wait (a blip is not a verdict); only a terminal operation state —
    // or an actually-missing operation (404: nothing was ever accepted) —
    // ends it. Connections reload after every terminal success.
    const loadConns = async () => {
      try {
        for (let i = 0; i < 450; i++) {
          let op = null;
          try { op = await api(`/sessions/${id}/operation`); }
          catch (e) {
            // 404 = no operation row: pre-202 sessions and never-accepted
            // launches may still hold live capabilities — fall through to
            // the server-served connections read instead of abandoning it.
            if (e && e.status === 404) break;
          }
          if (stop) return;
          if (op && op.state === "succeeded") break;
          if (op && (op.state === "failed" || op.state === "interrupted")) {
            setConns(null);
            setErr(`deploy ${op.state}: ${op.error || op.phase}`);
            return;
          }
          await new Promise(r => setTimeout(r, 2000));
        }
        if (stop) return;
        const c = await api(`/sessions/${id}/connections`);
        if (!stop) setConns(c.connections);
      } catch { if (!stop) setConns(null); }
    };
    loadConns();
    const tick = async () => {
      try {
        const d = await api(`/sessions/${id}/live`);
        if (stop) return;
        setLive(d);
        if (!startRef.current && d.started_at) startRef.current = new Date(d.started_at).getTime();
        if (startRef.current) setSeconds(Math.max(0, Math.floor((Date.now() - startRef.current) / 1000)));
        // 202 lifecycle: the executor promotes provisioning → ready in the
        // background. Keep polling even during a running match: the attacker
        // can fail while service probes and the match clock keep running.
        api(`/sessions/${id}`).then(s => { if (!stop) setSess(s); }).catch(() => {});
      } catch (e) { /* transient */ }
    };
    tick();
    const t = setInterval(tick, 2000);
    const tin = () => {
      api(`/sessions/${id}/injects`)
        .then(d => { if (!stop) setInjects(d); })
        .catch(() => { if (!stop) setInjects(null); });
    };
    tin();
    const ti = setInterval(tin, 5000);
    const tc = setInterval(() => { if (startRef.current) setSeconds(s => s + 1); }, 1000);
    return () => { stop = true; clearInterval(t); clearInterval(ti); clearInterval(tc); };
  }, [id]);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    setLogEvents([]);
    const load = async () => {
      try {
        // Filter BEFORE the tail on the API: telemetry volume must not hide
        // the last AI action. The API still enforces competition redaction.
        const kind = logKind ? `&action_type=${encodeURIComponent(logKind)}` : "";
        const events = await api(`/events?session_id=${id}&tail=20${kind}`);
        if (!stop) { setLogEvents(events); setLogError(null); }
      } catch (e) { if (!stop) setLogError(String(e.message || e)); }
    };
    load();
    const timer = setInterval(load, 5000);
    return () => { stop = true; clearInterval(timer); };
  }, [id, logKind]);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    setHint("");
    api(`/events?session_id=${id}&action_type=hint&tail=1`).then(events => {
      if (!stop && events.length) {
        const payload = events[0].payload || {};
        setHint(payload.redacted || (payload.hint || "").trim() ||
          "The last model hint was empty. No usable hint was generated.");
      }
    }).catch(() => {});
    return () => { stop = true; };
  }, [id]);

  async function act(fn, label) {
    setBusy(true); setErr(null);
    try { await fn(); } catch (e) { setErr(`${label}: ${e.message || e}`); }
    setBusy(false);
    router.replace(router.asPath, undefined, { scroll: false });
  }
  const beginMatch = () => act(async () => {
    // BEGIN: server clock + attack worker start together (pilot step 4)
    await api(`/sessions/${id}/begin`, { method: "POST" });
    setSess(await api(`/sessions/${id}`));
  }, "begin match");
  const startRed = () => act(async () => {
    await api(`/run/${sess.scenario_id}`, { method: "POST", body: { session_id: id } });
    setSess(await api(`/sessions/${id}`));
  }, "start red");
  const stopRed = () => act(async () => {
    await api(`/runs/${sess.active_run}/stop`, { method: "POST" });
    setSess(await api(`/sessions/${id}`));
  }, "stop red");
  const endSession = () => {
    if (!confirm("End match? Stops red, takes a trusted final score, revokes tokens and destroys the owned lab.")) return;
    act(async () => {
      const r = await api(`/sessions/${id}/end`, { method: "POST" });
      setSess(await api(`/sessions/${id}`));
      if (!r.ok || !r.lease_released)
        throw new Error(r.note || "cleanup incomplete — range reservation retained");
    }, "end");
  };
  // 202 lifecycle: launch/reset are accepted immediately and completed by
  // the supervised executor — poll the durable operation, then refresh
  // server-served state. A lost response never re-posts (no second deploy).
  const awaitOperation = async (opId) => {
    for (let i = 0; i < 150; i++) {
      const op = await api(`/sessions/${id}/operation`);
      if (op.operation_id !== opId) return op;
      if (op.state === "succeeded") return op;
      if (op.state === "failed" || op.state === "interrupted")
        throw new Error(`deploy ${op.state}: ${op.error || op.phase}`);
      await new Promise(r => setTimeout(r, 2000));
    }
    throw new Error("deploy timed out waiting for the operation");
  };
  const redeploy = () => act(async () => {
    const acc = await api(`/sessions/${id}/launch`, { method: "POST" });
    setOpNote(`deploy ${acc.operation_id.slice(0, 8)}… accepted, provisioning`);
    try {
      await awaitOperation(acc.operation_id);
    } finally {
      setOpNote(null);
    }
    const c = await api(`/sessions/${id}/connections`);
    setConns(c.connections);
    setSess(await api(`/sessions/${id}`));
  }, "redeploy");
  const askHint = () => act(async () => {
    const r = await api(`/sessions/${id}/hint`, { method: "POST", body: { question: "" } });
    setHint((r.hint || "").trim() || "The model returned an empty hint. No usable hint was generated.");
  }, "hint");
  const submitInject = (releaseId) => act(async () => {
    // identity-bound; the FIRST answer decides (duplicates never re-decide)
    await api(`/sessions/${id}/injects/${releaseId}`, {
      method: "POST", body: { content: injectDraft[releaseId] || "" },
    });
    setInjects(await api(`/sessions/${id}/injects`));
  }, "inject submission");

  if (err && !sess) return <p className="bad">{err}</p>;
  if (!sess) return <p className="dim">loading…</p>;
  const mm = String(Math.floor(seconds / 60)).padStart(2, "0"), ss = String(seconds % 60).padStart(2, "0");
  const running = sess.status === "running" || sess.status === "stopping";
  const match = sess.match;
  // SERVER-clock countdown: the match ends at the server deadline, not on a
  // client timer. Remaining time is derived from deadline_at on every render.
  let remaining = null;
  if (match && match.state === "running" && match.deadline_at) {
    remaining = Math.max(0, Math.floor((new Date(match.deadline_at).getTime() - Date.now()) / 1000));
  }
  const rmm = remaining === null ? null : String(Math.floor(remaining / 60)).padStart(2, "0");
  const rss = remaining === null ? null : String(remaining % 60).padStart(2, "0");

  return (
    <div className="grid">
      <div>
        <div className="panel">
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <h2>{sess.scenario_id} — <span className="phase">{live?.red_phase || sess.status}</span></h2>
            {remaining !== null && <span style={{ fontSize: 24 }} title="server match clock — ends at the deadline">{rmm}:{rss}</span>}
            {remaining === null && running && <span style={{ fontSize: 24 }}>{mm}:{ss}</span>}
          </div>
          <p className="dim">status: {sess.status} {sess.outcome && `(${sess.outcome})`}
            {sess.active_run && ` · red run ${sess.active_run.slice(0, 8)}`} ·
             phases advance only when verifiers pass</p>
          {live?.attacker && <div aria-label="Attacker status">
            <p className={["failed", "cancel-unknown"].includes(live.attacker.status) ? "bad" : "dim"}>
              AI worker: {live.attacker.status}
              {live.attacker.outcome && ` · ${live.attacker.outcome}`}
              {live.attacker.event_age_s != null && ` · last AI event ${live.attacker.event_age_s}s ago`}
            </p>
            {live.attacker.error && <p className="bad">{live.attacker.error}</p>}
            {["queued", "running"].includes(live.attacker.status) && live.attacker.event_age_s >= 300 &&
              <p className="bad">No AI event for at least 5 minutes. The match clock and web uptime do not prove attacker progress.</p>}
          </div>}
          {match && match.state === "ready" && (
            <p className="dim">lab ready — <b>begins idle-expiry</b>
              {match.ready_expires_at && ` at ${new Date(match.ready_expires_at).toLocaleTimeString()}`}
              {" "}if not begun; match runs {match.duration_minutes} min from Begin
              (attack pace {match.pace_seconds}s/action).</p>
          )}
          {match && (match.state === "finalizing" || match.state === "interrupted") && (
            <p className="bad">match cleanup {match.state} ({match.expiry_reason || "recovery"}) —
              {" "}range stays reserved until teardown completes; retry with “end session”.</p>
          )}
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            {match && match.state === "ready" && !running &&
              <button onClick={beginMatch} disabled={busy}>▶ begin match ({match.duration_minutes} min)</button>}
            {(!match || match.state !== "ready") && !running &&
              sess.status !== "complete" && sess.status !== "failed" &&
              (!match || !["finalizing", "interrupted"].includes(match.state)) &&
              <button onClick={startRed} disabled={busy}>▶ start red</button>}
            {sess.active_run && <button onClick={stopRed} disabled={busy}>■ stop red</button>}
            {sess.status !== "complete" && <button className="danger" onClick={endSession} disabled={busy}>end session</button>}
          </div>
          {err && <p className="bad">{err}</p>}
          {opNote && <p className="dim">{opNote}</p>}
        </div>
        <div className="panel">
          <h3>connections</h3>
          {conns && conns.length ? (
            <ul>{conns.map(c => (
              <li key={c.host}><code>{c.ssh}</code></li>))}</ul>
          ) : conns ? (
            <p className="dim">no active connection capability — launch/redeploy to
              {" "}<a href="#" onClick={e => { e.preventDefault(); redeploy(); }}>re-issue</a></p>
          ) : (
            <p className="dim">loading…</p>
          )}
          <p className="dim">Defend: SSH through the bastion with the token login; every keystroke
             is recorded and replayable.</p>
          <p className="dim">SSH also requires this device’s public key to be enrolled by the operator
            for your application account. The token username alone is not sufficient.
            If your key is not offered automatically, use <code>ssh -i path/to/your/private-key</code>
            {" "}with the connection options above. Keep the private key on your device.</p>
        </div>
        <div className="panel">
          <h3>web uptime</h3>
          <p className="dim">Service availability only — this does not measure AI progress or security.</p>
          {live?.uptime?.coverage_error && <p className="bad">{live.uptime.coverage_error}</p>}
          {live?.uptime?.scored ? (
            <>
              <p style={{ fontSize: 20 }}>
                <span className={live.uptime.latest?.state === "up" ? "ok" : "bad"}>
                  ●</span>{" "}
                {live.uptime.pct_up}% up{" "}
                <span className="dim">({live.uptime.up} up / {live.uptime.down} down ·{" "}
                  {live.uptime.unknown} unknown · coverage {live.uptime.coverage_pct}%)</span>
              </p>
              <p className="dim">
                latest: {live.uptime.latest?.state}
                {live.uptime.latest?.latency_ms != null && ` ${live.uptime.latest.latency_ms}ms`}
                {live.uptime.stale && " · STALE (probe not fresh — checks paused)"}
                {" · scored only among valid checks; separate from the security score"}
              </p>
            </>
          ) : (
            <p className="dim">unscored — no valid checks yet (unknown/missed never count)</p>
          )}
        </div>
        <div className="panel">
          <h3>injects</h3>
          {!injects ? <p className="dim">loading…</p>
            : injects.releases.length === 0 ? (
            <p className="dim">no injects released for this match</p>) : (
            <>
              <ul>{injects.releases.map(r => {
                const open = new Date(r.scheduled_at).getTime() <= Date.now();
                const past = new Date(r.deadline_at).getTime() < Date.now();
                return (
                  <li key={r.release_id} style={{ marginBottom: 10 }}>
                    <b>{r.inject_id.replace("@1", "")}</b>{" "}
                    <span className={r.status === "correct" ? "ok"
                      : r.status === "pending" ? "dim" : "bad"}>[{r.status}]</span>
                    <br />
                    <span className="dim">{r.description}</span>
                    {r.kind === "written" && <><br />
                      <span className="dim">advisory feedback only — never verified points</span></>}
                    <br />
                    <span className="dim">
                      {open ? (past ? "window closed" : `closes ${new Date(r.deadline_at).toLocaleTimeString()}`)
                        : `opens ${new Date(r.scheduled_at).toLocaleTimeString()}`}
                    </span>
                    {r.status === "pending" && open && !past &&
                      <>
                        <br />
                        <textarea rows={2} style={{ width: "100%" }}
                          placeholder="your answer / actions taken…"
                          value={injectDraft[r.release_id] || ""}
                          onChange={e => setInjectDraft({ ...injectDraft, [r.release_id]: e.target.value })} />
                        <button onClick={() => submitInject(r.release_id)} disabled={busy}>submit</button>
                      </>}
                  </li>
                );
              })}</ul>
              <p className="dim">
                inject score: {injects.score.scored
                  ? `${injects.score.correct}/${injects.score.technical_closed} (${injects.score.pct}%)`
                  : "unscored"}{" "}
                — separate from availability and the security scorecard
              </p>
            </>)}
        </div>
        <div className="panel">
          <h3>detections</h3>
          {(!live || live.detections.length === 0) && <p className="dim">nothing verified yet</p>}
          <ul>{live?.detections.map(d => (
            <li key={d.event_id}>
              {d.passed ? <span className="bad">● objective {d.objective} CONFIRMED</span>
                : <span className="dim">○ {d.objective} not yet</span>}{" "}
              <span className="dim">{new Date(d.ts).toLocaleTimeString()}</span>
            </li>))}
          </ul>
        </div>
        <div className="panel">
          <h3>recent log</h3>
          <label>Show events{" "}
            <select aria-label="Event filter" value={logKind} onChange={e => setLogKind(e.target.value)}>
              <option value="">all recent</option>
              <option value="action_intent">AI commands dispatched</option>
              <option value="action_result">AI command results</option>
              <option value="agent_note">AI notes and errors</option>
              <option value="verifier">verifier results</option>
              <option value="hint">coach hints</option>
            </select>
          </label>
          {logError && <p className="bad">Log refresh failed: {logError}</p>}
          {!logEvents.length && <p className="dim">No matching events yet.</p>}
          <table><tbody>
            {logEvents.map(e => (
              <tr key={e.event_id}>
                <td className="dim">{new Date(e.ts).toLocaleTimeString()}</td>
                <td>{e.actor}</td><td>{e.action_type}</td><td>{e.phase || ""}</td>
                <td><details><summary>details #{e.event_id}</summary>
                  <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
                    {JSON.stringify(e.payload, null, 2)}
                  </pre>
                </details></td>
              </tr>))}
          </tbody></table>
        </div>
      </div>
      <div>
        <div className="panel">
          <h3>coach</h3>
          <button onClick={askHint} disabled={busy}>{busy ? "thinking…" : "request hint"}</button>
          {hint && <p style={{ marginTop: 12 }}>{hint}</p>}
        </div>
        <div className="panel">
          <h3>after action</h3>
          <Link href={`/session/${id}/report`}>graded AAR →</Link><br />
          <Link href={`/session/${id}/replay`}>replay ↔ timeline →</Link>
        </div>
      </div>
    </div>
  );
}
