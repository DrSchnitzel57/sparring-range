import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import { api } from "../../lib/api";
import ActivityPanel from "../../components/ActivityPanel";
import CoachPanel from "../../components/CoachPanel";
import ReplayPanel from "../../components/ReplayPanel";
import ReportPanel from "../../components/ReportPanel";

// One session, five views (plan 20): Overview · Activity · Coach · Replay ·
// Report. Tabs deep-link through ?tab= (reload-safe, keyboard accessible)
// and old URLs (/session/x/replay, /report) still exist as thin pages.

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "activity", label: "Activity" },
  { id: "coach", label: "Coach" },
  { id: "replay", label: "Replay" },
  { id: "report", label: "Report" },
];

export default function LiveSession() {
  const router = useRouter();
  const id = router.query.id;
  const tab = TABS.some(t => t.id === router.query.tab) ? router.query.tab : "overview";
  const [sess, setSess] = useState(null);
  const [live, setLive] = useState(null);
  const [conns, setConns] = useState(null);
  const [keyEnroll, setKeyEnroll] = useState(null);
  const [injects, setInjects] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [opNote, setOpNote] = useState(null);
  const [seconds, setSeconds] = useState(0);
  const [qualBlockers, setQualBlockers] = useState(null);
  const startRef = useRef(null);
  const tabsRef = useRef(null);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    api(`/sessions/${id}`).then(s => { if (!stop) setSess(s); })
      .catch(e => setErr(String(e.message || e)));
    // connection instructions are SERVED BY THE API (pilot step 4): they
    // survive refreshes and other devices — no browser-session secret.
    // Follows the durable operation to its terminal state: provisioning
    // outlasts any fixed retry budget, so this polls the full server-side
    // operation deadline. Transient poll failures NEVER abort the wait.
    const loadConns = async () => {
      try {
        for (let i = 0; i < 450; i++) {
          let op = null;
          try { op = await api(`/sessions/${id}/operation`); }
          catch (e) {
            if (e && e.status === 404) break;   // never-accepted/legacy: fall through
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
        if (!stop) { setConns(c.connections); setKeyEnroll(c.key_enrollment || null); }
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
        api(`/sessions/${id}`).then(s => {
          if (stop) return;
          setSess(s);
          // LIVE-07: show WHAT blocks Begin (and why) before the click —
          // the same classification the server gate applies.
          if (s.match && s.match.state === "ready")
            api("/safety/qualification")
              .then(q => setQualBlockers(q.begin_blockers || []))
              .catch(() => setQualBlockers(null));
          else setQualBlockers(null);
        }).catch(() => {});
      } catch { /* transient */ }
    };
    tick();
    const t = setInterval(tick, 2000);
    const tin = () => api(`/sessions/${id}/injects`)
      .then(d => { if (!stop) setInjects(d); })
      .catch(() => { if (!stop) setInjects(null); });
    tin();
    const ti = setInterval(tin, 5000);
    const tc = setInterval(() => { if (startRef.current) setSeconds(s => s + 1); }, 1000);
    return () => { stop = true; clearInterval(t); clearInterval(ti); clearInterval(tc); };
  }, [id]);

  function setTab(next) {
    router.replace(`/session/${id}?tab=${next}`, undefined, { scroll: false });
  }
  function onTabsKey(e) {
    const i = TABS.findIndex(t => t.id === tab);
    if (e.key === "ArrowRight") { e.preventDefault(); tabsRef.current?.children[Math.min(i + 1, TABS.length - 1)]?.focus(); tabsRef.current?.children[Math.min(i + 1, TABS.length - 1)]?.click?.(); }
    if (e.key === "ArrowLeft") { e.preventDefault(); tabsRef.current?.children[Math.max(i - 1, 0)]?.focus(); tabsRef.current?.children[Math.max(i - 1, 0)]?.click?.(); }
  }

  async function act(fn, label) {
    setBusy(true); setErr(null);
    try { await fn(); } catch (e) { setErr(`${label}: ${e.message || e}`); }
    setBusy(false);
  }
  const beginMatch = () => act(async () => {
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
    try { await awaitOperation(acc.operation_id); } finally { setOpNote(null); }
    const c = await api(`/sessions/${id}/connections`);
    setConns(c.connections);
    setKeyEnroll(c.key_enrollment || null);
    setSess(await api(`/sessions/${id}`));
  }, "redeploy");
  const submitInject = (releaseId) => act(async () => {
    await api(`/sessions/${id}/injects/${releaseId}`, {
      method: "POST", body: { content: injectDraft[releaseId] || "" },
    });
    setInjects(await api(`/sessions/${id}/injects`));
  }, "inject submission");
  const [injectDraft, setInjectDraft] = useState({});

  if (err && !sess) return <p className="bad">{err}</p>;
  if (!sess) return <p className="dim">loading…</p>;
  const mm = String(Math.floor(seconds / 60)).padStart(2, "0"), ss = String(seconds % 60).padStart(2, "0");
  const running = sess.status === "running" || sess.status === "stopping";
  const match = sess.match;
  let remaining = null;
  if (match && match.state === "running" && match.deadline_at)
    remaining = Math.max(0, Math.floor((new Date(match.deadline_at).getTime() - Date.now()) / 1000));
  const rmm = remaining === null ? null : String(Math.floor(remaining / 60)).padStart(2, "0");
  const rss = remaining === null ? null : String(remaining % 60).padStart(2, "0");

  return (
    <>
      <div className="row" style={{ marginBottom: 10 }}>
        <Link href="/home" className="dim">← dashboard</Link>
        <h2 style={{ margin: 0 }}>{sess.scenario_id}</h2>
        <span className="phase">{live?.red_phase || sess.status}</span>
        <span className="spacer" />
        {remaining !== null && <span className="mono" style={{ fontSize: 22 }}
          title="server match clock — ends at the deadline">{rmm}:{rss}</span>}
        {remaining === null && running && <span className="mono" style={{ fontSize: 22 }}>{mm}:{ss}</span>}
      </div>
      <div className="tabs" role="tablist" aria-label="Session views" ref={tabsRef}
           onKeyDown={onTabsKey}>
        {TABS.map(t => (
          <button key={t.id} role="tab" id={`tab-${t.id}`}
                  aria-selected={tab === t.id} aria-controls={`panel-${t.id}`}
                  onClick={() => setTab(t.id)} data-tab={t.id}>{t.label}</button>))}
      </div>

      {err && <p className="bad" role="alert">{err}</p>}

      <div role="tabpanel" id={`panel-${tab}`} hidden={false}>
        {tab === "overview" && <Overview id={id} sess={sess} live={live} conns={conns}
          injects={injects} busy={busy} opNote={opNote}
          qualBlockers={qualBlockers} keyEnroll={keyEnroll}
          beginMatch={beginMatch} startRed={startRed} stopRed={stopRed}
          endSession={endSession} redeploy={redeploy} submitInject={submitInject}
          injectDraft={injectDraft} setInjectDraft={setInjectDraft} setTab={setTab} />}
        {tab === "activity" && <ActivityPanel sid={id} focusEvent={router.query.event} />}
        {tab === "coach" && <CoachPanel sid={id} />}
        {tab === "replay" && <ReplayPanel sid={id} />}
        {tab === "report" && <ReportPanel sid={id} />}
      </div>
    </>
  );
}

function Overview({ id, sess, live, conns, injects, busy, opNote,
                    qualBlockers, keyEnroll,
                    beginMatch, startRed, stopRed, endSession, redeploy,
                    submitInject, injectDraft, setInjectDraft, setTab }) {
  const match = sess.match;
  const running = sess.status === "running" || sess.status === "stopping";
  return (
    <div className="grid">
      <div>
        <div className="panel">
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
          <div className="row" style={{ marginTop: 8 }}>
            {match && match.state === "ready" && !running &&
              qualBlockers && qualBlockers.length > 0 && (
              <p className="bad" data-testid="begin-blockers">
                begin is blocked: {qualBlockers.join(" · ")}
              </p>)}
            {match && match.state === "ready" && !running &&
              <button onClick={beginMatch} disabled={busy}
                      data-testid="begin-button"
                      data-blocked={qualBlockers && qualBlockers.length ? "yes" : "no"}
                      title={qualBlockers && qualBlockers.length
                        ? qualBlockers.join(" · ") : undefined}>▶ begin match ({match.duration_minutes} min)</button>}
            {(!match || match.state !== "ready") && !running &&
              sess.status !== "complete" && sess.status !== "failed" &&
              (!match || !["finalizing", "interrupted"].includes(match.state)) &&
              <button onClick={startRed} disabled={busy}>▶ start red</button>}
            {sess.active_run && <button onClick={stopRed} disabled={busy}>■ stop red</button>}
            {sess.status !== "complete" && <button className="danger" onClick={endSession} disabled={busy}>end session</button>}
            <button className="ghost" onClick={() => setTab("report")}>report →</button>
            <button className="ghost" onClick={() => setTab("replay")}>replay →</button>
          </div>
          {opNote && <p className="dim">{opNote}</p>}
        </div>
        <div className="panel">
          <h3>connections</h3>
          {conns && conns.length ? (
            <ul data-testid="connections-list">{conns.map(c => (
              <li key={c.host} data-testid={`connection-${c.host}`}>
                {c.member_ssh === false ? (
                  <span className="dim" data-testid={`connection-note-${c.host}`}>
                    {c.note || "no member SSH for this host"}
                  </span>
                ) : (
                  <code>{c.ssh}</code>
                )}
                {c.role && <span className="dim"> — {c.role}</span>}
              </li>))}</ul>
          ) : conns ? (
            <p className="dim">no active connection capability — launch/redeploy to
              {" "}<a href="#" onClick={e => { e.preventDefault(); redeploy(); }}>re-issue</a></p>
          ) : (
            <p className="dim">loading…</p>
          )}
          {keyEnroll && keyEnroll.enrolled === false && (
            <p className="bad" data-testid="key-enrollment-warning">
              Your account has NO public key enrolled — the bastion will refuse
              SSH even with a valid token. Add your desktop’s PUBLIC key
              (operator: “rangectl bastion enroll &lt;account&gt; key.pub”,
              or the bastion admin page). Fingerprints confirm the enrollment
              only — they never expose key material.
            </p>
          )}
          <p className="dim">Defend: SSH through the bastion with the token login; every keystroke
            is recorded and replayable. SSH also requires your account’s public key
            to be enrolled — the token username alone is not sufficient. The attacker
            machine is red-operator territory (dispatched red operations), not an SSH host.</p>
        </div>
        <div className="panel">
          <h3>web uptime</h3>
          <p className="dim">Service availability only — this does not measure AI progress or security.</p>
          {live?.uptime?.coverage_error && <p className="bad">{live.uptime.coverage_error}</p>}
          {live?.uptime?.scored ? (
            <>
              <p style={{ fontSize: 20 }}>
                <span className={live.uptime.latest?.state === "up" ? "ok" : "bad"}>●</span>{" "}
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
      </div>
      <div>
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
          <h3>need a nudge?</h3>
          <p className="dim">The coach knows this session’s evidence, starts with
            hints, and never runs anything for you.</p>
          <button className="ghost" onClick={() => setTab("coach")}>open the coach →</button>
        </div>
      </div>
    </div>
  );
}
