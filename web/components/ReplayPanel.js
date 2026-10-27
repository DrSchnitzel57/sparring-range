import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";

// Synchronized review (plan 20): attacker command output (timed chunks)
// and the defender's recorded cast play on ONE session clock with
// play/pause/seek/speed and previous/next command. It works WITHOUT any
// defender cast (command-only playback drives the clock), says so when
// events fall outside cast coverage, and never invents frames: casts
// that are missing or corrupt stay honest per-entry errors, chunk gaps
// and truncation render as marked gaps, and operations from before
// timed capture stay command-only lines.
const SPEEDS = [0.5, 1, 2, 4, 8];

function fmt(s) {
  if (s === null || s === undefined || Number.isNaN(s)) return "—";
  const neg = s < 0; const x = Math.abs(s);
  const m = Math.floor(x / 60), r = Math.floor(x % 60);
  return `${neg ? "-" : ""}${String(m).padStart(2, "0")}:${String(r).padStart(2, "0")}`;
}

export default function ReplayPanel({ sid }) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [selCast, setSelCast] = useState(0);
  const [frames, setFrames] = useState(null);     // selected cast frames
  const [framesErr, setFramesErr] = useState(null);
  const [actorF, setActorF] = useState("");
  const [typeF, setTypeF] = useState("");
  const [timeline, setTimeline] = useState([]);
  const [cursor, setCursor] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [chunkRows, setChunkRows] = useState(null); // [{at, kind, text, op}]
  const [now, setNow] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [seekAt, setSeekAt] = useState(null);
  const [playerErr, setPlayerErr] = useState(null);
  const rootRef = useRef(null);
  const playerRef = useRef(null);
  const clockRef = useRef({ t: 0, last: null, speed: 1, dur: 0 });

  const casts = useMemo(() => (data?.casts || []).filter(c => !c.error), [data]);
  const broken = (data?.casts || []).filter(c => c.error);
  const cast = casts[selCast];
  const ops = data?.operations || [];
  const sealed = !!data?.sealed;

  // ---- data: projection page, then per-cast frames and per-op chunks ----
  const loadPage = useCallback(async (after) => {
    const q = new URLSearchParams({ limit: "200" });
    if (after) q.set("after_event_id", String(after));
    if (actorF) q.set("actor", actorF);
    if (typeF) q.set("action_type", typeF);
    const d = await api(`/sessions/${sid}/replay?${q.toString()}`);
    return d;
  }, [sid, actorF, typeF]);

  useEffect(() => {
    if (!sid) return;
    let stop = false;
    setTimeline([]); setCursor(0); setFrames(null); setChunkRows(null);
    (async () => {
      try {
        const d = await loadPage(0);
        if (stop) return;
        setData(d); setTimeline(d.timeline); setCursor(d.has_more && d.timeline.length
          ? d.timeline[d.timeline.length - 1].event_id : 0);
        setHasMore(d.has_more);
        if (!d.sealed && d.operations.length) {
          const all = [];
          for (const op of d.operations) {
            if (!op.has_output) continue;
            let after = null;
            for (;;) {
              const r = await api(`/sessions/${sid}/operations/${op.op_uuid}/output`
                + (after !== null ? `?after_seq=${after}` : ""));
              all.push(...r.chunks.map(c => ({ ...c, op_uuid: op.op_uuid, at: Date.parse(c.ts) / 1000, cmd: op.command })));
              if (!r.has_more) break;
              after = r.next_after_seq;
            }
          }
          if (!stop) setChunkRows(all);
        } else if (!stop) setChunkRows([]);
      } catch (e) { if (!stop) setErr(String(e.message || e)); }
    })();
    return () => { stop = true; };
  }, [sid, loadPage]);

  const loadMore = async () => {
    const d = await loadPage(cursor);
    setTimeline(tl => tl.concat(d.timeline));
    setHasMore(d.has_more);
    if (d.has_more && d.timeline.length)
      setCursor(d.timeline[d.timeline.length - 1].event_id);
  };

  useEffect(() => {
    if (!cast) { setFrames(null); return; }
    let stop = false;
    setFrames(null); setFramesErr(null);
    api(`/recordings/${cast.recording_id}`)
      .then(d => { if (!stop) setFrames(d); })
      .catch(e => { if (!stop) setFramesErr(String(e.message || e)); });
    return () => { stop = true; };
  }, [cast?.recording_id]);  // eslint-disable-line react-hooks/exhaustive-deps

  // ---- the session clock -------------------------------------------------
  // t0 anchors on the defender cast's epoch when present; without any cast
  // the clock starts at the earliest attacker-side timestamp (command-only
  // playback is honest playback, not a fake cast).
  const epoch = cast?.header?.timestamp || null;
  const { t0, duration } = useMemo(() => {
    const stamps = [];
    if (epoch) stamps.push(epoch);
    ops.forEach(o => { if (o.ts) stamps.push(Date.parse(o.ts) / 1000);
                       if (o.end_ts) stamps.push(Date.parse(o.end_ts) / 1000); });
    (chunkRows || []).forEach(c => stamps.push(c.at));
    timeline.forEach(e => stamps.push(Date.parse(e.ts) / 1000));
    if (!stamps.length) return { t0: null, duration: 0 };
    const start = Math.min(...stamps);
    const end = Math.max(...stamps) + 5;
    let dur = Math.max(1, end - start);
    if (epoch && cast?.frame_count) dur = Math.max(dur, cast.duration_s + (epoch - start));
    return { t0: start, duration: dur };
  }, [epoch, cast, ops, chunkRows, timeline]);

  const opOffsets = useMemo(
    () => ops.filter(o => o.ts).map(o => ({ ...o, off: Date.parse(o.ts) / 1000 - t0 }))
             .sort((a, b) => a.off - b.off),
    [ops, t0]);

  const seek = useCallback((t) => {
    const c = Math.max(0, Math.min(t, clockRef.current.dur || t));
    clockRef.current.t = c;
    setSeekAt(Math.round(c * 10) / 10);
    setNow(c);
    const p = playerRef.current;
    if (p?.seek) { try { p.seek(c - (epoch ? 0 : 0)); } catch { /* surfaced below */ } }
  }, [epoch]);

  // keep the clock loop independent of renders
  useEffect(() => { clockRef.current.speed = speed; }, [speed]);
  useEffect(() => { clockRef.current.dur = duration; }, [duration]);
  useEffect(() => {
    if (!playing) { clockRef.current.last = null; return; }
    let raf;
    const step = (ms) => {
      const c = clockRef.current;
      if (c.last !== null) {
        c.t += ((ms - c.last) / 1000) * c.speed;
        if (c.t >= c.dur) { c.t = c.dur; setNow(c.t); setPlaying(false); return; }
        setNow(c.t);
        // defender follows the master clock when it drifts
        const p = playerRef.current;
        if (p?.getCurrentTime && p?.seek) {
          try {
            const dt = p.getCurrentTime();
            if (Math.abs(dt - c.t) > 0.4) p.seek(c.t);
          } catch { /* player not ready yet */ }
        }
      }
      c.last = ms;
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => { cancelAnimationFrame(raf); clockRef.current.last = null; };
  }, [playing]);

  // ---- defender player (asciinema-player fed from fetched frames) -------
  useEffect(() => {
    if (!frames || !rootRef.current) return;
    let cancelled = false;
    const lines = [JSON.stringify(frames.header)]
      .concat(frames.frames.map(f => JSON.stringify(f)));
    const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "application/octet-stream" }));
    import("asciinema-player").then((mod) => {
      if (cancelled || !rootRef.current) return;
      const A = mod.default ?? mod;
      playerRef.current = A.create(url, rootRef.current,
        { autoPlay: false, preload: true, loop: false, terminalName: "xterm-256color" });
      playerRef.current.addEventListener?.("error", (e) =>
        setPlayerErr(String(e?.message ?? e)));
    }).catch((e) => { if (!cancelled) setPlayerErr(String(e?.message ?? e)); });
    return () => {
      cancelled = true;
      if (playerRef.current) { try { playerRef.current.pause(); } catch {} }
      if (rootRef.current) rootRef.current.innerHTML = "";
      playerRef.current = null;
      URL.revokeObjectURL(url);
    };
  }, [frames]);

  // pause the real player with the master clock
  useEffect(() => {
    const p = playerRef.current;
    if (!p) return;
    try { playing ? p.play() : p.pause(); } catch { /* not loaded */ }
  }, [playing, frames]);

  // ---- attacker pane: entries up to the current second -------------------
  const attackerLines = useMemo(() => {
    if (t0 === null) return [];
    const evs = [];
    ops.forEach(o => {
      if (!o.ts || !o.command) return;
      evs.push({ at: Date.parse(o.ts) / 1000 - t0, kind: "cmd",
                 text: `$ ${o.command}`, op: o.op_uuid });
    });
    (chunkRows || []).forEach(c => {
      evs.push({ at: c.at - t0, kind: c.kind === "output" ? "out" : c.kind,
                 text: c.text || (c.kind === "gap" ? `[capture gap${c.dropped_bytes ? `: ${c.dropped_bytes} bytes dropped` : ""}]`
                                                    : "[output truncated at quota]") });
    });
    evs.sort((a, b) => a.at - b.at);
    return evs.filter(e => e.at <= now);
  }, [ops, chunkRows, t0, now]);

  const currentOpIndex = useMemo(() => {
    let idx = -1;
    opOffsets.forEach((o, i) => { if (o.off <= now) idx = i; });
    return idx;
  }, [opOffsets, now]);

  const prevCmd = () => {
    const t = opOffsets.filter(o => o.off < now - 0.05).pop();
    if (t) seek(Math.max(0, t.off));
  };
  const nextCmd = () => {
    const t = opOffsets.find(o => o.off > now + 0.05);
    if (t) seek(t.off);
  };

  const onKeyDown = (e) => {
    if (["INPUT", "SELECT", "TEXTAREA"].includes(e.target.tagName)) return;
    if (e.key === " ") { e.preventDefault(); setPlaying(p => !p); }
    if (e.key === "ArrowLeft") seek(now - 5);
    if (e.key === "ArrowRight") seek(now + 5);
  };

  if (err) return <p className="bad" role="alert">{err}</p>;
  if (!data) return <p className="dim">loading replay…</p>;

  const epochMissing = casts.length > 0 && !epoch;
  const mode = cast ? "cast+commands" : "commands-only";

  return (
    <div className="grid" onKeyDown={onKeyDown} tabIndex={0} role="region"
         aria-label="Replay player"
         data-now={String(Math.round(now * 10) / 10)}
         data-duration={String(Math.round(duration * 10) / 10)}
         data-playing={String(playing)} data-speed={String(speed)}
         data-seek-at={seekAt === null ? "" : String(seekAt)}
         data-mode={mode} data-ops={String(opOffsets.length)}
         data-op-cursor={String(currentOpIndex)}
         data-player-error={playerErr || ""}>
      <div>
        <div className="panel" aria-label="Player controls">
          <div className="player-controls">
            <button onClick={() => setPlaying(p => !p)} aria-label={playing ? "Pause" : "Play"}>
              {playing ? "⏸ pause" : "▶ play"}</button>
            <button className="ghost" onClick={() => seek(0)}>⏮</button>
            <button className="ghost" onClick={prevCmd} disabled={currentOpIndex < 0}>⟨ prev command</button>
            <button className="ghost" onClick={nextCmd} disabled={currentOpIndex >= opOffsets.length - 1}>next command ⟩</button>
            <input type="range" min="0" max={Math.max(duration, 0.1)} step="0.1"
                   value={Math.min(now, duration)} aria-label="Seek"
                   onChange={(e) => seek(Number(e.target.value))} />
            <span className="mono dim">{fmt(now)} / {fmt(duration)}</span>
            <select aria-label="Playback speed" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
              {SPEEDS.map(s => <option key={s} value={s}>{s}×</option>)}
            </select>
          </div>
          <p className="dim" style={{ fontSize: ".82rem" }}>
            {cast ? `defender cast: ${cast.name || cast.recording_id} · ${cast.frame_count} frames · ${fmt(cast.duration_s)}`
                  : "no defender cast — attacker output plays on the session clock (command-only playback; nothing is invented)"}
            {broken.length > 0 && ` · ${broken.length} unreadable cast: ${broken[0].error}`}
          </p>
          {epochMissing && <p className="bad">selected cast has no epoch header — cross-track alignment disabled</p>}
        </div>
        <div className="panel">
          <h3>attacker output <span className="dim" style={{ fontWeight: 400 }}>(timed capture)</span></h3>
          <div className="term" aria-label="Attacker output">
            {sealed && <div className="chunk-trunc">this match is still sealed — attacker commands
              and output are revealed when it completes</div>}
            {!sealed && attackerLines.length === 0 && <span className="dim">no attacker output up to this point{opOffsets.length ? " — seek forward or step commands" : " — this session has no recorded operations"}.</span>}
            {attackerLines.map((e, i) => (
              <div key={i} className={e.kind === "cmd" ? "cmdline" : e.kind === "gap" ? "chunk-gap" : e.kind === "truncated" ? "chunk-trunc" : ""}>
                {e.text}
              </div>))}
          </div>
          {ops.length === 0 && <p className="dim">no operations recorded.</p>}
        </div>
        {casts.length > 1 && (
          <div className="panel">
            <label>defender cast{" "}
              <select value={selCast} onChange={(e) => setSelCast(Number(e.target.value))}>
                {casts.map((c, i) => <option key={c.recording_id} value={i}>{c.name || c.recording_id}</option>)}
              </select></label>
          </div>
        )}
        <div className="panel">
          <h3>defender terminal</h3>
          {framesErr && <p className="bad">cast fetch failed: {framesErr}</p>}
          {!cast && !framesErr && <p className="dim">no defender recording exists for this session —
            recordings appear when someone defends through the bastion.</p>}
          {cast && !frames && !framesErr && <p className="dim">loading cast frames…</p>}
          <div ref={rootRef} style={{ minHeight: cast ? 100 : 0 }} />
        </div>
      </div>
      <div className="panel" aria-label="Session timeline">
        <h3>session timeline</h3>
        <div className="row" style={{ marginBottom: 8 }}>
          <select aria-label="Actor filter" value={actorF} onChange={(e) => setActorF(e.target.value)}>
            <option value="">any actor</option>
            {["red", "blue", "system", "telemetry", "coach", "member"].map(a => <option key={a}>{a}</option>)}
          </select>
          <select aria-label="Event type filter" value={typeF} onChange={(e) => setTypeF(e.target.value)}>
            <option value="">any type</option>
            {["action_intent", "action_result", "verifier", "detection", "hint", "coach_message", "connection_noise"].map(a => <option key={a}>{a}</option>)}
          </select>
        </div>
        {timeline.map((e) => {
          const off = t0 === null ? null : Date.parse(e.ts) / 1000 - t0;
          const pre = off !== null && off < 0;
          const past = off !== null && off <= now;
          const isNoise = e.action_type === "connection_noise";
          return (
            <div key={`${e.event_id}-${e.collapsed || 0}`}
                 className={`tl-row${past && !pre ? " current" : ""}`}
                 style={{ opacity: past ? 1 : 0.45 }}
                 role="button" tabIndex={0}
                 onKeyDown={(ev) => { if (ev.key === "Enter" && off >= 0) seek(off); }}
                 title={`#${e.event_id}${e.collapsed ? ` (${e.collapsed} events folded)` : ""}`}
                 onClick={() => { if (off !== null && off >= 0) seek(off); }}>
              <span className="tl-off">{off === null ? "—" : pre ? "pre-rec" : fmt(off)}</span>
              <span className={isNoise ? "dim" : e.actor === "red" ? "bad" : (e.actor || "").startsWith("blue") ? "ok" : "dim"}>
                {e.actor} {e.action_type}{e.collapsed ? ` ×${e.collapsed}` : ""} {e.phase || ""}
              </span>
            </div>);
        })}
        {hasMore && <button className="ghost" onClick={loadMore}>load older events →</button>}
        <p className="dim" style={{ fontSize: ".8rem" }}>clicking an event seeks the clock; playback
          never scores anything — the trusted scorecard comes only from verifiers.</p>
      </div>
    </div>
  );
}
