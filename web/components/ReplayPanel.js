import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";

// Synchronized review (plan 20; review findings 4/10/11). Attacker command
// output (timed chunks) and the defender's recorded cast play on ONE session
// clock with play/pause/seek/speed and previous/next command.
//
// Bounded by construction (finding 11): the page loads ONE timeline page, ONE
// cast page and ONE operation page — never the whole audit. Further data is
// pulled by SERVER cursors only when the clock actually needs it (operations
// pages ahead of the playhead, per-operation chunk pages as its command
// approaches, timeline pages on explicit request). A collapsed noise run
// advances by the server's RAW consumed cursor, so paging can never stall or
// re-consume.
//
// Clock honesty (findings 4/10): the defender player's own clock is relative
// to the CAST epoch, the master clock to the session start — the two differ
// by exactly (cast_epoch - session_t0), and every player seek/drift-correction
// applies that offset instead of assuming they coincide. Chunk placement uses
// the observed pipe read time (read_ts) when recorded; persist time is only
// the fallback, and it says so. Missing/corrupt casts, chunk gaps, quota
// truncation, and incomplete (orphan/intent-only) operations stay honestly
// labeled — nothing is invented.
const SPEEDS = [0.5, 1, 2, 4, 8];
const OPS_LOOKAHEAD = 30;    // s of operation pages kept ahead of the playhead
const CHUNK_LOOKAHEAD = 3;   // s before a command its output starts loading

function fmt(s) {
  if (s === null || s === undefined || Number.isNaN(s)) return "—";
  const neg = s < 0; const x = Math.abs(s);
  const m = Math.floor(x / 60), r = Math.floor(x % 60);
  return `${neg ? "-" : ""}${String(m).padStart(2, "0")}:${String(r).padStart(2, "0")}`;
}

const parseTs = (iso) => (iso ? Date.parse(iso) / 1000 : null);

// absolute position of an operation on the wall clock: intent time, else the
// result time (an honest orphan only HAS a result time — finding 6)
const opAbs = (o) => parseTs(o.ts) ?? parseTs(o.end_ts);

// merge one operations page into the by-op_uuid map: the server groups within
// a bounded event window, so an operation whose intent and result straddle a
// page boundary arrives twice and must be united client-side (the page-local
// "orphan" half is a paging artifact, not history).
function mergeOpsPage(map, page) {
  for (const op of page.operations || []) {
    const prev = map.get(op.op_uuid);
    if (!prev) { map.set(op.op_uuid, op); continue; }
    const m = { ...prev };
    if (m.command == null && op.command != null) m.command = op.command;
    if (m.ts == null && op.ts != null) { m.ts = op.ts; m.intent_event_id = op.intent_event_id; }
    if (op.duplicate_intent_event_ids)
      m.duplicate_intent_event_ids = [...new Set([...(m.duplicate_intent_event_ids || []),
        ...op.duplicate_intent_event_ids])];
    if (op.result_event_id != null) {
      m.result_event_id = op.result_event_id; m.end_ts = op.end_ts;
      m.exit_code = op.exit_code; m.timed_out = op.timed_out;
      m.cancel_state = op.cancel_state; m.capture = op.capture;
    }
    m.has_output = !!(m.has_output || op.has_output);
    m.registered = op.registered ?? m.registered;
    m.incomplete = !(m.intent_event_id != null && m.result_event_id != null);
    m.orphan_result = m.intent_event_id == null && !!(prev.orphan_result || op.orphan_result);
    map.set(op.op_uuid, m);
  }
}

export default function ReplayPanel({ sid }) {
  const [data, setData] = useState(null);            // replay page meta
  const [err, setErr] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [tlNext, setTlNext] = useState(null);        // raw server cursor
  const [casts, setCasts] = useState([]);
  const [castsNext, setCastsNext] = useState(null);
  const [ops, setOps] = useState([]);
  const [opsNext, setOpsNext] = useState(null);      // null = exhausted
  const [opsLoadedOnce, setOpsLoadedOnce] = useState(false);
  const [chunkRows, setChunkRows] = useState(null);  // [{at, kind, text, op...}]
  const [chunksFetched, setChunksFetched] = useState(0);
  const [selCast, setSelCast] = useState(0);
  const [frames, setFrames] = useState(null);        // selected cast frames
  const [framesErr, setFramesErr] = useState(null);
  const [actorF, setActorF] = useState("");
  const [typeF, setTypeF] = useState("");
  const [now, setNow] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [seekAt, setSeekAt] = useState(null);
  const [playerErr, setPlayerErr] = useState(null);
  const [playerAt, setPlayerAt] = useState(null);
  const rootRef = useRef(null);
  const playerRef = useRef(null);
  const clockRef = useRef({ t: 0, last: null, speed: 1, dur: 0 });

  // pump coordination — generation object stops every in-flight loop when the
  // session view resets; cursor/flag refs keep loops out of render state
  const genRef = useRef({ stopped: true });
  const opsMapRef = useRef(new Map());
  const opsNextRef = useRef(null);
  const opsTargetRef = useRef(null);
  const opsPumpingRef = useRef(false);
  const opsRetryRef = useRef(false);
  const chunkOpsRef = useRef(new Set());             // op_uuids fully fetched
  const chunkPumpingRef = useRef(false);
  const chunkRetryRef = useRef(false);
  const sealedRef = useRef(false);
  const tlInitRef = useRef(false);
  const clockT0Ref = useRef(null);
  const horizonRef = useRef(null);                   // max op abs ts loaded
  const clockResolvedRef = useRef(false);

  const castsOk = useMemo(() => (casts || []).filter(c => !c.error), [casts]);
  const broken = (casts || []).filter(c => c.error);
  const cast = castsOk[selCast];
  const sealed = !!data?.sealed;

  const epoch = cast?.header?.timestamp || null;
  // ---- operations horizon pump (finding 11: load pages, never all) -------
  const pumpOps = useCallback(async (uptoAbs) => {
    const gen = genRef.current;
    if (uptoAbs != null) opsTargetRef.current = Math.max(opsTargetRef.current ?? 0, uptoAbs);
    if (opsPumpingRef.current) { opsRetryRef.current = true; return; }
    opsPumpingRef.current = true;
    try {
      do {
        opsRetryRef.current = false;
        while (!gen.stopped && opsNextRef.current !== null) {
          const target = opsTargetRef.current;
          const loaded = [...opsMapRef.current.values()];
          const horizon = loaded.length
            ? Math.max(...loaded.map(o => parseTs(o.end_ts) ?? parseTs(o.ts) ?? -Infinity), -Infinity)
            : -Infinity;
          if (target == null || horizon >= target) break;
          const after = opsNextRef.current;
          const r = await api(`/sessions/${sid}/operations?after_event_id=${after}&limit=100`);
          if (gen.stopped) return;
          mergeOpsPage(opsMapRef.current, r);
          setOps([...opsMapRef.current.values()]);
          opsNextRef.current = r.has_more ? r.next_after_event_id : null;
          setOpsNext(opsNextRef.current);
          // a non-advancing raw cursor would be a server bug; refuse to spin
          if (r.has_more && (r.next_after_event_id == null || r.next_after_event_id <= after)) break;
        }
      } while (!gen.stopped && opsRetryRef.current && opsNextRef.current !== null);
    } catch (e) { if (!gen.stopped) setErr(String(e.message || e)); }
    opsPumpingRef.current = false;
  }, [sid]);

  // ---- per-operation chunk pump (finding 11: lazy per-op, all pages) -----
  const pumpChunks = useCallback(async () => {
    const gen = genRef.current;
    if (sealedRef.current) return;
    if (chunkPumpingRef.current) { chunkRetryRef.current = true; return; }
    chunkPumpingRef.current = true;
    try {
      for (;;) {
        if (gen.stopped) return;
        const t0 = clockT0Ref.current;
        const nowT = clockRef.current.t;
        const due = [...opsMapRef.current.values()].find(o =>
          o.has_output && !chunkOpsRef.current.has(o.op_uuid) &&
          // t0 unknown means the clock is not resolvable yet — that is NOT
          // a license to bulk-fetch everything; wait for a real position
          t0 !== null && (opAbs(o) === null ||
                          opAbs(o) - t0 <= nowT + CHUNK_LOOKAHEAD));
        if (!due) break;
        const rows = [];
        let after = null;
        for (;;) {
          const r = await api(`/sessions/${sid}/operations/${due.op_uuid}/output`
            + (after !== null ? `?after_seq=${after}&limit=200` : "?limit=200"));
          if (gen.stopped) return;
          for (const c of r.chunks) {
            // finding 10: place output at the observed read time; persist ts
            // is only the fallback for rows captured before read timing.
            const at = c.read_ts ?? parseTs(c.ts);
            rows.push({ ...c, at, op_uuid: due.op_uuid, cmd: due.command });
          }
          if (!r.hidden && !r.has_more) break;
          if (r.hidden || r.next_after_seq == null) break;
          after = r.next_after_seq;
        }
        chunkOpsRef.current.add(due.op_uuid);
        setChunksFetched(chunkOpsRef.current.size);
        if (rows.length) setChunkRows(prev => (prev || []).concat(rows));
      }
    } catch (e) { if (!gen.stopped) setErr(String(e.message || e)); }
    chunkPumpingRef.current = false;
    if (chunkRetryRef.current) { chunkRetryRef.current = false; void pumpChunks(); }
  }, [sid]);

  // ---- initial load: exactly ONE page of each track ----------------------
  useEffect(() => {
    if (!sid) return;
    genRef.current = { stopped: false };
    const gen = genRef.current;
    tlInitRef.current = false;   // filters effect must not re-fetch page 0 on this load
    opsMapRef.current = new Map();
    chunkOpsRef.current = new Set();
    opsNextRef.current = null; opsTargetRef.current = null;
    setOps([]); setOpsNext(null); setOpsLoadedOnce(false);
    setChunkRows(null); setChunksFetched(0);
    setTimeline([]); setTlNext(null); setCasts([]); setCastsNext(null);
    setSelCast(0); setFrames(null); setFramesErr(null); setPlayerAt(null);
    clockResolvedRef.current = false;
    clockRef.current.t = 0; setNow(0); setSeekAt(null); setErr(null);
    (async () => {
      try {
        const [d, c, o] = await Promise.all([
          api(`/sessions/${sid}/replay?limit=200`),
          api(`/sessions/${sid}/casts?limit=20`),
          api(`/sessions/${sid}/operations?limit=100`),
        ]);
        if (gen.stopped) return;
        setData(d);
        sealedRef.current = !!d.sealed;
        setTimeline(d.timeline);
        setTlNext(d.has_more ? d.next_after_event_id : null);
        setCasts(c.casts);
        setCastsNext(c.has_more ? c.next_after : null);
        mergeOpsPage(opsMapRef.current, o);
        setOps([...opsMapRef.current.values()]);
        setOpsLoadedOnce(true);
        opsNextRef.current = o.hidden ? null : (o.has_more ? o.next_after_event_id : null);
        setOpsNext(opsNextRef.current);
        if (!o.hidden) {
          await pumpOps(null);
          await pumpChunks();
          if (!gen.stopped) setChunkRows(prev => prev ?? []);
        } else setChunkRows([]);
      } catch (e) { if (!gen.stopped) setErr(String(e.message || e)); }
    })();
    return () => { gen.stopped = true; };
  }, [sid, pumpOps, pumpChunks]);

  // ---- timeline paging (server RAW cursor; filters re-page only that) ----
  const loadTimelinePage = useCallback(async (after) => {
    const q = new URLSearchParams({ limit: "200" });
    if (after) q.set("after_event_id", String(after));
    if (actorF) q.set("actor", actorF);
    if (typeF) q.set("action_type", typeF);
    return api(`/sessions/${sid}/replay?${q.toString()}`);
  }, [sid, actorF, typeF]);

  useEffect(() => {   // (re)page the timeline when filters change
    if (!sid) return;
    if (!tlInitRef.current) { tlInitRef.current = true; return; }  // initial page already loaded above
    const gen = genRef.current;
    (async () => {
      try {
        const d = await loadTimelinePage(0);
        if (gen.stopped) return;
        setTimeline(d.timeline);
        setTlNext(d.has_more ? d.next_after_event_id : null);
      } catch (e) { if (!gen.stopped) setErr(String(e.message || e)); }
    })();
  }, [loadTimelinePage]);  // eslint-disable-line react-hooks/exhaustive-deps

  const loadMore = async () => {
    if (tlNext === null) return;
    const d = await loadTimelinePage(tlNext);
    setTimeline(tl => tl.concat(d.timeline));
    setTlNext(d.has_more ? d.next_after_event_id : null);
  };

  const loadMoreCasts = async () => {
    if (castsNext === null) return;
    const c = await api(`/sessions/${sid}/casts?after=${castsNext}&limit=20`);
    setCasts(prev => prev.concat(c.casts));
    setCastsNext(c.has_more ? c.next_after : null);
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

  // ---- the session clock --------------------------------------------------
  // F6: the anchor is the SERVER's canonical session_t0 (the session's first
  // event, unfiltered) — never a client-side min() over whatever the current
  // actor/type filters happen to show, which used to shift the cast offset
  // mid-view. Only when the server gives no anchor (old deployments) does
  // the clock fall back to the earliest observed stamp (attacker-only
  // playback stays honest playback, not a fake cast).
  const { t0, duration } = useMemo(() => {
    const canon = data?.session_t0 ? Date.parse(data.session_t0) / 1000 : null;
    const stamps = [];
    if (epoch) stamps.push(epoch);
    ops.forEach(o => { if (o.ts) stamps.push(Date.parse(o.ts) / 1000);
                       if (o.end_ts) stamps.push(Date.parse(o.end_ts) / 1000); });
    (chunkRows || []).forEach(c => { if (c.at != null) stamps.push(c.at); });
    timeline.forEach(e => stamps.push(Date.parse(e.ts) / 1000));
    if (canon === null && !stamps.length) return { t0: null, duration: 0 };
    const start = canon !== null ? canon : Math.min(...stamps);
    const end = Math.max(...(canon === null ? stamps : [...stamps, canon])) + 5;
    let dur = Math.max(1, end - start);
    if (epoch && cast?.duration_s) dur = Math.max(dur, cast.duration_s + (epoch - start));
    return { t0: start, duration: dur };
  }, [data?.session_t0, epoch, cast, ops, chunkRows, timeline]);
  clockT0Ref.current = t0;

  // once the clock resolves, the lookahead window at t=0 must load promptly
  // (still only the due operations — never a bulk fetch)
  useEffect(() => {
    if (t0 === null) { clockResolvedRef.current = false; return; }
    if (!clockResolvedRef.current) {
      clockResolvedRef.current = true;
      void pumpChunks();
    }
  }, [t0, pumpChunks]);

  // the player's ZERO sits at the cast epoch, the master clock's at t0; the
  // difference is exactly this offset (finding 4) — never assume it is zero.
  const castRel = epoch && t0 !== null ? epoch - t0 : 0;
  const castRelRef = useRef(0);
  useEffect(() => { castRelRef.current = castRel; }, [castRel]);

  const dataFinal = opsNext === null && tlNext === null;

  const readPlayerAt = useCallback(() => {
    const p = playerRef.current;
    if (!p?.getCurrentTime) return;
    try {
      const v = Math.round(p.getCurrentTime() * 10) / 10;
      setPlayerAt(prev => (prev === v ? prev : v));
    } catch { /* player not ready yet */ }
  }, []);

  const seek = useCallback((t) => {
    // with more data still unloaded the known duration is NOT a ceiling —
    // clamping here would hide events the server has already counted
    const bounded = dataFinal ? Math.min(t, clockRef.current.dur || t) : t;
    const c = Math.max(0, bounded);
    clockRef.current.t = c;
    setSeekAt(Math.round(c * 10) / 10);
    setNow(c);
    const p = playerRef.current;
    const playerT = c - castRelRef.current;
    if (p?.seek) {
      try {
        // F6: seeking back before the cast START must not leave the player
        // frozen on its last in-cast frame — the documented contract is
        // "before the epoch the player holds frame zero".
        if (playerT >= 0) p.seek(playerT);
        else if (p.getCurrentTime && p.getCurrentTime() > 0) p.seek(0);
      } catch { /* surfaced below */ }
    }
    readPlayerAt();
    if (t0 !== null) void pumpOps(t0 + c + OPS_LOOKAHEAD / 2);
    void pumpChunks();
  }, [dataFinal, t0, pumpOps, pumpChunks, readPlayerAt]);

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
        if (c.t >= c.dur && dataFinal) { c.t = c.dur; setNow(c.t); setPlaying(false); return; }
        setNow(c.t);
        readPlayerAt();
        // defender follows the master clock when it drifts — in PLAYER time
        const p = playerRef.current;
        if (p?.getCurrentTime && p?.seek) {
          const target = c.t - castRelRef.current;
          try {
            if (target >= 0) {
              const dt = p.getCurrentTime();
              if (Math.abs(dt - target) > 0.4) p.seek(target);
            } else if (p.getCurrentTime() > 0) {
              // F6: before the cast epoch the player HOLDS FRAME ZERO —
              // it follows the session clock instead of freezing wherever
              // the last in-cast frame left it.
              p.seek(0);
            }
          } catch { /* player not ready yet */ }
        }
        if (t0 !== null && c.t > (horizonRef.current ?? 0) - OPS_LOOKAHEAD)
          void pumpOps(t0 + c + OPS_LOOKAHEAD);
        void pumpChunks();
      }
      c.last = ms;
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => { cancelAnimationFrame(raf); clockRef.current.last = null; };
  }, [playing, dataFinal, t0, pumpOps, pumpChunks, readPlayerAt]);

  useEffect(() => {
    const abs = ops.map(opAbs).filter(v => v != null);
    horizonRef.current = abs.length ? Math.max(...abs) : null;
  }, [ops]);

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

  // pause the real player with the master clock; before the cast epoch the
  // player holds frame zero — the session clock runs, the cast does not
  const inCastNow = now >= castRel - 0.05;
  useEffect(() => {
    const p = playerRef.current;
    if (!p) return;
    try { playing && inCastNow ? p.play() : p.pause(); } catch { /* not loaded */ }
  }, [playing, frames, inCastNow]);

  // ---- attacker pane: entries up to the current second -------------------
  const attackerLines = useMemo(() => {
    if (t0 === null) return [];
    const evs = [];
    ops.forEach(o => {
      const a = opAbs(o);
      if (a === null) return;
      if (o.command) evs.push({ at: a - t0, kind: "cmd", text: `$ ${o.command}`, op: o.op_uuid });
      else if (o.incomplete)
        evs.push({ at: a - t0, kind: "gap", op: o.op_uuid,
                   text: `[incomplete operation ${o.op_uuid} — ${o.orphan_result
                     ? "result without any recorded command start"
                     : "no command recorded"}]` });
    });
    (chunkRows || []).forEach(c => {
      if (c.at == null) return;
      evs.push({ at: c.at - t0, kind: c.kind === "output" ? "out" : c.kind,
                 text: c.text || (c.kind === "gap" ? `[capture gap${c.dropped_bytes ? `: ${c.dropped_bytes} bytes dropped` : ""}]`
                                                  : "[output truncated at quota]") });
    });
    evs.sort((a, b) => a.at - b.at);
    return evs.filter(e => e.at <= now);
  }, [ops, chunkRows, t0, now]);

  const opOffsets = useMemo(
    () => ops.filter(o => opAbs(o) !== null).map(o => ({ ...o, off: opAbs(o) - t0 }))
             .sort((a, b) => a.off - b.off),
    [ops, t0]);

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

  const epochMissing = castsOk.length > 0 && !epoch;
  const mode = cast ? "cast+commands" : "commands-only";

  return (
    <div className="grid" onKeyDown={onKeyDown} tabIndex={0} role="region"
         aria-label="Replay player"
         data-now={String(Math.round(now * 10) / 10)}
         data-duration={String(Math.round(duration * 10) / 10)}
         data-duration-final={String(dataFinal)}
         data-playing={String(playing)} data-speed={String(speed)}
         data-seek-at={seekAt === null ? "" : String(seekAt)}
         data-player-at={playerAt === null ? "" : String(playerAt)}
         data-mode={mode} data-ops={String(opOffsets.length)}
         data-ops-loaded={String(ops.length)}
         data-ops-ready={String(opsLoadedOnce)}
         data-ops-more={String(opsNext !== null)}
         data-chunks-ops={String(chunksFetched)}
         data-chunks-ready={String(chunkRows !== null)}
         data-casts-loaded={String(casts.length)}
         data-casts-more={String(castsNext !== null)}
         data-cast-offset={String(Math.round(castRel * 10) / 10)}
         data-tl-next={tlNext === null ? "" : String(tlNext)}
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
            <span className="mono dim">{fmt(now)} / {fmt(duration)}{dataFinal ? "" : " +"}</span>
            <select aria-label="Playback speed" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
              {SPEEDS.map(s => <option key={s} value={s}>{s}×</option>)}
            </select>
          </div>
          <p className="dim" style={{ fontSize: ".82rem" }}>
            {cast ? `defender cast: ${cast.name || cast.recording_id} · ${cast.frame_count} frames · ${fmt(cast.duration_s)}`
                  : "no defender cast — attacker output plays on the session clock (command-only playback; nothing is invented)"}
            {broken.length > 0 && ` · ${broken.length} unreadable cast: ${broken[0].error}`}
            {data.casts_total > casts.length && ` · ${data.casts_total - casts.length} more cast(s) not loaded`}
            {cast && Math.round(castRel) > 0 && ` · cast starts ${Math.round(castRel)}s after the session clock begins`}
          </p>
          {epochMissing && <p className="bad">selected cast has no epoch header — cross-track alignment disabled</p>}
          {(chunkRows || []).length > 0 &&
            <p className="dim" data-testid="timing-provenance" style={{ fontSize: ".82rem" }}>
              attacker timing: {(chunkRows || []).some(c => c.read_ts != null)
                ? "WORKER-CLAIMED pipe-read time (advisory: window-bounded at ingest, not server-verified)"
                : "server persist time (fallback — coarser than the capture)"}
            </p>}
          {(opsNext !== null || ops.some(o => o.has_output)) &&
            <p className="dim" style={{ fontSize: ".82rem" }}>output loads as the clock reaches each command (bounded pages; nothing bulk-downloaded).</p>}
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
          {ops.length === 0 && data.operations_total > 0 &&
            <p className="dim">operations exist but none fall in the loaded page.</p>}
          {ops.length === 0 && data.operations_total === 0 && <p className="dim">no operations recorded.</p>}
        </div>
        {(castsOk.length > 1 || castsNext !== null) && (
          <div className="panel">
            <label>defender cast{" "}
              <select value={selCast} onChange={(e) => setSelCast(Number(e.target.value))}>
                {castsOk.map((c, i) => <option key={c.recording_id} value={i}>{c.name || c.recording_id}</option>)}
              </select></label>
            {castsNext !== null &&
              <button className="ghost" onClick={loadMoreCasts}>load more casts →</button>}
          </div>
        )}
        <div className="panel">
          <h3>defender terminal</h3>
          <div data-player-slot className="player-slot">
            {framesErr && <p className="bad">cast fetch failed: {framesErr}</p>}
            {!cast && !framesErr && <p className="dim">no defender recording exists for this session —
              recordings appear when someone defends through the bastion.</p>}
            {cast && !frames && !framesErr && <p className="dim">loading cast frames…</p>}
            <div ref={rootRef} style={{ minHeight: cast ? 100 : 0 }} />
          </div>
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
            <div key={`${e.first_event_id ?? e.event_id}-${e.collapsed || 0}`}
                 className={`tl-row${past && !pre ? " current" : ""}`}
                 style={{ opacity: past ? 1 : 0.45 }}
                 role="button" tabIndex={0}
                 data-off={off === null ? "" : String(Math.round(off * 10) / 10)}
                 onKeyDown={(ev) => { if (ev.key === "Enter" && off >= 0) seek(off); }}
                 title={`#${e.event_id}${e.collapsed ? ` (${e.collapsed} events folded)` : ""}`}
                 onClick={() => { if (off !== null && off >= 0) seek(off); }}>
              <span className="tl-off">{off === null ? "—" : pre ? "pre-rec" : fmt(off)}</span>
              <span className={isNoise ? "dim" : e.actor === "red" ? "bad" : (e.actor || "").startsWith("blue") ? "ok" : "dim"}>
                {e.actor} {e.action_type}{e.collapsed ? ` ×${e.collapsed}` : ""} {e.phase || ""}
              </span>
            </div>);
        })}
        {tlNext !== null && <button className="ghost" onClick={loadMore}>load older events →</button>}
        <p className="dim" style={{ fontSize: ".8rem" }}>clicking an event seeks the clock; playback
          never scores anything — the trusted scorecard comes only from verifiers.</p>
      </div>
    </div>
  );
}
