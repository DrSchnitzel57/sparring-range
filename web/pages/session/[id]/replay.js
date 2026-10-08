import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/router";
import { api } from "../../../lib/api";

// Real terminal playback via the maintained asciinema-player, with the event
// timeline aligned on the RECORDING's epoch (header.timestamp) — F17. Selecting
// a different recording re-anchors everything.
export default function Replay() {
  const router = useRouter();
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [sel, setSel] = useState(0);
  const [now, setNow] = useState(0);
  const [duration, setDuration] = useState(0);
  // last seek is observable (data-seek-at): the player instance lives in a
  // ref, and a browser test must assert the REAL seek happened
  const [seekAt, setSeekAt] = useState(null);
  const rootRef = useRef(null);
  const playerRef = useRef(null);

  const sid = router.query.id;
  useEffect(() => {
    if (!sid) return;
    api(`/sessions/${sid}/replay`).then(setData).catch(e => setErr(String(e.message || e)));
  }, [sid]);

  const casts = useMemo(() => (data?.casts || []).filter(c => !c.error), [data]);
  const broken = (data?.casts || []).filter(c => c.error);
  const cast = casts[sel];

  // rebuild a .cast stream and feed it to asciinema-player (browser-only)
  useEffect(() => {
    if (!cast || !rootRef.current) return;
    let cancelled = false;
    const lines = [JSON.stringify(cast.header)]
      .concat(cast.frames.map(f => JSON.stringify(f)));
    const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "application/octet-stream" }));
    import("asciinema-player").then((mod) => {
      if (cancelled || !rootRef.current) return;
      const A = mod.default ?? mod;
      playerRef.current = A.create(url, rootRef.current, { autoPlay: false, loop: false, terminalName: "xterm-256color" });
      playerRef.current.addEventListener?.("played", () => {});
      const t = setInterval(() => {
        if (playerRef.current?.getCurrentTime) setNow(playerRef.current.getCurrentTime());
        if (playerRef.current?.getDuration) setDuration(playerRef.current.getDuration());
      }, 250);
      playerRef.current._timer = t;
    });
    return () => {
      cancelled = true;
      if (playerRef.current) {
        clearInterval(playerRef.current._timer);
        try { playerRef.current.pause(); } catch {}
      }
      if (rootRef.current) rootRef.current.innerHTML = "";
      URL.revokeObjectURL(url);
    };
  }, [cast]);

  if (err) return <p className="bad">{err}</p>;
  if (!data) return <p className="dim">loading replay…</p>;
  if (casts.length === 0)
    return <p className="dim">no playable recording for this session yet — defend through the
      bastion first{broken.length ? ` (${broken.length} unreadable: ${broken[0].error})` : ""}.</p>;

  // event offsets are relative to THIS recording's epoch anchor
  const epoch = cast.header?.timestamp;
  const offsetOf = (iso) => (epoch ? (new Date(iso).getTime() / 1000) - epoch : null);

  return (
    <div className="grid">
      <div className="panel">
        <h2>replay</h2>
        {casts.length > 1 && (
          <select value={sel} onChange={(e) => setSel(Number(e.target.value))} style={{ marginBottom: 8 }}>
            {casts.map((c, i) => <option key={c.recording_id} value={i}>{c.name || c.recording_id}</option>)}
          </select>
        )}
        <div ref={rootRef} style={{ minHeight: 100 }} />
        {!epoch && <p className="bad">recording has no epoch header — timeline alignment disabled</p>}
      </div>
      <div className="panel" data-seek-at={seekAt === null ? "" : String(seekAt)}
           data-now={String(now)}>
        <h3>event timeline</h3>
        {data.timeline.map((e) => {
          const off = offsetOf(e.ts);
          const active = off !== null && off >= 0 && off <= now;
          return (
            <div key={e.event_id}
                 style={{ opacity: off === null ? 0.5 : (active ? 1 : 0.35), cursor: off >= 0 ? "pointer" : "default" }}
                 title={`#${e.event_id}`}
                 onClick={() => { if (off >= 0) { playerRef.current?.seek(off); setSeekAt(off); } }}>
              <span className="dim">{off === null ? "—" : (off >= 0 ? `${off.toFixed(1)}s` : "pre-rec")}</span>{" "}
              <span className={e.actor === "red" ? "bad" : (e.actor || "").startsWith("blue") ? "ok" : "dim"}>
                {e.actor} {e.action_type} {e.phase || ""}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
