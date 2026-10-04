import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/router";
import { api } from "../../../lib/api";

// asciinema .cast playback scrubbed in sync with the event timeline: the slider
// is the wall-clock offset into the recording; events at/below the cursor are
// highlighted so you can rewatch yourself against what red was doing.
export default function Replay() {
  const router = useRouter();
  const [data, setData] = useState(null);
  const [t, setT] = useState(0);
  const [playing, setPlaying] = useState(false);
  const termRef = useRef(null);
  const rafRef = useRef(null);

  useEffect(() => { if (router.query.id) api(`/sessions/${router.query.id}/replay`).then(setData).catch(() => {}); }, [router.query.id]);

  const cast = data?.casts?.[0];
  const maxT = cast?.frames?.length ? cast.frames[cast.frames.length - 1][0] : 0;

  const screen = useMemo(() => {
    if (!cast) return "";
    let out = "";
    for (const [dt, dir, s] of cast.frames) {
      if (dt > t) break;
      if (dir === "o") out += s;            // show target output; mark input
      else out += `\x1b[33m${s.replace("\n", "")}\x1b[0m`;
    }
    return out;
  }, [cast, t]);

  useEffect(() => {
    if (!playing || !cast) return;
    let last = performance.now(); let cur = t;
    const step = (now) => {
      cur += (now - last) / 1000; last = now;
      if (cur >= maxT) { setPlaying(false); setT(maxT); return; }
      setT(cur); rafRef.current = requestAnimationFrame(step);
    };
    rafRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(rafRef.current);
  }, [playing]);

  useEffect(() => { if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight; }, [screen]);

  if (!data) return <p className="dim">loading replay…</p>;
  if (!cast) return <p className="dim">no .cast recording for this session (defend through the bastion first).</p>;

  const t0 = data.timeline.length ? new Date(data.timeline[0].ts).getTime() : 0;
  return (
    <div className="grid">
      <div className="panel">
        <h2>replay — {cast.name}</h2>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
          <button onClick={() => setPlaying(!playing)}>{playing ? "pause" : "play"}</button>
          <input type="range" min="0" max={maxT} step="0.05" value={t} onChange={(e) => setT(Number(e.target.value))} style={{ flex: 1 }} />
          <span className="dim">{t.toFixed(1)}s / {maxT.toFixed(1)}s</span>
        </div>
        <pre className="cast" ref={termRef}>{screen}</pre>
      </div>
      <div className="panel">
        <h3>event timeline</h3>
        {data.timeline.map((e) => {
          const off = (new Date(e.ts).getTime() - t0) / 1000;
          const active = off <= t;
          return (
            <div key={e.event_id} style={{ opacity: active ? 1 : 0.35, cursor: "pointer" }}
                 onClick={() => setT(Math.max(0, off))}>
              <span className="dim">{off.toFixed(1)}s</span>{" "}
              <span className={e.actor === "red" ? "bad" : e.actor.startsWith("blue") ? "ok" : "dim"}>
                {e.actor} {e.action_type} {e.phase || ""}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
