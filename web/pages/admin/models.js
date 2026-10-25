import { useEffect, useState } from "react";
import { api } from "../../lib/api";

// Operator model administration (plan 19). The provider credential is
// WRITE-ONLY: the create/rotate forms send it once and NO list, job row,
// pin or error message here can ever show it back — the API only ever
// returns masked shapes. Profile edits create NEW versions and demote old
// ones; sessions pin a version for their whole life, so rotation shows up
// as a visible 503 for pinned sessions until an explicit rebind. Every
// model admission (including probes and retries) is a job row: the queue,
// the single running slot, and cancellation are observable here, nowhere
// else.
function isOperator() {
  return typeof window !== "undefined"
    && localStorage.getItem("sr_role") === "operator";
}

export default function AdminModels() {
  const [profiles, setProfiles] = useState([]);
  const [roles, setRoles] = useState({});
  const [jobs, setJobs] = useState([]);
  const [counts, setCounts] = useState({});
  const [err, setErr] = useState(null);
  const [note, setNote] = useState(null);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState({ name: "", base_url: "", model_name: "",
                                       api_key: "", max_completion_tokens: "",
                                       thinking_level: "none",
                                       context_window: "", timeout_s: "" });
  const [rotateFor, setRotateFor] = useState(null);
  const [rotateKey, setRotateKey] = useState("");
  const [rebind, setRebind] = useState({ session_id: "", role: "attacker" });

  const load = () => {
    api("/admin/model/profiles?all_versions=true")
      .then(d => { setProfiles(d.profiles); setRoles(d.roles || {}); })
      .catch(e => setErr(String(e.message || e)));
    api("/admin/model/jobs").then(d => { setJobs(d.jobs); setCounts(d.counts); })
      .catch(e => setErr(String(e.message || e)));
  };
  useEffect(load, []);

  if (!isOperator()) return <p className="bad">operator only</p>;

  const run = async (label, fn) => {
    setBusy(true); setErr(null); setNote(null);
    try { await fn(); setNote(label); load(); }
    catch (e) { setErr(String(e.message || e)); }
    setBusy(false);
  };

  const num = v => (v === "" ? undefined : Number(v));
  const create = () => run("profile created (v1, active)", () =>
    api("/admin/model/profiles", { method: "POST", body: {
      name: draft.name, base_url: draft.base_url, model_name: draft.model_name,
      api_key: draft.api_key,
      thinking_level: draft.thinking_level,
      max_completion_tokens: num(draft.max_completion_tokens),
      context_window: num(draft.context_window),
      timeout_s: num(draft.timeout_s) } })
      .then(() => setDraft({ name: "", base_url: "", model_name: "",
                             api_key: "", max_completion_tokens: "",
                             thinking_level: "none", context_window: "",
                             timeout_s: "" })));

  const rotate = (name) => run("rotated: new version active, old demoted, "
    + "its queued jobs cancelled — pinned sessions need an explicit rebind",
    () => api(`/admin/model/profiles/${name}/revise`, { method: "POST", body: {
      name, model_name: draft.model_name || undefined,
      thinking_level: draft.thinking_level !== "none"
        ? draft.thinking_level : undefined,
      max_completion_tokens: num(draft.max_completion_tokens),
      context_window: num(draft.context_window),
      timeout_s: num(draft.timeout_s),
      api_key: rotateKey || undefined } })
      .then(() => { setRotateFor(null); setRotateKey(""); }));

  const revoke = (p) => run("version revoked; nothing was substituted", () =>
    api(`/admin/model/profiles/${p.profile_id}/revoke`,
        { method: "POST", body: { reason: "revoked from admin panel" } }));

  const probe = (p) => run("probe queued — it admits through the same slot "
    + "as everything else; watch the job list", () =>
    api("/admin/model/probe", { method: "POST",
                                body: { role: "coach", profile_name: p.name } }));

  const setRole = (role, profileName) => run(`role ${role} → ${profileName}`, () =>
    api("/admin/model/roles", { method: "PUT",
                                body: { role, profile_name: profileName } }));

  const cancelJob = (j) => run("cancellation is an obligation: queued dies "
    + "un-run; running keeps the slot until the live call returns", () =>
    api(`/admin/model/jobs/${j.job_id}/cancel`, { method: "POST" }));

  const rebindSession = () => run("session rebound to the role's current "
    + "active version", () =>
    api(`/admin/model/sessions/${rebind.session_id}/rebind`,
        { method: "POST", body: { role: rebind.role } }));

  const active = profiles.filter(p => p.status === "active");
  const running = jobs.filter(j => j.state === "running");
  return (
    <>
      <h2>model administration</h2>
      {err && <p className="bad" data-testid="admin-error">{err}</p>}
      {note && <p className="ok" data-testid="admin-note">{note}</p>}
      <div className="panel">
        <h3>role bindings</h3>
        {["attacker", "coach", "summarizer"].map(role => (
          <p key={role}>
            {role}: <b data-testid={`role-${role}`}>{roles[role] || "—"}</b>{" "}
            <select value={roles[role] || ""} disabled={busy}
                    onChange={e => setRole(role, e.target.value)}>
              <option value="" disabled>select active profile…</option>
              {active.map(p => <option key={p.name} value={p.name}>{p.name}</option>)}
            </select>
          </p>
        ))}
        <p className="dim">overrides live in the database, never in the
          environment; sessions pin the version that served their first use.</p>
      </div>
      <div className="grid">
        <div>
          <div className="panel">
            <h3>profiles (versions are immutable; edits rotate)</h3>
            <table data-testid="profile-table">
              <thead><tr><th>name</th><th>v</th><th>status</th><th>model</th>
                <th>key</th><th></th></tr></thead>
              <tbody>
                {profiles.map(p => (
                  <tr key={p.profile_id}>
                    <td>{p.name}</td>
                    <td>{p.version}</td>
                    <td data-testid={`status-${p.name}-${p.version}`}>{p.status}</td>
                    <td>{p.model_name}</td>
                    <td>{p.api_key_set ? "set" : "—"}</td>
                    <td>
                      {p.status === "active" && (
                        <button disabled={busy} data-testid={`rotate-${p.name}`}
                                onClick={() => setRotateFor(p.name)}>rotate</button>)}
                      {p.status === "active" && (
                        <button disabled={busy} onClick={() => revoke(p)}>revoke</button>)}
                      {p.status === "active" && (
                        <button disabled={busy} onClick={() => probe(p)}>probe</button>)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="dim">the key column proves a credential EXISTS —
              no screen here can ever read one back.</p>
          </div>
          <div className="panel">
            <h3>{rotateFor ? `rotate ${rotateFor}` : "new profile"}</h3>
            <label>name <input data-testid="field-name" value={rotateFor || draft.name}
              disabled={!!rotateFor}
              onChange={e => setDraft({ ...draft, name: e.target.value })} /></label>
            {!rotateFor && (<>
              <label>base URL <input value={draft.base_url}
                onChange={e => setDraft({ ...draft, base_url: e.target.value })} /></label>
              <label>max completion tokens <input value={draft.max_completion_tokens}
                onChange={e => setDraft({ ...draft, max_completion_tokens: e.target.value })} /></label>
            </>)}
            <label>model name <input data-testid="field-model" value={draft.model_name}
              onChange={e => setDraft({ ...draft, model_name: e.target.value })} /></label>
            <label>api key {rotateFor ? "(empty keeps current)" : ""}
              <input type="password" data-testid="field-key"
                value={rotateFor ? rotateKey : draft.api_key}
                onChange={e => rotateFor ? setRotateKey(e.target.value)
                  : setDraft({ ...draft, api_key: e.target.value })} /></label>
            <details>
              <summary>advanced (pinned per version)</summary>
              <label>thinking level
                <select value={draft.thinking_level}
                        onChange={e => setDraft({ ...draft, thinking_level: e.target.value })}>
                  {["none", "low", "medium", "high"].map(l =>
                    <option key={l}>{l}</option>)}
                </select></label>
              <label>context window <input data-testid="field-context"
                placeholder="262144" value={draft.context_window}
                onChange={e => setDraft({ ...draft, context_window: e.target.value })} /></label>
              <label>max completion tokens <input
                placeholder="32768 (incl. thinking)"
                value={draft.max_completion_tokens}
                onChange={e => setDraft({ ...draft, max_completion_tokens: e.target.value })} /></label>
              <label>timeout (s, ≤ 900) <input placeholder="900"
                value={draft.timeout_s}
                onChange={e => setDraft({ ...draft, timeout_s: e.target.value })} /></label>
              <p className="dim">generation kwargs are allowlisted server-side
                (temperature/top_p/penalties only); messages, tools, auth and
                destinations can never be overridden by a profile.</p>
            </details>
            {rotateFor
              ? <button disabled={busy} data-testid="rotate-confirm"
                        onClick={() => rotate(rotateFor)}>rotate (new version)</button>
              : <button disabled={busy} data-testid="create-profile"
                        onClick={create}>create profile</button>}
          </div>
          <div className="panel">
            <h3>rebind a session after rotation/revocation</h3>
            <p className="dim">the only way a pinned session continues on
              models — an explicit, audited operator act.</p>
            <label>session <input data-testid="field-session" value={rebind.session_id}
              onChange={e => setRebind({ ...rebind, session_id: e.target.value })} /></label>
            <label>role
              <select value={rebind.role}
                      onChange={e => setRebind({ ...rebind, role: e.target.value })}>
                {["attacker", "coach", "summarizer"].map(r =>
                  <option key={r}>{r}</option>)}
              </select></label>
            <button disabled={busy || !rebind.session_id}
                    data-testid="rebind-confirm" onClick={rebindSession}>rebind</button>
          </div>
        </div>
        <div>
          <div className="panel">
            <h3>model jobs — one slot, durable queue</h3>
            <p className="dim" data-testid="job-counts">
              {Object.entries(counts).map(([k, v]) => `${k}: ${v}`).join(" · ")
                || "no jobs yet"}
            </p>
            {running.length > 1 &&
              <p className="bad">the database forbids more than one RUNNING row</p>}
            <ul>
              {jobs.slice(0, 25).map(j => (
                <li key={j.job_id} data-testid={`job-${j.kind}-${j.state}`}>
                  <b>{j.kind}</b> · {j.state} · p{j.priority} · a{j.attempt}
                  {j.profile_name ? ` · ${j.profile_name}` : ""}
                  {j.cancel_requested ? " · cessation requested" : ""}
                  {j.error ? ` — ${String(j.error).slice(0, 120)}` : ""}{" "}
                  {(j.state === "queued" || j.state === "running") &&
                    <button disabled={busy} data-testid="cancel-job"
                            onClick={() => cancelJob(j)}>cancel</button>}
                </li>
              ))}
            </ul>
            <button onClick={load}>refresh</button>
          </div>
        </div>
      </div>
    </>
  );
}
