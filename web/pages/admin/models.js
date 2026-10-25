import { useEffect, useState } from "react";
import { api } from "../../lib/api";

// Operator model administration (plan 19, review round). The provider
// credential is WRITE-ONLY and DB-role-isolated (secret store): the list
// shows set / — / unknown — presence as far as the APP role knows, never
// the value. Profile edits create NEW versions; a NON-secret edit marks
// the old one SUPERSEDED (pinned sessions keep running), a key
// replacement REVOKES EVERY version carrying the replaced credential
// (pinned sessions fail visibly until an explicit rebind). The thinking
// wire preset declares HOW levels encode (none disables via the
// chat-template toggle, graded levels send distinct reasoning_effort);
// Custom thinking levels must DECLARE how they reach the wire — the form
// only offers the two permitted request fields (reasoning_effort,
// chat_template_kwargs); anything else is refused server-side. Cessation
// obligations (state cessation_unknown) hold the single admission slot
// until a bounded, audited operator resolution releases them.
function isOperator() {
  return typeof window !== "undefined"
    && localStorage.getItem("sr_role") === "operator";
}

const STD_LEVELS = ["none", "low", "medium", "high"];
const EFFORTS = ["minimal", "low", "medium", "high", "xhigh", "none"];
// Known thinking-encoding presets (server THINKING_PRESETS). The preset
// decides HOW a level reaches the wire (distinct field values, verified
// per level); an unknown name is refused before any request.
const WIRE_PRESETS = ["", "llama.cpp"];
const emptyDraft = { name: "", base_url: "", model_name: "", api_key: "",
                     max_completion_tokens: "", thinking_level: "none",
                     wire_preset: "",
                     custom_level: "", custom_effort: "", custom_kwargs: "",
                     context_window: "", timeout_s: "",
                     compaction_ratio: "" };

export default function AdminModels() {
  const [profiles, setProfiles] = useState([]);
  const [roles, setRoles] = useState({});
  const [jobs, setJobs] = useState([]);
  const [counts, setCounts] = useState({});
  const [err, setErr] = useState(null);
  const [note, setNote] = useState(null);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState(emptyDraft);
  const [rotateFor, setRotateFor] = useState(null);
  const [rotateKey, setRotateKey] = useState("");
  const [rebind, setRebind] = useState({ session_id: "", role: "attacker" });
  const [discover, setDiscover] = useState(null);
  const [resolveJob, setResolveJob] = useState(null);
  const [resolveText, setResolveText] = useState("");

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

  // Build the thinking fields: standard levels need no map; a custom
  // level ships an EXPLICIT request-field mapping (validated server-side
  // — an unmappable level is a configuration error, never a silent no-op).
  const thinkingFields = () => {
    if (draft.thinking_level !== "custom…") {
      return { thinking_level: draft.thinking_level,
               thinking_map: undefined };
    }
    const level = (draft.custom_level || "").trim();
    const target = {};
    if (draft.custom_effort) target.reasoning_effort = draft.custom_effort;
    if (draft.custom_kwargs.trim()) {
      // may throw → the caller surfaces it as a visible error
      target.chat_template_kwargs = JSON.parse(draft.custom_kwargs);
    }
    if (!level || Object.keys(target).length === 0) {
      throw new Error("a custom thinking level needs a name AND a mapping "
        + "(reasoning_effort and/or chat_template_kwargs) — an unencodable "
        + "level is refused, never silently ignored");
    }
    return { thinking_level: level, thinking_map: { [level]: target } };
  };

  const create = () => run("profile created (v1, active)", () => {
    const thinking = thinkingFields();
    return api("/admin/model/profiles", { method: "POST", body: {
      name: draft.name, base_url: draft.base_url, model_name: draft.model_name,
      api_key: draft.api_key,
      ...thinking,
      ...(draft.wire_preset
          ? { capabilities: { thinking: { wire_preset: draft.wire_preset } } }
          : {}),
      max_completion_tokens: num(draft.max_completion_tokens),
      context_window: num(draft.context_window),
      compaction_ratio: num(draft.compaction_ratio),
      timeout_s: num(draft.timeout_s) } })
      .then(() => setDraft(emptyDraft));
  });

  const rotate = (name) => run(rotateKey
    ? "credential REPLACED: every version carrying the replaced credential "
      + "is revoked (queued jobs cancelled, running ones asked to cease); "
      + "pinned sessions fail visibly until an explicit rebind"
    : "non-secret edit: old version SUPERSEDED — sessions already pinned to "
      + "it keep running on it; new sessions get the new version",
    () => {
      const thinking = (rotateFor && draft.thinking_level === "none"
        && !draft.custom_level) ? {} : thinkingFields();
      return api(`/admin/model/profiles/${name}/revise`, { method: "POST", body: {
        name, model_name: draft.model_name || undefined,
        ...thinking,
        ...(draft.wire_preset
            ? { capabilities: { thinking: { wire_preset: draft.wire_preset } } }
            : {}),
        max_completion_tokens: num(draft.max_completion_tokens),
        context_window: num(draft.context_window),
        compaction_ratio: num(draft.compaction_ratio),
        timeout_s: num(draft.timeout_s),
        api_key: rotateKey || undefined } })
        .then(() => { setRotateFor(null); setRotateKey(""); });
    });

  const revoke = (p) => run("version revoked; its credential is deleted and "
    + "nothing was substituted", () =>
    api(`/admin/model/profiles/${p.profile_id}/revoke`,
        { method: "POST", body: { reason: "revoked from admin panel" } }));

  const probe = (p) => run("probe queued — it admits through the same slot "
    + "as everything else; watch the job list", () =>
    api("/admin/model/probe", { method: "POST",
                                body: { role: "coach", profile_name: p.name } }));

  // Capability discovery is a CATALOG read (GET {base}/models), never a
  // completion; it does not authorize a thinking level by itself.
  const discoverCaps = (p) => {
    setDiscover(null);
    run("catalog fetched — record capabilities deliberately; the endpoint "
      + "listing alone does not prove thinking support", () =>
      api(`/admin/model/profiles/${p.profile_id}/discover`)
        .then(d => setDiscover({ name: p.name, models: d.models })));
  };

  const setRole = (role, profileName) => run(`role ${role} → ${profileName}`, () =>
    api("/admin/model/roles", { method: "PUT",
                                body: { role, profile_name: profileName } }));

  const cancelJob = (j) => run("cancellation is an obligation: queued dies "
    + "un-run; a RUNNING call is CLOSED by the watcher and stays an "
    + "UNCERTAIN cessation until its return confirms otherwise", () =>
    api(`/admin/model/jobs/${j.job_id}/cancel`, { method: "POST" }));

  const resolveCessation = (j) => run("cessation obligation resolved and "
    + "audited; the admission slot is released (never auto-expired)", () =>
    api(`/admin/model/jobs/${j.job_id}/resolve-cessation`,
        { method: "POST", body: { resolution: resolveText } })
      .then(() => { setResolveJob(null); setResolveText(""); }));

  const rebindSession = () => run("session rebound to the role's current "
    + "active version", () =>
    api(`/admin/model/sessions/${rebind.session_id}/rebind`,
        { method: "POST", body: { role: rebind.role } }));

  const active = profiles.filter(p => p.status === "active");
  const running = jobs.filter(j => j.state === "running");
  const obligations = jobs.filter(j => j.state === "cessation_unknown");
  const keyCell = p => (p.api_key_set === true ? "set"
    : p.api_key_set === false ? "—" : "unknown");
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
          environment; a session freezes ALL role versions at its first use —
          later overrides never move a live session.</p>
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
                    <td data-testid={`keyset-${p.name}-${p.version}`}>
                      {keyCell(p)}</td>
                    <td>
                      {p.status === "active" && (
                        <button disabled={busy} data-testid={`rotate-${p.name}`}
                                onClick={() => {
                                  setDraft({ ...draft, wire_preset: "" });
                                  setRotateFor(p.name);
                                }}>rotate</button>)}
                      {p.status === "active" && (
                        <button disabled={busy} onClick={() => revoke(p)}>revoke</button>)}
                      {p.status === "active" && (
                        <button disabled={busy} onClick={() => probe(p)}>probe</button>)}
                      {(p.status === "active" || p.status === "superseded") && (
                        <button disabled={busy} data-testid={`discover-${p.name}-${p.version}`}
                                onClick={() => discoverCaps(p)}>discover</button>)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {discover && (
              <p data-testid="discover-result">{discover.name}:{" "}
                {discover.models.join(", ") || "no models listed"}</p>)}
            <p className="dim">the key column reports presence as far as the
              application DB role can tell (unknown = the secret store is
              unreachable); provider keys live only behind the dedicated
              secret identity — no screen here can read one back.</p>
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
            <label>api key {rotateFor ? "(empty = NON-secret edit: keeps the "
              + "current credential; a value REPLACES it and revokes the "
              + "previous version)" : "(write-only)"}
              <input type="password" data-testid="field-key"
                value={rotateFor ? rotateKey : draft.api_key}
                onChange={e => rotateFor ? setRotateKey(e.target.value)
                  : setDraft({ ...draft, api_key: e.target.value })} /></label>
            <details>
              <summary>advanced (pinned per version)</summary>
              <label>thinking level
                <select data-testid="field-thinking" value={draft.thinking_level}
                        onChange={e => setDraft({ ...draft, thinking_level: e.target.value })}>
                  {[...STD_LEVELS, "custom…"].map(l => <option key={l}>{l}</option>)}
                </select></label>
              <label>thinking wire preset
                <select data-testid="field-wire-preset" value={draft.wire_preset}
                        onChange={e => setDraft({ ...draft, wire_preset: e.target.value })}>
                  <option value="">(default: llama.cpp)</option>
                  {WIRE_PRESETS.filter(x => x).map(x => <option key={x}>{x}</option>)}
                </select></label>
              {draft.thinking_level === "custom…" && (<>
                <label>custom level name <input data-testid="field-custom-level"
                  placeholder="e.g. budgeted" value={draft.custom_level}
                  onChange={e => setDraft({ ...draft, custom_level: e.target.value })} /></label>
                <label>reasoning_effort
                  <select data-testid="field-custom-effort"
                          value={draft.custom_effort}
                          onChange={e => setDraft({ ...draft, custom_effort: e.target.value })}>
                    <option value="">(not set)</option>
                    {EFFORTS.map(x => <option key={x}>{x}</option>)}
                  </select></label>
                <label>chat_template_kwargs (JSON)
                  <input data-testid="field-custom-kwargs" placeholder='{"thinking": true, "thinking_budget": 2048}'
                    value={draft.custom_kwargs}
                    onChange={e => setDraft({ ...draft, custom_kwargs: e.target.value })} /></label>
                <p className="dim">a custom level MUST declare how it reaches
                  the wire — only reasoning_effort and chat_template_kwargs
                  are permitted; unmapped levels are refused before any
                  request.</p>
              </>)}
              <label>context window <input data-testid="field-context"
                placeholder="262144" value={draft.context_window}
                onChange={e => setDraft({ ...draft, context_window: e.target.value })} /></label>
              <label>max completion tokens <input
                placeholder="32768 (incl. thinking)"
                value={draft.max_completion_tokens}
                onChange={e => setDraft({ ...draft, max_completion_tokens: e.target.value })} /></label>
              <label>compaction ratio (0.05–0.99) <input
                data-testid="field-compaction" placeholder="0.8"
                value={draft.compaction_ratio}
                onChange={e => setDraft({ ...draft, compaction_ratio: e.target.value })} /></label>
              <label>timeout (s, ≤ 900) <input placeholder="900"
                value={draft.timeout_s}
                onChange={e => setDraft({ ...draft, timeout_s: e.target.value })} /></label>
              <p className="dim">generation kwargs are allowlisted server-side
                (temperature/top_p/penalties only); messages, tools, auth and
                destinations can never be overridden by a profile.</p>
            </details>
            {rotateFor
              ? <button disabled={busy} data-testid="rotate-confirm"
                        onClick={() => rotate(rotateFor)}>
                  {rotateKey ? "rotate credential (revokes old)"
                              : "edit (supersedes old)"}
                </button>
              : <button disabled={busy} data-testid="create-profile"
                        onClick={create}>create profile</button>}
          </div>
          <div className="panel">
            <h3>rebind a session after credential revocation</h3>
            <p className="dim">the only way a pinned session continues on
              models — an explicit, audited operator act; refused while the
              session has queued or running model work.</p>
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
            {obligations.length > 0 && (
              <p className="bad" data-testid="obligation-warning">
                {obligations.length} cessation obligation(s) hold the slot —
                the provider may still be working; resolve below, never wait
                for auto-expiry (there is none)</p>)}
            {running.length > 1 &&
              <p className="bad">the database forbids more than one live
                obligation per slot</p>}
            <ul>
              {jobs.slice(0, 25).map(j => (
                <li key={j.job_id} data-testid={`job-${j.kind}-${j.state}`}>
                  <b>{j.kind}</b> · {j.state} · p{j.priority} · a{j.attempt}
                  {j.profile_name ? ` · ${j.profile_name}` : ""}
                  {j.cancel_requested ? " · cessation requested" : ""}
                  {j.deadline_at ? ` · by ${j.deadline_at.slice(11, 19)}Z` : ""}
                  {j.error ? ` — ${String(j.error).slice(0, 120)}` : ""}{" "}
                  {(j.state === "queued" || j.state === "running") &&
                    <button disabled={busy} data-testid="cancel-job"
                            onClick={() => cancelJob(j)}>cancel</button>}
                  {j.state === "cessation_unknown" &&
                    <button disabled={busy} data-testid="resolve-job"
                            onClick={() => setResolveJob(j.job_id)}>resolve…</button>}
                  {resolveJob === j.job_id && (<>
                    <input data-testid="resolve-text" value={resolveText}
                      placeholder="what you confirmed about the provider side"
                      onChange={e => setResolveText(e.target.value)} />
                    <button disabled={busy || !resolveText.trim()}
                            data-testid="resolve-confirm"
                            onClick={() => resolveCessation(j)}>
                      release slot</button>
                  </>)}
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
