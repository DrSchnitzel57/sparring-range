import { useEffect, useState } from "react";
import { api } from "../../lib/api";

// Operator bastion key enrollment (plan 22 LIVE-06). The defender bastion
// refused a desktop key because the CURRENT account had no enrolled public
// key — enrollment lived only in an operator file nobody could query.
// This panel is the supported answer: PUBLIC keys in, SHA256 fingerprints
// out; the operator commissioning file stays untouched, and enrolling
// takes effect on the NEXT authentication (the bastion hot-reloads — no
// restart). A private-key paste is refused by the API before storage.
function isOperator() {
  return typeof window !== "undefined"
    && localStorage.getItem("sr_role") === "operator";
}

export default function AdminBastion() {
  const [enrolled, setEnrolled] = useState({});
  const [meta, setMeta] = useState({});
  const [err, setErr] = useState(null);
  const [note, setNote] = useState(null);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState({ username: "", public_key: "" });

  const load = () => {
    api("/admin/bastion/enrollment")
      .then(d => { setEnrolled(d.enrolled || {}); setMeta(d); })
      .catch(e => setErr(String(e.message || e)));
  };
  useEffect(load, []);

  if (!isOperator()) {
    return <div className="panel"><p className="dim">operator only.</p></div>;
  }

  const enroll = async (e) => {
    e.preventDefault();
    setBusy(true); setErr(null); setNote(null);
    try {
      const r = await api("/admin/bastion/enrollment", {
        method: "POST",
        body: { username: draft.username, public_key: draft.public_key },
      });
      setNote(r.created
        ? `enrolled ${r.fingerprints[r.fingerprints.length - 1]} for ${r.username}`
        : `that key was already enrolled for ${r.username}`);
      setDraft({ username: draft.username, public_key: "" });
      load();
    } catch (ex) { setErr(String(ex.message || ex)); }
    setBusy(false);
  };

  const revoke = async (username, fingerprint) => {
    setErr(null);
    try {
      await api(`/admin/bastion/enrollment?username=${encodeURIComponent(username)}`
        + `&fingerprint=${encodeURIComponent(fingerprint)}`, { method: "DELETE" });
      load();
    } catch (ex) { setErr(String(ex.message || ex)); }
  };

  const accounts = Object.keys(enrolled).sort();
  return (
    <div className="panel" data-testid="bastion-enrollment">
      <h3>bastion key enrollment</h3>
      <p className="dim">
        Public keys only — never paste a private key. Enrolling takes effect
        on the next SSH authentication without a service restart. This store
        is merged with (never replaces) the operator commissioning file
        {meta.operator_file_configured ? " (configured)." : " (NOT configured — set SR_BASTION_AUTHORIZED_KEYS_FILE)."}
      </p>
      {err && <p className="bad" data-testid="bastion-error">{err}</p>}
      {note && <p className="dim" data-testid="bastion-note">{note}</p>}
      <form onSubmit={enroll}>
        <input aria-label="username" placeholder="account"
               data-testid="enroll-username" value={draft.username}
               onChange={e => setDraft({ ...draft, username: e.target.value })} />
        <textarea aria-label="public key" rows={3}
          placeholder={"ssh-ed25519 AAAA… comment"}
          data-testid="enroll-key" value={draft.public_key}
          onChange={e => setDraft({ ...draft, public_key: e.target.value })} />
        <button type="submit" disabled={busy || !draft.username || !draft.public_key}>
          enroll public key
        </button>
      </form>
      <table data-testid="enrolled-accounts">
        <thead><tr><th>account</th><th>fingerprint</th><th></th></tr></thead>
        <tbody>
          {accounts.flatMap(u => (enrolled[u] || []).map(fp => (
            <tr key={`${u}:${fp}`}>
              <td>{u}</td>
              <td><code>{fp}</code></td>
              <td><button className="ghost" disabled={busy}
                          data-testid={`revoke-${u}-${fp.replace(/[^A-Za-z0-9]/g, "")}`}
                          onClick={() => revoke(u, fp)}>revoke</button></td>
            </tr>
          )))}
        </tbody>
      </table>
      {!accounts.length && <p className="dim">no API-enrolled keys yet — accounts
        covered only by the operator commissioning file still work.</p>}
    </div>
  );
}
