import { useState } from "react";
import { useRouter } from "next/router";
import { api, saveSession } from "../lib/api";

export default function Home() {
  const [username, setU] = useState("");
  const [password, setP] = useState("");
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const router = useRouter();
  async function login(e) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      const r = await api("/auth/login", { method: "POST", body: { username, password } });
      saveSession(r);
      router.push("/library");
    } catch (e2) { setErr(String(e2.message || e2)); setBusy(false); }
  }
  return (
    <div className="panel" style={{ maxWidth: 420, margin: "60px auto" }}>
      <h2>sparring-range — login</h2>
      <p className="dim">Real credential login (operator-provisioned accounts). Tokens expire;
        no internet, no SSO — home-LAN gym.</p>
      <form onSubmit={login} style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <input placeholder="username" value={username} onChange={(e) => setU(e.target.value)} autoFocus />
        <input placeholder="password" type="password" value={password} onChange={(e) => setP(e.target.value)} />
        <button type="submit" disabled={busy || !username || !password}>{busy ? "…" : "enter the gym"}</button>
      </form>
      {err && <p className="bad">{err}</p>}
    </div>
  );
}
