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
      router.push("/home");
    } catch (e2) { setErr(String(e2.message || e2)); setBusy(false); }
  }
  return (
    <div className="panel" style={{ maxWidth: 430, margin: "70px auto" }}>
      <h2>sparring-range</h2>
      <p className="dim">Sign in with your operator-provisioned account. Real
        credentials, expiring tokens, no internet, no SSO.</p>
      <form onSubmit={login} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <label className="dim">username
          <input placeholder="username" value={username} autoComplete="username"
            onChange={(e) => setU(e.target.value)} autoFocus /></label>
        <label className="dim">password
          <input placeholder="password" type="password" autoComplete="current-password"
            value={password} onChange={(e) => setP(e.target.value)} /></label>
        <button type="submit" disabled={busy || !username || !password}>{busy ? "…" : "enter the gym"}</button>
      </form>
      {err && <p className="bad" role="alert">{err}</p>}
    </div>
  );
}
