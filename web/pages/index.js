import { useState } from "react";
import { useRouter } from "next/router";
import { api, saveSession } from "../lib/api";

export default function Home() {
  const [username, setU] = useState("");
  const [err, setErr] = useState(null);
  const router = useRouter();
  async function login(e) {
    e.preventDefault();
    try {
      const r = await api("/auth/login", { method: "POST", body: { username } });
      saveSession(r);
      router.push("/library");
    } catch (e2) { setErr(String(e2)); }
  }
  return (
    <div className="panel" style={{ maxWidth: 420, margin: "60px auto" }}>
      <h2>sparring-range — login</h2>
      <p className="dim">LAN gym account (Drew creates members). No internet, no SSO — home-LAN trust.</p>
      <form onSubmit={login} style={{ display: "flex", gap: 8 }}>
        <input placeholder="username" value={username} onChange={(e) => setU(e.target.value)} />
        <button type="submit">enter the gym</button>
      </form>
      {err && <p className="bad">{err}</p>}
    </div>
  );
}
