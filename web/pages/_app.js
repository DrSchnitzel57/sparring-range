import "../styles/global.css";
import Link from "next/link";
import { useEffect, useState } from "react";
import { currentUser, logout } from "../lib/api";

export default function App({ Component, pageProps }) {
  const [user, setUser] = useState(null);
  useEffect(() => setUser(currentUser()), []);
  return (
    <div className="shell">
      <header className="topbar">
        <Link href="/library" className="brand">sparring-range</Link>
        <nav>
          <Link href="/library">library</Link>
          <Link href="/progress">progress</Link>
          {user && <a href="#" onClick={(e) => { logout(); location.href = "/"; }}>{user} (logout)</a>}
        </nav>
      </header>
      <main><Component {...pageProps} /></main>
    </div>
  );
}
