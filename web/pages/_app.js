import "../styles/global.css";
import "asciinema-player/dist/bundle/asciinema-player.css";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { currentUser, logout, getToken } from "../lib/api";

export default function App({ Component, pageProps }) {
  const [user, setUser] = useState(null);
  const router = useRouter();
  useEffect(() => {
    const u = currentUser();
    setUser(u);
    if (!getToken() && u === null && router.pathname !== "/") router.replace("/");
  }, [router.pathname]);
  const isLogin = router.pathname === "/";
  return (
    <div className="shell">
      <header className="topbar">
        <Link href="/library" className="brand">sparring-range</Link>
        <nav>
          <Link href="/library">library</Link>
          <Link href="/progress">progress</Link>
          {user && <a href="#" onClick={(e) => { e.preventDefault(); logout(); location.href = "/"; }}>{user} (logout)</a>}
        </nav>
      </header>
      <main><Component {...pageProps} /></main>
    </div>
  );
}
