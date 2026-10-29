import "../styles/global.css";
import "asciinema-player/dist/bundle/asciinema-player.css";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { currentUser, logout, getToken, getRole } from "../lib/api";

function Nav() {
  const router = useRouter();
  const [user, setUser] = useState(null);
  useEffect(() => { setUser(currentUser()); }, [router.pathname]);
  const link = (href, label) => (
    <Link href={href} className={router.pathname === href ? "active" : ""}>{label}</Link>
  );
  return (
    <header className="topbar">
      <div className="row" style={{ gap: 18 }}>
        <Link href="/home" className="brand">⚔ sparring-range</Link>
        <nav aria-label="Primary">
          {link("/home", "home")}
          {link("/library", "library")}
          {link("/progress", "progress")}
          {link("/safety", "safety")}
          {getRole() === "operator" && link("/admin/models", "models")}
          {getRole() === "operator" && link("/admin/bastion", "bastion")}
        </nav>
      </div>
      <nav aria-label="Account">
        {user && (
          <>
            <span className="user-chip">{user}</span>
            <a href="#" onClick={(e) => { e.preventDefault(); logout(); location.href = "/"; }}>log out</a>
          </>
        )}
      </nav>
    </header>
  );
}

export default function App({ Component, pageProps }) {
  const router = useRouter();
  useEffect(() => {
    // the API is the authority; an unauthenticated visitor goes to login
    if (typeof window !== "undefined" && !getToken() && router.pathname !== "/") {
      router.replace("/");
    }
  }, [router.pathname]);
  const isLogin = router.pathname === "/";
  return (
    <div className="shell">
      {!isLogin && <Nav />}
      <main><Component {...pageProps} /></main>
    </div>
  );
}
