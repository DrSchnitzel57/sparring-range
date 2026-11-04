"use client";

// A member's guest console page.
//
// The page carries a capability token from the lab API (minted per guest,
// revoked on reset, 1 h TTL). The token is the whole authority: the appliance
// resolves it to the guest's VNC endpoint, authenticates THAT conversation
// with the guest's password, and the browser only ever sees "no security".
import Head from "next/head";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { RFBClient } from "../lib/rfb";

export default function ConsolePage() {
  const canvasRef = useRef(null);
  const clientRef = useRef(null);
  const [status, setStatus] = useState("waiting for token");
  const [guest, setGuest] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    setGuest(params.get("guest") || "");
    if (!token) return;
    const wsProto = window.location.protocol === "https:" ? "wss" : "ws";
    const url = `${wsProto}://${window.location.host}/api/console/${token}/stream`;
    const client = new RFBClient({
      url, canvas: canvasRef.current, onStatus: setStatus,
    });
    clientRef.current = client;
    client.connect();
    return () => { client.close(); clientRef.current = null; };
  }, []);

  return (
    <>
      <Head><title>Guest console — sparring-range</title></Head>
      <main style={{ padding: "1rem" }}>
        <p>
          <Link href="/home">← home</Link>
          {guest ? <> &nbsp;·&nbsp; console: <b className="mono">{guest}</b></> : null}
        </p>
        <p className="dim">status: <b>{status}</b></p>
        <div className="console-frame">
          <canvas ref={canvasRef} tabIndex={0}
                  style={{ width: "100%", background: "#000",
                           outline: "none", cursor: "crosshair" }} />
        </div>
      </main>
    </>
  );
}
