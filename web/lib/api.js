// Thin API client. The web app is JUST another client of the FastAPI front door
// (Part 3) — no direct DB, no business logic here, only views + fetch.
const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function api(path, opts = {}) {
  const token = typeof window !== "undefined" ? localStorage.getItem("sr_token") : null;
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (token) headers["X-Token"] = token;
  const res = await fetch(BASE + path, { ...opts, headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json();
}

export function saveSession(o) {
  localStorage.setItem("sr_token", o.token);
  localStorage.setItem("sr_user", o.username);
}
export const currentUser = () => (typeof window !== "undefined" ? localStorage.getItem("sr_user") : null);
export const logout = () => { localStorage.removeItem("sr_token"); localStorage.removeItem("sr_user"); };
