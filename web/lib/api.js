// Thin, HONEST API client — the web app is just another authenticated client
// of the FastAPI front door. Bearer tokens; on 401 the user is bounced to
// login (F04: no username-as-credential theater).
const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export function getToken() {
  return typeof window !== "undefined" ? localStorage.getItem("sr_token") : null;
}

export async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(BASE + path, {
    ...opts,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401) {
    if (typeof window !== "undefined" && !location.pathname.startsWith("/login")) {
      localStorage.removeItem("sr_token");
      location.href = "/";
    }
    throw new Error("session expired — log in again");
  }
  if (!res.ok) {
    let detail = await res.text();
    try {
      const j = JSON.parse(detail);
      if (typeof j.detail === "string") detail = j.detail;
      else if (j.detail?.reasons) detail = j.detail.reasons.join("; ");
      else detail = JSON.stringify(j.detail ?? j);
    } catch {}
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.status === 204 ? null : res.json();
}

export function saveSession(o) {
  localStorage.setItem("sr_token", o.token);
  localStorage.setItem("sr_user", o.username);
  localStorage.setItem("sr_role", o.role || "member");
}
export const currentUser = () =>
  typeof window !== "undefined" ? localStorage.getItem("sr_user") : null;
export const logout = () => {
  ["sr_token", "sr_user", "sr_role"].forEach((k) => localStorage.removeItem(k));
};

// connection instructions from launch live in sessionStorage keyed by session
export const saveConnections = (sid, conns) =>
  sessionStorage.setItem(`sr_conns_${sid}`, JSON.stringify(conns));
export const getConnections = (sid) => {
  const v = sessionStorage.getItem(`sr_conns_${sid}`);
  return v ? JSON.parse(v) : null;
};
