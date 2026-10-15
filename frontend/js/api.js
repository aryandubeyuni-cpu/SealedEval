// All calls to the backend live here, one function per endpoint in docs/API.md.

// 127.0.0.1, not "localhost": on Windows "localhost" tries IPv6 first and every call waits ~2 s
// before falling back, because uvicorn listens on IPv4 only.
const API = "http://127.0.0.1:8001";

async function request(method, path) {
  let res;
  try {
    res = await fetch(API + path, { method });
  } catch {
    throw new Error(`Backend offline: cannot reach ${API}. Start it with scripts/run_backend.ps1 (or .sh).`);
  }
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error((data && (data.error || data.detail)) || `${method} ${path} failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

const Api = {
  health:           ()           => request("GET",  "/api/health"),
  runNaive:         ()           => request("POST", "/api/run/naive"),
  runSealed:        ()           => request("POST", "/api/run/sealed"),
  runMisconfigured: ()           => request("POST", "/api/run/misconfigured"),
  preflight:        ()           => request("GET",  "/api/preflight"),
  log:              (limit = 50) => request("GET",  `/api/log?limit=${limit}`),
  bundle:           ()           => request("GET",  "/api/bundle"),
  verifyBundle:     ()           => request("POST", "/api/bundle/verify"),
  tamperBundle:     ()           => request("POST", "/api/bundle/tamper"),
  reset:            ()           => request("POST", "/api/reset"),
  view:             (role)       => request("GET",  `/api/view/${encodeURIComponent(role)}`),
  results:          ()           => request("GET",  "/api/results"),
};
