// All calls to the backend live here, one function per endpoint in docs/API.md.

const API = "http://localhost:8000";

async function request(method, path, body) {
  const options = { method, headers: {} };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const res = await fetch(API + path, options);
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error((data && data.detail) || `${method} ${path} failed: ${res.status}`);
  }
  return data;
}

const Api = {
  health:       ()          => request("GET",  "/api/health"),
  runNaive:     (body = {}) => request("POST", "/api/run/naive", body),
  runSealed:    (body = {}) => request("POST", "/api/run/sealed", body),
  preflight:    ()          => request("GET",  "/api/preflight"),
  log:          (since = 0) => request("GET",  `/api/log?since=${since}`),
  bundle:       ()          => request("GET",  "/api/bundle"),
  verifyBundle: (body = {}) => request("POST", "/api/bundle/verify", body),
  tamperBundle: (body = {}) => request("POST", "/api/bundle/tamper", body),
  view:         (role)      => request("GET",  `/api/view/${encodeURIComponent(role)}`),
};
