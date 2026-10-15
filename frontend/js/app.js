// UI logic. Talks to the backend only through Api (js/api.js).

function setBackendStatus(online) {
  const el = document.getElementById("backend-status");
  el.textContent = online ? "Backend connected" : "Backend offline";
  el.className = "status " + (online ? "status-ok" : "status-bad");
}

async function checkBackend() {
  try {
    const res = await Api.health();
    setBackendStatus(res.status === "ok");
  } catch {
    setBackendStatus(false);
  }
}

document.addEventListener("DOMContentLoaded", checkBackend);
