"""FastAPI app: wires HTTP routes to backend modules. Routes only, no business logic. Contract: docs/API.md."""

import threading

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.broker.broker import ROLES
from app.demo import store
from app.demo.naive_run import run_naive
from app.demo.sealed_run import run_sealed

app = FastAPI(title="SealedEval API", version="0.2.0")

# The frontend is served separately by `python -m http.server 5500`.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5500", "http://127.0.0.1:5500"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Only one run (or tamper/reset) at a time. Routes are plain `def`, so FastAPI runs them in a
# thread pool and GET /api/log keeps answering while a run is in progress.
RUN_LOCK = threading.Lock()


def error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


def exclusive(action: str, fn, log_name: str | None = None):
    """Run `fn` under the run lock: 409 if busy, 404 if its inputs don't exist, 500 on failure."""
    if not RUN_LOCK.acquire(blocking=False):
        return error(409, "a run is in progress")
    try:
        if log_name:
            store.set_active_log(log_name)
        return fn()
    except store.NotReady as e:
        return error(404, str(e))
    except Exception as e:  # surface the reason to the dashboard instead of a bare 500
        return error(500, f"{action} failed: {e}")
    finally:
        RUN_LOCK.release()


def safe(action: str, fn):
    """Same error mapping as `exclusive`, without taking the lock (read-only routes)."""
    try:
        return fn()
    except store.NotReady as e:
        return error(404, str(e))
    except Exception as e:
        return error(500, f"{action} failed: {e}")


# ------------------------------------------------------------ routes

@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/run/naive")
def run_naive_route():
    return exclusive("naive run", run_naive, log_name="naive")


@app.post("/api/run/sealed")
def run_sealed_route():
    return exclusive("sealed run", run_sealed, log_name="sealed")


@app.post("/api/run/misconfigured")
def run_misconfigured_route():
    def run():
        r = run_sealed(misconfigured=True)
        return {"status": r["status"], "reason": r.get("reason"), "failing_probes": r.get("failing_probes", []),
                "preflight": r.get("preflight")}
    return exclusive("misconfigured run", run, log_name="misconfigured")


@app.get("/api/preflight")
def preflight_route():
    return safe("pre-flight", store.preflight_check)


@app.get("/api/log")
def log_route(limit: int = Query(50, ge=1, le=500)):
    return safe("reading the log", lambda: store.read_log(limit))


@app.get("/api/bundle")
def bundle_route():
    return safe("loading the bundle", store.load_bundle)


@app.post("/api/bundle/verify")
def verify_route():
    return safe("verification", store.verify_latest)


@app.post("/api/bundle/tamper")
def tamper_route():
    return exclusive("tamper", store.tamper_latest)


@app.post("/api/reset")
def reset_route():
    return exclusive("reset", store.reset_data)


@app.get("/api/view/{role}")
def view_route(role: str):
    if role not in ROLES:
        return error(404, f"unknown role {role!r}; use one of: {', '.join(ROLES)}")
    return safe("role view", lambda: store.role_view(role))


@app.get("/api/results")
def results_route():
    return safe("loading results", store.load_results)
