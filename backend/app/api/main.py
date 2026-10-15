"""FastAPI app: wires HTTP routes to backend modules. Routes only, no business logic. Contract: docs/API.md."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SealedEval API", version="0.1.0")

# The frontend is served separately by `python -m http.server 5500`.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5500", "http://127.0.0.1:5500"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}
