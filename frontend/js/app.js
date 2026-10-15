// UI logic. Talks to the backend only through Api (js/api.js).

const state = {
  results: { naive: null, sealed: null, misconfigured: null },
  bundle: null,
  verify: null,     // last verify result: {ok, checks, first_bad_index}
  preflight: null,  // {passed, probes, source, aborted, failing}
  role: "operator",
  busy: false,
};

// ------------------------------------------------------------ small DOM helpers

const $ = (id) => document.getElementById(id);

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  Object.assign(el, props);
  el.append(...children.flat().filter((c) => c !== null && c !== undefined && c !== false));
  return el;
}

function clear(el) {
  el.replaceChildren();
  return el;
}

const badge = (kind, text) => h("span", { className: `badge ${kind}` }, text);
const shortHash = (x) => (x ? `${x.slice(0, 10)}…${x.slice(-6)}` : "—");

function showError(message) {
  const bar = $("error");
  bar.textContent = message;
  bar.hidden = false;
}

function clearError() {
  $("error").hidden = true;
}

// ------------------------------------------------------------ backend status

async function checkBackend() {
  const el = $("backend-status");
  try {
    const res = await Api.health();
    const ok = res.status === "ok";
    el.className = "status " + (ok ? "ok" : "bad");
    el.querySelector(".text").textContent = ok ? "Backend connected" : "Backend unhealthy";
    return ok;
  } catch {
    el.className = "status bad";
    el.querySelector(".text").textContent = "Backend offline";
    return false;
  }
}

// ------------------------------------------------------------ 3. comparison table

const bad = (label, detail) => ({ kind: "bad", label, detail });
const good = (label, detail) => ({ kind: "good", label, detail });

function evidenceCell(mode) {
  if (mode === "naive") return bad("FAILED", "no evidence produced");
  if (!state.verify) return { kind: "none", label: "NOT CHECKED", detail: "click Verify evidence" };
  return state.verify.ok ? good("PASSED", "signature + hash chain OK") : bad("FAILED", tamperSummary());
}

const ROWS = [
  ["Red read blue's rules", (m) => (m.red_read_blue_rules ? bad("LEAKED", "rules + secret policy read") : good("BLOCKED", "sandbox denied"))],
  ["Timing inference accuracy", (m) => {
    const detail = `${m.timing_inference_accuracy}% (chance ${m.chance_baseline}%)`;
    return m.timing_inference_accuracy > m.chance_baseline ? bad("LEAKED", detail) : good("BLOCKED", detail);
  }],
  ["Cache leak recovered secret", (m) => (m.cache_leak_recovered_secret ? bad("LEAKED", "secret prompt recovered") : good("BLOCKED", "salted per tenant"))],
  ["Blue adapted mid-test", (m) => (m.blue_adapted_mid_test ? bad("LEAKED", "defense changed mid-test") : good("BLOCKED", "defense read-only"))],
  ["Escape attempt", (m) => (m.escape_succeeded ? bad("LEAKED", "escape succeeded") : good("BLOCKED", "denied"))],
  ["Tripwire fired (time to detect)", (m) => (m.tripwire_fired ? good("PASSED", `${m.time_to_detect_ms} ms, run frozen`) : bad("FAILED", "escape went unnoticed"))],
  ["Pre-flight", (m) => (m.preflight_passed ? good("PASSED", "all probes denied") : bad("FAILED", "run continued anyway"))],
  ["Evidence verifies", (m, mode) => evidenceCell(mode)],
];

function renderComparison() {
  const body = clear($("compare-body"));
  for (const [name, cellFor] of ROWS) {
    const cells = ["naive", "sealed"].map((mode) => {
      const r = state.results[mode];
      if (!r || r.status !== "completed") return h("td", {}, badge("none", "NOT RUN"));
      const c = cellFor(r.metrics, mode);
      return h("td", {}, badge(c.kind, c.label), h("span", { className: "detail" }, c.detail || ""));
    });
    body.append(h("tr", {}, h("td", {}, name), ...cells));
  }
}

// ------------------------------------------------------------ 4. stories

function renderList(el, lines, emptyText) {
  clear(el);
  if (!lines || !lines.length) el.append(h("li", { className: "empty" }, emptyText));
  else lines.forEach((line) => el.append(h("li", {}, line)));
}

function renderStories() {
  renderList($("went-wrong"), state.results.naive?.what_went_wrong, "Run the naive test to see what leaks.");
  renderList($("held"), state.results.sealed?.what_held, "Run SealedEval to see what it prevents.");
}

// ------------------------------------------------------------ 5. pre-flight

function renderPreflight() {
  const p = state.preflight;
  $("preflight-source").textContent = p ? `from ${p.source}` : "";

  const banner = $("abort-banner");
  banner.hidden = !(p && p.aborted);
  if (p && p.aborted) {
    clear(banner).append(
      h("strong", {}, "RUN ABORTED BY PRE-FLIGHT"),
      h("span", {}, "Escape probes succeeded, so no attack was ever run: "),
      h("span", {}, (p.failing || []).join(", ")),
    );
  }

  const body = clear($("preflight-body"));
  if (!p || !p.probes) {
    body.append(h("tr", {}, h("td", { colSpan: 4, className: "note" }, "Not run yet.")));
    return;
  }
  for (const probe of p.probes) {
    body.append(h("tr", {},
      h("td", {}, probe.zone),
      h("td", {}, probe.probe),
      h("td", {}, probe.denied ? badge("good", "YES") : badge("bad", "NO")),
      h("td", {}, probe.passed ? badge("good", "PASSED") : badge("bad", "FAILED")),
    ));
  }
}

// ------------------------------------------------------------ 6. commitments

function renderCommitments() {
  const el = clear($("commitments"));
  const sealed = state.results.sealed;
  if (!sealed || !sealed.commitments) {
    el.append(h("p", { className: "note" }, "Run SealedEval: red, blue, the model and the contract are hashed before anything runs."));
    return;
  }
  const c = sealed.commitments;
  const v = sealed.verification || {};
  const rows = [
    ["Red Merkle root", c.red_root, v.red_commitment_matches],
    ["Blue fingerprint", c.blue_hash, v.blue_fingerprint_unchanged],
    ["Model fingerprint", c.model_hash, v.model_weights_unchanged],
    ["Contract hash", c.contract_hash, state.bundle ? state.bundle.contract_hash === c.contract_hash : undefined],
  ];
  for (const [label, hash, matches] of rows) {
    const hashEl = h("span", { className: "hash", title: `${hash}\n(click to copy)`, textContent: shortHash(hash) });
    hashEl.addEventListener("click", () => copyHash(hashEl, hash));
    const match = matches === undefined
      ? h("span", { className: "match none" }, "not checked")
      : h("span", { className: `match ${matches ? "ok" : "bad"}` }, matches ? "✓ matches after reveal" : "✗ MISMATCH");
    el.append(h("div", { className: "commit-row" }, h("span", { className: "label" }, label), hashEl, match));
  }
}

async function copyHash(el, hash) {
  try {
    await navigator.clipboard.writeText(hash);
    el.textContent = "copied!";
  } catch {
    el.textContent = hash; // clipboard blocked: show it in full so it can be selected
    return;
  }
  setTimeout(() => (el.textContent = shortHash(hash)), 900);
}

// ------------------------------------------------------------ 7. evidence

const LABEL_ORDER = ["ENFORCED", "VERIFIED", "MONITORED", "NOT_COVERED"];

function tamperSummary() {
  const v = state.verify;
  if (!v || v.ok) return "";
  return v.first_bad_index !== null && v.first_bad_index !== undefined
    ? `tampering at log entry ${v.first_bad_index}`
    : `failed: ${v.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")}`;
}

function renderEvidence() {
  const status = $("evidence-status");
  const v = state.verify;
  if (!state.bundle) {
    status.className = "evidence-status neutral";
    status.textContent = "No evidence bundle yet: run SealedEval.";
  } else if (!v) {
    status.className = "evidence-status neutral";
    status.textContent = "Bundle signed. Click “Verify evidence” to check it.";
  } else if (v.ok) {
    status.className = "evidence-status ok";
    clear(status).append("✓ Evidence verified",
      h("small", {}, "Signature valid · hash chain intact · log matches the signed bundle · commitments present"));
  } else {
    status.className = "evidence-status bad";
    const where = v.first_bad_index !== null && v.first_bad_index !== undefined ? ` at log entry ${v.first_bad_index}` : "";
    clear(status).append(`✗ TAMPERING DETECTED${where}`,
      h("small", {}, v.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`).join(" · ")));
  }

  const sig = v && v.checks.find((c) => c.name === "signature_valid");
  $("signature-status").textContent = !state.bundle ? ""
    : sig ? `Ed25519 signature: ${sig.ok ? "valid" : "INVALID"}` : "Ed25519 signature: not checked yet";

  const el = clear($("claims"));
  if (!state.bundle) return;
  for (const label of LABEL_ORDER) {
    const claims = state.bundle.claims.filter((c) => c.label === label);
    if (!claims.length) continue;
    el.append(h("div", { className: "claim-group" },
      h("h3", {}, h("span", { className: `pill ${label}` }, label.replace("_", " "))),
      claims.map((c) => h("div", { className: "claim" },
        c.holds === null ? null : h("span", { className: `holds ${c.holds ? "ok" : "bad"}` }, c.holds ? "✓" : "✗"),
        h("div", { className: "title" }, c.claim),
        h("div", { className: "ev" }, c.evidence),
      )),
    ));
  }
}

// ------------------------------------------------------------ 8. role views

async function loadRole(role) {
  state.role = role;
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.role === role));
  const el = $("role-view");
  try {
    renderRole(await Api.view(role));
  } catch (e) {
    clear(el).append(h("p", { className: "note" }, e.status === 404 ? "Run SealedEval to see what each role can see." : e.message));
  }
}

function renderRole(view) {
  const el = clear($("role-view"));
  const d = view.data;
  el.append(h("div", { className: "visible" }, "Contract allows: ", view.visible.map((x) => h("code", {}, x + " "))));

  if (view.role === "blue") {
    el.append(
      h("div", { className: "big-number" }, `${d.progress.processed} `, h("small", {}, `of ${d.progress.total} processed`)),
      h("p", { className: "note" }, "That is all blue sees during the run: no prompts, no verdicts, no timing. Details only after the reveal."),
    );
  } else if (view.role === "red") {
    el.append(
      h("p", { className: "note" }, "Red sees only the response text: one unified refusal or an answer. No rule names, no verdicts, no timing differences."),
      h("table", { className: "grid-table" },
        h("thead", {}, h("tr", {}, h("th", {}, "Prompt"), h("th", {}, "Response red received"))),
        h("tbody", {}, d.responses.map((r) => h("tr", {}, h("td", {}, r.prompt_id), h("td", {}, r.response))))),
    );
  } else {
    el.append(
      h("dl", { className: "kv" },
        h("dt", {}, "Health"), h("dd", {}, d.health),
        h("dt", {}, "Processed"), h("dd", {}, String(d.processed)),
        h("dt", {}, "Tick misses"), h("dd", {}, String(d.tick_misses)),
        h("dt", {}, "Rejections"), h("dd", {}, String(d.rejections)),
        h("dt", {}, "Alerts"), h("dd", {}, d.alerts.length ? d.alerts.map((a) => `#${a.index} ${a.event_type}`).join(", ") : "none"),
      ),
      h("p", { className: "note" }, "The operator sees health and alerts only: no prompt text, no verdicts."),
    );
  }
  el.append(h("details", {}, h("summary", {}, "Raw response"), h("pre", {}, JSON.stringify(view, null, 2))));
}

// ------------------------------------------------------------ 9. live log

const EVENT_CLASS = {
  tripwire_triggered: "alert", run_frozen: "alert", preflight_failed: "alert", run_aborted: "alert",
  auth_rejected: "warn", schema_rejected: "warn", salt_missing: "warn", sandbox_denied: "warn", tick_miss: "warn",
  commitments: "good", preflight_passed: "good", reveal: "good",
};

async function refreshLog() {
  let log;
  try {
    log = await Api.log(50);
  } catch (e) {
    $("chain-status").className = "chain bad";
    $("chain-status").textContent = e.message;
    return;
  }
  $("log-source").textContent = log.source ? `${log.source} run · ${log.total} entries` : "";
  const chain = $("chain-status");
  if (!log.total) {
    chain.className = "chain neutral";
    chain.textContent = "No log yet";
  } else if (log.verify.ok) {
    chain.className = "chain ok";
    chain.textContent = `✓ Chain intact (${log.total} entries)`;
  } else {
    chain.className = "chain bad";
    chain.textContent = `✗ Chain broken at entry ${log.verify.first_bad_index}`;
  }

  const body = clear($("log-body"));
  for (const e of [...log.entries].reverse()) {
    const broken = !log.verify.ok && e.index === log.verify.first_bad_index;
    body.append(h("tr", { className: broken ? "alert" : EVENT_CLASS[e.event_type] || "" },
      h("td", {}, String(e.index)),
      h("td", {}, e.event_type + (broken ? "  ← tampered" : "")),
      h("td", {}, e.hash.slice(0, 12)),
    ));
  }
}

// ------------------------------------------------------------ data loading

async function refreshResults() {
  state.results = await Api.results();
}

async function refreshBundle() {
  try {
    state.bundle = await Api.bundle();
  } catch (e) {
    if (e.status !== 404) throw e;
    state.bundle = null;
  }
}

function renderAll() {
  renderComparison();
  renderStories();
  renderPreflight();
  renderCommitments();
  renderEvidence();
}

// ------------------------------------------------------------ actions

const ACTIONS = {
  naive: {
    text: "Running naive test… (~5s)",
    run: async () => {
      await Api.runNaive();
      await refreshResults();
    },
  },
  sealed: {
    text: "Running sealed test… (~10s)",
    run: async () => {
      const r = await Api.runSealed();
      state.preflight = { ...r.preflight, source: "SealedEval run" };
      await refreshResults();
      await refreshBundle();
      state.verify = await Api.verifyBundle();
    },
  },
  misconfigured: {
    text: "Running with a misconfigured sandbox… (~2s)",
    run: async () => {
      const r = await Api.runMisconfigured();
      state.preflight = { ...r.preflight, source: "misconfigured run", aborted: r.status === "aborted", failing: r.failing_probes };
    },
  },
  preflight: {
    text: "Running pre-flight probes…",
    run: async () => {
      state.preflight = { ...(await Api.preflight()), source: "standalone probe run" };
    },
  },
  verify: {
    text: "Verifying evidence…",
    run: async () => {
      await refreshBundle();
      state.verify = await Api.verifyBundle();
    },
  },
  tamper: {
    text: "Tampering with the log…",
    run: async () => {
      state.verify = (await Api.tamperBundle()).verify;
    },
  },
  reset: {
    text: "Resetting…",
    run: async () => {
      await Api.reset();
      Object.assign(state, { verify: null, preflight: null, bundle: null });
      await refreshResults();
    },
  },
};

function setBusy(busy, text = "") {
  state.busy = busy;
  document.querySelectorAll("[data-action]").forEach((b) => (b.disabled = busy));
  $("busy").hidden = !busy;
  $("busy-text").textContent = text;
}

async function runAction(name) {
  if (state.busy) return;
  clearError();
  setBusy(true, ACTIONS[name].text);
  const poll = setInterval(refreshLog, 2000); // live log while the run is in progress
  try {
    await ACTIONS[name].run();
  } catch (e) {
    showError(e.status === 409 ? "Another run is already in progress. Wait for it to finish." : e.message);
  } finally {
    clearInterval(poll);
    setBusy(false);
    renderAll();
    refreshLog();
    loadRole(state.role);
  }
}

// ------------------------------------------------------------ start-up

document.addEventListener("DOMContentLoaded", async () => {
  document.querySelectorAll("[data-action]").forEach((b) => b.addEventListener("click", () => runAction(b.dataset.action)));
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => loadRole(t.dataset.role)));
  setInterval(checkBackend, 5000);

  renderAll();
  if (!(await checkBackend())) {
    showError(`Backend offline: cannot reach ${API}. Start it with scripts/run_backend.ps1 (or .sh), then refresh.`);
    return;
  }
  try {
    await refreshResults();
    await refreshBundle();
    if (state.results.sealed?.preflight) state.preflight = { ...state.results.sealed.preflight, source: "latest SealedEval run" };
  } catch (e) {
    showError(e.message);
  }
  renderAll();
  refreshLog();
  loadRole(state.role);
});
