"""End-to-end demo: naive vs sealed, then verify, tamper and verify again. Run: python -m app.demo.run_all"""

import shutil
import time

from app.core.crypto import DATA_DIR
from app.demo.naive_run import run_naive
from app.demo.sealed_run import run_sealed
from app.evidence.verify import tamper_log, verify_bundle


def yes_no(value: bool, bad_when: bool) -> str:
    return ("YES" if value else "no") + ("  <-- leak" if value == bad_when else "")


def print_table(rows: list[tuple[str, str, str]]) -> None:
    headers = ("Check", "Naive", "SealedEval")
    widths = [max(len(r[i]) for r in rows + [headers]) for i in range(3)]
    line = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    print(line)
    print("| " + " | ".join(h.ljust(w) for h, w in zip(headers, widths)) + " |")
    print(line)
    for r in rows:
        print("| " + " | ".join(c.ljust(w) for c, w in zip(r, widths)) + " |")
    print(line)


def main() -> None:
    t0 = time.perf_counter()
    print("Running NAIVE (shared environment)...")
    naive = run_naive()
    print(f"  done in {time.perf_counter() - t0:.1f}s")
    for line in naive["what_went_wrong"]:
        print(f"  - {line}")

    t1 = time.perf_counter()
    print("\nRunning SEALED (SealedEval)...")
    sealed = run_sealed()
    print(f"  done in {time.perf_counter() - t1:.1f}s")
    for line in sealed["what_held"]:
        print(f"  - {line}")

    bundle_path, log_path = DATA_DIR / "bundle.json", DATA_DIR / "sealed_events.jsonl"
    print("\nVerifying evidence bundle...")
    clean = verify_bundle(bundle_path, log_path)
    for c in clean["checks"]:
        print(f"  [{'OK' if c['ok'] else 'FAIL'}] {c['name']}: {c['detail']}")

    # Tamper with a COPY, so the real evidence in data/ stays valid for the dashboard.
    tampered_log = DATA_DIR / "sealed_events_tampered.jsonl"
    shutil.copyfile(log_path, tampered_log)
    index = tamper_log(tampered_log)
    print(f"\nTampered with log entry {index} (copy: {tampered_log.name}); verifying again...")
    dirty = verify_bundle(bundle_path, tampered_log)
    for c in dirty["checks"]:
        print(f"  [{'OK' if c['ok'] else 'FAIL'}] {c['name']}: {c['detail']}")

    n, s = naive["metrics"], sealed["metrics"]
    print("\nNaive vs SealedEval")
    print_table([
        ("Red read blue's rules", yes_no(n["red_read_blue_rules"], True), yes_no(s["red_read_blue_rules"], True)),
        ("Timing inference accuracy (chance)",
         f"{n['timing_inference_accuracy']}% ({n['chance_baseline']}%)",
         f"{s['timing_inference_accuracy']}% ({s['chance_baseline']}%)"),
        ("Distinct refusal messages", str(n["distinct_refusal_texts"]), str(s["distinct_refusal_texts"])),
        ("Cache leak recovered secret", yes_no(n["cache_leak_recovered_secret"], True),
         yes_no(s["cache_leak_recovered_secret"], True)),
        ("Blue adapted mid-test", yes_no(n["blue_adapted_mid_test"], True), yes_no(s["blue_adapted_mid_test"], True)),
        ("Escape attempt", "succeeded" if n["escape_succeeded"] else "denied",
         "succeeded" if s["escape_succeeded"] else "denied"),
        ("Tripwire fired / time to detect", "no (no tripwires)",
         f"yes, {s['time_to_detect_ms']} ms, run frozen" if s["tripwire_fired"] else "no"),
        ("Pre-flight", "FAILED (run continued)" if not n["preflight_passed"] else "passed",
         "passed" if s["preflight_passed"] else "FAILED"),
        ("Commitments match after run", "n/a (none made)",
         "yes" if s["red_commitment_matches"] and s["blue_fingerprint_unchanged"] and s["model_weights_unchanged"]
         else "NO"),
        ("Bundle verifies", "n/a (no evidence)", "yes" if clean["ok"] else "NO"),
        ("Bundle verifies after tamper", "n/a (no evidence)",
         f"no -> tamper detected at entry {dirty['first_bad_index']}" if not dirty["ok"] else "YES  <-- undetected"),
    ])

    print("\nMisconfigured sealed run (red zone given NAIVE_CONFIG)...")
    bad = run_sealed(misconfigured=True)
    print(f"  status: {bad['status']} ({bad.get('reason', '')})")
    if bad["status"] == "aborted":
        print(f"  failing probes: {', '.join(bad['failing_probes'])}")

    print(f"\nTotal time {time.perf_counter() - t0:.1f}s. Results saved to {DATA_DIR}")


if __name__ == "__main__":
    main()
