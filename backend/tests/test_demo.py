"""End-to-end checks: naive leaks, sealed blocks, bundle verifies, tamper detected, misconfig aborts. Run: python -m tests.test_demo"""

import shutil
import sys
import tempfile
from pathlib import Path

from app.demo.naive_run import run_naive
from app.demo.sealed_run import run_sealed
from app.evidence.verify import tamper_log, verify_bundle

results = []


def check(name: str, condition) -> None:
    results.append(bool(condition))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}")


def test_demo(tmp: Path):
    n = run_naive(data_dir=tmp)["metrics"]
    check("NAIVE: red read blue's rules", n["red_read_blue_rules"])
    check(f"NAIVE: timing inference {n['timing_inference_accuracy']}% beats chance {n['chance_baseline']}%",
          n["timing_inference_accuracy"] > n["chance_baseline"])
    check("NAIVE: cache leak recovered blue's secret", n["cache_leak_recovered_secret"])
    check("NAIVE: blue adapted mid-test", n["blue_adapted_mid_test"])
    check("NAIVE: escape succeeded, no tripwire", n["escape_succeeded"] and not n["tripwire_fired"])
    check("NAIVE: pre-flight failed", not n["preflight_passed"])

    sealed = run_sealed(data_dir=tmp)
    s = sealed["metrics"]
    check(f"SEALED: completed (status={sealed['status']})", sealed["status"] == "completed")
    check("SEALED: red could NOT read blue's rules", not s["red_read_blue_rules"])
    check(f"SEALED: timing inference {s['timing_inference_accuracy']}% no better than chance {s['chance_baseline']}%",
          s["timing_inference_accuracy"] <= s["chance_baseline"])
    check("SEALED: exactly one refusal text", s["distinct_refusal_texts"] == 1)
    check("SEALED: cache leak blocked", not s["cache_leak_recovered_secret"])
    check("SEALED: blue could NOT adapt mid-test", not s["blue_adapted_mid_test"])
    check(f"SEALED: escape denied, tripwire fired in {s['time_to_detect_ms']} ms, run frozen",
          not s["escape_succeeded"] and s["tripwire_fired"] and s["run_frozen"])
    check("SEALED: commitments match after the run",
          s["red_commitment_matches"] and s["blue_fingerprint_unchanged"] and s["model_weights_unchanged"])
    check(f"SEALED: overlap with public jailbreaks = {s['overlap_percent']}%", s["overlap_percent"] == 25.0)

    bundle, log = tmp / "bundle.json", tmp / "sealed_events.jsonl"
    clean = verify_bundle(bundle, log)
    check("Bundle verifies", clean["ok"])

    tampered = tmp / "tampered.jsonl"
    shutil.copyfile(log, tampered)
    index = tamper_log(tampered)
    dirty = verify_bundle(bundle, tampered)
    check(f"Tamper detected at entry {dirty['first_bad_index']} (edited entry {index})",
          not dirty["ok"] and dirty["first_bad_index"] == index)

    bad = run_sealed(misconfigured=True, data_dir=tmp)
    check(f"Misconfigured run aborted by pre-flight ({bad.get('failing_probes')})", bad["status"] == "aborted")

    check("Results files saved", all((tmp / f).exists() for f in
                                     ("naive_results.json", "sealed_results.json", "bundle.json")))


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        test_demo(Path(d))
    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)
