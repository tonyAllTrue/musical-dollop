import json
from typing import Any, Dict, List

import config
from github_issues import (
    create_issues_for_threshold_breaches,
    create_issues_for_hard_failures,
    create_failed_category_issues_for_results,  # per-category via GraphQL
)

# Non-failing statuses (pipeline continues)
ALLOWED_NONFAIL_STATUSES = {
    "COMPLETED",
    "POLL_TIMEOUT_CONTINUE",
    "POLL_TIMEOUT_PARTIAL",
    "POLL_TIMEOUT",
    "EXTENDED_POLL_TIMEOUT",
}

def _severity_idx(level: str | None) -> int | None:
    if level is None:
        return None
    return config.SEVERITY_INDEX.get(config.normalize_outcome(level))

def _worse(a: str | None, b: str | None) -> str | None:
    """Return the worse (more severe) of two outcome levels using severity order.
       Unknown/None is treated as unknown and does not auto-fail."""
    ia = _severity_idx(a)
    ib = _severity_idx(b)
    if ia is None:  # a unknown
        return b
    if ib is None:  # b unknown
        return a
    return a if ia < ib else b

def finalize_and_exit(all_results: List[Dict[str, Any]]) -> int:
    # Summaries
    completed_results         = [r for r in all_results if r.get("status") == "COMPLETED"]
    timeout_continue_results  = [r for r in all_results if r.get("status") == "POLL_TIMEOUT_CONTINUE"]
    timeout_partial_results   = [r for r in all_results if r.get("status") == "POLL_TIMEOUT_PARTIAL"]
    extended_timeout_results  = [r for r in all_results if r.get("status") == "EXTENDED_POLL_TIMEOUT"]

    print(f"\n{'='*80}")
    print("FINAL ROLLING PARALLEL PENTEST RESULTS SUMMARY")
    print(f"{'='*80}")
    print(f"Total resources processed: {len(all_results)}")
    print(f"Successfully completed: {len(completed_results)}")
    print(f"Timed out (may still be running): {len(timeout_continue_results)}")
    print(f"Timed out (partial results): {len(timeout_partial_results)}")
    print(f"Extended timeout (still running): {len(extended_timeout_results)}")

    # Anything not in allowed list is a "hard failure" (start failures, exceptions, etc.)
    hard_failures = [r for r in all_results if r.get("status") not in ALLOWED_NONFAIL_STATUSES]

    if hard_failures:
        print("\nFailed Resources (hard failures):")
        for r in hard_failures:
            attempts_info = f" (after {r['final_attempt']} attempts)" if r.get("final_attempt") else ""
            print(f"  - {r.get('resource_name')}: {r.get('status')}{attempts_info}")

    # Outcome summary (includes partial outcomes)
    outcomes: Dict[str, int] = {}
    results_with_outcomes = completed_results + timeout_partial_results
    worst_known_outcome: str | None = None
    unknown_outcomes = 0

    if results_with_outcomes:
        print("\nOutcome Summary:")
        for r in results_with_outcomes:
            raw = r.get("outcome")
            outcome = config.normalize_outcome(raw) or "Unknown"
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
            if outcome == "Unknown":
                unknown_outcomes += 1
            status_indicator = "✓" if r.get("status") == "COMPLETED" else "⚠"
            print(f"  {status_indicator} {r.get('resource_name')}: {raw or 'Unknown'}")
            # Track worst known (skip Unknown)
            if outcome != "Unknown":
                worst_known_outcome = _worse(worst_known_outcome, outcome)

        print("\nOutcome Distribution:")
        for outcome, count in outcomes.items():
            print(f"  {outcome}: {count} resources")

    print(f"Unknown outcomes (non-blocking): {unknown_outcomes}")

    print(f"\nWorst known outcome across all resources: {worst_known_outcome or 'None'}")

    # ---------------------------
    # Action & Exit Logic
    # ---------------------------
    exit_code = 0

    # Threshold handling (consider only KNOWN outcomes and only completed/partial results)
    threshold = config.normalize_outcome(config.FAIL_OUTCOME_AT_OR_ABOVE) if config.FAIL_OUTCOME_AT_OR_ABOVE else ""
    breaches: List[Dict[str, Any]] = []
    if threshold:
        t_idx = config.SEVERITY_INDEX.get(threshold)
        if results_with_outcomes and t_idx is not None:
            for r in results_with_outcomes:
                r_out = config.normalize_outcome(r.get("outcome"))
                if r_out and config.SEVERITY_INDEX.get(r_out, 999) <= t_idx:
                    breaches.append(r)

        # Create GH issues if configured
        if breaches and config.ON_THRESHOLD_ACTION in ("issue", "both"):
            created_tb = create_issues_for_threshold_breaches(breaches, threshold)
            if created_tb:
                print(f"📝 Created {created_tb} GitHub issue(s) for outcome threshold breaches.")
            # Also create one issue per failed category for these executions
            created_cat = create_failed_category_issues_for_results(breaches)
            if created_cat:
                print(f"📝 Created {created_cat} per-category GitHub issue(s) via GraphQL.")

        # Decide pass/fail based on ON_THRESHOLD_ACTION
        if breaches:
            if config.ON_THRESHOLD_ACTION in ("fail", "both"):
                print(f"❌ {len(breaches)} resource(s) breached threshold {threshold.capitalize()}. Failing.")
                exit_code = 1
            else:
                print(f"ℹ️ {len(breaches)} resource(s) breached threshold {threshold.capitalize()}, but ON_THRESHOLD_ACTION={config.ON_THRESHOLD_ACTION}; not failing.")
        else:
            # No breaches detected (either all below threshold or no known outcomes)
            w_idx = _severity_idx(worst_known_outcome) if worst_known_outcome is not None else None
            if w_idx is None:
                print(f"✅ No known outcomes to compare to threshold '{threshold.capitalize()}'; passing.")
            else:
                print(f"✅ Worst known outcome {worst_known_outcome.capitalize()} is below threshold {threshold.capitalize()}. Passing.")
    else:
        print("✅ No outcome threshold set; passing regardless of outcomes.")

    # Hard failure actions: ON_HARD_FAILURES_ACTION
    if hard_failures:
        # Create issues if configured
        if config.ON_HARD_FAILURES_ACTION in ("issue", "both"):
            created_hf = create_issues_for_hard_failures(hard_failures)
            if created_hf:
                print(f"📝 Created {created_hf} GitHub issue(s) for hard failures.")

        # Fail if action demands failure
        should_fail_hard = (
            (config.ON_HARD_FAILURES_ACTION in ("fail", "both"))
        )
        if should_fail_hard:
            print(f"❌ {len(hard_failures)} hard failure(s). Failing (ON_HARD_FAILURES_ACTION={config.ON_HARD_FAILURES_ACTION}).")
            exit_code = 1
        else:
            print(f"ℹ️ {len(hard_failures)} hard failure(s), ON_HARD_FAILURES_ACTION={config.ON_HARD_FAILURES_ACTION}; not failing pipeline.")

    # Save JSON before exiting
    results_filename = "pentest_results_summary.json"
    with open(results_filename, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n[+] Detailed results saved to {results_filename}")

    return exit_code