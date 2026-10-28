# Task 13 — Python Defensive Log Analyzer Implementation & Test Report

- **Developer / Analyst Name:** Gowtham
- **Assessment Module:** Cybersecurity Assessment — Task 13 (Defensive Prototype & Unit Testing)
- **Implementation File:** `src/log_analyzer.py`
- **Unit Test File:** `tests/test_log_analyzer.py`
- **Generated Report File:** `reports/analysis_results.json`
- **Date:** 2026-10-28

---

## 1. Architecture & Workflow Overview

`src/log_analyzer.py` is a defensive command-line prototype written using Python's standard library (`argparse`, `csv`, `json`, `collections`, `datetime`, `pathlib`). It performs five sequential stages:

1. **CSV Ingestion:** Reads authentication records from the input path (`--input data/auth_logs.csv`).
2. **Schema & Value Validation:** Verifies that all five required columns (`timestamp`, `username`, `source_ip`, `event`, `result`) exist and are non-empty, validates ISO-8601 timestamps via `datetime.fromisoformat()`, normalizes usernames to lowercase so case variations (e.g., `Jordan` vs. `jordan`) are correlated accurately, and checks allowed values (`login`, `success` / `failure`). Raises `LogValidationError` on malformed input.
3. **Chronological Ordering:** Sorts all validated events by parsed timestamp before evaluating stateful sequence rules.
4. **Rule Evaluation:** Evaluates the four demonstration triage rules defined in Section 7 of the specification.
5. **JSON Report Output:** Writes a structured report (`--output reports/analysis_results.json`) containing summary metrics, configured thresholds, detailed triage alerts, and a responsible-use disclaimer.

---

## 2. Implemented Detection Rules

| Rule ID | Rule Name | Trigger Condition in Prototype | Triage Meaning |
| :--- | :--- | :--- | :--- |
| `R1_REPEATED_FAILURES` | **Repeated failures** | At least **5** failed login events from one `source_ip`. | Flag for investigation. |
| `R2_SUCCESS_AFTER_FAILURES` | **Success after failures** | At least **3** earlier failures for the same `username` + `source_ip` before a `success`. | Verify account and session. |
| `R3_MULTIPLE_ACCOUNTS` | **Multiple accounts** | One `source_ip` has activity across at least **3** distinct usernames. | Check shared-source behavior or enumeration. |
| `R4_AFTER_HOURS_SUCCESS` | **After-hours success** | Successful login (`result == "success"`) outside `06:00–22:00`. | Compare with expected schedule. |

---

## 3. Execution Commands & Console Output

### Command 1 — Run the Analyzer
```bash
python src/log_analyzer.py --input data/auth_logs.csv --output reports/analysis_results.json
```

### Actual Console Output (`reports/sample_run_output.txt`)
```text
=== Authentication Log Analyzer Summary ===
Input file        : data/auth_logs.csv
Total events      : 18 (Success: 8, Failure: 10)
Distinct accounts : 9
Distinct IPs      : 7
Total alerts      : 4
  - Repeated failures       : 1
  - Success after failures  : 1
  - Multiple accounts       : 1
  - After-hours success     : 1
JSON report saved : reports/analysis_results.json
```

---

## 4. Test Plan Execution & Results (Section 9)

### Command 2 — Run the Automated Unit Tests
```bash
python -m unittest discover -s tests -v
```

### Test Plan Verification Matrix (`T1`–`T5`)

| Test ID | Scenario | Unit Test Method | Expected Result | Actual Result |
| :--- | :--- | :--- | :--- | :--- |
| **T1** | Five failed events from one IP (`192.0.2.20`). | `test_t1_five_failed_events_from_one_ip_triggers_alert` | Repeated-failed-logins alert (`failure_count == 5`). | **PASS (`ok`)** |
| **T2** | Three failures then success for same user/IP (`maya` @ `192.0.2.20`). | `test_t2_three_failures_then_success_triggers_alert` | Success-after-failures alert (`earlier_failure_count == 3`). | **PASS (`ok`)** |
| **T3** | Only two failures from one IP (`203.0.113.12`). | `test_t3_only_two_failures_from_one_ip_no_alert` | No repeated-failure threshold alert (`len(alerts) == 0`). | **PASS (`ok`)** |
| **T4** | Successful login at `23:48` in sample data (`jordan` @ `203.0.113.88`). | `test_t4_successful_login_at_2348_triggers_after_hours_alert` | After-hours triage alert (`R4_AFTER_HOURS_SUCCESS`). | **PASS (`ok`)** |
| **T5** | Missing required CSV column or invalid ISO timestamp. | `test_t5_missing_required_column_or_invalid_timestamp_raises_error` | Raises `LogValidationError` input validation error. | **PASS (`ok`)** |

---

## 5. Limitations & Responsible Deployment Notes

- **Synthetic Scope:** `data/auth_logs.csv` is a small synthetic dataset designed to validate rule logic and triage workflows; it does not represent production traffic volume.
- **No Time-Windowed Rate Calculation:** The prototype counts total failures per IP or prior to a success across the file rather than sliding time windows (e.g., 5 failures within 60 seconds).
- **Static Business Hours:** The `06:00–22:00` window does not account for global time zones, shift workers, or automated service accounts.
- **Triage Indicator Only:** Alerts generated by `src/log_analyzer.py` are triage indicators, not proof of compromise or attribution. Always corroborate with MFA, session, device, and network ownership records before taking containment actions.
