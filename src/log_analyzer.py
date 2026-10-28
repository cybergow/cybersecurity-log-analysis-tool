#!/usr/bin/env python3
"""
Cybersecurity Assessment — Task 13: Defensive Authentication Log Analyzer Prototype.

Reads authentication events from a CSV file, validates required columns and values,
sorts events chronologically by ISO-8601 timestamp, evaluates four defensive triage
detection rules, and writes a structured JSON report. Uses only Python's standard library.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, time
from pathlib import Path
from typing import Any, Dict, Iterable, List

REQUIRED_COLUMNS = ("timestamp", "username", "source_ip", "event", "result")
ALLOWED_EVENTS = {"login"}
ALLOWED_RESULTS = {"success", "failure"}

REPEATED_FAILURE_THRESHOLD = 5
SUCCESS_AFTER_FAILURES_THRESHOLD = 3
MULTIPLE_ACCOUNTS_THRESHOLD = 3
NORMAL_HOURS_START = time(6, 0, 0)
NORMAL_HOURS_END = time(22, 0, 0)


class LogValidationError(ValueError):
    """Raised when the input CSV is missing required columns or contains invalid values."""


def parse_timestamp(raw_ts: str, row_num: int = 0) -> datetime:
    """Parse an ISO-8601 timestamp string and raise LogValidationError if invalid."""
    if not raw_ts or not raw_ts.strip():
        raise LogValidationError(f"Row {row_num}: Missing timestamp value.")
    cleaned = raw_ts.strip()
    try:
        return datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise LogValidationError(
            f"Row {row_num}: Invalid ISO-8601 timestamp '{raw_ts}'."
        ) from exc


def validate_and_normalize_rows(rows: Iterable[Dict[str, Any]], fieldnames: Iterable[str] | None) -> List[Dict[str, Any]]:
    """Validate CSV headers and row values, returning events sorted by timestamp."""
    if fieldnames is None:
        raise LogValidationError("CSV file is empty or missing a header row.")

    present_columns = [col.strip() for col in fieldnames if col is not None]
    missing = [col for col in REQUIRED_COLUMNS if col not in present_columns]
    if missing:
        raise LogValidationError(
            f"Missing required CSV column(s): {', '.join(missing)}"
        )

    normalized: List[Dict[str, Any]] = []
    for index, raw_row in enumerate(rows, start=2):
        row = {k.strip(): (v.strip() if isinstance(v, str) else "") for k, v in raw_row.items() if k is not None}

        for col in REQUIRED_COLUMNS:
            if not row.get(col):
                raise LogValidationError(f"Row {index}: Missing value for required column '{col}'.")

        parsed_dt = parse_timestamp(row["timestamp"], row_num=index)
        event_type = row["event"].lower()
        result_type = row["result"].lower()

        if event_type not in ALLOWED_EVENTS:
            raise LogValidationError(
                f"Row {index}: Invalid event type '{row['event']}'. Expected one of {sorted(ALLOWED_EVENTS)}."
            )
        if result_type not in ALLOWED_RESULTS:
            raise LogValidationError(
                f"Row {index}: Invalid result '{row['result']}'. Expected one of {sorted(ALLOWED_RESULTS)}."
            )

        normalized.append(
            {
                "timestamp": row["timestamp"],
                "_dt": parsed_dt,
                "username": row["username"].lower(),
                "source_ip": row["source_ip"],
                "event": event_type,
                "result": result_type,
            }
        )

    normalized.sort(key=lambda item: item["_dt"])
    return normalized


def load_csv_events(csv_path: str | Path) -> List[Dict[str, Any]]:
    """Read and validate authentication events from a CSV file path."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Input CSV file not found: {path}")

    with path.open(mode="r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return validate_and_normalize_rows(reader, reader.fieldnames)


def evaluate_rules(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluate the four demonstration detection rules on chronologically sorted events:
      1. Repeated failures: At least 5 failed login events from one IP.
      2. Success after failures: At least 3 earlier failures for the same username/IP before a success.
      3. Multiple accounts: One IP has activity for at least 3 distinct usernames.
      4. After-hours success: Successful login outside 06:00-22:00.
    """
    alerts: List[Dict[str, Any]] = []

    # Rule 1: Repeated failures by source_ip (>= 5 failed login events)
    failures_by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev["result"] == "failure":
            failures_by_ip[ev["source_ip"]].append(ev)

    for source_ip, fail_events in sorted(failures_by_ip.items()):
        if len(fail_events) >= REPEATED_FAILURE_THRESHOLD:
            touched_users = sorted({e["username"] for e in fail_events})
            alerts.append(
                {
                    "rule_id": "R1_REPEATED_FAILURES",
                    "rule": "Repeated failures",
                    "severity": "medium",
                    "source_ip": source_ip,
                    "usernames": touched_users,
                    "failure_count": len(fail_events),
                    "first_seen": fail_events[0]["timestamp"],
                    "last_seen": fail_events[-1]["timestamp"],
                    "meaning": "Flag for investigation.",
                    "possible_interpretation": "Password mistakes or guessing activity.",
                    "recommended_followup": "Check account, MFA, source ownership, and rate limiting.",
                }
            )

    # Rule 2: Success after failures (>= 3 earlier failures for the same username/IP before a success)
    prior_failures_by_pair: Dict[tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for ev in events:
        pair = (ev["username"], ev["source_ip"])
        if ev["result"] == "failure":
            prior_failures_by_pair[pair].append(ev)
        elif ev["result"] == "success":
            earlier_failures = prior_failures_by_pair[pair]
            if len(earlier_failures) >= SUCCESS_AFTER_FAILURES_THRESHOLD:
                alerts.append(
                    {
                        "rule_id": "R2_SUCCESS_AFTER_FAILURES",
                        "rule": "Success after failures",
                        "severity": "high",
                        "username": ev["username"],
                        "source_ip": ev["source_ip"],
                        "earlier_failure_count": len(earlier_failures),
                        "first_failure_timestamp": earlier_failures[0]["timestamp"],
                        "success_timestamp": ev["timestamp"],
                        "meaning": "Verify account and session.",
                        "possible_interpretation": "Could be legitimate recovery or successful guessing.",
                        "recommended_followup": "Verify with user; review session/device records.",
                    }
                )
            prior_failures_by_pair[pair] = []

    # Rule 3: Multiple accounts (One IP has activity for at least 3 distinct usernames)
    users_by_ip: Dict[str, set[str]] = defaultdict(set)
    events_by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ev in events:
        users_by_ip[ev["source_ip"]].add(ev["username"])
        events_by_ip[ev["source_ip"]].append(ev)

    for source_ip, user_set in sorted(users_by_ip.items()):
        if len(user_set) >= MULTIPLE_ACCOUNTS_THRESHOLD:
            ip_events = events_by_ip[source_ip]
            alerts.append(
                {
                    "rule_id": "R3_MULTIPLE_ACCOUNTS",
                    "rule": "Multiple accounts",
                    "severity": "medium",
                    "source_ip": source_ip,
                    "distinct_username_count": len(user_set),
                    "usernames": sorted(user_set),
                    "total_events": len(ip_events),
                    "first_seen": ip_events[0]["timestamp"],
                    "last_seen": ip_events[-1]["timestamp"],
                    "meaning": "Check shared-source behavior or enumeration.",
                    "possible_interpretation": "Could be enumeration or a shared VPN/NAT source.",
                    "recommended_followup": "Confirm network ownership and expected usage.",
                }
            )

    # Rule 4: After-hours success (Successful login outside 06:00-22:00)
    for ev in events:
        if ev["result"] == "success":
            ev_time = ev["_dt"].time()
            is_outside_hours = ev_time < NORMAL_HOURS_START or ev_time > NORMAL_HOURS_END
            if is_outside_hours:
                alerts.append(
                    {
                        "rule_id": "R4_AFTER_HOURS_SUCCESS",
                        "rule": "After-hours success",
                        "severity": "low",
                        "username": ev["username"],
                        "source_ip": ev["source_ip"],
                        "timestamp": ev["timestamp"],
                        "normal_window": "06:00-22:00",
                        "meaning": "Compare with expected schedule.",
                        "possible_interpretation": "May be unusual for that account.",
                        "recommended_followup": "Compare schedule and approved remote access.",
                    }
                )

    total_failures = sum(1 for e in events if e["result"] == "failure")
    total_successes = sum(1 for e in events if e["result"] == "success")
    rule_counts = {
        "Repeated failures": sum(1 for a in alerts if a["rule"] == "Repeated failures"),
        "Success after failures": sum(1 for a in alerts if a["rule"] == "Success after failures"),
        "Multiple accounts": sum(1 for a in alerts if a["rule"] == "Multiple accounts"),
        "After-hours success": sum(1 for a in alerts if a["rule"] == "After-hours success"),
    }

    clean_events = [
        {k: v for k, v in e.items() if k != "_dt"}
        for e in events
    ]

    return {
        "summary": {
            "total_events": len(clean_events),
            "total_failures": total_failures,
            "total_successes": total_successes,
            "distinct_users": len({e["username"] for e in clean_events}),
            "distinct_ips": len({e["source_ip"] for e in clean_events}),
            "total_alerts": len(alerts),
            "alerts_by_rule": rule_counts,
        },
        "thresholds": {
            "repeated_failures_min": REPEATED_FAILURE_THRESHOLD,
            "success_after_failures_min": SUCCESS_AFTER_FAILURES_THRESHOLD,
            "multiple_accounts_min": MULTIPLE_ACCOUNTS_THRESHOLD,
            "normal_hours_window": "06:00-22:00",
        },
        "alerts": alerts,
        "disclaimer": (
            "These are demonstration triage rules. Alerts do not prove compromise "
            "or attribute an actor; corroborate with MFA, session, device, and network context."
        ),
    }


def analyze_csv(input_path: str | Path, output_path: str | Path | None = None) -> Dict[str, Any]:
    """Load events from CSV, evaluate rules, and optionally write JSON report to output_path."""
    events = load_csv_events(input_path)
    report = evaluate_rules(events)
    report["input_file"] = str(input_path)

    if output_path is not None:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")

    return report


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs CSV and generate a JSON triage report."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to input authentication logs CSV (e.g. data/auth_logs.csv)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to output JSON report (e.g. reports/analysis_results.json)",
    )
    args = parser.parse_args(argv)

    report = analyze_csv(args.input, args.output)
    summary = report["summary"]

    print("=== Authentication Log Analyzer Summary ===")
    print(f"Input file        : {args.input}")
    print(f"Total events      : {summary['total_events']} (Success: {summary['total_successes']}, Failure: {summary['total_failures']})")
    print(f"Distinct accounts : {summary['distinct_users']}")
    print(f"Distinct IPs      : {summary['distinct_ips']}")
    print(f"Total alerts      : {summary['total_alerts']}")
    for rule_name, count in summary["alerts_by_rule"].items():
        print(f"  - {rule_name:<24}: {count}")
    print(f"JSON report saved : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
