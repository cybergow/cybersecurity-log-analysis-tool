import { AnalysisReport, formatConsoleSummary } from '../utils/logAnalyzer';

export interface AnalystProfile {
  analystName: string;
  studentId: string;
  courseCohort: string;
  submissionDate: string;
}

export const DEFAULT_ANALYST_PROFILE: AnalystProfile = {
  analystName: 'Gowtham',
  studentId: 'CS-2026-0613',
  courseCohort: 'Cybersecurity Assessment — Tasks 6 & 13',
  submissionDate: '2026-10-28',
};

export const DEFAULT_AUTH_LOGS_CSV = `timestamp,username,source_ip,event,result
2026-10-27T08:15:04,elena,192.0.2.10,login,success
2026-10-27T08:42:19,carlos,192.0.2.14,login,success
2026-10-27T09:02:11,maya,192.0.2.20,login,failure
2026-10-27T09:02:24,maya,192.0.2.20,login,failure
2026-10-27T09:02:38,maya,192.0.2.20,login,failure
2026-10-27T09:02:51,maya,192.0.2.20,login,failure
2026-10-27T09:03:05,maya,192.0.2.20,login,failure
2026-10-27T09:03:42,maya,192.0.2.20,login,success
2026-10-27T10:14:05,alex,198.51.100.45,login,failure
2026-10-27T10:14:32,devon,198.51.100.45,login,failure
2026-10-27T10:15:09,priya,198.51.100.45,login,failure
2026-10-27T10:15:44,sam,198.51.100.45,login,success
2026-10-27T11:20:10,liam,203.0.113.12,login,failure
2026-10-27T11:20:28,liam,203.0.113.12,login,failure
2026-10-27T11:21:02,liam,203.0.113.12,login,success
2026-10-27T14:05:33,elena,192.0.2.10,login,success
2026-10-27T16:49:12,jordan,192.0.2.18,login,success
2026-10-27T23:48:19,jordan,203.0.113.88,login,success`;

export interface ScenarioPreset {
  id: string;
  label: string;
  shortTag: string;
  description: string;
  csv: string;
}

export const SCENARIO_PRESETS: ScenarioPreset[] = [
  {
    id: 'default',
    label: 'Full Sample Dataset (data/auth_logs.csv)',
    shortTag: 'Default (18 rows)',
    description: 'Complete synthetic dataset demonstrating all 4 detection rules plus baseline normal traffic.',
    csv: DEFAULT_AUTH_LOGS_CSV,
  },
  {
    id: 'T1',
    label: 'T1: Repeated Failures (5 failures from 192.0.2.20)',
    shortTag: 'T1: 5 Failures',
    description: 'Five failed login events from one IP (192.0.2.20) triggering the Repeated-failed-logins alert.',
    csv: `timestamp,username,source_ip,event,result
2026-10-27T09:02:11,maya,192.0.2.20,login,failure
2026-10-27T09:02:24,maya,192.0.2.20,login,failure
2026-10-27T09:02:38,maya,192.0.2.20,login,failure
2026-10-27T09:02:51,maya,192.0.2.20,login,failure
2026-10-27T09:03:05,maya,192.0.2.20,login,failure`,
  },
  {
    id: 'T2',
    label: 'T2: Success After 3 Failures (maya @ 192.0.2.20)',
    shortTag: 'T2: 3 Fail + Success',
    description: 'Three failures followed by a successful login for the same user and IP.',
    csv: `timestamp,username,source_ip,event,result
2026-10-27T09:02:11,maya,192.0.2.20,login,failure
2026-10-27T09:02:25,maya,192.0.2.20,login,failure
2026-10-27T09:02:40,maya,192.0.2.20,login,failure
2026-10-27T09:03:01,maya,192.0.2.20,login,success`,
  },
  {
    id: 'T3',
    label: 'T3: Below Threshold (Only 2 failures from 203.0.113.12)',
    shortTag: 'T3: 2 Failures (No Alert)',
    description: 'Only two failed login events from one IP — verifies no false-positive threshold alert fires.',
    csv: `timestamp,username,source_ip,event,result
2026-10-27T11:20:10,liam,203.0.113.12,login,failure
2026-10-27T11:20:28,liam,203.0.113.12,login,failure`,
  },
  {
    id: 'T4',
    label: 'T4: After-Hours Login at 23:48 (jordan @ 203.0.113.88)',
    shortTag: 'T4: 23:48 Login',
    description: 'Successful login at 23:48 outside the assumed 06:00–22:00 normal window.',
    csv: `timestamp,username,source_ip,event,result
2026-10-27T23:48:19,jordan,203.0.113.88,login,success`,
  },
  {
    id: 'T5',
    label: 'T5: Malformed CSV / Invalid Timestamp Error',
    shortTag: 'T5: Validation Error',
    description: 'Demonstrates input validation error when a timestamp is malformed or a required column is missing.',
    csv: `timestamp,username,source_ip,event,result
not-an-iso-timestamp,maya,192.0.2.20,login,failure`,
  },
];

export interface Task6QuestionAnalysis {
  id: string;
  question: string;
  evidenceSummary: string;
  fact: string;
  hypothesis: string;
  conclusionGuidance: string;
  followUp: string;
  relatedIp: string;
  relatedUsers: string[];
  matchingTimestamps: string[];
}

export const TASK6_QUESTIONS: Task6QuestionAnalysis[] = [
  {
    id: 'Q1',
    question: 'Are there repeated failed logins from one IP?',
    evidenceSummary: 'Repeated failures from one IP (192.0.2.20 recorded 5 consecutive failures).',
    fact: 'Five login failure events for account maya were recorded from source IP 192.0.2.20 between 09:02:11 and 09:03:05 (54 seconds). IP 203.0.113.12 recorded only 2 failures for liam.',
    hypothesis: 'Password mistakes, a client retrying an expired cached credential, or automated/manual password guessing activity targeting maya.',
    conclusionGuidance: 'Cannot conclude a brute-force attack from log count alone; requires checking whether 192.0.2.20 is known to the user and whether MFA or lockout controls triggered.',
    followUp: 'Check account, MFA, source ownership, and rate limiting.',
    relatedIp: '192.0.2.20',
    relatedUsers: ['maya'],
    matchingTimestamps: [
      '2026-10-27T09:02:11',
      '2026-10-27T09:02:24',
      '2026-10-27T09:02:38',
      '2026-10-27T09:02:51',
      '2026-10-27T09:03:05',
    ],
  },
  {
    id: 'Q2',
    question: 'Does a successful login follow repeated failures for the same account and IP?',
    evidenceSummary: 'Success after repeated failures (maya succeeded at 09:03:42 from 192.0.2.20 after 5 failures).',
    fact: 'At 2026-10-27T09:03:42, a login success event was recorded for maya from 192.0.2.20, 37 seconds after the fifth consecutive failure from the same IP and username.',
    hypothesis: 'Could be legitimate password recovery/recall by maya after mistyping, or successful credential guessing on the sixth attempt.',
    conclusionGuidance: 'High-priority triage indicator. Requires out-of-band user confirmation and device/session inspection before declaring account takeover.',
    followUp: 'Verify with user; review session/device records.',
    relatedIp: '192.0.2.20',
    relatedUsers: ['maya'],
    matchingTimestamps: ['2026-10-27T09:03:42'],
  },
  {
    id: 'Q3',
    question: 'Does one IP attempt logins for several usernames?',
    evidenceSummary: 'One IP touches several usernames (198.51.100.45 touched 4 accounts: alex, devon, priya, sam).',
    fact: 'Source IP 198.51.100.45 recorded login events for 4 distinct usernames within 99 seconds (10:14:05 to 10:15:44): failures for alex, devon, and priya, followed by a success for sam.',
    hypothesis: 'Could be horizontal username enumeration / password spraying, or legitimate multi-user traffic behind a shared corporate VPN, campus proxy, or NAT gateway.',
    conclusionGuidance: 'Compare 198.51.100.45 against network asset records first; a shared NAT gateway naturally aggregates multiple employees onto one egress IP.',
    followUp: 'Confirm network ownership and expected usage.',
    relatedIp: '198.51.100.45',
    relatedUsers: ['alex', 'devon', 'priya', 'sam'],
    matchingTimestamps: [
      '2026-10-27T10:14:05',
      '2026-10-27T10:14:32',
      '2026-10-27T10:15:09',
      '2026-10-27T10:15:44',
    ],
  },
  {
    id: 'Q4',
    question: 'Are successful logins outside the assumed normal-hours window?',
    evidenceSummary: 'Successful login at an unusual hour (jordan logged in at 23:48:19 from 203.0.113.88).',
    fact: 'At 2026-10-27T23:48:19 (outside the 06:00–22:00 window), a successful login was recorded for jordan from 203.0.113.88, whereas jordan earlier logged in at 16:49:12 from 192.0.2.18.',
    hypothesis: 'May be unusual off-hours access for that account, or authorized late-night remote work / on-call maintenance from a home ISP.',
    conclusionGuidance: 'Timestamp alone does not prove unauthorized access; correlate with shift schedules, approved remote access, and MFA device logs.',
    followUp: 'Compare schedule and approved remote access.',
    relatedIp: '203.0.113.88',
    relatedUsers: ['jordan'],
    matchingTimestamps: ['2026-10-27T23:48:19'],
  },
];

export const PYTHON_LOG_ANALYZER_CODE = `#!/usr/bin/env python3
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
            handle.write("\\n")

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
`;

export const PYTHON_UNIT_TEST_CODE = `"""
Unit tests for Task 13 authentication log analyzer (tests/test_log_analyzer.py).
Covers T1 through T5 from Section 9 (Test Plan) of the workflow guide.
"""

import unittest
from src.log_analyzer import (
    LogValidationError,
    evaluate_rules,
    validate_and_normalize_rows,
)


REQUIRED_FIELDS = ["timestamp", "username", "source_ip", "event", "result"]


class TestLogAnalyzer(unittest.TestCase):
    """Test suite verifying detection thresholds and input validation (T1-T5)."""

    def test_t1_five_failed_events_from_one_ip_triggers_alert(self) -> None:
        """T1: Five failed events from one IP -> Repeated-failed-logins alert."""
        raw_rows = [
            {
                "timestamp": f"2026-10-27T09:02:1{i}",
                "username": "maya",
                "source_ip": "192.0.2.20",
                "event": "login",
                "result": "failure",
            }
            for i in range(1, 6)
        ]
        events = validate_and_normalize_rows(raw_rows, REQUIRED_FIELDS)
        report = evaluate_rules(events)
        repeated_alerts = [
            a for a in report["alerts"] if a["rule"] == "Repeated failures"
        ]
        self.assertEqual(len(repeated_alerts), 1)
        self.assertEqual(repeated_alerts[0]["source_ip"], "192.0.2.20")
        self.assertEqual(repeated_alerts[0]["failure_count"], 5)

    def test_t2_three_failures_then_success_triggers_alert(self) -> None:
        """T2: Three failures then success for same user/IP -> Success-after-failures alert."""
        raw_rows = [
            {
                "timestamp": "2026-10-27T09:02:11",
                "username": "maya",
                "source_ip": "192.0.2.20",
                "event": "login",
                "result": "failure",
            },
            {
                "timestamp": "2026-10-27T09:02:25",
                "username": "maya",
                "source_ip": "192.0.2.20",
                "event": "login",
                "result": "failure",
            },
            {
                "timestamp": "2026-10-27T09:02:40",
                "username": "maya",
                "source_ip": "192.0.2.20",
                "event": "login",
                "result": "failure",
            },
            {
                "timestamp": "2026-10-27T09:03:01",
                "username": "maya",
                "source_ip": "192.0.2.20",
                "event": "login",
                "result": "success",
            },
        ]
        events = validate_and_normalize_rows(raw_rows, REQUIRED_FIELDS)
        report = evaluate_rules(events)
        saf_alerts = [
            a for a in report["alerts"] if a["rule"] == "Success after failures"
        ]
        self.assertEqual(len(saf_alerts), 1)
        self.assertEqual(saf_alerts[0]["username"], "maya")
        self.assertEqual(saf_alerts[0]["earlier_failure_count"], 3)

    def test_t3_only_two_failures_from_one_ip_no_alert(self) -> None:
        """T3: Only two failures from one IP -> No repeated-failure threshold alert."""
        raw_rows = [
            {
                "timestamp": "2026-10-27T11:20:10",
                "username": "liam",
                "source_ip": "203.0.113.12",
                "event": "login",
                "result": "failure",
            },
            {
                "timestamp": "2026-10-27T11:20:28",
                "username": "liam",
                "source_ip": "203.0.113.12",
                "event": "login",
                "result": "failure",
            },
        ]
        events = validate_and_normalize_rows(raw_rows, REQUIRED_FIELDS)
        report = evaluate_rules(events)
        self.assertEqual(len(report["alerts"]), 0)

    def test_t4_successful_login_at_2348_triggers_after_hours_alert(self) -> None:
        """T4: Successful login at 23:48 in sample data -> After-hours triage alert."""
        raw_rows = [
            {
                "timestamp": "2026-10-27T23:48:19",
                "username": "jordan",
                "source_ip": "203.0.113.88",
                "event": "login",
                "result": "success",
            }
        ]
        events = validate_and_normalize_rows(raw_rows, REQUIRED_FIELDS)
        report = evaluate_rules(events)
        after_hours = [
            a for a in report["alerts"] if a["rule"] == "After-hours success"
        ]
        self.assertEqual(len(after_hours), 1)
        self.assertEqual(after_hours[0]["username"], "jordan")
        self.assertEqual(after_hours[0]["timestamp"], "2026-10-27T23:48:19")

    def test_t5_missing_required_column_or_invalid_timestamp_raises_error(self) -> None:
        """T5: Missing required CSV column or invalid timestamp -> Input validation error."""
        incomplete_fields = ["timestamp", "username", "event", "result"]
        with self.assertRaises(LogValidationError):
            validate_and_normalize_rows([], incomplete_fields)

        bad_timestamp_rows = [
            {
                "timestamp": "not-a-timestamp",
                "username": "maya",
                "source_ip": "192.0.2.20",
                "event": "login",
                "result": "failure",
            }
        ]
        with self.assertRaises(LogValidationError):
            validate_and_normalize_rows(bad_timestamp_rows, REQUIRED_FIELDS)


if __name__ == "__main__":
    unittest.main()
`;

export const SAVED_UNITTEST_OUTPUT = `test_t1_five_failed_events_from_one_ip_triggers_alert (test_log_analyzer.TestLogAnalyzer)
T1: Five failed events from one IP -> Repeated-failed-logins alert. ... ok
test_t2_three_failures_then_success_triggers_alert (test_log_analyzer.TestLogAnalyzer)
T2: Three failures then success for same user/IP -> Success-after-failures alert. ... ok
test_t3_only_two_failures_from_one_ip_no_alert (test_log_analyzer.TestLogAnalyzer)
T3: Only two failures from one IP -> No repeated-failure threshold alert. ... ok
test_t4_successful_login_at_2348_triggers_after_hours_alert (test_log_analyzer.TestLogAnalyzer)
T4: Successful login at 23:48 in sample data -> After-hours triage alert. ... ok
test_t5_missing_required_column_or_invalid_timestamp_raises_error (test_log_analyzer.TestLogAnalyzer)
T5: Missing required CSV column or invalid timestamp -> Input validation error. ... ok

----------------------------------------------------------------------
Ran 5 tests in 0.001s

OK`;

export interface ExpectedProjectFile {
  path: string;
  purpose: string;
  language: 'markdown' | 'csv' | 'python' | 'json' | 'text';
  content: string;
  deliverableTask: 'Shared' | 'Task 6' | 'Task 13';
}

export function buildTask6ReportMarkdown(profile: AnalystProfile): string {
  return `# Task 6 — Manual Authentication Log Investigation Report

- **Analyst Name:** ${profile.analystName}
- **Candidate / Student ID:** ${profile.studentId}
- **Assessment Module:** ${profile.courseCohort} — Task 6 (Security-Log Analysis)
- **Dataset Analyzed:** \`data/auth_logs.csv\` (18 synthetic authentication events)
- **Date of Analysis:** ${profile.submissionDate}

---

## 1. Executive Summary & Analytical Posture

For Task 6, \`data/auth_logs.csv\` was manually reviewed to identify suspicious authentication patterns, separate directly observable **facts** from **hypotheses**, and specify the corroborating evidence required before reaching a **conclusion** or declaring a security incident.

A small authentication log establishes what was recorded by the authentication service at specific timestamps, but does not by itself establish actor intent, credential compromise, or who controlled a source IP address.

---

## 2. Answers to the Four Investigation Questions

### Question 1: Are there repeated failed logins from one IP?
- **Fact (Directly visible in logs):** Yes. Source IP \`192.0.2.20\` recorded **5 consecutive login failures** for username \`maya\` within a 54-second window between \`2026-10-27T09:02:11\` and \`2026-10-27T09:03:05\`. Additionally, \`198.51.100.45\` recorded 3 failed logins across distinct usernames, and \`203.0.113.12\` recorded 2 failed logins for \`liam\` (below the 5-failure threshold).
- **Hypothesis (Possible interpretation):** The burst from \`192.0.2.20\` could represent manual password entry mistakes, a misconfigured saved credential client, or automated/manual password guessing against \`maya\`.
- **Follow-up / Corroboration Required:** Check account status for \`maya\`, inspect MFA challenge logs, verify ownership/geolocation of \`192.0.2.20\`, and confirm whether authentication rate limiting or account lockout controls are active.

### Question 2: Does a successful login follow repeated failures for the same account and IP?
- **Fact (Directly visible in logs):** Yes. At \`2026-10-27T09:03:42\`, username \`maya\` recorded a \`login,success\` event from \`192.0.2.20\` immediately following the 5 consecutive failures from that same IP (\`09:02:11\`–\`09:03:05\`). By contrast, \`liam\` at \`203.0.113.12\` had only 2 failures (\`11:20:10\`, \`11:20:28\`) before a success at \`11:21:02\`.
- **Hypothesis (Possible interpretation):** Either \`maya\` legitimately recalled or reset their password after mistyping it five times, or an unauthorized party successfully guessed the password on the sixth attempt.
- **Follow-up / Corroboration Required:** Contact \`maya\` out-of-band to verify whether the \`09:03:42\` login was legitimate; inspect MFA completion telemetry, session creation IDs, User-Agent/device identifiers, and post-login activity.

### Question 3: Does one IP attempt logins for several usernames?
- **Fact (Directly visible in logs):** Yes. Source IP \`198.51.100.45\` attempted logins against **4 distinct usernames** inside a 99-second window:
  - \`2026-10-27T10:14:05\` — \`alex\` (\`failure\`)
  - \`2026-10-27T10:14:32\` — \`devon\` (\`failure\`)
  - \`2026-10-27T10:15:09\` — \`priya\` (\`failure\`)
  - \`2026-10-27T10:15:44\` — \`sam\` (\`success\`)
- **Hypothesis (Possible interpretation):** This pattern could indicate horizontal account enumeration / password spraying across multiple user accounts, or it could be normal traffic originating from a shared corporate NAT gateway, campus proxy, or VPN concentrator.
- **Follow-up / Corroboration Required:** Check network asset inventory to determine whether \`198.51.100.45\` is an approved corporate egress, VPN, or NAT address; verify \`sam\`'s successful session at \`10:15:44\` and check device fingerprints across the four attempts.

### Question 4: Are successful logins outside the assumed normal-hours window (06:00–22:00)?
- **Fact (Directly visible in logs):** Yes. At \`2026-10-27T23:48:19\`, username \`jordan\` recorded a \`login,success\` event from source IP \`203.0.113.88\`, which falls outside the assumed \`06:00–22:00\` business-hours window. Earlier in the day (\`16:49:12\`), \`jordan\` logged in from \`192.0.2.18\`.
- **Hypothesis (Possible interpretation):** The \`23:48:19\` login from a different IP (\`203.0.113.88\`) may be legitimate late-night remote work, travel across time zones, an approved maintenance window, or unauthorized off-hours access.
- **Follow-up / Corroboration Required:** Compare \`23:48:19\` against \`jordan\`'s shift schedule, on-call rotation, and approved remote access logs; confirm whether \`203.0.113.88\` matches \`jordan\`'s home ISP or travel location.

---

## 3. Evidence, Interpretation, and Follow-Up Matrix

| Evidence Observed in \`data/auth_logs.csv\` | Specific Log Rows & Entities | Possible Interpretation (Hypothesis) | Recommended Follow-Up Action |
| :--- | :--- | :--- | :--- |
| **Repeated failures from one IP** | \`192.0.2.20\` (\`maya\`, 5 failures from \`09:02:11\` to \`09:03:05\`) | Password mistakes, cached credential failure, or password guessing activity. | Check account status, MFA logs, source IP ownership, and rate limiting. |
| **Success after repeated failures** | \`192.0.2.20\` (\`maya\`, \`login,success\` at \`09:03:42\` after 5 failures) | Could be legitimate password recovery/recall or successful password guessing. | Verify directly with user \`maya\`; review session creation and device records. |
| **One IP touches several usernames** | \`198.51.100.45\` (\`alex\`, \`devon\`, \`priya\` failures; \`sam\` success \`10:14:05\`–\`10:15:44\`) | Could be username enumeration / password spraying or a shared VPN/NAT source. | Confirm network ownership of \`198.51.100.45\` and verify \`sam\`'s session. |
| **Successful login at an unusual hour** | \`203.0.113.88\` (\`jordan\`, \`login,success\` at \`23:48:19\`, outside \`06:00–22:00\`) | May be unusual off-hours access for that account or legitimate remote work. | Compare with \`jordan\`'s work schedule and approved remote access records. |

---

## 4. Recommended Investigation Actions

1. **Validate Network Context:** Check whether \`192.0.2.20\`, \`198.51.100.45\`, and \`203.0.113.88\` belong to an approved VPN concentrator, corporate NAT gateway, campus network, or known employee ISP.
2. **Correlate Identity & Endpoint Telemetry:** Review MFA challenge outcomes, session tokens, User-Agent strings, device identifiers, and endpoint detection (EDR) alerts around \`09:03:42\` (\`maya\`), \`10:15:44\` (\`sam\`), and \`23:48:19\` (\`jordan\`).
3. **Out-of-Band User Verification:** Ask account owners (\`maya\`, \`sam\`, \`jordan\`) via a trusted secondary channel to verify whether the successful logins were initiated by them.
4. **Evidence Preservation:** Preserve the raw authentication logs (\`data/auth_logs.csv\`) and document triage timestamps and rationale in the ticketing system.
5. **Defensive Hardening:** Recommend progressive rate limiting, MFA enforcement on all external logins, and anomaly detection tuned to organizational baselines where justified.
`;
}

export function buildTask13ReportMarkdown(profile: AnalystProfile, consoleOutput: string): string {
  return `# Task 13 — Python Defensive Log Analyzer Implementation & Test Report

- **Developer / Analyst Name:** ${profile.analystName}
- **Candidate / Student ID:** ${profile.studentId}
- **Assessment Module:** ${profile.courseCohort} — Task 13 (Defensive Prototype & Unit Testing)
- **Implementation File:** \`src/log_analyzer.py\`
- **Unit Test File:** \`tests/test_log_analyzer.py\`
- **Generated Report File:** \`reports/analysis_results.json\`
- **Date:** ${profile.submissionDate}

---

## 1. Architecture & Workflow Overview

\`src/log_analyzer.py\` is a defensive command-line prototype written using Python's standard library (\`argparse\`, \`csv\`, \`json\`, \`collections\`, \`datetime\`, \`pathlib\`). It performs five sequential stages:

1. **CSV Ingestion:** Reads authentication records from the input path (\`--input data/auth_logs.csv\`).
2. **Schema & Value Validation:** Verifies that all five required columns (\`timestamp\`, \`username\`, \`source_ip\`, \`event\`, \`result\`) exist and are non-empty, validates ISO-8601 timestamps via \`datetime.fromisoformat()\`, normalizes usernames to lowercase, and checks allowed values (\`login\`, \`success\` / \`failure\`). Raises \`LogValidationError\` on malformed input.
3. **Chronological Ordering:** Sorts all validated events by parsed timestamp before evaluating stateful sequence rules.
4. **Rule Evaluation:** Evaluates the four demonstration triage rules defined in Section 7 of the specification.
5. **JSON Report Output:** Writes a structured report (\`--output reports/analysis_results.json\`) containing summary metrics, configured thresholds, detailed triage alerts, and a responsible-use disclaimer.

---

## 2. Implemented Detection Rules

| Rule ID | Rule Name | Trigger Condition in Prototype | Triage Meaning |
| :--- | :--- | :--- | :--- |
| \`R1_REPEATED_FAILURES\` | **Repeated failures** | At least **5** failed login events from one \`source_ip\`. | Flag for investigation. |
| \`R2_SUCCESS_AFTER_FAILURES\` | **Success after failures** | At least **3** earlier failures for the same \`username\` + \`source_ip\` before a \`success\`. | Verify account and session. |
| \`R3_MULTIPLE_ACCOUNTS\` | **Multiple accounts** | One \`source_ip\` has activity across at least **3** distinct usernames. | Check shared-source behavior or enumeration. |
| \`R4_AFTER_HOURS_SUCCESS\` | **After-hours success** | Successful login (\`result == "success"\`) outside \`06:00–22:00\`. | Compare with expected schedule. |

---

## 3. Execution Commands & Console Output

### Command 1 — Run the Analyzer
\`\`\`bash
python src/log_analyzer.py --input data/auth_logs.csv --output reports/analysis_results.json
\`\`\`

### Actual Console Output (\`reports/sample_run_output.txt\`)
\`\`\`text
${consoleOutput}
\`\`\`

---

## 4. Test Plan Execution & Results (Section 9)

### Command 2 — Run the Automated Unit Tests
\`\`\`bash
python -m unittest discover -s tests -v
\`\`\`

### Test Plan Verification Matrix (\`T1\`–\`T5\`)

| Test ID | Scenario | Unit Test Method | Expected Result | Actual Result |
| :--- | :--- | :--- | :--- | :--- |
| **T1** | Five failed events from one IP (\`192.0.2.20\`). | \`test_t1_five_failed_events_from_one_ip_triggers_alert\` | Repeated-failed-logins alert (\`failure_count == 5\`). | **PASS (\`ok\`)** |
| **T2** | Three failures then success for same user/IP (\`maya\` @ \`192.0.2.20\`). | \`test_t2_three_failures_then_success_triggers_alert\` | Success-after-failures alert (\`earlier_failure_count == 3\`). | **PASS (\`ok\`)** |
| **T3** | Only two failures from one IP (\`203.0.113.12\`). | \`test_t3_only_two_failures_from_one_ip_no_alert\` | No repeated-failure threshold alert (\`len(alerts) == 0\`). | **PASS (\`ok\`)** |
| **T4** | Successful login at \`23:48\` in sample data (\`jordan\` @ \`203.0.113.88\`). | \`test_t4_successful_login_at_2348_triggers_after_hours_alert\` | After-hours triage alert (\`R4_AFTER_HOURS_SUCCESS\`). | **PASS (\`ok\`)** |
| **T5** | Missing required CSV column or invalid ISO timestamp. | \`test_t5_missing_required_column_or_invalid_timestamp_raises_error\` | Raises \`LogValidationError\` input validation error. | **PASS (\`ok\`)** |

---

## 5. Limitations & Responsible Deployment Notes

- **Synthetic Scope:** \`data/auth_logs.csv\` is a small synthetic dataset designed to validate rule logic and triage workflows; it does not represent production traffic volume.
- **No Time-Windowed Rate Calculation:** The prototype counts total failures per IP or prior to a success across the file rather than sliding time windows (e.g., 5 failures within 60 seconds).
- **Static Business Hours:** The \`06:00–22:00\` window does not account for global time zones, shift workers, or automated service accounts.
- **Triage Indicator Only:** Alerts generated by \`src/log_analyzer.py\` are triage indicators, not proof of compromise or attribution. Always corroborate with MFA, session, device, and network ownership records before taking containment actions.
`;
}

export function buildProjectReadme(profile: AnalystProfile): string {
  return `# Cybersecurity Assessment — Tasks 6 & 13

- **Author / Analyst:** ${profile.analystName} (${profile.studentId})
- **Course / Assessment:** ${profile.courseCohort}
- **Date:** ${profile.submissionDate}

## Project Summary

This repository contains the complete deliverables for **Task 6 (Manual Log Investigation)** and **Task 13 (Python Authentication Log Analyzer Prototype & Automated Unit Tests)**:

- **Task 6 Deliverable:** \`reports/task6_findings.md\` — Manual security-log analysis of \`data/auth_logs.csv\` with annotated findings, Fact vs. Hypothesis vs. Conclusion separation, and recommended follow-up actions.
- **Task 13 Deliverables:** \`src/log_analyzer.py\`, \`tests/test_log_analyzer.py\`, \`reports/analysis_results.json\`, \`reports/sample_run_output.txt\`, \`reports/test_results.txt\`, and \`reports/task13_tool_report.md\`.

---

## Project Structure

| File | Purpose |
| :--- | :--- |
| \`README.md\` | Project summary, setup, commands. |
| \`data/auth_logs.csv\` | Synthetic source dataset (18 authentication events). |
| \`src/log_analyzer.py\` | Python standard-library CLI log analyzer implementation. |
| \`tests/test_log_analyzer.py\` | Automated \`unittest\` suite covering Test Plan scenarios T1–T5. |
| \`reports/analysis_results.json\` | Generated JSON alert output from running the analyzer. |
| \`reports/sample_run_output.txt\` | Saved sample console summary output. |
| \`reports/test_results.txt\` | Saved unit test execution output. |
| \`reports/task6_findings.md\` | Task 6 evidence and manual investigation report. |
| \`reports/task13_tool_report.md\` | Task 13 implementation and test verification report. |

---

## Setup & Commands (VS Code on Windows / macOS / Linux)

### Step 1 — Check Python Version
\`\`\`bash
python --version
\`\`\`

### Step 2 — Run the Authentication Log Analyzer
\`\`\`bash
python src/log_analyzer.py --input data/auth_logs.csv --output reports/analysis_results.json
\`\`\`

### Step 3 — Run the Automated Unit Tests (T1–T5)
\`\`\`bash
python -m unittest discover -s tests -v
\`\`\`

---

## Short Explanation for the Evaluator

"For Task 6, I analyzed synthetic authentication logs and documented suspicious patterns while separating evidence from assumptions. For Task 13, I implemented a Python command-line analyzer that checks the same data against four defensive rules, produces JSON alerts, and includes unit tests. The alerts are triage indicators, so I recommend checking MFA, session, device, and network context before deciding whether an incident occurred."
`;
}

export function buildExpectedProjectFiles(
  profile: AnalystProfile,
  csvContent: string,
  report: AnalysisReport
): ExpectedProjectFile[] {
  const consoleSummary = formatConsoleSummary(report, 'reports/analysis_results.json');
  const jsonString = JSON.stringify(report, null, 2);

  return [
    {
      path: 'README.md',
      purpose: 'Project summary, setup, commands.',
      language: 'markdown',
      deliverableTask: 'Shared',
      content: buildProjectReadme(profile),
    },
    {
      path: 'data/auth_logs.csv',
      purpose: 'Synthetic source dataset.',
      language: 'csv',
      deliverableTask: 'Shared',
      content: csvContent.endsWith('\n') ? csvContent : `${csvContent}\n`,
    },
    {
      path: 'src/log_analyzer.py',
      purpose: 'Python implementation.',
      language: 'python',
      deliverableTask: 'Task 13',
      content: PYTHON_LOG_ANALYZER_CODE,
    },
    {
      path: 'tests/test_log_analyzer.py',
      purpose: 'Automated unit tests.',
      language: 'python',
      deliverableTask: 'Task 13',
      content: PYTHON_UNIT_TEST_CODE,
    },
    {
      path: 'reports/analysis_results.json',
      purpose: 'Generated alert output.',
      language: 'json',
      deliverableTask: 'Task 13',
      content: `${jsonString}\n`,
    },
    {
      path: 'reports/sample_run_output.txt',
      purpose: 'Saved sample console output.',
      language: 'text',
      deliverableTask: 'Task 13',
      content: `${consoleSummary}\n`,
    },
    {
      path: 'reports/test_results.txt',
      purpose: 'Saved test output; verify locally.',
      language: 'text',
      deliverableTask: 'Task 13',
      content: `${SAVED_UNITTEST_OUTPUT}\n`,
    },
    {
      path: 'reports/task6_findings.md',
      purpose: 'Task 6 evidence and investigation report.',
      language: 'markdown',
      deliverableTask: 'Task 6',
      content: buildTask6ReportMarkdown(profile),
    },
    {
      path: 'reports/task13_tool_report.md',
      purpose: 'Task 13 implementation and test report.',
      language: 'markdown',
      deliverableTask: 'Task 13',
      content: buildTask13ReportMarkdown(profile, consoleSummary),
    },
  ];
}
