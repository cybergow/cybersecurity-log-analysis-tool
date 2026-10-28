"""
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
        # Case A: Missing 'source_ip' column
        incomplete_fields = ["timestamp", "username", "event", "result"]
        with self.assertRaises(LogValidationError):
            validate_and_normalize_rows([], incomplete_fields)

        # Case B: Invalid timestamp format
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
