"""
SecureNova Project 4 - Task 4
Anomaly Detection Regression Runner

Tests all three required anomaly categories using deterministic,
local synthetic event streams derived from Project 3 scenarios.

1. F-01: More than 20 LLM API requests in 60 seconds.
2. F-02: Scope change between consecutive agent requests.
3. Expired synthetic token reuse.

No live Gemini API, real bearer token, or production API is used.
"""

from __future__ import annotations

import hashlib
import json

from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.project4.anomaly_detection.anomaly_detector import (
    AnomalyDetector,
)


# ============================================================
# 1. CONFIGURATION AND EVIDENCE PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[3]

EVIDENCE_DIR = (
    PROJECT_ROOT
    / "evidence"
    / "project4"
    / "task4_anomaly_detection"
)

RESULT_FILE = (
    EVIDENCE_DIR
    / "task4_anomaly_detection_results.json"
)

# Fixed timestamps make all tests deterministic and repeatable.
BASE_TIME = datetime(
    2026, 11, 9, 10, 0, 0,
    tzinfo=timezone.utc,
)


# ============================================================
# 2. COMMON HELPERS
# ============================================================

def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def print_alert(
    alert: dict,
    alert_number: int,
) -> None:

    print("\n" + "-" * 76)
    print(f"ANOMALY ALERT {alert_number}")
    print("-" * 76)

    print("Timestamp UTC:", alert["timestamp_utc"])
    print("Identity:", alert["identity"])
    print("Event type:", alert["event_type"])
    print("Detector:", alert["detector"])
    print("Severity:", alert["severity"])
    print("Reason:", alert["reason"])

    print("\nAlert context:")

    print(
        json.dumps(
            alert["context"],
            indent=4,
            ensure_ascii=False,
        )
    )


def save_evidence(evidence: dict) -> None:

    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with RESULT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            evidence,
            file,
            indent=4,
            ensure_ascii=False,
        )

    print("\nEvidence saved:")
    print(RESULT_FILE)


# ============================================================
# 3. DETECTOR 1
# LLM REQUEST VOLUME SPIKE
# Project 3-derived scenario: F-01
# ============================================================

def test_request_volume_spike() -> dict:

    print("\n" + "=" * 76)
    print("TEST 1 - LLM API REQUEST VOLUME SPIKE")
    print("Scenario: F-01 - Indirect Prompt Injection Replay")
    print("=" * 76)

    detector = AnomalyDetector(
        request_threshold=20,
        window_seconds=60,
    )

    identity = "agent-secure-nova"

    triggered_alert = None
    alert_at_request_20 = None

    request_count = 21

    print("Identity:", identity)
    print("Threshold: More than 20 requests")
    print("Window: 60 seconds")
    print("Simulated requests:", request_count)

    for index in range(1, request_count + 1):

        timestamp = BASE_TIME + timedelta(
            seconds=(index - 1) * 2
        )

        alert = detector.record_llm_request(
            identity=identity,
            timestamp_utc=timestamp,
            request_id=f"F01-LLM-REQ-{index:03d}",
        )

        if index == 20:
            alert_at_request_20 = alert

        if alert is not None:
            triggered_alert = alert

    passed = (
        alert_at_request_20 is None
        and triggered_alert is not None
        and triggered_alert["context"]["request_count_in_window"] == 21
    )

    print("Alert at exactly 20 requests:", alert_at_request_20 is not None)
    print("Alert at request 21:", triggered_alert is not None)
    print("Expected threshold behavior:", "PASS" if passed else "FAIL")

    if triggered_alert:
        print_alert(triggered_alert, 1)

    return {
        "test_id": "ANOMALY-01",
        "project3_reference": "F-01",
        "scenario": "LLM API request volume spike",
        "requests_generated": request_count,
        "window_seconds": 60,
        "threshold": 20,
        "alert_at_20_requests": alert_at_request_20 is not None,
        "alert_at_21_requests": triggered_alert is not None,
        "alert": triggered_alert,
        "test_passed": passed,
    }


# ============================================================
# 4. DETECTOR 2
# AGENT SCOPE CHANGE
# Project 3-derived scenario: F-02
# ============================================================

def test_scope_change() -> dict:

    print("\n" + "=" * 76)
    print("TEST 2 - AGENT SCOPE CHANGE")
    print("Scenario: F-02 - Agent Identity Spoofing Replay")
    print("=" * 76)

    detector = AnomalyDetector()

    identity = "agent-finops-audit"

    original_scopes = [
        "read.ai-data",
    ]

    changed_scopes = [
        "read.ai-data",
        "write:admin",
    ]

    print("Agent identity:", identity)
    print("Initial scopes:", original_scopes)

    first_alert = detector.record_scope_request(
        identity=identity,
        scopes=original_scopes,
        timestamp_utc=BASE_TIME + timedelta(minutes=2),
        request_id="F02-SCOPE-REQ-001",
    )

    print("Initial request alert:", first_alert is not None)
    print("Next request scopes:", changed_scopes)

    second_alert = detector.record_scope_request(
        identity=identity,
        scopes=changed_scopes,
        timestamp_utc=BASE_TIME + timedelta(minutes=2, seconds=1),
        request_id="F02-SCOPE-REQ-002",
    )

    passed = (
        first_alert is None
        and second_alert is not None
        and "write:admin" in second_alert["context"]["added_scopes"]
    )

    print(
        "Scope-change detection:",
        "PASS" if passed else "FAIL",
    )

    if second_alert:
        print_alert(second_alert, 2)

    return {
        "test_id": "ANOMALY-02",
        "project3_reference": "F-02",
        "scenario": "Unexpected agent scope change",
        "identity": identity,
        "initial_scopes": original_scopes,
        "changed_scopes": changed_scopes,
        "baseline_alert": first_alert,
        "scope_change_alert": second_alert,
        "test_passed": passed,
    }


# ============================================================
# 5. DETECTOR 3
# EXPIRED TOKEN REUSE
# Synthetic controlled token fixture
# ============================================================

def test_expired_token_reuse() -> dict:

    print("\n" + "=" * 76)
    print("TEST 3 - EXPIRED TOKEN REUSE")
    print("Scenario: Controlled synthetic expired-token replay")
    print("=" * 76)

    detector = AnomalyDetector()

    identity = "agent-secure-nova"

    issued_at = BASE_TIME + timedelta(minutes=5)
    expires_at = issued_at + timedelta(seconds=60)

    # This is a SHA-256 fingerprint of a synthetic fixture label.
    # It is NOT a real access token or refresh token.
    synthetic_fixture = b"SECURENOVA-EXPIRED-TOKEN-FIXTURE-ONLY"

    token_fingerprint = hashlib.sha256(
        synthetic_fixture
    ).hexdigest()

    detector.register_token(
        identity=identity,
        token_fingerprint=token_fingerprint,
        expires_at_utc=expires_at,
    )

    print("Agent identity:", identity)
    print("Token type: Synthetic test fixture")
    print("Token fingerprint prefix:", token_fingerprint[:16])
    print("Token expiry UTC:", iso_utc(expires_at))

    # A use immediately before expiry must not alert.
    valid_use = detector.record_token_use(
        identity=identity,
        token_fingerprint=token_fingerprint,
        timestamp_utc=expires_at - timedelta(seconds=1),
        request_id="TOKEN-REQ-001",
    )

    print(
        "Alert before expiry:",
        valid_use is not None,
    )

    # Reuse after expiry must alert.
    expired_reuse = detector.record_token_use(
        identity=identity,
        token_fingerprint=token_fingerprint,
        timestamp_utc=expires_at + timedelta(seconds=1),
        request_id="TOKEN-REQ-002",
    )

    passed = (
        valid_use is None
        and expired_reuse is not None
        and expired_reuse["event_type"] == "EXPIRED_TOKEN_REUSE"
    )

    print(
        "Expired-token reuse detection:",
        "PASS" if passed else "FAIL",
    )

    if expired_reuse:
        print_alert(expired_reuse, 3)

    return {
        "test_id": "ANOMALY-03",
        "project3_reference": "Controlled synthetic token fixture",
        "scenario": "Expired token reuse",
        "identity": identity,
        "token_type": "SYNTHETIC_TEST_FIXTURE",
        "token_fingerprint_prefix": token_fingerprint[:16],
        "token_expires_at_utc": iso_utc(expires_at),
        "valid_use_alert": valid_use,
        "expired_reuse_alert": expired_reuse,
        "test_passed": passed,
    }


# ============================================================
# 6. MAIN
# ============================================================

def main() -> None:

    print("=" * 76)
    print("SecureNova - Project 4 - Task 4")
    print("ANOMALY DETECTION REGRESSION TESTS")
    print("=" * 76)

    print("\nDetection requirements:")
    print("1. More than 20 LLM requests in 60 seconds.")
    print("2. Scope change between consecutive agent requests.")
    print("3. Expired-token reuse.")

    print("\nExecution type: LOCAL DETERMINISTIC SIMULATION")
    print("Raw token values used: NO")
    print("Live Gemini requests: NO")
    print("Production API calls: NO")

    results = [
        test_request_volume_spike(),
        test_scope_change(),
        test_expired_token_reuse(),
    ]

    total = len(results)

    passed_count = sum(
        1 for result in results
        if result["test_passed"]
    )

    alerts = [
        result["alert"]
        for result in results
        if result.get("alert") is not None
    ]

    alerts.extend(
        result["scope_change_alert"]
        for result in results
        if result.get("scope_change_alert") is not None
    )

    alerts.extend(
        result["expired_reuse_alert"]
        for result in results
        if result.get("expired_reuse_alert") is not None
    )

    all_passed = (
        total == 3
        and passed_count == 3
        and len(alerts) == 3
    )

    evidence = {
        "project": "SecureNova",
        "task": "Project 4 - Task 4: Anomaly Detection",
        "execution_timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "execution_type": "LOCAL DETERMINISTIC SIMULATION",
        "detectors": {
            "request_volume": {
                "threshold": 20,
                "window_seconds": 60,
                "comparison": ">",
            },
            "scope_change": {
                "comparison": "consecutive requests",
            },
            "expired_token_reuse": {
                "comparison": "request timestamp >= expiry",
            },
        },
        "summary": {
            "total_tests": total,
            "passed_tests": passed_count,
            "failed_tests": total - passed_count,
            "alerts_generated": len(alerts),
            "overall_result": "PASS" if all_passed else "FAIL",
        },
        "test_results": results,
        "alerts": alerts,
        "security_notes": [
            "All event streams are deterministic synthetic fixtures.",
            "F-01 and F-02 are Project 3-derived scenario references.",
            "Expired-token reuse uses a synthetic fingerprint, not a real token.",
            "No raw bearer tokens or refresh tokens were logged.",
            "No live Gemini or production API calls were made.",
        ],
    }

    save_evidence(evidence)

    print("\n" + "=" * 76)
    print("PROJECT 4 - TASK 4 SUMMARY")
    print("=" * 76)

    print("Total anomaly tests:", total)
    print("Passed:", passed_count)
    print("Failed:", total - passed_count)
    print("Alerts generated:", len(alerts))

    print("\nIndividual test results:")

    for result in results:
        print(
            f"{result['test_id']:<16}"
            f"{'PASS' if result['test_passed'] else 'FAIL'}"
        )

    print("\nOVERALL RESULT:", evidence["summary"]["overall_result"])


if __name__ == "__main__":
    main()