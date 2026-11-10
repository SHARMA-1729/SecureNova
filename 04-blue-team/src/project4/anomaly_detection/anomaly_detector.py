
"""
SecureNova Project 4 - Task 4
Anomaly Detection Engine

Detectors:
1. More than 20 LLM requests in a rolling 60-second window.
2. Scope change between consecutive requests from the same identity.
3. Reuse of a registered token after its expiry.

All timestamps are normalized to UTC.
Token values are never accepted or logged; only SHA-256
fingerprints of synthetic or externally supplied token IDs
are used.
"""

from __future__ import annotations

import re

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any


class AnomalyDetector:
    """Stateful detector for SecureNova agent security events."""

    def __init__(
        self,
        request_threshold: int = 20,
        window_seconds: int = 60,
    ) -> None:

        if request_threshold < 1:
            raise ValueError("Request threshold must be positive.")

        if window_seconds < 1:
            raise ValueError("Window duration must be positive.")

        self.request_threshold = request_threshold
        self.window = timedelta(seconds=window_seconds)

        self._request_times: dict[str, deque[datetime]] = {}
        self._volume_alert_active: dict[str, bool] = {}

        self._last_scopes: dict[str, frozenset[str]] = {}

        self._registered_tokens: dict[str, dict[str, Any]] = {}
        self._expired_token_alerted: set[str] = set()

    # ========================================================
    # COMMON HELPERS
    # ========================================================

    @staticmethod
    def _parse_timestamp(value: str | datetime) -> datetime:

        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            normalized = value.strip().replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
        else:
            raise TypeError("Timestamp must be an ISO string or datetime.")

        if parsed.tzinfo is None:
            raise ValueError("Timestamp must include a UTC offset.")

        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _format_timestamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _validate_identity(identity: str) -> None:

        if not isinstance(identity, str) or not identity.strip():
            raise ValueError("A valid agent identity is required.")

    @staticmethod
    def _validate_fingerprint(fingerprint: str) -> None:

        if (
            not isinstance(fingerprint, str)
            or not re.fullmatch(r"[a-fA-F0-9]{64}", fingerprint)
        ):
            raise ValueError(
                "Token identifier must be a SHA-256 hex fingerprint. "
                "Never provide a raw token."
            )

    @staticmethod
    def _build_alert(
        *,
        timestamp: datetime,
        identity: str,
        event_type: str,
        detector: str,
        reason: str,
        context: dict[str, Any],
        severity: str = "HIGH",
    ) -> dict[str, Any]:

        return {
            "timestamp_utc": timestamp.astimezone(timezone.utc).isoformat(),
            "identity": identity,
            "event_type": event_type,
            "detector": detector,
            "severity": severity,
            "reason": reason,
            "context": context,
        }

    # ========================================================
    # DETECTOR 1
    # LLM REQUEST VOLUME SPIKE
    # ========================================================

    def record_llm_request(
        self,
        *,
        identity: str,
        timestamp_utc: str | datetime,
        request_id: str,
    ) -> dict[str, Any] | None:

        self._validate_identity(identity)

        timestamp = self._parse_timestamp(timestamp_utc)

        if identity not in self._request_times:
            self._request_times[identity] = deque()
            self._volume_alert_active[identity] = False

        request_window = self._request_times[identity]

        # Remove requests older than the rolling 60-second window.
        window_start = timestamp - self.window

        while (
            request_window
            and request_window[0] < window_start
        ):
            request_window.popleft()

        request_window.append(timestamp)

        current_count = len(request_window)

        # Clear the alert-active flag when the count drops
        # back to the permitted threshold.
        if current_count <= self.request_threshold:
            self._volume_alert_active[identity] = False
            return None

        # Emit one alert per continuous volume-spike episode.
        if self._volume_alert_active[identity]:
            return None

        self._volume_alert_active[identity] = True

        return self._build_alert(
            timestamp=timestamp,
            identity=identity,
            event_type="LLM_API_REQUEST_VOLUME_SPIKE",
            detector="REQUEST_VOLUME_60_SECOND_WINDOW",
            reason=(
                f"LLM request count exceeded "
                f"{self.request_threshold} requests "
                f"within {self.window.total_seconds():.0f} seconds."
            ),
            context={
                "request_id": request_id,
                "request_count_in_window": current_count,
                "threshold": self.request_threshold,
                "window_seconds": int(self.window.total_seconds()),
                "threshold_operator": ">",
            },
        )

    # ========================================================
    # DETECTOR 2
    # SCOPE CHANGE BETWEEN CONSECUTIVE REQUESTS
    # ========================================================

    def record_scope_request(
        self,
        *,
        identity: str,
        scopes: list[str] | tuple[str, ...] | set[str],
        timestamp_utc: str | datetime,
        request_id: str,
    ) -> dict[str, Any] | None:

        self._validate_identity(identity)

        timestamp = self._parse_timestamp(timestamp_utc)

        if not isinstance(scopes, (list, tuple, set)):
            raise TypeError("Scopes must be a list, tuple, or set.")

        if any(
            not isinstance(scope, str) or not scope.strip()
            for scope in scopes
        ):
            raise ValueError("Every scope must be a non-empty string.")

        current_scopes = frozenset(scopes)
        previous_scopes = self._last_scopes.get(identity)

        # Always update the baseline for the next request.
        self._last_scopes[identity] = current_scopes

        # The first request establishes the baseline.
        if previous_scopes is None:
            return None

        if previous_scopes == current_scopes:
            return None

        return self._build_alert(
            timestamp=timestamp,
            identity=identity,
            event_type="AGENT_SCOPE_CHANGE",
            detector="CONSECUTIVE_REQUEST_SCOPE_MONITOR",
            reason=(
                "Agent scopes changed between consecutive requests "
                "for the same identity."
            ),
            context={
                "request_id": request_id,
                "previous_scopes": sorted(previous_scopes),
                "current_scopes": sorted(current_scopes),
                "added_scopes": sorted(
                    current_scopes - previous_scopes
                ),
                "removed_scopes": sorted(
                    previous_scopes - current_scopes
                ),
            },
        )

    # ========================================================
    # TOKEN REGISTRATION
    # ========================================================

    def register_token(
        self,
        *,
        identity: str,
        token_fingerprint: str,
        expires_at_utc: str | datetime,
    ) -> None:
        """Register an issued token using only its SHA-256 fingerprint."""

        self._validate_identity(identity)
        self._validate_fingerprint(token_fingerprint)

        expiry = self._parse_timestamp(expires_at_utc)

        self._registered_tokens[token_fingerprint] = {
            "identity": identity,
            "expires_at": expiry,
        }

    # ========================================================
    # DETECTOR 3
    # EXPIRED TOKEN REUSE
    # ========================================================

    def record_token_use(
        self,
        *,
        identity: str,
        token_fingerprint: str,
        timestamp_utc: str | datetime,
        request_id: str,
    ) -> dict[str, Any] | None:

        self._validate_identity(identity)
        self._validate_fingerprint(token_fingerprint)

        timestamp = self._parse_timestamp(timestamp_utc)

        token_record = self._registered_tokens.get(
            token_fingerprint
        )

        # An unknown fingerprint cannot be evaluated by this registry.
        if token_record is None:
            return None

        expiry = token_record["expires_at"]

        if identity != token_record["identity"]:
            return self._build_alert(
                timestamp=timestamp,
                identity=identity,
                event_type="TOKEN_IDENTITY_MISMATCH",
                detector="TOKEN_IDENTITY_BINDING",
                reason=(
                    "A registered token fingerprint was used "
                    "by a different agent identity."
                ),
                context={
                    "request_id": request_id,
                    "token_fingerprint_prefix": token_fingerprint[:16],
                    "registered_identity": token_record["identity"],
                },
            )

        # A token is expired at or after its expiry timestamp.
        if timestamp < expiry:
            return None

        # Avoid duplicate alerts for the same expired token.
        if token_fingerprint in self._expired_token_alerted:
            return None

        self._expired_token_alerted.add(token_fingerprint)

        return self._build_alert(
            timestamp=timestamp,
            identity=identity,
            event_type="EXPIRED_TOKEN_REUSE",
            detector="TOKEN_EXPIRY_REUSE_MONITOR",
            reason=(
                "A previously registered token was reused "
                "at or after its expiry timestamp."
            ),
            context={
                "request_id": request_id,
                "token_fingerprint_prefix": token_fingerprint[:16],
                "token_expires_at_utc": self._format_timestamp(expiry),
                "token_reused_at_utc": self._format_timestamp(timestamp),
            },
        )
