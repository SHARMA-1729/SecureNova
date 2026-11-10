"""
Demonstrate Project 4 JWT output redaction using an actual
Project 3 Gemini vulnerable-baseline response.

The original Project 3 evidence is read-only.
"""

from __future__ import annotations

import hashlib
import json

from datetime import datetime, timezone
from pathlib import Path

from src.project4.guardrails.run_task1_guardrails import (
    JWT_PATTERN,
    redact_jwt_values,
)


# ------------------------------------------------------------
# FILE PATHS
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[3]

SOURCE_FILE = (
    PROJECT_ROOT
    / "evidence"
    / "task1_prompt_injection"
    / "DOC-03_vulnerable_baseline_result.json"
)

EVIDENCE_DIR = (
    PROJECT_ROOT
    / "evidence"
    / "project4"
    / "task1_guardrails"
)

OUTPUT_FILE = (
    EVIDENCE_DIR
    / "task1_project3_model_response_redaction_demo.json"
)


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

def main() -> None:

    if not SOURCE_FILE.exists():
        raise FileNotFoundError(
            f"Project 3 response file not found: {SOURCE_FILE}"
        )

    with SOURCE_FILE.open(
        "r",
        encoding="utf-8-sig",
    ) as file:
        project3_result = json.load(file)

    if project3_result.get("profile") != "VULNERABLE_BASELINE":
        raise ValueError(
            "The selected result is not a vulnerable-baseline response."
        )

    if project3_result.get("synthetic_jwt_disclosed") is not True:
        raise ValueError(
            "The selected Project 3 result is not marked as a "
            "successful synthetic JWT disclosure."
        )

    original_response = project3_result.get(
        "model_response_verbatim"
    )

    if not isinstance(original_response, str) or not original_response.strip():
        raise ValueError(
            "The saved Gemini model response is empty or invalid."
        )

    # Find JWT-shaped values in the actual Gemini response.
    matched_values = JWT_PATTERN.findall(original_response)

    if not matched_values:
        raise RuntimeError(
            "No JWT-shaped credential was found in the saved response."
        )

    # Apply the same Project 4 redaction function.
    redacted_response = redact_jwt_values(original_response)

    jwt_removed = JWT_PATTERN.search(redacted_response) is None

    if not jwt_removed:
        raise RuntimeError(
            "JWT redaction failed: a JWT-shaped value remains."
        )

    # --------------------------------------------------------
    # TERMINAL DEMONSTRATION
    # --------------------------------------------------------

    print("=" * 75)
    print("SecureNova - Project 4 - JWT Output Guardrail")
    print("Actual Project 3 Gemini Response")
    print("=" * 75)

    print("\nSOURCE EVIDENCE:")
    print("File:", SOURCE_FILE.name)
    print("Provider:", project3_result.get("provider"))
    print("Model:", project3_result.get("model"))
    print("Profile:", project3_result.get("profile"))
    print("Attack ID:", project3_result.get("attack_id"))

    print("\n" + "=" * 75)
    print("BEFORE REDACTION - ORIGINAL GEMINI RESPONSE")
    print("=" * 75)

    print(original_response)

    print("\n" + "=" * 75)
    print("AFTER REDACTION - PROJECT 4 OUTPUT")
    print("=" * 75)

    print(redacted_response)

    print("\n" + "=" * 75)
    print("REDACTION VERIFICATION")
    print("=" * 75)

    print("JWT-shaped values detected:", len(matched_values))
    print("JWT removed:", jwt_removed)
    print(
        "Redaction placeholder added:",
        "[REDACTED]" in redacted_response,
    )
    print(
        "Actual model response used:",
        bool(project3_result.get("model_response_verbatim")),
    )

    print("\nRESULT:", "PASS" if jwt_removed else "FAIL")

    # --------------------------------------------------------
    # SAVE PROJECT 4 EVIDENCE
    # --------------------------------------------------------

    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    evidence = {
        "project": "SecureNova",
        "task": "Project 4 - Task 1 JWT Output Redaction",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_project": "Project 3",
        "source_file": SOURCE_FILE.name,
        "source_attack_id": project3_result.get("attack_id"),
        "provider": project3_result.get("provider"),
        "model": project3_result.get("model"),
        "profile": project3_result.get("profile"),
        "original_response_sha256": hashlib.sha256(
            original_response.encode("utf-8")
        ).hexdigest(),
        "jwt_values_detected": len(matched_values),
        "jwt_removed": jwt_removed,
        "redacted_response": redacted_response,
        "result": "PASS" if jwt_removed else "FAIL",
        "limitations": [
            "Uses an existing saved Project 3 Gemini response.",
            "The disclosed JWT is synthetic and has an invalid test signature.",
            "The Project 3 source evidence was not modified.",
        ],
    }

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            evidence,
            file,
            indent=4,
            ensure_ascii=False,
        )

    print("\nProject 4 evidence saved:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()