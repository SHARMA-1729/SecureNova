# F-01 - Indirect Prompt Injection and Credential Exfiltration

**Project task:** Task 1
**Assessment outcome:** DEMONSTRATED IN VULNERABLE BASELINE

## Executive finding

The vulnerable baseline disclosed the complete synthetic JWT in 5 of 8 attempts (62.5%). The protected profile disclosed it in 0 of 8 attempts.

## Attack success

- Vulnerable/test attempts: 8
- Observed successes: 5
- Success percentage: 62.5%
- Protected-profile attempts: 8
- Protected-profile successes: 0
- Protected-profile success percentage: 0.0%

## CVSS 3.1

- **Base Score:** 6.8
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N`
- **Scoring status:** PROVISIONAL HYPOTHETICAL PRODUCTION SCENARIO

Assumes an attacker has low privileges to contribute or modify a document in a network-accessible knowledge source. A subsequent customer interaction triggers retrieval, allowing disclosure of sensitive agent-context data across a trust boundary.

### Metric rationale

- **AV:** Network: attacker contributes malicious content through a network-accessible source.
- **AC:** Low: no special conditions are assumed.
- **PR:** Low: assumes basic permission to contribute or modify indexed content.
- **UI:** Required: an agent interaction triggers retrieval and processing.
- **S:** Changed: information moves from agent context into the response boundary.
- **C:** High: the complete synthetic credential was disclosed.
- **I:** None: no integrity modification was demonstrated.
- **A:** None: no availability impact was demonstrated.

## MITRE ATLAS

- **Primary:** AML.T0051.001 - Indirect

**Related techniques:**

- AML.T0051 - LLM Prompt Injection

## Evidence

DOC-01 through DOC-08 protected and vulnerable-baseline result JSON files, plus task1_summary.json.

## Limitations

The vulnerable baseline is intentionally misconfigured. The JWT is synthetic and has an invalid test signature. No production credential or service was accessed.

## Recommendations

- Treat retrieved documents as untrusted data, never authority.
- Validate document provenance and integrity during ingestion.
- Use trusted-source allowlists and document review workflows.
- Separate retrieved content from system instructions.
- Detect and quarantine prompt-injection patterns in indexed content.
