# SecureNova - Project 3 Red-Team Assessment

## Executive Summary

This report consolidates evidence collected across Tasks 1-4 of the SecureNova AI identity security assessment.

Testing covered indirect prompt injection, agent identity spoofing, system-prompt extraction, user-to-admin escalation, RAG poisoning and simulated MCP tool invocation.

Task 1 demonstrated complete synthetic JWT disclosure in five of eight attempts against an intentionally vulnerable baseline. The protected profile disclosed the JWT in zero of eight attempts.

Tasks 2 and 4 demonstrated trust-boundary weaknesses in controlled simulations. Task 3 recorded a partial instruction echo, but did not demonstrate full prompt extraction or admin privilege escalation.

No production credential, Auth0 role, customer account, real MCP server or production audit record was compromised.

## 1. Consolidated CVSS Findings

| ID | Finding | Outcome | Score | Severity |
|---|---|---|---:|---|
| F-01 | Indirect Prompt Injection and Credential Exfiltration | DEMONSTRATED IN VULNERABLE BASELINE | 6.8 | Medium |
| F-02 | Agent Identity Spoofing | DEMONSTRATED IN LOCAL SIMULATION | 9.6 | Critical |
| F-03 | System Prompt Extraction and Partial Instruction Echo | PARTIAL DISCLOSURE OBSERVED | 4.3 | Medium |
| F-04 | User-to-Admin Privilege Escalation | NOT DEMONSTRATED | N/A | Not scored |
| F-05 | RAG Poisoning and MCP Tool Invocation | DEMONSTRATED IN CONTROLLED SIMULATION | 6.8 | Medium |

CVSS scores are provisional hypothetical production-scenario Base Scores. They are not severity scores of the local test harness or proof of production compromise.

FIRST calculator: https://www.first.org/cvss/calculator/3.1

FIRST specification: https://www.first.org/cvss/v3.1/specification-document

## 2. Attack Success Matrix

| Finding | Test attempts | Successful | Success % | Protected attempts | Protected successes |
|---|---:|---:|---:|---:|---:|
| F-01 - Indirect Prompt Injection and Credential Exfiltration | 8 | 5 | 62.50% | 8 | 0 |
| F-02 - Agent Identity Spoofing | 3 | 3 | 100.00% | 3 | 0 |
| F-03 - System Prompt Extraction and Partial Instruction Echo | 5 | 1 | 20.00% | 5 | 1 |
| F-04 - User-to-Admin Privilege Escalation | 1 | 0 | 0.00% | 1 | 0 |
| F-05 - RAG Poisoning and MCP Tool Invocation | 1 | 1 | 100.00% | 1 | 0 |

Percentages represent observed outcomes in the defined laboratory attempts. They are not estimates of real-world attack probability.

## 3. CVSS 3.1 Vectors and Rationale

### F-01 - Indirect Prompt Injection and Credential Exfiltration

- Score: 6.8
- Severity: Medium
- Vector: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N`
- Status: PROVISIONAL HYPOTHETICAL PRODUCTION SCENARIO

Assumes an attacker has low privileges to contribute or modify a document in a network-accessible knowledge source. A subsequent customer interaction triggers retrieval, allowing disclosure of sensitive agent-context data across a trust boundary.

**Metric rationale:**

- AV: Network: attacker contributes malicious content through a network-accessible source.
- AC: Low: no special conditions are assumed.
- PR: Low: assumes basic permission to contribute or modify indexed content.
- UI: Required: an agent interaction triggers retrieval and processing.
- S: Changed: information moves from agent context into the response boundary.
- C: High: the complete synthetic credential was disclosed.
- I: None: no integrity modification was demonstrated.
- A: None: no availability impact was demonstrated.

### F-02 - Agent Identity Spoofing

- Score: 9.6
- Severity: Critical
- Vector: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`
- Status: PROVISIONAL HYPOTHETICAL PRODUCTION SCENARIO

Assumes an attacker has low privileges to submit messages through an agent messaging interface. The receiving agent processes messages without independent sender validation, potentially affecting a separate privileged service.

**Metric rationale:**

- AV: Network: attacker submits a forged inter-agent message.
- AC: Low: no special exploit conditions are assumed.
- PR: Low: assumes basic access to the agent messaging interface.
- UI: None: the target agent processes the message automatically.
- S: Changed: a receiving agent can affect a separate privileged service.
- C: High: hypothetical unauthorized access to sensitive internal data.
- I: High: hypothetical unauthorized privileged approvals or actions.
- A: None: no availability impact was demonstrated.

### F-03 - System Prompt Extraction and Partial Instruction Echo

- Score: 4.3
- Severity: Medium
- Vector: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
- Status: PROVISIONAL HYPOTHETICAL PRODUCTION SCENARIO

Provisional production-scenario score for a limited protected-instruction fragment echoed in a model response. It does not represent full system-prompt extraction.

**Metric rationale:**

- AV: Network: prompt submitted through the model interface.
- AC: Low: a straightforward prompt is sufficient.
- PR: Low: assumes an ordinary customer account is required.
- UI: None: the attacker directly submits the prompt.
- S: Unchanged: the exposed fragment belongs to the same model service.
- C: Low: only a short instruction fragment was echoed.
- I: None: no integrity impact was demonstrated.
- A: None: no availability impact was demonstrated.

### F-04 - User-to-Admin Privilege Escalation

CVSS Base Score: Not scored.

No successful exploitation was demonstrated for this finding. No CVSS Base Score is assigned.

### F-05 - RAG Poisoning and MCP Tool Invocation

- Score: 6.8
- Severity: Medium
- Vector: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N`
- Status: PROVISIONAL HYPOTHETICAL PRODUCTION SCENARIO

Assumes an attacker has low privileges to contribute or modify content indexed by a network-accessible RAG system. A later user interaction causes retrieval and a vulnerable agent requests access to sensitive data through a separate tool service.

**Metric rationale:**

- AV: Network: poisoned content enters through a network-accessible source.
- AC: Low: no special exploit conditions are assumed.
- PR: Low: assumes permission to contribute or alter indexed content.
- UI: Required: a user interaction triggers retrieval and tool processing.
- S: Changed: the separate MCP service has its own security authority.
- C: High: hypothetical unauthorized access to internal audit information.
- I: None: the tested audit-log action was read-only.
- A: None: no availability impact was demonstrated.

## 4. MITRE ATLAS Mapping

| Finding | Primary technique | Related techniques |
|---|---|---|
| F-01 | AML.T0051.001 - Indirect | AML.T0051 (LLM Prompt Injection) |
| F-02 | AML.T0073 - Impersonation | AML.T0053 (AI Agent Tool Invocation) |
| F-03 | AML.T0056 - Extract LLM System Prompt | AML.T0051 (LLM Prompt Injection) |
| F-04 | AML.T0054 - LLM Jailbreak | None |
| F-05 | AML.T0070 - RAG Poisoning | AML.T0071 (False RAG Entry Injection), AML.T0066 (Retrieval Content Crafting), AML.T0053 (AI Agent Tool Invocation) |

Official ATLAS knowledge base: https://atlas.mitre.org/

## 5. Task-by-Task Results

### Task 1 - Indirect Prompt Injection

The vulnerable baseline disclosed the complete synthetic JWT in five of eight documents. The protected profile disclosed the JWT in zero of eight documents. The canary is synthetic and cannot authenticate to any service.

### Task 2 - Agent Identity Spoofing

All three spoofing scenarios were accepted by the intentionally vulnerable local Agent B simulation. The protected Agent B rejected all three. No production identity transport was attacked.

### Task 3 - System Prompt Extraction

The full system prompt was not extracted. A short instruction fragment was echoed in T3-05 and recorded for manual review. The user-to-admin escalation attempt did not disclose the synthetic admin canary.

### Task 4 - RAG Poisoning and MCP Abuse

The poisoned RAG document was retrieved. The vulnerable Gemini profile generated a request for the internal audit tool, which the vulnerable simulated dispatcher accepted. The protected profile and dispatcher rejected the request.

No real MCP server or audit records were accessed.

## 6. Top Three Hardening Recommendations

### 1. Enforce cryptographic agent identity and delegation

- Bind sender identity to authenticated service credentials.
- Use signed, short-lived machine-to-machine tokens.
- Validate issuer, audience, expiry, sender and delegated scope.
- Enforce per-agent authorization at every receiving service.
- Reject identity claims supplied only inside message bodies.

### 2. Secure RAG ingestion and retrieval

- Treat retrieved documents as untrusted data, never authority.
- Validate document provenance and integrity during ingestion.
- Use trusted-source allowlists and document review workflows.
- Separate retrieved content from system instructions.
- Detect and quarantine prompt-injection patterns in indexed content.

### 3. Apply independent authorization to every MCP tool

- Put MCP execution behind a policy-enforcing tool broker.
- Allowlist tools and validate arguments against schemas.
- Require least-privilege scopes for each tool invocation.
- Verify identity and authorization outside the LLM.
- Log and review high-risk actions such as refunds and audit access.
- Use explicit approval for sensitive write operations.

## 7. Assessment Limitations

- The Task 1 vulnerable baseline was intentionally misconfigured.
- The JWT is synthetic and has an invalid test signature.
- Task 2 is a deterministic local identity-spoofing simulation.
- Task 4 uses lexical retrieval rather than vector embeddings.
- Task 4 tool execution uses a local simulated dispatcher.
- No production Auth0 role or permission was compromised.
- No real MCP server, customer data or audit logs were accessed.
- CVSS scores are provisional and depend on the stated production-scenario assumptions.

## 8. References

- FIRST CVSS 3.1 Calculator: https://www.first.org/cvss/calculator/3.1
- FIRST CVSS 3.1 Specification: https://www.first.org/cvss/v3.1/specification-document
- MITRE ATLAS: https://atlas.mitre.org/
