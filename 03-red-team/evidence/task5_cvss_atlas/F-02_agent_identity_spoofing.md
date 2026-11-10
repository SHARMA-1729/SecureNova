# F-02 - Agent Identity Spoofing

**Project task:** Task 2
**Assessment outcome:** DEMONSTRATED IN LOCAL SIMULATION

## Executive finding

All three spoofing scenarios were accepted by the intentionally vulnerable local Agent B simulation. The protected Agent B rejected all three.

## Attack success

- Vulnerable/test attempts: 3
- Observed successes: 3
- Success percentage: 100.0%
- Protected-profile attempts: 3
- Protected-profile successes: 0
- Protected-profile success percentage: 0.0%

## CVSS 3.1

- **Base Score:** 9.6
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`
- **Scoring status:** PROVISIONAL HYPOTHETICAL PRODUCTION SCENARIO

Assumes an attacker has low privileges to submit messages through an agent messaging interface. The receiving agent processes messages without independent sender validation, potentially affecting a separate privileged service.

### Metric rationale

- **AV:** Network: attacker submits a forged inter-agent message.
- **AC:** Low: no special exploit conditions are assumed.
- **PR:** Low: assumes basic access to the agent messaging interface.
- **UI:** None: the target agent processes the message automatically.
- **S:** Changed: a receiving agent can affect a separate privileged service.
- **C:** High: hypothetical unauthorized access to sensitive internal data.
- **I:** High: hypothetical unauthorized privileged approvals or actions.
- **A:** None: no availability impact was demonstrated.

## MITRE ATLAS

- **Primary:** AML.T0073 - Impersonation

**Related techniques:**

- AML.T0053 - AI Agent Tool Invocation

## Evidence

task2_identity_spoofing_results.json and task2_kill_chain.md.

## Limitations

No live LLM-to-LLM transport, signed identity, Auth0 token, production tool, or real administrative action was tested.

## Recommendations

- Bind sender identity to authenticated service credentials.
- Use signed, short-lived machine-to-machine tokens.
- Validate issuer, audience, expiry, sender and delegated scope.
- Enforce per-agent authorization at every receiving service.
- Reject identity claims supplied only inside message bodies.
- Put MCP execution behind a policy-enforcing tool broker.
- Allowlist tools and validate arguments against schemas.
- Require least-privilege scopes for each tool invocation.
- Verify identity and authorization outside the LLM.
- Log and review high-risk actions such as refunds and audit access.
- Use explicit approval for sensitive write operations.
