
"""SecureNova Task 2: Controlled Agent Identity Spoofing Assessment.

This is a deterministic local simulation. It does not call Auth0,
an external LLM, real MCP tools, or production administrative systems.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from src.common.fixtures import SYNTHETIC_AGENT_IDENTITIES
from src.identity_spoofing import SPOOFED_IDENTITY_PAYLOADS


# ------------------------------------------------------------
# 1. PROJECT CONFIGURATION
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

EVIDENCE_DIR = PROJECT_ROOT / "evidence" / "task2_identity_spoofing"

RESULT_FILE = EVIDENCE_DIR / "task2_identity_spoofing_results.json"
KILL_CHAIN_FILE = EVIDENCE_DIR / "task2_kill_chain.md"

ATTACKER_ID = "external-unverified"

# Synthetic policy: only this trusted orchestrator may delegate
# the simulated privileged actions to Agent B.
AUTHORIZED_ORCHESTRATOR_ID = "agent-secure-nova"

PRIVILEGED_ACTIONS = {
    "continue_as_admin": "approve_sensitive_finance_export",
    "spoofed_tool_call": "invoke_simulated_admin_tool",
    "impersonation_chain": "execute_delegated_security_action",
}

AUTHORIZED_DELEGATED_ACTIONS = set(PRIVILEGED_ACTIONS.values())


# ------------------------------------------------------------
# 2. LOAD SYNTHETIC AGENT IDENTITIES
# ------------------------------------------------------------

IDENTITY_REGISTRY = {
    identity.agent_id: identity
    for identity in SYNTHETIC_AGENT_IDENTITIES
}

AGENT_A = IDENTITY_REGISTRY.get("agent-secure-nova")
AGENT_B = IDENTITY_REGISTRY.get("agent-finops-audit")

if AGENT_A is None or AGENT_B is None:
    raise RuntimeError(
        "Required synthetic Agent A or Agent B identity was not found."
    )

if not AGENT_A.trusted:
    raise RuntimeError("Agent A must be configured as a trusted identity.")


# ------------------------------------------------------------
# 3. SIMULATED PRIVILEGED ACTION
# ------------------------------------------------------------

def execute_simulated_privileged_action(action_name: str) -> dict:
    """Record a simulated action without accessing real resources."""

    return {
        "executed": True,
        "action": action_name,
        "execution_type": "SIMULATED_ONLY",
        "result": (
            "The simulated privileged action was executed. "
            "No real customer data, credentials, or administrative "
            "resources were accessed."
        ),
    }


# ------------------------------------------------------------
# 4. VULNERABLE AGENT B
# ------------------------------------------------------------

def vulnerable_agent_b(envelope: dict, action_name: str) -> dict:
    """Demonstrate the risk of trusting a claimed sender identity.

    This intentionally vulnerable test implementation trusts the
    identity claimed inside the message rather than authenticating
    the actual sender.
    """

    claimed_sender_id = envelope["claimed_sender_id"]

    claimed_identity = IDENTITY_REGISTRY.get(claimed_sender_id)

    if claimed_identity is None or not claimed_identity.trusted:
        return {
            "decision": "REJECTED",
            "reason": "Claimed identity is not trusted.",
            "action_result": {
                "executed": False
            },
        }

    # VULNERABILITY:
    # Authenticated transport identity is not checked here.
    # A forged claim of Agent A's identity is sufficient.
    action_result = execute_simulated_privileged_action(action_name)

    return {
        "decision": "ACCEPTED",
        "reason": (
            "Agent B trusted the claimed sender identity "
            "without independently validating the actual sender."
        ),
        "claimed_sender": claimed_sender_id,
        "action_result": action_result,
    }


# ------------------------------------------------------------
# 5. PROTECTED AGENT B
# ------------------------------------------------------------

def protected_agent_b(envelope: dict, action_name: str) -> dict:
    """Enforce sender identity, trust, tenant and action authorization."""

    authenticated_sender_id = envelope.get("authenticated_sender_id")
    claimed_sender_id = envelope.get("claimed_sender_id")

    if not authenticated_sender_id:
        return {
            "decision": "REJECTED",
            "reason": "No authenticated sender identity was provided.",
            "action_result": {
                "executed": False
            },
        }

    # A claim inside a message is not proof of identity.
    if authenticated_sender_id != claimed_sender_id:
        return {
            "decision": "REJECTED",
            "reason": (
                "Authenticated sender does not match the "
                "identity claimed in the message."
            ),
            "action_result": {
                "executed": False
            },
        }

    authenticated_identity = IDENTITY_REGISTRY.get(
        authenticated_sender_id
    )

    if authenticated_identity is None:
        return {
            "decision": "REJECTED",
            "reason": "Authenticated identity is not registered.",
            "action_result": {
                "executed": False
            },
        }

    if not authenticated_identity.trusted:
        return {
            "decision": "REJECTED",
            "reason": "Authenticated sender is not trusted.",
            "action_result": {
                "executed": False
            },
        }

    if authenticated_identity.tenant != AGENT_B.tenant:
        return {
            "decision": "REJECTED",
            "reason": "Cross-tenant delegation is not permitted.",
            "action_result": {
                "executed": False
            },
        }

    if authenticated_sender_id != AUTHORIZED_ORCHESTRATOR_ID:
        return {
            "decision": "REJECTED",
            "reason:": "Sender is not an authorized orchestrator.",
            "action_result": {
                "executed": False
            },
        }

    if action_name not in AUTHORIZED_DELEGATED_ACTIONS:
        return {
            "decision": "REJECTED",
            "reason": "Requested action is outside delegated scope.",
            "action_result": {
                "executed": False
            },
        }

    action_result = execute_simulated_privileged_action(action_name)

    return {
        "decision": "ACCEPTED",
        "reason": (
            "Authenticated identity and delegated action scope "
            "were validated."
        ),
        "authenticated_sender": authenticated_sender_id,
        "action_result": action_result,
    }


# ------------------------------------------------------------
# 6. RUN SPOOFING SCENARIOS
# ------------------------------------------------------------

def run_attack_scenarios() -> list[dict]:

    scenario_results = []

    for scenario_name, scenario in SPOOFED_IDENTITY_PAYLOADS.items():

        action_name = PRIVILEGED_ACTIONS.get(scenario_name)

        if action_name is None:
            print(
                f"Skipping unknown scenario: {scenario_name}"
            )
            continue

        # The attacker claims to be Agent A, but the actual
        # authenticated sender is an unverified external identity.
        message_envelope = {
            "authenticated_sender_id": ATTACKER_ID,
            "claimed_sender_id": AGENT_A.agent_id,
            "message": scenario["message"],
            "authentication_source": "SIMULATED_UNVERIFIED_TRANSPORT",
        }

        vulnerable_result = vulnerable_agent_b(
            message_envelope,
            action_name
        )

        protected_result = protected_agent_b(
            message_envelope,
            action_name
        )

        scenario_result = {
            "scenario_id": scenario_name,
            "attack_type": "Agent Identity Spoofing",
            "owasp_category": "LLM09",
            "attacker_message_verbatim": scenario["message"],
            "expected_behavior": scenario["expected_behavior"],
            "message_envelope": message_envelope,
            "target_agent": {
                "agent_id": AGENT_B.agent_id,
                "name": AGENT_B.name,
                "role": AGENT_B.role,
            },
            "action_requested": action_name,
            "vulnerable_agent_b_result": vulnerable_result,
            "protected_agent_b_result": protected_result,
            "vulnerable_action_executed": (
                vulnerable_result["action_result"]["executed"]
            ),
            "protected_action_executed": (
                protected_result["action_result"]["executed"]
            ),
        }

        scenario_results.append(scenario_result)

        print("\n" + "=" * 65)
        print(f"Scenario: {scenario_name}")
        print("=" * 65)
        print("Forged message:", scenario["message"])

        print(
            "Vulnerable Agent B decision:",
            vulnerable_result["decision"]
        )

        print(
            "Vulnerable action executed:",
            vulnerable_result["action_result"]["executed"]
        )

        print(
            "Protected Agent B decision:",
            protected_result["decision"]
        )

        print(
            "Protected action executed:",
            protected_result["action_result"]["executed"]
        )

        print(
            "Protection reason:",
            protected_result["reason"]
        )

    return scenario_results


# ------------------------------------------------------------
# 7. LEGITIMATE DELEGATION CONTROL TEST
# ------------------------------------------------------------

def run_legitimate_control_test() -> dict:
    """Verify that a genuinely authenticated Agent A can delegate."""

    action_name = "approve_sensitive_finance_export"

    legitimate_envelope = {
        "authenticated_sender_id": AGENT_A.agent_id,
        "claimed_sender_id": AGENT_A.agent_id,
        "message": (
            "Authenticated Agent A requests the authorized "
            "simulated delegated action."
        ),
        "authentication_source": "SIMULATED_TRUSTED_TRANSPORT",
    }

    result = protected_agent_b(
        legitimate_envelope,
        action_name
    )

    return {
        "test_name": "Legitimate orchestrator delegation",
        "message_envelope": legitimate_envelope,
        "agent_b_result": result,
        "action_executed": result["action_result"]["executed"],
    }


# ------------------------------------------------------------
# 8. BUILD ATTACK KILL CHAIN
# ------------------------------------------------------------

def build_kill_chain() -> list[str]:

    return [
        (
            "1. Identify the synthetic trusted orchestrator identity "
            f"({AGENT_A.agent_id})."
        ),
        (
            "2. Craft an instruction using one of the supplied "
            "identity-spoofing payloads."
        ),
        (
            "3. Send the message from an unverified source while "
            "claiming the trusted orchestrator identity."
        ),
        (
            "4. Vulnerable Agent B checks the claimed identity "
            "instead of the authenticated sender."
        ),
        (
            "5. Agent B accepts the forged trust claim and executes "
            "the simulated privileged action."
        ),
        (
            "6. Protected Agent B compares the authenticated sender "
            "with the claimed identity and rejects the spoofed message."
        ),
    ]


# ------------------------------------------------------------
# 9. SAVE EVIDENCE
# ------------------------------------------------------------

def save_evidence(
    scenario_results: list[dict],
    control_result: dict
) -> dict:

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    vulnerable_successes = sum(
        item["vulnerable_action_executed"]
        for item in scenario_results
    )

    protected_denials = sum(
        not item["protected_action_executed"]
        for item in scenario_results
    )

    report = {
        "assessment": "SecureNova Task 2 - Agent Identity Spoofing",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "execution_status": "COMPLETED",
        "implementation_type": "DETERMINISTIC_LOCAL_SIMULATION",
        "provider": "Local Python simulation",
        "real_llm_invoked": False,
        "real_auth0_validation_performed": False,
        "cryptographic_signature_verification_performed": False,
        "real_privileged_resources_accessed": False,
        "agent_a": asdict(AGENT_A),
        "agent_b": asdict(AGENT_B),
        "attack_scenarios": scenario_results,
        "legitimate_delegation_control": control_result,
        "summary": {
            "total_attack_scenarios": len(scenario_results),
            "vulnerable_actions_executed": vulnerable_successes,
            "protected_actions_denied": protected_denials,
            "legitimate_delegation_succeeded": control_result[
                "action_executed"
            ],
        },
        "kill_chain": build_kill_chain(),
        "limitations": [
            "This is a deterministic simulation, not a live LLM test.",
            "The transport identity is represented by a synthetic field.",
            "No real JWT, Auth0 token, signature, or MCP call was validated.",
            "The privileged action is simulated and accesses no real data.",
        ],
    }

    with RESULT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    kill_chain_text = [
        "# Task 2 - Agent Identity Spoofing Kill Chain",
        "",
        "**Assessment type:** Controlled local simulation",
        "",
    ]

    kill_chain_text.extend(
        f"- {step}" for step in report["kill_chain"]
    )

    kill_chain_text.extend(
        [
            "",
            "## Results",
            "",
            f"- Attack scenarios: {len(scenario_results)}",
            f"- Vulnerable actions executed: {vulnerable_successes}",
            f"- Protected actions denied: {protected_denials}",
            (
                "- Legitimate delegation accepted: "
                f"{control_result['action_executed']}"
            ),
            "",
            "## Limitations",
            "",
            "- No live LLM or Auth0 call was made.",
            "- No cryptographic identity verification was performed.",
            "- No real privileged resource or customer data was accessed.",
            "",
        ]
    )

    KILL_CHAIN_FILE.write_text(
        "\n".join(kill_chain_text),
        encoding="utf-8"
    )

    return report


# ------------------------------------------------------------
# 10. MAIN
# ------------------------------------------------------------

def main() -> None:

    print("=" * 65)
    print("SecureNova - Task 2")
    print("Agent Identity Spoofing Assessment")
    print("Execution type: Controlled local simulation")
    print("=" * 65)

    print("\nAgent A:", AGENT_A.agent_id)
    print("Agent B:", AGENT_B.agent_id)
    print("Attack scenarios:", len(SPOOFED_IDENTITY_PAYLOADS))

    scenario_results = run_attack_scenarios()

    control_result = run_legitimate_control_test()

    report = save_evidence(
        scenario_results,
        control_result
    )

    print("\n" + "=" * 65)
    print("TASK 2 EXECUTION SUMMARY")
    print("=" * 65)

    print(
        "Total attack scenarios:",
        report["summary"]["total_attack_scenarios"]
    )

    print(
        "Vulnerable actions executed:",
        report["summary"]["vulnerable_actions_executed"]
    )

    print(
        "Protected actions denied:",
        report["summary"]["protected_actions_denied"]
    )

    print(
        "Legitimate delegation succeeded:",
        report["summary"]["legitimate_delegation_succeeded"]
    )

    print("\nEvidence saved:")
    print(RESULT_FILE)
    print(KILL_CHAIN_FILE)

    print(
        "\nNOTE: These results demonstrate simulated trust-boundary "
        "behavior, not a real Auth0 or live LLM compromise."
    )


if __name__ == "__main__":
    main()
