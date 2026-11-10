
"""SecureNova Project 4 - NeMo custom input guardrail action."""

from nemoguardrails.actions import action
from nemoguardrails.actions.rail_outcome import RailOutcome

from src.project4.guardrails.policy import inspect_input


@action(name="check_securenova_input")
async def check_securenova_input(text: str) -> RailOutcome:
    """
    Inspect incoming user content using the SecureNova policy.

    Returns an explicit NeMo rail decision:
    - BLOCK when a configured security rule matches.
    - ALLOW when no configured rule matches.
    """

    decision = inspect_input(text)

    if not decision["allowed"]:
        return RailOutcome.block(
            reason=decision["reason"],
            metadata={
                "rule_id": decision["rule_id"],
                "security_policy": "SecureNova Project 4"
            }
        )

    return RailOutcome.allow(
        reason=decision["reason"],
        metadata={
            "security_policy": "SecureNova Project 4"
        }
    )
