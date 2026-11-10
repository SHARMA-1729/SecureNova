"""Synthetic identity and security fixtures for controlled assessment exercises."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SyntheticAgentIdentity:
    """A synthetic identity used in test scenarios only."""

    agent_id: str
    name: str
    email: str
    role: str
    tenant: str
    trusted: bool = False


SYNTHETIC_AGENT_IDENTITIES = [
    SyntheticAgentIdentity(
        agent_id="agent-secure-nova",
        name="SecureNova Policy Agent",
        email="policy.agent@secure-nova.example",
        role="policy-assistant",
        tenant="secure-nova-prod",
        trusted=True,
    ),
    SyntheticAgentIdentity(
        agent_id="agent-finops-audit",
        name="Finance Audit Assistant",
        email="finance.audit@secure-nova.example",
        role="audit-assistant",
        tenant="secure-nova-prod",
        trusted=False,
    ),
]

SYNTHETIC_TEST_EMAILS = [
    "customer-ops@secure-nova.example",
    "support-bot@secure-nova.example",
    "security-audit@secure-nova.example",
]
