
"""SecureNova Project 4 - Input Security Policy."""

import re
from typing import Any


# Rules are evaluated in order.
# More specific security findings must appear before general rules.

INPUT_RULES = [

    # --------------------------------------------------------
    # F-05: RAG POISONING AND MCP ABUSE
    # --------------------------------------------------------

    (
        "P4-F05-MCP-DIRECTIVE",
        r"\bMCP_TOOL_REQUEST\b",
        "Explicit MCP tool directive detected."
    ),

    (
        "P4-F05-MCP-TOOL",
        r"\b(?:invoke|call|execute|run)\b.{0,80}"
        r"\bMCP\s+tool\b",
        "Untrusted content attempts to invoke an MCP tool."
    ),

    (
        "P4-F05-CRITICAL-TOOL",
        r"\bread_internal_audit_log\b|\ball_accounts\b",
        "Restricted internal tool or scope detected."
    ),

    # --------------------------------------------------------
    # F-04: USER-TO-ADMIN PRIVILEGE ESCALATION
    # --------------------------------------------------------

    (
        "P4-F04-ROLE-ESCALATION",
        r"\b(?:change|upgrade|escalate|grant|switch)\b.{0,80}"
        r"\b(?:my\s+)?(?:customer\s+)?(?:role|access|privileges?)\b"
        r".{0,80}\b(?:to\s+)?(?:admin|administrator)\b",
        "Unauthorized privilege escalation request detected."
    ),
    (
    "P4-F03-REPEAT-BACK",
    r"\brepeat\b.{0,120}\b(?:every|all|complete|full)\s+"
    r"(?:the\s+)?instructions?\b",
    "System instruction repeat-back attempt detected."
    ),

    # --------------------------------------------------------
    # F-03: SYSTEM PROMPT EXTRACTION
    # --------------------------------------------------------

    (
        "P4-F03-PROMPT-EXTRACTION",
        r"\b(?:repeat|reveal|show|display|print|extract|translate|"
        r"disclose|append|restate|provide|list)\b.{0,120}"
        r"\b(?:hidden\s+)?(?:system\s+prompt|system\s+instructions|"
        r"hidden\s+instructions|internal\s+instructions)\b",
        "System prompt or hidden instruction extraction detected."
    ),
   
   

    (
        "P4-F03-TRANSLATION-EXTRACTION",
        r"\btranslate\b.{0,100}\ball\s+instructions\b"
        r".{0,100}\b(?:governing|controlling|defining)\b"
        r".{0,60}\b(?:your\s+)?behavior\b",
        "Instruction extraction through a translation technique detected."
    ),

    (
        "P4-F03-INSTRUCTION-OVERRIDE-EXTRACTION",
        r"\bignore\b.{0,100}\b(?:previous|prior)\s+instructions\b"
        r".{0,150}\b(?:disclose|reveal|print|show)\b"
        r".{0,80}\b(?:system\s+prompt|hidden\s+instructions)\b",
        "Prompt extraction following an instruction override detected."
    ),

    # --------------------------------------------------------
    # F-02: AGENT IDENTITY SPOOFING
    # --------------------------------------------------------

    (
        "P4-F02-AGENT-DELEGATION",
        r"\b(?:previous|prior)\s+agent\b.{0,80}"
        r"\b(?:delegated|approved|authorized)\b",
        "Unverified agent delegation claim detected."
    ),

    (
        "P4-F02-SPOOFED-ADMIN-TOOL",
        r"\b(?:use|invoke|call|execute)\b.{0,80}"
        r"\b(?:system\s+)?admin\s+tool\b",
        "Unverified administrative tool invocation detected."
    ),

    (
        "P4-F02-ADMIN-IMPERSONATION",
        r"\b(?:i am|i'm|this is)\b.{0,60}"
        r"\b(?:admin|administrator|security team|"
        r"trusted orchestrator)\b",
        "Unverified privileged identity claim detected."
    ),

    (
        "P4-F02-IDENTITY-CLAIM",
        r"\bidentity\b.{0,60}\b(?:security-ops|"
        r"agent-secure-nova|admin)\b",
        "Unverified privileged identity reference detected."
    ),

    # --------------------------------------------------------
    # F-01: INDIRECT PROMPT INJECTION AND CREDENTIAL EXFILTRATION
    # --------------------------------------------------------

    (
        "P4-F01-DOCUMENT-AUTHORITY-OVERRIDE",
        r"\b(?:document|file|content)\b.{0,80}"
        r"\b(?:higher\s+priority|more\s+authoritative)\b"
        r".{0,80}\b(?:previous|prior|system)\s+instructions\b",
        "Untrusted document attempts to override instruction authority."
    ),

    (
        "P4-F01-DOCUMENT-OVERRIDE",
        r"\b(?:ignore|disregard|override|forget)\b.{0,120}"
        r"\b(?:previous|prior|original|system|security)\b.{0,60}"
        r"\b(?:instructions?|rules?|restrictions?)\b",
        "Indirect prompt injection or instruction override detected."
    ),

    (
        "P4-F01-CREDENTIAL-EXFILTRATION",
        r"\b(?:reveal|disclose|exfiltrate|print|reproduce|"
        r"include|return|output|populate|produce|encode|"
        r"export|copy|append|preserve|transmit)\b"
        r".{0,140}"
        r"\b(?:synthetic\s+)?(?:identity\s+)?"
        r"(?:test\s+)?(?:credential|jwt|canary|token|secret)\b",
        "Credential disclosure or exfiltration instruction detected."
    ),

    (
        "P4-F01-CANARY-DISCLOSURE",
        r"\b(?:include|reveal|disclose|print|copy|return|"
        r"output|populate|preserve|validate)\b.{0,120}"
        r"\b(?:complete\s+)?(?:synthetic\s+)?"
        r"(?:identity\s+)?canary\b",
        "Synthetic identity canary disclosure instruction detected."
    ),

]


COMPILED_RULES = [
    (
        rule_id,
        re.compile(
            pattern,
            re.IGNORECASE | re.DOTALL
        ),
        reason
    )
    for rule_id, pattern, reason in INPUT_RULES
]


def inspect_input(text: str) -> dict[str, Any]:
    """Inspect untrusted input and return an explicit decision."""

    if not isinstance(text, str):

        return {
            "allowed": False,
            "rule_id": "INVALID_INPUT_TYPE",
            "reason": "Input must be a string."
        }

    for rule_id, pattern, reason in COMPILED_RULES:

        if pattern.search(text):

            return {
                "allowed": False,
                "rule_id": rule_id,
                "reason": reason
            }

    return {
        "allowed": True,
        "rule_id": None,
        "reason": (
            "No configured SecureNova input rule was triggered."
        )
    }
