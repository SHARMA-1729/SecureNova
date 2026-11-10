
"""Verified MITRE ATLAS mappings for SecureNova Project 3."""

ATLAS_MAPPINGS = {
    "F-01": {
        "title": "Indirect Prompt Injection",
        "primary": {
            "id": "AML.T0051.001",
            "name": "Indirect",
        },
        "related": [
            {
                "id": "AML.T0051",
                "name": "LLM Prompt Injection",
            }
        ],
        "outcome": "Complete synthetic JWT disclosure demonstrated in vulnerable baseline; zero disclosures in protected profile.",
    },

    "F-02": {
        "title": "Agent Identity Spoofing",
        "primary": {
            "id": "AML.T0073",
            "name": "Impersonation",
        },
        "related": [
            {
                "id": "AML.T0053",
                "name": "AI Agent Tool Invocation",
            }
        ],
        "outcome": "Demonstrated in deterministic local simulation.",
    },

    "F-03": {
        "title": "System Prompt Extraction",
        "primary": {
            "id": "AML.T0056",
            "name": "Extract LLM System Prompt",
        },
        "related": [
            {
                "id": "AML.T0051",
                "name": "LLM Prompt Injection",
            }
        ],
        "outcome": "Partial protected-instruction fragment echoed; full prompt not extracted.",
    },

    "F-04": {
        "title": "User-to-Admin Privilege Escalation",
        "primary": {
            "id": "AML.T0054",
            "name": "LLM Jailbreak",
        },
        "related": [],
        "outcome": "Attempted; admin privilege escalation not demonstrated.",
    },

    "F-05": {
        "title": "RAG Poisoning and MCP Abuse",
        "primary": {
            "id": "AML.T0070",
            "name": "RAG Poisoning",
        },
        "related": [
            {
                "id": "AML.T0071",
                "name": "False RAG Entry Injection",
            },
            {
                "id": "AML.T0066",
                "name": "Retrieval Content Crafting",
            },
            {
                "id": "AML.T0053",
                "name": "AI Agent Tool Invocation",
            },
        ],
        "outcome": "Demonstrated in controlled Gemini and simulated MCP tests.",
    },
}

__all__ = ["ATLAS_MAPPINGS"]
