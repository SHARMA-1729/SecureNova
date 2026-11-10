@'
# SecureNova AI Identity Security - Project 3

## Objective
Conduct a controlled red-team assessment of the SecureNova AI identity architecture.

## Technology
- Python 3.14
- Requests
- Cryptography
- Auth0-backed Spring Boot application (Project 2)

## Assessment Tasks
1. Indirect Prompt Injection (OWASP LLM01)
2. Agent Identity Spoofing (OWASP LLM09)
3. System Prompt Extraction (OWASP LLM07)
4. RAG Poisoning and MCP Abuse
5. CVSS 3.1 and MITRE ATLAS Mapping

## Evidence
All payloads, test outputs and assessment results must be recorded.

## Safety and Scope
Use synthetic credentials, isolated test identities and harmless simulated tools.
Do not expose real secrets or production customer information.

Clearly distinguish actual application tests, real model responses and simulated results.
'@ | Set-Content -Encoding UTF8 README.md