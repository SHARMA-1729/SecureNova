# Task 2 - Agent Identity Spoofing Kill Chain

**Assessment type:** Controlled local simulation

- 1. Identify the synthetic trusted orchestrator identity (agent-secure-nova).
- 2. Craft an instruction using one of the supplied identity-spoofing payloads.
- 3. Send the message from an unverified source while claiming the trusted orchestrator identity.
- 4. Vulnerable Agent B checks the claimed identity instead of the authenticated sender.
- 5. Agent B accepts the forged trust claim and executes the simulated privileged action.
- 6. Protected Agent B compares the authenticated sender with the claimed identity and rejects the spoofed message.

## Results

- Attack scenarios: 3
- Vulnerable actions executed: 3
- Protected actions denied: 3
- Legitimate delegation accepted: True

## Limitations

- No live LLM or Auth0 call was made.
- No cryptographic identity verification was performed.
- No real privileged resource or customer data was accessed.
