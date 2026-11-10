"""
SecureNova Project 4 - Task 2
Ed25519 agent message signing and verification.

Demonstrates:
1. Load encrypted Ed25519 private key.
2. Sign a canonical agent message.
3. Verify the original message.
4. Change one character.
5. Reject the tampered message.
6. Save timestamped JSON evidence.

No real agent transport or production service is used.
"""

from __future__ import annotations

import base64
import copy
import getpass
import hashlib
import json

from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ============================================================
# 1. PATHS AND CONFIGURATION
# ============================================================

AGENT_ID = "agent-secure-nova"

PROJECT_ROOT = Path(__file__).resolve().parents[3]

LOCAL_APPDATA = Path.home() / "AppData" / "Local"

PRIVATE_KEY_FILE = (
    LOCAL_APPDATA
    / "SecureNova"
    / "Project4"
    / "keys"
    / f"{AGENT_ID}_ed25519_private.pem"
)

PUBLIC_KEY_FILE = (
    PROJECT_ROOT
    / "evidence"
    / "project4"
    / "task2_identity_binding"
    / f"{AGENT_ID}_ed25519_public.pem"
)

EVIDENCE_DIR = (
    PROJECT_ROOT
    / "evidence"
    / "project4"
    / "task2_identity_binding"
)

RESULT_FILE = (
    EVIDENCE_DIR
    / "ed25519_message_verification_results.json"
)


# ============================================================
# 2. CANONICAL MESSAGE SERIALIZATION
# ============================================================

def canonical_message(message: dict) -> bytes:
    """
    Serialize message fields consistently.

    Sorting keys and removing unnecessary whitespace ensures
    the same message produces identical signed bytes.
    """

    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


# ============================================================
# 3. LOAD ENCRYPTED PRIVATE KEY
# ============================================================

def load_private_key() -> Ed25519PrivateKey:

    if not PRIVATE_KEY_FILE.exists():
        raise FileNotFoundError(
            f"Private key not found: {PRIVATE_KEY_FILE}"
        )

    passphrase = getpass.getpass(
        "Enter the Ed25519 private-key encryption passphrase: "
    )

    try:
        key = serialization.load_pem_private_key(
            PRIVATE_KEY_FILE.read_bytes(),
            password=passphrase.encode("utf-8"),
        )
    finally:
        del passphrase

    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(
            "The loaded private key is not an Ed25519 key."
        )

    return key


# ============================================================
# 4. LOAD TRUSTED PUBLIC KEY
# ============================================================

def load_public_key() -> Ed25519PublicKey:

    if not PUBLIC_KEY_FILE.exists():
        raise FileNotFoundError(
            f"Public key not found: {PUBLIC_KEY_FILE}"
        )

    key = serialization.load_pem_public_key(
        PUBLIC_KEY_FILE.read_bytes()
    )

    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(
            "The loaded public key is not an Ed25519 key."
        )

    return key


# ============================================================
# 5. CREATE AGENT MESSAGE
# ============================================================

def create_agent_message() -> dict:

    return {
        "agent_id": AGENT_ID,
        "message_id": "SN-TASK2-MSG-001",
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "recipient": "agent-finops-audit",
        "scope": [
            "read.ai-data",
        ],
        "message": (
            "SecureNova agent requests an authorized "
            "customer-policy data lookup."
        ),
    }


# ============================================================
# 6. SIGN OUTGOING MESSAGE
# ============================================================

def sign_message(
    private_key: Ed25519PrivateKey,
    message: dict,
) -> dict:

    signature = private_key.sign(
        canonical_message(message)
    )

    return {
        "message": copy.deepcopy(message),
        "signature_base64": base64.b64encode(
            signature
        ).decode("ascii"),
        "signature_algorithm": "Ed25519",
    }


# ============================================================
# 7. VERIFY RECEIVED MESSAGE
# ============================================================

def verify_message(
    public_key: Ed25519PublicKey,
    signed_envelope: dict,
) -> dict:

    message = signed_envelope["message"]

    signature = base64.b64decode(
        signed_envelope["signature_base64"],
        validate=True,
    )

    try:

        public_key.verify(
            signature,
            canonical_message(message),
        )

        return {
            "verified": True,
            "status": "ACCEPTED",
            "reason": "Ed25519 signature verification succeeded.",
        }

    except InvalidSignature:

        return {
            "verified": False,
            "status": "REJECTED",
            "reason": "Ed25519 signature verification failed.",
        }


# ============================================================
# 8. MAIN TEST
# ============================================================

def main() -> None:

    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 72)
    print("SecureNova - Project 4 - Task 2")
    print("Ed25519 Agent Message Signing and Verification")
    print("=" * 72)

    # Load sender's encrypted private key and receiver's
    # separately stored trusted public key.
    private_key = load_private_key()
    public_key = load_public_key()

    # Confirm both keys are from the same key pair.
    sender_public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    receiver_public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    if sender_public_bytes != receiver_public_bytes:
        raise RuntimeError(
            "Sender and receiver public keys do not match."
        )

    fingerprint = hashlib.sha256(
        receiver_public_bytes
    ).hexdigest()

    print("\nAgent identity:", AGENT_ID)
    print("Signature algorithm: Ed25519")
    print("Sender/receiver public keys match: True")
    print("Public-key SHA-256 fingerprint:", fingerprint)

    # --------------------------------------------------------
    # ORIGINAL SIGNED MESSAGE
    # --------------------------------------------------------

    message = create_agent_message()

    signed_envelope = sign_message(
        private_key,
        message,
    )

    print("\n" + "=" * 72)
    print("ORIGINAL OUTGOING AGENT MESSAGE")
    print("=" * 72)

    print("Message ID:", message["message_id"])
    print("Sender:", message["agent_id"])
    print("Recipient:", message["recipient"])
    print("Message:", message["message"])
    print("Signature algorithm:", signed_envelope["signature_algorithm"])
    print("Digital signature generated: True")

    original_result = verify_message(
        public_key,
        signed_envelope,
    )

    print("\nORIGINAL MESSAGE VERIFICATION")
    print("Status:", original_result["status"])
    print("Reason:", original_result["reason"])

    # --------------------------------------------------------
    # TAMPER MESSAGE: CHANGE ONE CHARACTER
    # --------------------------------------------------------

    tampered_envelope = copy.deepcopy(
        signed_envelope
    )

    original_text = tampered_envelope["message"]["message"]

    # Change one character while preserving the original signature.
    tampered_envelope["message"]["message"] = (
        original_text.replace(
            "authorized",
            "authorizxd",
            1,
        )
    )

    if tampered_envelope["message"]["message"] == original_text:
        raise RuntimeError(
            "Tampering test did not modify the message."
        )

    print("\n" + "=" * 72)
    print("TAMPERED AGENT MESSAGE TEST")
    print("=" * 72)

    print("Original message:", original_text)
    print(
        "Tampered message:",
        tampered_envelope["message"]["message"],
    )
    print("Original signature reused: True")

    tampered_result = verify_message(
        public_key,
        tampered_envelope,
    )

    print("\nTAMPERED MESSAGE VERIFICATION")
    print("Status:", tampered_result["status"])
    print("Reason:", tampered_result["reason"])

    print("\n" + "=" * 72)
    print("SECURITY VERIFICATION SUMMARY")
    print("=" * 72)

    print(
        "Original signed message accepted:",
        original_result["verified"],
    )

    print(
        "Tampered message rejected:",
        not tampered_result["verified"],
    )

    changed_characters = sum(
    first != second
    for first, second in zip(
        original_text,
        tampered_envelope["message"]["message"],
    )
    )

    print("Characters changed:", changed_characters)

    # --------------------------------------------------------
    # SAVE TIMESTAMPED EVIDENCE
    # --------------------------------------------------------

    evidence = {
        "project": "SecureNova",
        "task": "Project 4 - Task 2: Ed25519 Identity Binding",
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "implementation_type": "CONTROLLED LOCAL CRYPTOGRAPHIC TEST",
        "agent_id": AGENT_ID,
        "signature_algorithm": "Ed25519",
        "public_key_sha256_fingerprint": fingerprint,
        "sender_receiver_keys_match": True,
        "original_message": signed_envelope,
        "original_verification": {
            **original_result,
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "identity": AGENT_ID,
            "event_type": "SIGNED_MESSAGE_VERIFICATION",
        },
        "tampered_message": tampered_envelope,
        "tampered_verification": {
            **tampered_result,
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "identity": AGENT_ID,
            "event_type": "TAMPERED_MESSAGE_REJECTION",
        },
        "summary": {
            "original_message_accepted": original_result["verified"],
            "tampered_message_rejected": (
                not tampered_result["verified"]
            ),
        },
        "limitations": [
            "Local cryptographic demonstration.",
            "No live inter-agent network transport was used.",
            "No production MCP tool or business API was called.",
        ],
    }

    with RESULT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            evidence,
            file,
            indent=4,
            ensure_ascii=False,
        )

    test_passed = (
        original_result["verified"]
        and not tampered_result["verified"]
    )

    print("\nRESULT:", "PASS" if test_passed else "FAIL")
    print("\nEvidence saved:")
    print(RESULT_FILE)

    if not test_passed:
        raise RuntimeError(
            "The Ed25519 signature verification test failed."
        )


if __name__ == "__main__":
    main()