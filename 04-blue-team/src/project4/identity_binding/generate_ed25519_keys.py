"""
SecureNova Project 4 - Task 2
Generate an Ed25519 agent identity key pair.

Security:
- Private key is encrypted using a passphrase.
- Private key is stored outside the project workspace.
- Public key is saved in Project 4 evidence.
- Private key contents and passphrase are never printed.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os

from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


# ============================================================
# 1. CONFIGURATION
# ============================================================

AGENT_ID = "agent-secure-nova"

PROJECT_ROOT = Path(__file__).resolve().parents[3]

EVIDENCE_DIR = (
    PROJECT_ROOT
    / "evidence"
    / "project4"
    / "task2_identity_binding"
)

PUBLIC_KEY_FILE = (
    EVIDENCE_DIR
    / f"{AGENT_ID}_ed25519_public.pem"
)

METADATA_FILE = (
    EVIDENCE_DIR
    / "ed25519_key_generation_evidence.json"
)

# Store the private key in the current Windows user's
# Local AppData directory, outside the project workspace.
LOCAL_APPDATA = Path(
    os.environ.get(
        "LOCALAPPDATA",
        str(Path.home() / "AppData" / "Local"),
    )
)

PRIVATE_KEY_DIR = (
    LOCAL_APPDATA
    / "SecureNova"
    / "Project4"
    / "keys"
)

PRIVATE_KEY_FILE = (
    PRIVATE_KEY_DIR
    / f"{AGENT_ID}_ed25519_private.pem"
)


# ============================================================
# 2. PASSphrase INPUT
# ============================================================

def get_encryption_passphrase() -> bytes:

    while True:

        first = getpass.getpass(
            "Enter a new private-key encryption passphrase "
            "(minimum 12 characters): "
        )

        if len(first) < 12:
            print("Passphrase must contain at least 12 characters.")
            continue

        second = getpass.getpass(
            "Re-enter the passphrase: "
        )

        if first != second:
            print("Passphrases do not match. Try again.")
            continue

        return first.encode("utf-8")


# ============================================================
# 3. GENERATE AND SAVE KEYS
# ============================================================

def main() -> None:

    print("=" * 72)
    print("SecureNova - Project 4 - Task 2")
    print("Ed25519 Agent Identity Key Generation")
    print("=" * 72)

    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    PRIVATE_KEY_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Never silently overwrite an existing identity key.
    existing_files = [
        path
        for path in [
            PRIVATE_KEY_FILE,
            PUBLIC_KEY_FILE,
            METADATA_FILE,
        ]
        if path.exists()
    ]

    if existing_files:

        print("\nERROR: Existing key/evidence files detected.")

        for path in existing_files:
            print("Existing:", path)

        print(
            "\nNo files were overwritten. "
            "Use the existing key pair or investigate the files first."
        )

        return

    passphrase = get_encryption_passphrase()

    # Generate a fresh Ed25519 private key.
    private_key = Ed25519PrivateKey.generate()

    public_key = private_key.public_key()

    # Serialize private key as encrypted PKCS8 PEM.
    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase
        ),
    )

    # Serialize public key in SubjectPublicKeyInfo PEM format.
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Calculate SHA-256 fingerprint from raw public-key bytes.
    raw_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    fingerprint = hashlib.sha256(
        raw_public_key
    ).hexdigest()

    # Create private key without overwriting an existing file.
    with PRIVATE_KEY_FILE.open("xb") as file:
        file.write(encrypted_private_pem)

    # Create public key without overwriting an existing file.
    with PUBLIC_KEY_FILE.open("xb") as file:
        file.write(public_pem)

    # Record safe metadata only.
    evidence = {
        "project": "SecureNova",
        "task": "Project 4 - Task 2: Ed25519 Identity Binding",
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "agent_id": AGENT_ID,
        "algorithm": "Ed25519",
        "private_key": {
            "file_created": PRIVATE_KEY_FILE.exists(),
            "storage": "Windows Local AppData outside project workspace",
            "encryption": "PEM PKCS8 with BestAvailableEncryption",
            "path": str(PRIVATE_KEY_FILE),
            "private_key_contents_logged": False,
        },
        "public_key": {
            "file_created": PUBLIC_KEY_FILE.exists(),
            "format": "PEM SubjectPublicKeyInfo",
            "path": str(PUBLIC_KEY_FILE),
            "sha256_fingerprint": fingerprint,
        },
        "private_key_passphrase_logged": False,
    }

    with METADATA_FILE.open(
        "x",
        encoding="utf-8",
    ) as file:
        json.dump(
            evidence,
            file,
            indent=4,
            ensure_ascii=False,
        )

    # Clear the local reference to the passphrase bytes.
    del passphrase

    print("\n" + "=" * 72)
    print("ED25519 KEY GENERATION COMPLETE")
    print("=" * 72)

    print("Agent identity:", AGENT_ID)
    print("Algorithm: Ed25519")

    print("\nPRIVATE KEY")
    print("File created:", PRIVATE_KEY_FILE.exists())
    print("Encryption: Enabled (encrypted PKCS8 PEM)")
    print("Storage:", PRIVATE_KEY_FILE)

    print("\nPUBLIC KEY")
    print("File created:", PUBLIC_KEY_FILE.exists())
    print("Format: PEM")
    print("Storage:", PUBLIC_KEY_FILE)

    print("\nPUBLIC KEY SHA-256 FINGERPRINT:")
    print(fingerprint)

    print("\nPrivate key contents displayed: NO")
    print("Passphrase displayed: NO")

    print("\nEvidence metadata saved:")
    print(METADATA_FILE)

    print("\nRESULT: PASS")


if __name__ == "__main__":
    main()