"""Task 1 harness for indirect prompt-injection assessment."""

from __future__ import annotations

from src.prompt_injection.payloads import DOCUMENTS, SYNTHETIC_JWT, USER_REQUEST


def summarize_documents() -> dict:
    """Return an evaluation summary for the stored payloads."""
    return {
        "user_request": USER_REQUEST,
        "synthetic_jwt_present": bool(SYNTHETIC_JWT),
        "document_count": len(DOCUMENTS),
        "documents": [doc["id"] for doc in DOCUMENTS],
    }


if __name__ == "__main__":
    print(summarize_documents())
