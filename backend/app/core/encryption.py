"""AES-256-GCM credential encryption / decryption.

Credentials (api_token, zone_id, etc.) are serialised to canonical JSON,
encrypted with AES-256-GCM, and the resulting ciphertext + nonce are stored
separately in ``integrations.encrypted_credentials`` and
``integrations.credential_iv``.

The encryption key lives **only** in the server environment — it is never
written to the database or returned in API responses.

Usage
-----
    from app.core.encryption import encrypt_credentials, decrypt_credentials

    ciphertext, iv = encrypt_credentials({"api_token": "...", "zone_id": "..."})
    credentials    = decrypt_credentials(ciphertext, iv)
    # → {"api_token": "...", "zone_id": "..."}
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings


# ── Custom error ─────────────────────────────────────────────────────────────

class EncryptionKeyError(Exception):
    """Raised when ``ENCRYPTION_KEY`` is missing, not valid base64, or the
    wrong length.  Contains a human-readable message with remediation advice.
    """


# ── Internal helper ───────────────────────────────────────────────────────────

def _load_key() -> bytes:
    """Decode and validate the AES-256-GCM key from settings.

    Returns:
        32 raw bytes ready for use with ``AESGCM``.

    Raises:
        EncryptionKeyError: Key is absent, still a placeholder, not valid
            base64, or not exactly 32 bytes.
    """
    raw = settings.ENCRYPTION_KEY
    if not raw or raw.startswith("replace-with"):
        raise EncryptionKeyError(
            "ENCRYPTION_KEY is not configured.  Generate one with:\n"
            "  python3 -c \"import secrets, base64; "
            "print(base64.b64encode(secrets.token_bytes(32)).decode())\"\n"
            "and set it in your .env file."
        )
    try:
        key = base64.b64decode(raw)
    except Exception as exc:
        raise EncryptionKeyError(
            f"ENCRYPTION_KEY is not valid base64: {exc}"
        ) from exc
    if len(key) != 32:
        raise EncryptionKeyError(
            f"ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256).  "
            f"Got {len(key)} bytes.  Re-generate the key."
        )
    return key


# ── Public API ────────────────────────────────────────────────────────────────

def encrypt_credentials(credentials: dict) -> tuple[bytes, bytes]:
    """Serialise a credentials dict to canonical JSON and encrypt with AES-256-GCM.

    A fresh 96-bit nonce is generated for every call — the same key/nonce
    pair must never be reused, so the nonce is stored alongside the ciphertext.

    Args:
        credentials: Plain Python dict (e.g. ``{"api_token": "...",
            "zone_id": "..."}``) — must be JSON-serialisable.

    Returns:
        ``(ciphertext, iv)`` tuple:

        - ``ciphertext`` — AES-GCM ciphertext with the 16-byte authentication
          tag appended (as produced by the ``cryptography`` library).  Store
          in ``Integration.encrypted_credentials``.
        - ``iv`` — 12-byte nonce.  Store in ``Integration.credential_iv``.
          Required for decryption; not secret but must not be reused.

    Raises:
        EncryptionKeyError: ``ENCRYPTION_KEY`` is missing or malformed.
    """
    key = _load_key()
    iv = os.urandom(12)  # 96-bit nonce — NIST recommendation for AES-GCM
    plaintext = json.dumps(credentials, sort_keys=True).encode()
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)  # aad=None
    return ciphertext, iv


def decrypt_credentials(ciphertext: bytes, iv: bytes) -> dict:
    """Decrypt AES-256-GCM ciphertext and return the credentials dict.

    Args:
        ciphertext: Encrypted bytes from ``Integration.encrypted_credentials``.
        iv: 12-byte nonce from ``Integration.credential_iv``.

    Returns:
        The original credentials dict.

    Raises:
        EncryptionKeyError: ``ENCRYPTION_KEY`` is missing or malformed.
        cryptography.exceptions.InvalidTag: The ciphertext, IV, or key is
            wrong (tampered data or wrong environment key).
    """
    key = _load_key()
    plaintext = AESGCM(key).decrypt(iv, ciphertext, None)
    return json.loads(plaintext)
