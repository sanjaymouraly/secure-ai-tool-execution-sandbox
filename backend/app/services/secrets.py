"""Secret storage helpers.

Provider API keys are stored encrypted at rest with a Fernet key that lives
in the environment (``SAXIS_PROVIDER_SECRET_KEY``).  The key is never written
to the database, never returned to the browser and never handed to a sandbox
worker.  If no encryption key is configured the API refuses to persist a
credential rather than storing it in clear text.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

#: Environment variable that holds the Fernet key.
SECRET_KEY_ENV = "SAXIS_PROVIDER_SECRET_KEY"  # noqa: S105  # nosec B105


def _fernet(settings: Any) -> Fernet:
    raw = getattr(settings, "provider_secret_key", "") or os.getenv(SECRET_KEY_ENV, "")
    if not raw:
        raise RuntimeError(
            "No provider secret key is configured. Set SAXIS_PROVIDER_SECRET_KEY to a "
            'Fernet key (generate one with: python -c "from cryptography.fernet import '
            'Fernet; print(Fernet.generate_key().decode())").'
        )
    key = raw.encode("utf-8") if isinstance(raw, str) else raw
    try:
        return Fernet(key)
    except (ValueError, TypeError):
        # Accept a passphrase by deriving a 32 byte key from it.
        digest = hashlib.sha256(key).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def encryption_available(settings: Any) -> bool:
    """Return True when secrets can be encrypted at rest."""
    raw = getattr(settings, "provider_secret_key", "") or os.getenv(SECRET_KEY_ENV, "")
    return bool(raw)


def encrypt_secret(plaintext: str, settings: Any) -> str:
    """Encrypt a secret for storage."""
    if not plaintext:
        return ""
    return _fernet(settings).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str, settings: Any) -> str:
    """Decrypt a stored secret."""
    if not ciphertext:
        return ""
    try:
        return _fernet(settings).decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("The stored credential could not be decrypted.") from exc


def key_hint(plaintext: str) -> str:
    """Return a short, non-reversible hint for a credential."""
    if not plaintext:
        return ""
    if len(plaintext) <= 8:
        return "*" * len(plaintext)
    return f"{plaintext[:3]}...{plaintext[-3:]}"
