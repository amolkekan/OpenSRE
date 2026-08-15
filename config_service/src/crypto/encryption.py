"""
Column-level encryption for sensitive data using Fernet (symmetric encryption).

Encryption key management:
- Development: Generated key stored in .env (ENCRYPTION_KEY)
- Production: Fetched from AWS Secrets Manager or K8s secret
- Rotation: Set ENCRYPTION_KEY_PREVIOUS to the prior key during rotation

Security notes:
- Fernet uses AES-128 in CBC mode with HMAC for authentication
- Keys are base64-encoded 32-byte values
- Each encryption includes a timestamp for key rotation support
- Plaintext column fallback is allowed only in local dev (CONFIG_MODE=local)
"""

import os
from typing import List, Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from src.core.yaml_config import is_local_mode


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""

    pass


def _load_fernet_keys() -> List[Fernet]:
    """Load current and optional previous Fernet keys for multi-key decrypt."""
    keys: List[Fernet] = []
    current = os.getenv("ENCRYPTION_KEY", "").strip()
    previous = os.getenv("ENCRYPTION_KEY_PREVIOUS", "").strip()

    for label, material in (("ENCRYPTION_KEY", current), ("ENCRYPTION_KEY_PREVIOUS", previous)):
        if not material:
            continue
        if len(material) != 44:
            raise EncryptionError(
                f"{label} must be 44 characters (base64-encoded 32-byte key), "
                f"got {len(material)} characters. "
                "Generate a valid key with: python scripts/generate-encryption-key.py"
            )
        try:
            keys.append(Fernet(material.encode()))
        except Exception as e:
            raise EncryptionError(f"Failed to initialize {label}: {e}") from e

    if not keys:
        raise EncryptionError(
            "ENCRYPTION_KEY must be set for column encryption. "
            "Generate one with: python scripts/generate-encryption-key.py"
        )

    return keys


def is_plaintext_secret_allowed() -> bool:
    """Plaintext DB secrets are only permitted in explicit local dev mode."""
    explicit = os.getenv("ALLOW_PLAINTEXT_SECRETS", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    return is_local_mode() or explicit


class EncryptionService:
    """
    Handles encryption and decryption of sensitive data using Fernet.

    Decrypt tries ENCRYPTION_KEY first, then ENCRYPTION_KEY_PREVIOUS when set.
    """

    def __init__(self):
        keys = _load_fernet_keys()
        self._fernet = keys[0]
        self._multi = MultiFernet(keys) if len(keys) > 1 else None

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string value.

        Args:
            plaintext: The string to encrypt

        Returns:
            Base64-encoded encrypted value with format: "fernet:ENCRYPTED_DATA"
        """
        if not plaintext:
            return ""

        try:
            encrypted_bytes = self._fernet.encrypt(plaintext.encode())
            # Prefix with "fernet:" for version identification
            return f"fernet:{encrypted_bytes.decode()}"
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt an encrypted string value.

        Supports:
        - ``fernet:`` prefixed values (current + optional previous key)
        - legacy ``enc:`` prefix (Fernet payload without the fernet: label)

        Args:
            ciphertext: The encrypted string

        Returns:
            Decrypted plaintext string
        """
        if not ciphertext:
            return ""

        try:
            payload = ciphertext
            if payload.startswith("fernet:"):
                payload = payload[7:]
            elif payload.startswith("enc:"):
                payload = payload[4:]

            decryptor = self._multi or self._fernet
            decrypted_bytes = decryptor.decrypt(payload.encode())
            return decrypted_bytes.decode()
        except InvalidToken as e:
            raise EncryptionError(
                "Decryption failed: invalid token or corrupted data"
            ) from e
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}") from e

    def encrypt_dict(self, data: dict) -> dict:
        """
        Recursively encrypt sensitive values in a dictionary.

        Encrypts values for keys identified by ``is_sensitive_key`` in
        ``secret_redaction`` (tokens, secrets, API keys, passwords, etc.).

        Args:
            data: Dictionary that may contain sensitive values

        Returns:
            New dictionary with encrypted sensitive values
        """
        if not isinstance(data, dict):
            return data

        from src.core.secret_redaction import is_sensitive_key

        encrypted = {}

        for key, value in data.items():
            is_sensitive = is_sensitive_key(key)

            if is_sensitive and isinstance(value, str) and value:
                # Don't re-encrypt already encrypted values
                if not value.startswith(("fernet:", "enc:")):
                    encrypted[key] = self.encrypt(value)
                else:
                    encrypted[key] = value
            elif isinstance(value, dict):
                encrypted[key] = self.encrypt_dict(value)
            else:
                encrypted[key] = value

        return encrypted

    def decrypt_dict(self, data: dict) -> dict:
        """
        Recursively decrypt encrypted values in a dictionary.

        Args:
            data: Dictionary that may contain encrypted values

        Returns:
            New dictionary with decrypted values
        """
        if not isinstance(data, dict):
            return data

        decrypted = {}

        from src.core.secret_redaction import is_sensitive_key

        for key, value in data.items():
            if isinstance(value, str) and value.startswith(("fernet:", "enc:")):
                try:
                    decrypted[key] = self.decrypt(value)
                except EncryptionError:
                    if is_plaintext_secret_allowed():
                        decrypted[key] = value
                    else:
                        raise
            elif is_sensitive_key(key) and isinstance(value, str) and value:
                if is_plaintext_secret_allowed():
                    decrypted[key] = value
                else:
                    raise EncryptionError(
                        "Refusing to return plaintext secret field outside local/dev. "
                        "Re-encrypt the value or set CONFIG_MODE=local for development."
                    )
            elif isinstance(value, dict):
                decrypted[key] = self.decrypt_dict(value)
            else:
                decrypted[key] = value

        return decrypted

    @classmethod
    def generate_key(cls) -> str:
        """
        Generate a new Fernet encryption key.

        Returns:
            Base64-encoded 32-byte key suitable for ENCRYPTION_KEY env var
        """
        return Fernet.generate_key().decode()


# Singleton instance
_encryption_service: Optional[EncryptionService] = None


def get_encryption_service() -> EncryptionService:
    """Get or create the global encryption service instance."""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service


def reset_encryption_service() -> None:
    """Reset singleton (for tests)."""
    global _encryption_service
    _encryption_service = None


# Convenience functions
def encrypt(plaintext: str) -> str:
    """Encrypt a string value."""
    return get_encryption_service().encrypt(plaintext)


def decrypt(ciphertext: str) -> str:
    """Decrypt an encrypted string value."""
    return get_encryption_service().decrypt(ciphertext)


def encrypt_dict(data: dict) -> dict:
    """Encrypt sensitive values in a dictionary."""
    return get_encryption_service().encrypt_dict(data)


def decrypt_dict(data: dict) -> dict:
    """Decrypt encrypted values in a dictionary."""
    return get_encryption_service().decrypt_dict(data)
