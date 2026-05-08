"""
keygen.py — RSA key pair generation
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def generate_rsa_keypair(bits: int = 2048) -> tuple:
    """Generate an RSA private/public key pair.

    Args:
        bits: Key size in bits. Accepted values: 1024, 2048, 4096.

    Returns:
        (private_key, public_key) tuple of cryptography key objects.
    """
    if bits not in (1024, 2048, 4096):
        raise ValueError(f"Unsupported key size: {bits}. Choose 1024, 2048 or 4096.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(
    private_key,
    passphrase: bytes | None = None,
) -> bytes:
    """Serialize a private key to PEM bytes.

    Args:
        private_key: RSA private key object.
        passphrase: Optional passphrase bytes to encrypt the key.

    Returns:
        PEM-encoded bytes.
    """
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption,
    )


def serialize_public_key(public_key) -> bytes:
    """Serialize a public key to PEM bytes.

    Args:
        public_key: RSA public key object.

    Returns:
        PEM-encoded bytes.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# High-level save function
# ---------------------------------------------------------------------------

def save_keypair(
    bits: int = 2048,
    output_dir: str | Path = ".",
    name: str = "key",
    passphrase: bytes | None = None,
) -> tuple[Path, Path]:
    """Generate an RSA key pair and save it to PEM files.

    Args:
        bits: Key size in bits.
        output_dir: Directory where the files will be written.
        name: Base name for the output files.
        passphrase: Optional passphrase to protect the private key.

    Returns:
        (private_key_path, public_key_path) as Path objects.

    Raises:
        ValueError: If bits is not a valid key size.
        OSError: If the output directory cannot be created/written.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key, public_key = generate_rsa_keypair(bits)

    private_path = output_dir / f"{name}_private.pem"
    public_path  = output_dir / f"{name}_public.pem"

    # Write private key (restricted permissions on POSIX)
    private_bytes = serialize_private_key(private_key, passphrase)
    private_path.write_bytes(private_bytes)
    try:
        os.chmod(private_path, 0o600)
    except NotImplementedError:
        pass  # Windows — skip chmod

    # Write public key
    public_bytes = serialize_public_key(public_key)
    public_path.write_bytes(public_bytes)

    return private_path, public_path
