"""
signer.py — File signing with RSA + SHA-256
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from signtool import __version__

# Signature file format version (bump when the JSON schema changes)
SIG_FORMAT_VERSION = 1

ALGORITHM_LABEL = "RSA-SHA256-PKCS1v15"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_file(file_path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_private_key(key_path: Path, passphrase: bytes | None = None):
    """Load an RSA private key from a PEM file.

    Args:
        key_path: Path to the PEM private key file.
        passphrase: Optional passphrase bytes if the key is encrypted.

    Returns:
        RSA private key object.

    Raises:
        FileNotFoundError: Key file not found.
        ValueError: Key cannot be loaded (wrong passphrase / bad format).
    """
    if not key_path.exists():
        raise FileNotFoundError(f"Private key not found: {key_path}")

    pem_bytes = key_path.read_bytes()
    try:
        return serialization.load_pem_private_key(
            pem_bytes,
            password=passphrase,
            backend=default_backend(),
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Could not load private key '{key_path}': {exc}\n"
            "If the key is password-protected, provide --passphrase."
        ) from exc


# ---------------------------------------------------------------------------
# Core signing
# ---------------------------------------------------------------------------

def sign_file(
    file_path: Path,
    private_key,
    output_dir: Path | None = None,
) -> Path:
    """Sign a single file and write the .sig JSON file.

    Args:
        file_path: Path to the file to sign.
        private_key: RSA private key object.
        output_dir: Directory where the .sig file is written.
                    Defaults to the same directory as file_path.

    Returns:
        Path of the created .sig file.

    Raises:
        FileNotFoundError: If file_path does not exist.
    """
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        raise FileNotFoundError(f"File to sign not found: {file_path}")

    # --- Compute file hash ---
    file_hash = _sha256_file(file_path)

    # --- Sign the raw file bytes ---
    file_bytes = file_path.read_bytes()
    signature_bytes = private_key.sign(
        file_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    # --- Build .sig payload ---
    payload = {
        "version":   SIG_FORMAT_VERSION,
        "tool":      f"signtool v{__version__}",
        "algorithm": ALGORITHM_LABEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "filename":  file_path.name,
        "sha256":    file_hash,
        "signature": signature_b64,
    }

    # --- Determine output path ---
    if output_dir is None:
        output_dir = file_path.parent
    else:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    sig_path = output_dir / (file_path.name + ".sig")
    sig_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return sig_path


# ---------------------------------------------------------------------------
# Batch signing
# ---------------------------------------------------------------------------

def sign_files(
    file_paths: list[Path],
    private_key,
    output_dir: Path | None = None,
) -> list[tuple[Path, Path | None, str | None]]:
    """Sign multiple files.

    Args:
        file_paths: List of file paths to sign.
        private_key: RSA private key object.
        output_dir: Directory for .sig files.

    Returns:
        List of (file_path, sig_path_or_None, error_message_or_None).
    """
    results = []
    for fp in file_paths:
        try:
            sig_path = sign_file(fp, private_key, output_dir)
            results.append((fp, sig_path, None))
        except Exception as exc:  # noqa: BLE001
            results.append((fp, None, str(exc)))
    return results
