"""
verifier.py — Signature verification
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class SigMetadata:
    """Parsed content of a .sig file."""
    version:   int
    tool:      str
    algorithm: str
    timestamp: str
    filename:  str
    sha256:    str
    signature: str  # base64-encoded


@dataclass
class VerificationResult:
    """Result of a verification operation."""
    valid:           bool
    file_path:       Path
    sig_path:        Path
    metadata:        SigMetadata | None = None
    error:           str        | None = None
    hash_match:      bool              = False


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


def load_public_key(key_path: Path):
    """Load an RSA public key from a PEM file.

    Args:
        key_path: Path to the PEM public key file.

    Returns:
        RSA public key object.

    Raises:
        FileNotFoundError: Key file not found.
        ValueError: Key cannot be loaded.
    """
    if not key_path.exists():
        raise FileNotFoundError(f"Public key not found: {key_path}")

    pem_bytes = key_path.read_bytes()
    try:
        return serialization.load_pem_public_key(
            pem_bytes,
            backend=default_backend(),
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Could not load public key '{key_path}': {exc}") from exc


def load_sig_file(sig_path: Path) -> SigMetadata:
    """Parse a .sig JSON file into a SigMetadata object.

    Args:
        sig_path: Path to the .sig file.

    Returns:
        SigMetadata instance.

    Raises:
        FileNotFoundError: .sig file not found.
        ValueError: .sig file is malformed.
    """
    if not sig_path.exists():
        raise FileNotFoundError(f"Signature file not found: {sig_path}")

    try:
        data = json.loads(sig_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed .sig file '{sig_path}': {exc}") from exc

    required = {"version", "tool", "algorithm", "timestamp", "filename", "sha256", "signature"}
    missing  = required - data.keys()
    if missing:
        raise ValueError(f".sig file is missing fields: {', '.join(sorted(missing))}")

    return SigMetadata(
        version   = data["version"],
        tool      = data["tool"],
        algorithm = data["algorithm"],
        timestamp = data["timestamp"],
        filename  = data["filename"],
        sha256    = data["sha256"],
        signature = data["signature"],
    )


# ---------------------------------------------------------------------------
# Core verification
# ---------------------------------------------------------------------------

def verify_file(
    file_path: Path,
    public_key,
    sig_path:  Path | None = None,
) -> VerificationResult:
    """Verify the digital signature of a file.

    Args:
        file_path: Path to the file whose signature is to be verified.
        public_key: RSA public key object.
        sig_path: Path to the .sig file. If None, looks for {file_path}.sig.

    Returns:
        VerificationResult with all details.
    """
    file_path = Path(file_path).resolve()

    if not file_path.exists():
        return VerificationResult(
            valid=False,
            file_path=file_path,
            sig_path=sig_path or Path(str(file_path) + ".sig"),
            error=f"File not found: {file_path}",
        )

    # Resolve the .sig path
    if sig_path is None:
        sig_path = Path(str(file_path) + ".sig")
    else:
        sig_path = Path(sig_path).resolve()

    # Load the .sig metadata
    try:
        meta = load_sig_file(sig_path)
    except (FileNotFoundError, ValueError) as exc:
        return VerificationResult(
            valid=False,
            file_path=file_path,
            sig_path=sig_path,
            error=str(exc),
        )

    # --- Check file hash integrity ---
    actual_hash = _sha256_file(file_path)
    hash_match  = actual_hash == meta.sha256

    if not hash_match:
        return VerificationResult(
            valid=False,
            file_path=file_path,
            sig_path=sig_path,
            metadata=meta,
            hash_match=False,
            error=(
                "SHA-256 hash mismatch — the file may have been tampered with.\n"
                f"  Expected : {meta.sha256}\n"
                f"  Actual   : {actual_hash}"
            ),
        )

    # --- Verify cryptographic signature ---
    try:
        sig_bytes = base64.b64decode(meta.signature)
        file_bytes = file_path.read_bytes()
        public_key.verify(
            sig_bytes,
            file_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return VerificationResult(
            valid=False,
            file_path=file_path,
            sig_path=sig_path,
            metadata=meta,
            hash_match=True,
            error="Cryptographic signature is INVALID — signature does not match the public key.",
        )
    except Exception as exc:  # noqa: BLE001
        return VerificationResult(
            valid=False,
            file_path=file_path,
            sig_path=sig_path,
            metadata=meta,
            hash_match=True,
            error=f"Verification error: {exc}",
        )

    return VerificationResult(
        valid=True,
        file_path=file_path,
        sig_path=sig_path,
        metadata=meta,
        hash_match=True,
    )
