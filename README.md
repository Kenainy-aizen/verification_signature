# Digital Signature CLI Tool (ProjetSecWebMail)

## Description
A lightweight command-line interface (CLI) tool for generating RSA cryptographic keys, signing files with digital signatures, and verifying the integrity and authenticity of signed files. Built with Python and the `cryptography` library.

## Features
- Generate 2048-bit RSA key pairs (private/public PEM files)
- Sign arbitrary files using SHA-256 hashing and PKCS1v15 padding
- Verify digital signatures against original files using public keys
- Automatic creation of `keys/` and `signatures/` directories

## Prerequisites
- Python 3.7+
- `cryptography` Python package

## Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd ProjetSecWebMail
   ```
2. Install required dependencies:
   ```bash
   pip install cryptography
   ```

## Usage
The tool uses subcommands for different operations. Run `python main.py --help` for full usage details.

### 1. Generate RSA Key Pair
Generates a 2048-bit RSA private key (`keys/private.pem`) and public key (`keys/public.pem`):
```bash
python main.py generate-key
```
Output: `✅ Clés générées dans /keys`

### 2. Sign a File
Signs a target file and saves the signature to the `signatures/` directory with a `.sig` extension:
```bash
python main.py sign <path-to-file>
```
Example:
```bash
python main.py sign document.pdf
```
Output: `✅ Signature créée : signatures/document.pdf.sig`

### 3. Verify a Signature
Verifies a signature against the original file using the public key:
```bash
python main.py verify <path-to-file> <path-to-signature>
```
Example:
```bash
python main.py verify document.pdf signatures/document.pdf.sig
```
Output (valid): `✅ Signature VALIDE`
Output (invalid): `❌ Signature INVALIDE`

## Directory Structure
```
ProjetSecWebMail/
├── main.py                # Core CLI logic and cryptographic operations
├── keys/                  # Stores generated RSA keys (auto-created)
│   ├── private.pem        # Private key (unencrypted, handle with care!)
│   └── public.pem         # Public key for signature verification
├── signatures/            # Stores generated .sig files (auto-created)
└── README.md              # This file
```

## Technical Details
- **Key Algorithm**: RSA 2048-bit
- **Hashing Algorithm**: SHA-256
- **Padding Scheme**: PKCS1v15
- **Key Storage Format**: PEM (PKCS8 for private keys, SubjectPublicKeyInfo for public keys)
- **Signature Storage**: Raw binary `.sig` files

## Security Notes
⚠️ **Important**: The private key is stored unencrypted (no password protection) by default, as configured in `main.py` with `serialization.NoEncryption()`. For production use, consider adding a password-based encryption layer for the private key.

Never share your `private.pem` file. Only distribute the `public.pem` for signature verification.

## License
This project is currently unlicensed. Contact the project maintainer for usage permissions.