import argparse
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# 📁 dossiers
KEYS_DIR = "keys"
SIG_DIR = "signatures"

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(SIG_DIR, exist_ok=True)


# 🔑 Génération des clés
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Sauvegarde clé privée
    with open(f"{KEYS_DIR}/private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Sauvegarde clé publique
    with open(f"{KEYS_DIR}/public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("✅ Clés générées dans /keys")


# ✍️ Signature
def sign_file(file_path):
    # charger clé privée
    with open(f"{KEYS_DIR}/private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    # lire fichier
    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    sig_path = f"{SIG_DIR}/{os.path.basename(file_path)}.sig"

    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"✅ Signature créée : {sig_path}")


# ✅ Vérification
def verify_file(file_path, sig_path):
    # charger clé publique
    with open(f"{KEYS_DIR}/public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # lire fichier
    with open(file_path, "rb") as f:
        data = f.read()

    # lire signature
    with open(sig_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("✅ Signature VALIDE")
    except Exception:
        print("❌ Signature INVALIDE")


# 🖥️ CLI
def main():
    parser = argparse.ArgumentParser(description="CLI Signature Numérique")

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("generate-key")

    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("file")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("file")
    verify_parser.add_argument("signature")

    args = parser.parse_args()

    if args.command == "generate-key":
        generate_keys()
    elif args.command == "sign":
        sign_file(args.file)
    elif args.command == "verify":
        verify_file(args.file, args.signature)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
