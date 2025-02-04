import yaml
import os
import sys
import argparse
import subprocess
from pathlib import Path
import shutil  # Import shutil for cross-platform file operations
from datetime import datetime
import pytz
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def load_settings(yaml_path):
    with open(yaml_path, 'r') as file:
        return yaml.safe_load(file)

def delete_keys(private_key_path, public_key_path):
    if os.path.isfile(private_key_path):
        os.remove(private_key_path)
    if os.path.isfile(public_key_path):
        os.remove(public_key_path)

def delete_public_keys(public_keys_dir):
    public_keys = Path(public_keys_dir).glob("*.pem")
    for key in public_keys:
        key.unlink()

def generate_keys(private_key_path, public_key_path):
    Path(private_key_path).parent.mkdir(parents=True, exist_ok=True)
    Path(public_key_path).parent.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating private key at: {private_key_path}")
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", private_key_path, "-pkeyopt", "rsa_keygen_bits:2048"], check=True)
    
    print(f"Generating public key at: {public_key_path}")
    subprocess.run(["openssl", "rsa", "-pubout", "-in", private_key_path, "-out", public_key_path], check=True)

def copy_public_keys(public_key_path, service_name, public_keys_dir):
    destination_path = os.path.join(public_keys_dir, f"{service_name}_public_key.pem")
    if os.path.isfile(public_key_path):
        print(f"Copying {public_key_path} to {destination_path}")
        shutil.copy(public_key_path, destination_path)  # Use shutil.copy instead of subprocess.run(["cp", ...])
    else:
        print(f"Public key path not found: {public_key_path}")

def generate_key_pair():
    """
    Generate a public-private key pair with timezone-aware timestamp in metadata.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    metadata = {
        "generated_at": datetime.now(pytz.UTC).isoformat()
    }
    return private_key, public_key, metadata

def generate_symmetric_key(encryption_key_path):
    """
    Generate a symmetric AES key for message encryption.
    """
    from cryptography.hazmat.primitives import serialization  # Existing import

    key = os.urandom(32)  # Added: Generate a 256-bit AES key using os.urandom
    Path(encryption_key_path).parent.mkdir(parents=True, exist_ok=True)
    with open(encryption_key_path, 'wb') as key_file:
        key_file.write(key)
    print(f"Symmetric encryption key generated at: {encryption_key_path}")

def delete_symmetric_key(encryption_key_path):
    """
    Delete the symmetric AES key used for message encryption.
    """
    if os.path.isfile(encryption_key_path):
        os.remove(encryption_key_path)
        print(f"Symmetric encryption key deleted from: {encryption_key_path}")

def delete_all_signing_keys(private_keys, public_keys):
    for service in private_keys:
        delete_keys(private_keys[service], public_keys[service])

def regenerate_all_keys(private_keys, public_keys, public_keys_dir, encryption_key_path, services):
    delete_all_signing_keys(private_keys, public_keys)
    delete_public_keys(public_keys_dir)
    for service in services:
        generate_keys(private_keys[service], public_keys[service])
        copy_public_keys(public_keys[service], service, public_keys_dir)  # Copy public key after generation
    generate_symmetric_key(encryption_key_path)

def main():
    parser = argparse.ArgumentParser(description="Generate or delete cryptographic keys.")
    parser.add_argument('--regenerate-all-keys', action='store_true', help='Delete existing keys and regenerate them.')
    parser.add_argument('--delete-all-keys-only', action='store_true', help='Only delete all keys and exit.')
    parser.add_argument('--delete-signing-keys-only', action='store_true', help='Delete only the message signing keys.')
    parser.add_argument('--delete-encryption-key-only', action='store_true', help='Delete only the symmetric encryption key.')  # Added
    parser.add_argument('--regenerate-signing-keys-only', action='store_true', help='Regenerate only the message signing keys.')  # Added
    parser.add_argument('--regenerate-encryption-key-only', action='store_true', help='Regenerate only the symmetric encryption key.')  # Added
    args = parser.parse_args()

    settings = load_settings('settings.yml')
    
    cryptography = settings.get('cryptography')
    if not cryptography:
        print("Error: 'cryptography' section is missing in settings.yml")
        sys.exit(1)
    
    services = ['user_repository', 'integration_tests', 'unit_tests']  # Add more services here if needed
    
    private_keys = {service: cryptography['private_key_paths'].get(service) for service in services}
    public_keys = {service: cryptography['public_key_paths'].get(service) for service in services}
    public_keys_dir = cryptography.get('public_keys_dir')
    encryption_key_path = cryptography.get('encryption_key_path')  # Added
    
    if args.regenerate_all_keys or args.delete_all_keys_only or args.delete_signing_keys_only or args.delete_encryption_key_only or args.regenerate_signing_keys_only or args.regenerate_encryption_key_only:
        if args.regenerate_all_keys:
            regenerate_all_keys(private_keys, public_keys, public_keys_dir, encryption_key_path, services)
        elif args.delete_all_keys_only:
            delete_all_signing_keys(private_keys, public_keys)
            delete_public_keys(public_keys_dir)
            delete_symmetric_key(encryption_key_path)
            sys.exit(0)
        elif args.delete_signing_keys_only:
            delete_all_signing_keys(private_keys, public_keys)
            sys.exit(0)
        elif args.delete_encryption_key_only:
            delete_symmetric_key(encryption_key_path)
            sys.exit(0)
        elif args.regenerate_signing_keys_only:
            delete_all_signing_keys(private_keys, public_keys)
            for service in services:
                generate_keys(private_keys[service], public_keys[service])
                copy_public_keys(public_keys[service], service, public_keys_dir)  # Copy public key after generation
            sys.exit(0)
        elif args.regenerate_encryption_key_only:
            delete_symmetric_key(encryption_key_path)
            generate_symmetric_key(encryption_key_path)
            sys.exit(0)
    
    # Added: Check existence of keys when no options are specified
    if not any(vars(args).values()):
        missing_keys = []
        # Check private keys
        for service, path in private_keys.items():
            if not os.path.isfile(path):
                missing_keys.append(f"Missing Private Message Signing Key for {service}: {path}")
        # Check public keys
        for service, path in public_keys.items():
            if not os.path.isfile(path):
                missing_keys.append(f"Missing Public Message Signing Key for {service}: {path}")
        # Check encryption key
        if not os.path.isfile(encryption_key_path):
            missing_keys.append(f"Missing Message Encryption Key: {encryption_key_path}")
        
        if missing_keys:
            print("The following key(s) are missing:")
            for key in missing_keys:
                print(f"- {key}")
        else:
            print("All keys are present.")
        sys.exit(0)

if __name__ == "__main__":
    main()