from typing import Dict, Any
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import glob
import os
import json
from cryptography.exceptions import InvalidSignature

class MessageVerification():
    def __init__(self, settings: Dict[str, Any]):
        cryptography = settings.get('cryptography')
        if not cryptography:
            raise ValueError("Error: 'cryptography' section is missing in settings.yml")
        
        private_key_path = cryptography['private_key_paths'].get('user_repository')
        public_key_path = cryptography['public_key_paths'].get('user_repository')
        self.public_keys_dir = cryptography.get('public_keys_dir')
        
        if not private_key_path or not public_key_path:
            raise ValueError("Error: One or more cryptographic key paths are missing in settings.yml")
        
        self.private_key = self.__load_private_key(private_key_path)
        self.public_key = self.__load_public_key(public_key_path)

    def __load_private_key(self, path: str):
        """
        Load the private key from the specified file.

        Args:
            path (str): Path to the private key file.

        Returns:
            Private key object.
        """
        try:
            with open(path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
            return private_key  # Ensure 'private_key' is returned
        except Exception as e:
            raise

    def __load_public_key(self, path: str):
        """
        Load the public key from the specified file.

        Args:
            path (str): Path to the public key file.

        Returns:
            Public key object.
        """
        try:
            with open(path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                )
            return public_key  # Ensure 'public_key' is returned
        except Exception as e:
            raise

    def __load_public_keys(self, directory: str):
        """
        Load all public keys from the specified directory.

        Args:
            directory (str): Path to the directory containing public key files.

        Returns:
            List[PublicKey]: List of public key objects.
        """
        public_keys = []
        for key_path in glob.glob(os.path.join(directory, '*.pem')):
            try:
                with open(key_path, 'rb') as key_file:
                    public_key = serialization.load_pem_public_key(key_file.read())
                    public_keys.append(public_key)
            except Exception as e:
                pass
        return public_keys

    def verify_signature(self, signaturestring, message: Dict[str, Any]) -> bool:
        """
        Verify the cryptographic signature of a message using all available public keys.

        Args:
            message (Dict[str, Any]): The message containing the signature.

        Returns:
            bool: True if the signature is valid with any public key, False otherwise.
        """
        signature = bytes.fromhex(signaturestring)
        data = json.dumps({
            k: v for k, v in message.items() if k != 'signature'
        }, sort_keys=True, default=str).encode('utf-8')  # Added default=str to handle date serialization
        public_keys = self.__load_public_keys(self.public_keys_dir)
        for public_key in public_keys:
            try:
                public_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return True
            except InvalidSignature:
                continue
            except Exception as e:
                return False
        return False

    def sign_message(self, message: Dict[str, Any]) -> str:
        """
        Sign a message using the private key.

        Args:
            message (Dict[str, Any]): The message to be signed.

        Returns:
            str: The hexadecimal representation of the signature.
        """
        data = json.dumps({
            k: v for k, v in message.items() if k != 'signature'
        }, sort_keys=True, default=str).encode('utf-8')  # Added default=str to handle date serialization
        try:
           signature = self.private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
           return signature.hex()
        except Exception as e:
            raise