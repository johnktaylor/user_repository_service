from typing import Dict, Any
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import base64
import os


class MessageEncryption():
    def __init__(self, settings: Dict[str, Any]):
        cryptography = settings.get('cryptography')
        if not cryptography:
            raise ValueError("Error: 'cryptography' section is missing in settings.yml")

        self.encryption_keys = {}

    def handle_key_exchange(self, data: Dict[str, Any], original_message: Dict[str, Any]):
        """
        Handle key exchange.
        """
        return self.__generate_public_key_and_encryption_key(data, original_message)

    def __generate_public_key_and_encryption_key(self, data: Dict[str, Any], original_message: Dict[str, Any]):
        # Load client's public key
        client_public_key = serialization.load_pem_public_key(
            data["client_public_key"].encode('utf-8'),
            backend=default_backend()
        )

        if not original_message.get("client_id"):
            raise ValueError("Client ID is required")

        if not client_public_key:
            raise ValueError("Client public key is required")

        # Use the client's DH parameters to generate the server's key pair
        parameters = client_public_key.parameters()
        server_private_key = parameters.generate_private_key()
        server_public_key = server_private_key.public_key()

        # Compute shared secret using the client's public key and the server's private key
        shared_secret = server_private_key.exchange(client_public_key)

        # Derive symmetric encryption key from the shared secret using HKDF
        self.encryption_keys[original_message.get("client_id")] = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)

        print("*****************Encryption keys: ", self.encryption_keys, "*****************")
        for key, value in self.encryption_keys.items():
            print("*****************Key: ", key, "Value: ", value, "*****************")

        return server_public_key.public_bytes(
            serialization.Encoding.PEM, 
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')


    def encrypt_data(self, plaintext: str, client_id: str) -> str:
        """
        Encrypts the plaintext using AES CBC mode.

        Args:
            plaintext (str): The data to encrypt.

        Returns:
            str: The base64-encoded ciphertext.
        """
        if not client_id:
            raise ValueError("Client ID is required")

        if not self.encryption_keys.get(client_id):
            raise ValueError("Encryption key not set")

        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithms.AES(self.encryption_keys.get(client_id)), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()

        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt_data(self, ciphertext_b64: str, client_id: str) -> str:
        """
        Decrypts the base64-encoded ciphertext using AES CBC mode.

        Args:
            ciphertext_b64 (str): The base64-encoded ciphertext.

        Returns:
            str: The decrypted plaintext.
        """
        
        if not client_id:
            raise ValueError("Client ID is required")

        if not self.encryption_keys.get(client_id):
            raise ValueError("Encryption key not set")

        ciphertext = base64.b64decode(ciphertext_b64)
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.encryption_keys.get(client_id)), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode('utf-8')