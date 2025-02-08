from typing import Dict, Any
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import base64
import os



class MessageEncryption:
    def __init__(self, settings: Dict[str, Any]):
        self.settings = settings
        self.encryption_keys = {}

        self.algorithms = {
            "aes_cbc": MessageEncryptionAes256CBC(settings),
            "aes_gcm": MessageEncryptionAes256GCM(settings)
        }

    def handle_key_exchange(self, data: Dict[str, Any], original_message: Dict[str, Any]):
        """
        Handle key exchange.
        """
        print(f"*************Key exchange request received within MessageEncryptionAes256CBC:************** {data} *****************")
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

        salt = os.urandom(16)

        # Derive symmetric encryption key from the shared secret using HKDF
        self.encryption_keys[original_message.get("client_id")] = {"derived_key": HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret), "salt": salt}

        # Encode the server's public key and salt
        pk_bytes = server_public_key.public_bytes(
            serialization.Encoding.PEM, 
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        base64_salt = base64.b64encode(salt).decode('utf-8')

        return {"server_public_key": pk_bytes.decode('utf-8'), "salt": base64_salt}

    def encrypt_data(self, plaintext: str, algorithm: str, client_id: str) -> str:
        encryption_key_details = self.encryption_keys.get(client_id)
        if not client_id:
            raise ValueError("Client ID is required")
        if not encryption_key_details:
            raise ValueError("Encryption key not set")
        return self.algorithms[algorithm].encrypt_data(plaintext, encryption_key_details)

    def decrypt_data(self, ciphertext_b64: str, algorithm: str, client_id: str) -> str:
        encryption_key_details = self.encryption_keys.get(client_id)
        if not client_id:
            raise ValueError("Client ID is required")
        if not encryption_key_details:
            raise ValueError("Encryption key not set")
        return self.algorithms[algorithm].decrypt_data(ciphertext_b64, encryption_key_details)

    

class MessageEncryptionAes256CBC():
    def __init__(self, settings: Dict[str, Any]):
        cryptography = settings.get('cryptography')
        if not cryptography:
            raise ValueError("Error: 'cryptography' section is missing in settings.yml")

        self.encryption_keys = {}

    def encrypt_data(self, plaintext: str, encryption_key_details: Dict[str, Any]) -> str:
        """
        Encrypts the plaintext using AES CBC mode.


        Args:
            plaintext (str): The data to encrypt.

        Returns:
            str: The base64-encoded ciphertext.
        """
        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithms.AES(encryption_key_details.get("derived_key")), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()

        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt_data(self, ciphertext_b64: str, encryption_key_details: Dict[str, Any]) -> str:
        """
        Decrypts the base64-encoded ciphertext using AES CBC mode.


        Args:
            ciphertext_b64 (str): The base64-encoded ciphertext.

        Returns:
            str: The decrypted plaintext.
        """

        ciphertext = base64.b64decode(ciphertext_b64)
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(encryption_key_details.get("derived_key")), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()

        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode('utf-8')



class MessageEncryptionAes256GCM():
    def __init__(self, settings: Dict[str, Any]):
        cryptography = settings.get('cryptography')
        if not cryptography:
            raise ValueError("Error: 'cryptography' section is missing in settings.yml")

        self.encryption_keys = {}

    def encrypt_data(self, plaintext: str, encryption_key_details: Dict[str, Any]) -> str:
        """
        Encrypts the plaintext using AES CBC mode.

        Args:
            plaintext (str): The data to encrypt.

        Returns:
            str: The base64-encoded ciphertext.
        """
        # AES-GCM requires a 12-byte nonce
        nonce = os.urandom(12)
        key = encryption_key_details.get("derived_key")

        # Instantiate AESGCM with the derived key
        aesgcm = AESGCM(key)

        # Encrypt; no additional authenticated data (AAD) is provided here (pass None)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

        # Prepend the nonce to the ciphertext; both are needed for decryption
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    def decrypt_data(self, ciphertext_b64: str, encryption_key_details: Dict[str, Any]) -> str:
        """
        Decrypts the base64-encoded ciphertext using AES CBC mode.


        Args:
            ciphertext_b64 (str): The base64-encoded ciphertext.

        Returns:
            str: The decrypted plaintext.
        """
        # Decode the base64 data
        data = base64.b64decode(ciphertext_b64)

        # Extract the 12-byte nonce and the actual ciphertext (which includes the tag)
        nonce = data[:12]
        actual_ciphertext = data[12:]
        key = encryption_key_details.get("derived_key")

        aesgcm = AESGCM(key)

        # Decrypt; if the ciphertext was tampered with, this will raise an exception
        plaintext_bytes = aesgcm.decrypt(nonce, actual_ciphertext, None)
        return plaintext_bytes.decode('utf-8')