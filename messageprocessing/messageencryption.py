from typing import Dict, Any
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

class MessageEncryption():
    def __init__(self, settings: Dict[str, Any]):
        cryptography = settings.get('cryptography')
        if not cryptography:
            raise ValueError("Error: 'cryptography' section is missing in settings.yml")

        # Load the symmetric encryption key
        with open(cryptography['encryption_key_path'], 'rb') as key_file:
            self.encryption_key = key_file.read()
    
    def encrypt_data(self, plaintext: str) -> str:
        """
        Encrypts the plaintext using AES CBC mode.

        Args:
            plaintext (str): The data to encrypt.

        Returns:
            str: The base64-encoded ciphertext.
        """
        if not isinstance(plaintext, str):
            raise TypeError("Input data must be a string")

        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt_data(self, ciphertext_b64: str) -> str:
        """
        Decrypts the base64-encoded ciphertext using AES CBC mode.

        Args:
            ciphertext_b64 (str): The base64-encoded ciphertext.

        Returns:
            str: The decrypted plaintext.
        """
        if not isinstance(ciphertext_b64, str):
            raise TypeError("Input data must be a string")
        
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode('utf-8')