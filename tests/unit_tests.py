import os
import sys
import unittest
import logging
from cryptography.hazmat.primitives import serialization

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from user_repository import UserRepository, load_settings
from messageprocessing.messagedatefunctions import MessageDateFunctions
from messageprocessing.messageencryption import MessageEncryptionAes256CBC
from messageprocessing.messageverification import MessageVerification

# Configure logging to display debug messages
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class TestEncryptionFunctions(unittest.TestCase):

    def setUp(self):
        settings_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'settings.yml')
        settings = load_settings(settings_path)
        self.user_repo = UserRepository(
            settings=settings,
            messageverification=MessageVerification(settings),
            messageencryption=MessageEncryptionAes256CBC(settings),
            messagedatefunctions=MessageDateFunctions())
        self.private_key = self.__load_private_key(settings['cryptography']['private_key_paths']['unit_tests'])

    def __load_private_key(self, path: str):
        try:
            with open(path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
            return private_key  # Ensure 'private_key' is returned
        except Exception as e:
            raise

    def test_encrypt_data(self):
        logging.debug("Running test_encrypt_data")
        plaintext = "Test Message"
        encrypted = self.user_repo.encrypt_data(plaintext)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(plaintext, encrypted)
        self.assertTrue(len(encrypted) > 0)

    def test_decrypt_data(self):
        logging.debug("Running test_decrypt_data")
        plaintext = "Another Test"
        encrypted = self.user_repo.encrypt_data(plaintext)
        decrypted = self.user_repo.decrypt_data(encrypted)
        self.assertEqual(plaintext, decrypted)

    def test_sign_message(self):
        logging.debug("Running test_sign_message")
        message = {
            "client_id": "client123",
            "request_id": "req456",
            "timestamp": "2023-01-01T12:00:00Z",
            "operation": "create_users",
            "data": {
                "username": "test_user",
                "email": "test_user@example.com",
                "user_type": "human",
                "expiry_date": "2024-01-01T00:00:00Z"
            }
        }
        signature = self.user_repo.sign_message(message)
        self.assertIsInstance(signature, str)
        self.assertTrue(len(signature) > 0)

    def test_verify_signature(self):
        logging.debug("Running test_verify_signature")
        message = {
            "client_id": "client123",
            "request_id": "req456",
            "timestamp": "2023-01-01T12:00:00Z",
            "operation": "create_users",
            "data": {
                "username": "test_user",
                "email": "test_user@example.com",
                "user_type": "human",
                "expiry_date": "2024-01-01T00:00:00Z"
            }
        }
        signature = self.user_repo.sign_message(message)
        print (signature)
        is_valid = self.user_repo.verify_signature(signature, message)
        self.assertTrue(is_valid)

    def test_verify_signature_invalid(self):
        logging.debug("Running test_verify_signature_invalid")
        message = {
            "client_id": "client123",
            "request_id": "req456",
            "timestamp": "2023-01-01T12:00:00Z",
            "operation": "create_users",
            "data": {
                "username": "test_user",
                "email": "test_user@example.com",
                "user_type": "human",
                "expiry_date": "2024-01-01T00:00:00Z"
            }
        }
        signature = self.user_repo.sign_message(message)
        is_valid = self.user_repo.verify_signature(signature, message)
        self.assertTrue(is_valid)
        # Modify message to invalidate signature
        message["data"]["email"] = "modified@example.com"
        is_valid = self.user_repo.verify_signature(signature, message)
        self.assertFalse(is_valid)

    def test_encrypt_data_with_empty_string(self):
        """
        Test encrypting an empty string.
        """
        logging.debug("Running test_encrypt_data_with_empty_string")
        plaintext = ""
        encrypted = self.user_repo.encrypt_data(plaintext)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(plaintext, encrypted)
        self.assertTrue(len(encrypted) > 0)

    def test_decrypt_data_with_invalid_ciphertext(self):
        """
        Test decrypting an invalid ciphertext.
        """
        logging.debug("Running test_decrypt_data_with_invalid_ciphertext")
        invalid_ciphertext = "invalidciphertext"
        with self.assertRaises(ValueError):
            decrypted = self.user_repo.decrypt_data(invalid_ciphertext)

    def test_encrypt_decrypt_large_data(self):
        """
        Test encryption and decryption of large data inputs.
        """
        logging.debug("Running test_encrypt_decrypt_large_data")
        plaintext = "A" * 10**6  # 1 million characters
        encrypted = self.user_repo.encrypt_data(plaintext)
        self.assertIsInstance(encrypted, str)
        decrypted = self.user_repo.decrypt_data(encrypted)
        self.assertEqual(plaintext, decrypted)

    def test_encrypt_data_with_non_string_input(self):
        """
        Test encrypting data that is not a string.
        """
        logging.debug("Running test_encrypt_data_with_non_string_input")
        plaintext = 12345  # Integer input
        with self.assertRaises(TypeError):
            encrypted = self.user_repo.encrypt_data(plaintext)

    def test_decrypt_data_with_corrupted_ciphertext(self):
        """
        Test decrypting corrupted ciphertext data.
        """
        logging.debug("Running test_decrypt_data_with_corrupted_ciphertext")
        plaintext = "Valid Message"
        encrypted = self.user_repo.encrypt_data(plaintext)
        corrupted_encrypted = encrypted[:-10] + "corrupted"
        with self.assertRaises(ValueError):
            decrypted = self.user_repo.decrypt_data(corrupted_encrypted)