import unittest
import json
import sys
import os
import logging  # Added import for logging
import uuid  # Added import for uuid
import base64
from cryptography.hazmat.primitives import padding as sym_padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

import pika  # Added import for pika
import time  # Added import for time
import threading  # Added import for threading

# Adjust the import path to include the parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from user_repository import load_settings
except ImportError as e:
    print(f"Error importing user_repository: {e}")
    sys.exit(1)

# Configure logging to display debug messages
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class EncryptionTestUserRepository(unittest.TestCase):

    @classmethod
    def setUpClass(cls):    
        settings_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'settings.yml')

        cls.settings = load_settings(settings_path)
        
        # Use the integration_tests keys directly
        private_key_path = cls.settings['cryptography']['private_key_paths']['integration_tests']
        
        cls.private_signing_key = cls.__load_private_key(private_key_path)
        
        print("*****************Generating parameters*****************")
        cls.paramaters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        cls.server_encryption_key = None

        print("*****************Establishing RabbitMQ connection*****************")
        rabbitmq_config = cls.settings.get('rabbitmq', {})

        # Establish RabbitMQ connection
        cls.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=rabbitmq_config.get('host', 'localhost'),
                credentials=pika.PlainCredentials(
                    rabbitmq_config.get('user', 'guest'),
                    rabbitmq_config.get('password', 'guest')
                )
            )
        )
        cls.channel = cls.connection.channel()
        
        cls.rabbitmq_queue_name = rabbitmq_config.get('queue_name', 'user_repository')
        cls.rabbitmq_response_queue_name = rabbitmq_config.get('response_queue_name', 'user_repository_responses')

        # Declare queues
        print("*****************Declaring queues*****************")
        cls.channel.queue_declare(queue=cls.rabbitmq_queue_name)
        cls.channel.queue_declare(queue=cls.rabbitmq_response_queue_name)


        # Initialize a dictionary to hold responses keyed by request_id
        cls.responses = {}
        cls.responses_lock = threading.Lock()
        cls.response_event = threading.Event()

        # Start a thread to listen for responses
        print("*****************Starting response thread*****************")
        cls.response_thread = threading.Thread(target=cls.__listen_for_responses, daemon=True)
        cls.response_thread.start()

        cls.client_id = f"client_{str(uuid.uuid4())}"
        cls.timestamp = "2023-01-01T12:00:00Z"  # Ensure timestamp format
    
    @classmethod
    def tearDownClass(cls):
        # Close RabbitMQ connection
        cls.connection.close()

    @classmethod
    def __listen_for_responses(cls):
        """Listen to the 'user_repository_responses' queue and store responses based on request_id."""
        def on_response(ch, method, properties, body):
            response = json.loads(body)
            request_id = response.get('request_id')
            if request_id:
                with cls.responses_lock:
                    cls.responses[request_id] = response
                cls.response_event.set()
            ch.basic_ack(delivery_tag=method.delivery_tag)

        # Connect to RabbitMQ
        rabbitmq = cls.settings.get('rabbitmq')
        credentials = pika.PlainCredentials(rabbitmq['user'], rabbitmq['password'])
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq['host'], credentials=credentials))
        channel = connection.channel()
        channel.queue_declare(queue=cls.rabbitmq_response_queue_name)
        channel.basic_consume(queue=cls.rabbitmq_response_queue_name, on_message_callback=on_response)

        # Start consuming
        channel.start_consuming()

    @staticmethod
    def __load_private_key(path: str):
        with open(path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key

    def __perform_key_exchange_if_not_set(self, client_id, timestamp):
        if self.__class__.server_encryption_key is None:
            print("*****************Key is none, performing key exchange*****************")
            self.__class__.server_encryption_key = self.__perform_key_exchange(client_id, timestamp)
    
        return self.__class__.server_encryption_key

    def __perform_key_exchange(self, client_id, timestamp):
        print("*****************Performing key exchange*****************")

        ## Generate a private key using the parameters created in setUpClass
        client_private_key = self.__class__.paramaters.generate_private_key()

        client_public_key = client_private_key.public_key()

        message = {
            "client_id": client_id,
            "timestamp": timestamp,
            "operation": "key_exchange_request",
            "data": {"client_public_key": client_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')},
            "comment": "key_exchange_request"
        }

        message["request_id"] = str(uuid.uuid4())
        message["signature"] = self.__sign_message(message)
        response = self.__send_and_receive_message(message)

        if response["status"] != "success":
            self.fail(f"Key exchange request failed with status: {response['status']}")
        
        server_public_key = response["data"]["server_public_key"].encode('utf-8')

        salt = base64.b64decode(response["data"]["salt"])

        server_public_key = serialization.load_pem_public_key(
            server_public_key,
            backend=default_backend()
        )
        # Generate a shared secret
        shared_secret = client_private_key.exchange(server_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)

        return derived_key

    @staticmethod
    def __encrypt_data(plaintext: str, encryption_key) -> str:

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
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def __decrypt_data(ciphertext_b64: str, encryption_key) -> str:
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
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode('utf-8')
    
    @classmethod
    def __sign_message(cls, message: dict) -> str:
        """
        Sign a message using the private key.

        Args:
            message (dict): The message to be signed.

        Returns:
            str: The hexadecimal representation of the signature.
        """
        data = json.dumps({
            k: v for k, v in message.items() if k != 'signature'
        }, sort_keys=True, default=str).encode('utf-8')  # Added default=str to handle date serialization
        try:
            signature = cls.private_signing_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return signature.hex()
        except Exception as e:
            print(f"Error during message signing: {e}")
            raise

    def __send_and_receive_message(self, message):
        """Send a message and wait for the corresponding response."""
        request_id = message['request_id']  # Retrieve request_id from the message

        # Publish the message
        self.channel.basic_publish(
            exchange='',
            routing_key=self.rabbitmq_queue_name,
            body=json.dumps(message),
            properties=pika.BasicProperties(
                reply_to=self.rabbitmq_response_queue_name,
                correlation_id=request_id
            )
        )
        logging.info(f"Sent message with request_id: {request_id}")

        # Wait for the response
        start_time = time.time()
        while time.time() - start_time < 15:
            with self.responses_lock:
                if request_id in self.responses:
                    response = self.responses.pop(request_id)
                    return response
            time.sleep(0.1)  # Sleep briefly to wait for the response

        self.fail(f"No response received for request_id: {request_id} within timeout period.")

    def setUp(self):
        pass

    def test_key_exchange(self):
        """Test the key exchange process."""
        encryption_key = self.__perform_key_exchange_if_not_set(self.client_id, self.timestamp)
        self.assertIsNotNone(encryption_key)

    def test_create_users_encrypted(self):
        encryption_key = self.__perform_key_exchange_if_not_set(self.client_id, self.timestamp)

        logging.debug("Running test_create_users_encrypted")
        request_id = str(uuid.uuid4())  # Generate unique request_id
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "create_users",
            "encrypt": True,
            "data": {
                "username": f"jane_doe_{uuid.uuid4()}",  # Updated to ensure uniqueness
                "email": "jane@example.com",
                "user_type": "human",
                "expiry_date": "2025-01-01T00:00:00Z"
            },
            "comment": "test_create_users_encrypted"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["data"] = self.__encrypt_data(json.dumps(message["data"]), encryption_key)
        message["signature"] = self.__sign_message(message)
        response = self.__send_and_receive_message(message)  # Removed request_id parameter
        response_data = json.loads(self.__decrypt_data(response["data"], encryption_key))
        print("Create Users Encrypted Response:", response_data)
        if response["status"] != "success":
            self.fail(f"Create Users Encrypted failed with status: {response['status']}")

        self.assertEqual(response["status"], "success")
        self.assertIn("id", response_data)

    def test_get_users_by_id_encrypted(self):
        encryption_key = self.__perform_key_exchange_if_not_set(self.client_id, self.timestamp)

        logging.debug("Running test_get_users_encrypted")
        # First, create a user
        create_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "create_users",
            "encrypt": True,
            "data": {
                "username": f"jane_doe_{uuid.uuid4()}",
                "email": "jane@example.com",
                "user_type": "human",
                "expiry_date": "2025-01-01T00:00:00Z"
            },
            "comment": "test_get_users_encrypted"
        }
        create_message["request_id"] = create_request_id  # Include request_id in the message
        create_message["data"] = self.__encrypt_data(json.dumps(create_message["data"]), encryption_key)
        create_message["signature"] = self.__sign_message(create_message)
        create_response = self.__send_and_receive_message(create_message)  # Removed request_id parameter
        create_response_data = json.loads(self.__decrypt_data(create_response["data"], encryption_key))
        self.assertEqual(create_response["status"], "success")
        self.assertIn("id", create_response_data)
        user_id = create_response_data["id"]

        # Now, get the user with encryption handled by user_repository.py
        get_request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "get_users",
            "encrypt": True,
            "data": {
                "id": user_id
            },
            "comment": "test_get_users_encrypted"
        }
        get_message["request_id"] = get_request_id  # Include request_id in the message
        get_message["data"] = self.__encrypt_data(json.dumps(get_message["data"]), encryption_key)
        get_message["signature"] = self.__sign_message(get_message)
        response = self.__send_and_receive_message(get_message)  # Removed request_id parameter
        response_data = json.loads(self.__decrypt_data(response["data"], encryption_key))
        print("Get Users Encrypted Response:", response_data)
        if response["status"] != "success":
            logging.error("Encrypted user retrieval failed.")
            self.fail("Encrypted user retrieval failed.")
        self.assertEqual(response["status"], "success")
        self.assertEqual(response_data["id"], user_id)

    def test_batch_operation_encrypted(self):
        encryption_key = self.__perform_key_exchange_if_not_set(self.client_id, self.timestamp)

        logging.debug("Running test_batch_operation_encrypted")
        fixed_uuid = str(uuid.uuid4())
        reqid = str(uuid.uuid4())  # Generate a new request ID for the batch operation

        batch_message = {
            "client_id": self.client_id,
            "request_id": reqid,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "batch_operations",
            "encrypt": True,
            "data": {
                "actions": [
                    {
                        "action": "create_users",  # Updated action name
                        "data": {
                            "id": fixed_uuid,  # Specify the fixed UUID
                            "username": f"john_doe_batch_encrypted_{uuid.uuid4()}",  # Updated for uniqueness
                            "email": "john_batch@example.com",
                            "user_type": "human",
                            "expiry_date": "2024-01-01T00:00:00Z"  # Ensure timestamp format
                        }
                    },
                    {
                        "action": "create_user_details",
                        "data": {
                            "user_id": fixed_uuid,  # Use the same fixed UUID
                            "details": {"address": "123 Main St"},
                            "created_at": "2023-01-01T12:00:00Z",  # Updated to ISO format
                            "updated_at": "2023-01-01T12:00:00Z"   # Updated to ISO format
                        }
                    },
                    {
                        "action": "create_passwords",  # Updated action name
                        "data": {
                            "user_id": fixed_uuid,  # Use the same fixed UUID
                            "password_hash": "hashed_password",
                            "expiry_date": "2024-01-01T00:00:00Z",
                            "created_at": "2023-01-01T12:00:00Z"  # Updated to ISO format
                        }
                    }
                ]
            },
            "comment": "test_batch_operation_encrypted"
        }

        batch_message["data"] = self.__encrypt_data(json.dumps(batch_message["data"]), encryption_key)
        batch_message["signature"] = self.__sign_message(batch_message)
        response = self.__send_and_receive_message(batch_message)  # Removed request_id parameter
        logging.info("**************** Batch Operation Response: %s", response)

        print("Batch Operation Response:", response)
        response_data = json.loads(self.__decrypt_data(response["data"], encryption_key))
        if response["status"] != "success":
            print(f"Error: {response.get('message')}, Error Code: {response.get('error_code')}")
        self.assertEqual(response["status"], "success")
        self.assertEqual(len(response_data["results"]), 3)

if __name__ == '__main__':
    unittest.main(failfast=True)