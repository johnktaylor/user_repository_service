import unittest
import json
import sys
import os
import logging  # Added import for logging
import uuid  # Added import for uuid
import base64
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

import yaml  # Added import for YAML
import pika  # Added import for pika
import time  # Added import for time
import threading  # Added import for threading

# Adjust the import path to include the parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from user_repository import UserRepository, load_settings
except ImportError as e:
    print(f"Error importing user_repository: {e}")
    sys.exit(1)

# Configure logging to display debug messages
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class TestUserRepository(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        settings_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'settings.yml')
        cls.settings = load_settings(settings_path)
        
        # Use the integration_tests keys directly
        private_key_path = cls.settings['cryptography']['private_key_paths']['integration_tests']
        
        cls.private_key = cls.load_private_key(private_key_path)
        with open(cls.settings['cryptography']['encryption_key_path'], 'rb') as key_file:
            cls.encryption_key = key_file.read()
        
        # Validate encryption key length
        if len(cls.encryption_key) not in (16, 24, 32):
            raise ValueError(f"Invalid AES key length: {len(cls.encryption_key)} bytes. Key must be 16, 24, or 32 bytes long.")

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
        cls.channel.queue_declare(queue=cls.rabbitmq_queue_name)
        cls.channel.queue_declare(queue=cls.rabbitmq_response_queue_name)

        # Initialize a dictionary to hold responses keyed by request_id
        cls.responses = {}
        cls.responses_lock = threading.Lock()
        cls.response_event = threading.Event()

        # Start a thread to listen for responses
        cls.response_thread = threading.Thread(target=cls.listen_for_responses, daemon=True)
        cls.response_thread.start()
    
    @classmethod
    def listen_for_responses(cls):
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
    
    @classmethod
    def tearDownClass(cls):
        # Close RabbitMQ connection
        cls.connection.close()

    @staticmethod
    def load_private_key(path: str):
        with open(path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key

    @staticmethod
    def encrypt_data(plaintext: str, encryption_key) -> str:
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
    def decrypt_data(ciphertext_b64: str, encryption_key) -> str:
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
    
    def sign_message(self, message: dict) -> str:
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
            signature = self.private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return signature.hex()
        except Exception as e:
            print(f"Error during message signing: {e}")
            raise

    def setUp(self):
        # Removed generating request_id here
        self.client_id = "client123"
        self.timestamp = "2023-01-01T12:00:00Z"  # Ensure timestamp format

    def send_and_receive_message(self, message):
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

    def __create_user(self, testname, request_id, username, email="user@integration-tests.com"):
        request_id = str(uuid.uuid4())
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "create_users",
            "data": {"username": username, "email": email, "user_type": "human", "expiry_date": "2024-01-01T00:00:00Z"},
            "comment": testname
        }
        message["request_id"] = request_id
        message["signature"] = self.sign_message(message)
        response = self.send_and_receive_message(message)
        self.assertEqual(response["status"], "success")
        self.assertEqual(response["request_id"], request_id)
        self.assertIn("id", response["data"])
        self.assertIn("signature", response)
        return response

    def test_create_users_pass(self, testname="test_create_users_pass"):  # Updated method name from test_create_user to test_create_users
        logging.debug("Running test_create_users")
        response = self.__create_user(testname, str(uuid.uuid4()), "john_doe_" + str(uuid.uuid4()))
        print("Create Users Response:", response)
        if response["status"] != "success":
            self.fail(f"Create Users failed with status: {response['status']}")
        self.assertEqual(response["status"], "success")
        self.assertIn("id", response["data"])

    def test_create_users_fail(self):  # Updated method name from test_create_user to test_create_users
        logging.debug("Running test_create_users")
        request_id = str(uuid.uuid4())  # Generate unique request_id
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_users",  # Updated operation name
            "data": {
                "email": "john@example.com",
                "user_type": "human",
                "expiry_date": "2024-01-01T00:00:00Z"  # Ensure timestamp format
            },
            "comment": "test_create_users"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["signature"] = self.sign_message(message)
        response = self.send_and_receive_message(message)  # Removed request_id parameter
        print("Create Users Response:", response)
        if response["status"] != "error":
            self.fail(f"Create Users failed with status: {response['status']}")
        self.assertEqual(response["status"], "error")

    def test_create_users_encrypted(self):
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
        message["data"] = self.encrypt_data(json.dumps(message["data"]), self.encryption_key)
        message["signature"] = self.sign_message(message)
        response = self.send_and_receive_message(message)  # Removed request_id parameter
        response_data = json.loads(self.decrypt_data(response["data"], self.encryption_key))
        print("Create Users Encrypted Response:", response_data)
        if response["status"] != "success":
            self.fail(f"Create Users Encrypted failed with status: {response['status']}")
        self.assertEqual(response["status"], "success")
        self.assertIn("id", response_data)

    def test_update_users(self):
        logging.debug("Running test_update_users")
        # First, create a user to update using __create_user
        create_response = self.__create_user("test_update_users", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_response_data = create_response
        user_id = create_response_data["data"]["id"]

        # Now, update the user remains unchanged
        update_request_id = str(uuid.uuid4())  # Generate unique request_id
        update_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "update_users",  # Updated operation name
            "data": {
                "id": user_id,
                "username": f"john_doe_up_{uuid.uuid4()}",
                "email": "john_updated@example.com",
                "user_type": "human",
                "expiry_date": "2025-01-01T00:00:00Z"  # Ensure timestamp format
            },
            "comment": "test_update_users"
        }
        update_message["request_id"] = update_request_id  # Include request_id in the message
        update_message["signature"] = self.sign_message(update_message)
        response = self.send_and_receive_message(update_message)
        response_data = response
        print("Update Users Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], user_id)

    def test_delete_users(self):
        logging.debug("Running test_delete_users")
        # First, create a user to delete using __create_user
        create_response = self.__create_user("test_delete_users", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_response_data = create_response
        user_id = create_response_data["data"]["id"]

        # Now, delete the user remains unchanged
        delete_request_id = str(uuid.uuid4())  # Generate unique request_id
        delete_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "delete_users",
            "data": {
                "id": user_id
            },
            "comment": "test_delete_users"
        }
        delete_message["request_id"] = delete_request_id  # Include request_id in the message
        delete_message["signature"] = self.sign_message(delete_message)
        response = self.send_and_receive_message(delete_message)
        response_data = response
        print("Delete Users Response:", response_data)
        self.assertEqual(response_data["status"], "success")

    def test_get_users_by_id(self):
        logging.debug("Running test_get_users")
        # First, create a user to retrieve using __create_user
        create_response = self.__create_user("test_get_users_by_id", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_response_data = create_response
        user_id = create_response_data["data"]["id"]

        # Now, get the user
        get_request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "get_users",
            "data": {
                "id": user_id
            },
            "comment": "test_get_users"
        }
        get_message["request_id"] = get_request_id  # Include request_id in the message
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)
        response_data = response
        print("Get Users Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], user_id)

    def test_get_users_by_username(self):
        logging.debug("Running test_get_users_by_username")
        # First, create a user to retrieve using __create_user
        username = f"john_doe_{uuid.uuid4()}"
        create_response = self.__create_user("test_get_users_by_username", str(uuid.uuid4()), username)
        create_response_data = create_response
        user_id = create_response_data["data"]["id"]

        # Now, get the user by username
        get_request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "get_users_by_username",
            "data": {
                "username": username
            },
            "comment": "test_get_users_by_username"
        }
        get_message["request_id"] = get_request_id  # Include request_id in the message
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)
        response_data = response
        print("Get Users Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["username"], username)
        self.assertEqual(response_data["data"]["id"], user_id)

    def test_get_users_by_id_fail(self, user_id=""):
        if user_id == "":
            user_id = str(uuid.uuid4())

        get_request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "get_users",  # Updated operation name
            "data": {
                "id": user_id
            },
            "comment": "test_get_users"
        }
        get_message["request_id"] = get_request_id  # Include request_id in the message
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)  # Removed request_id parameter
        response_data = response
        print("Get Users Response:", response_data)
        self.assertEqual(response_data["status"], "error")
        self.assertEqual(response_data["error_code"], "NOT_FOUND")

    def test_get_users_by_id_encrypted(self):
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
        create_message["data"] = self.encrypt_data(json.dumps(create_message["data"]), self.encryption_key)
        create_message["signature"] = self.sign_message(create_message)
        create_response = self.send_and_receive_message(create_message)  # Removed request_id parameter
        create_response_data = json.loads(self.decrypt_data(create_response["data"], self.encryption_key))
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
        get_message["data"] = self.encrypt_data(json.dumps(get_message["data"]), self.encryption_key)
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)  # Removed request_id parameter
        response_data = json.loads(self.decrypt_data(response["data"], self.encryption_key))
        print("Get Users Encrypted Response:", response_data)
        if response["status"] != "success":
            logging.error("Encrypted user retrieval failed.")
            self.fail("Encrypted user retrieval failed.")
        self.assertEqual(response["status"], "success")
        self.assertEqual(response_data["id"], user_id)

    def test_batch_operation_pass(self, comment='test_batch_operation'):
        logging.debug("Running test_batch_operation")
        fixed_uuid = str(uuid.uuid4())  # Generate a fixed UUID for the test
        reqid = str(uuid.uuid4())  # Generate a new request ID for the batch operation
        batch_message = {
            "client_id": self.client_id,
            "request_id": reqid,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "batch_operations",
            "data": {
                "actions": [
                    {
                        "action": "create_users",  # Updated action name
                        "data": {
                            "id": fixed_uuid,  # Specify the fixed UUID
                            "username": f"john_doe_batch_{uuid.uuid4()}",  # Updated for uniqueness
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
            "comment": comment
        }

        batch_message["signature"] = self.sign_message(batch_message)
        response = self.send_and_receive_message(batch_message)  # Removed request_id parameter

        logging.info("**************** Batch Operation Response: %s", response)

        response_data = response["data"]
        print("Batch Operation Response:", response_data)
        if response["status"] != "success":
            print(f"Error: {response.get('message')}, Error Code: {response.get('error_code')}")
        self.assertEqual(response["status"], "success")
        print("*********************** Batch Operation Data:", response_data)
        self.assertEqual(len(response_data["results"]), 3)

    def test_batch_operation_fail(self, comment="test_batch_operation_fail"):
        logging.debug("Running test_batch_operation")
        fixed_uuid = str(uuid.uuid4())  # Generate a fixed UUID for the test
        reqid = str(uuid.uuid4())  # Generate a new request ID for the batch operation
        batch_message = {
            "client_id": self.client_id,
            "request_id": reqid,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "batch_operations",
            "data": {
                "actions": [
                    {
                        "action": "create_users",  # Updated action name
                        "data": {
                            "id": fixed_uuid,  # Specify the fixed UUID
                            "username": f"john_doe_batch_{uuid.uuid4()}",  # Updated for uniqueness
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
                            "user_id": str(uuid.uuid4()),  # Use the same fixed UUID
                            "password_hash": "hashed_password",
                            "expiry_date": "2024-01-01T00:00:00Z",
                            "created_at": "2023-01-01T12:00:00Z"  # Updated to ISO format
                        }
                    }
                ]
            },
            "comment": comment
        }

        batch_message["signature"] = self.sign_message(batch_message)
        response = self.send_and_receive_message(batch_message)  # Removed request_id parameter
        logging.info("**************** Batch Operation Response: %s", response)
        print("Batch Operation Response:", response)
        self.assertEqual(response["status"], "error")
        self.test_get_users_by_id_fail(fixed_uuid)

    def test_batch_operation_encrypted(self):
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

        batch_message["data"] = self.encrypt_data(json.dumps(batch_message["data"]), self.encryption_key)
        batch_message["signature"] = self.sign_message(batch_message)
        response = self.send_and_receive_message(batch_message)  # Removed request_id parameter
        logging.info("**************** Batch Operation Response: %s", response)

        print("Batch Operation Response:", response)
        response_data = json.loads(self.decrypt_data(response["data"], self.encryption_key))
        if response["status"] != "error":
            print(f"Error: {response.get('message')}, Error Code: {response.get('error_code')}")
        self.assertEqual(response["status"], "success")
        self.assertEqual(len(response_data["results"]), 3)

    def test_create_batch_after_error(self):
        self.test_create_users_fail()
        self.test_batch_operation_pass("test_create_batch_after_error")

    def test_create_user_after_batch_error(self):
        self.test_batch_operation_fail("test_create_user_after_batch_error")
        self.test_create_users_pass("test_create_user_after_batch_error")

    def test_create_multiple_batches(self):
        self.test_batch_operation_pass("test_create_multiple_batches_1")
        self.test_batch_operation_pass("test_create_multiple_batches_2")
        self.test_batch_operation_pass("test_create_multiple_batches_3")
        self.test_batch_operation_pass("test_create_multiple_batches_4")
        self.test_batch_operation_pass("test_create_multiple_batches_5")
        self.test_batch_operation_pass("test_create_multiple_batches_6")
        self.test_batch_operation_pass("test_create_multiple_batches_7")
        self.test_batch_operation_pass("test_create_multiple_batches_8")
        self.test_batch_operation_pass("test_create_multiple_batches_9")
        self.test_batch_operation_pass("test_create_multiple_batches_10")
        self.test_batch_operation_pass("test_create_multiple_batches_11")
        self.test_batch_operation_pass("test_create_multiple_batches_12")
        self.test_batch_operation_pass("test_create_multiple_batches_13")
        self.test_batch_operation_pass("test_create_multiple_batches_14")
        self.test_batch_operation_pass("test_create_multiple_batches_15")
        self.test_batch_operation_pass("test_create_multiple_batches_16")
        self.test_batch_operation_pass("test_create_multiple_batches_17")
        self.test_batch_operation_pass("test_create_multiple_batches_18")
        self.test_batch_operation_pass("test_create_multiple_batches_19")
        self.test_batch_operation_pass("test_create_multiple_batches_20")

    def test_create_user_details(self):
        logging.debug("Running test_create_user_details")
        # First, create a user using __create_user
        create_response = self.__create_user("test_create_user_details", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_response_data = create_response
        user_id = create_response_data["data"]["id"]

        # Now, create user details remains unchanged
        request_id = str(uuid.uuid4())  # Generate unique request_id
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "create_user_details",
            "data": {
                "user_id": user_id,
                "details": {"address": "123 Main St"},
                "created_at": "2023-01-01T12:00:00Z",
                "updated_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_create_user_details"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["signature"] = self.sign_message(message)
        response = self.send_and_receive_message(message)
        response_data = response
        print("Create User Details Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertIn("id", response_data["data"])

    def test_update_user_details(self):
        logging.debug("Running test_update_user_details")
        # First, create a user to associate with user details
        create_user_response = self.__create_user("test_update_user_details", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")  # Removed request_id parameter
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create user details
        create_details_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_details_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_user_details",
            "data": {
                "user_id": user_id,
                "details": {"address": "123 Main St"},
                "created_at": "2023-01-01T12:00:00Z",
                "updated_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_update_user_details"
        }
        create_details_message["request_id"] = create_details_request_id  # Include request_id in the message
        create_details_message["signature"] = self.sign_message(create_details_message)
        create_details_response = self.send_and_receive_message(create_details_message)  # Removed request_id parameter
        create_details_response_data = create_details_response
        self.assertEqual(create_details_response_data["status"], "success")
        details_id = create_details_response_data["data"]["id"]

        # Now, update the user details
        request_id = str(uuid.uuid4())  # Generate unique request_id
        update_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "update_user_details",
            "data": {
                "id": details_id,
                "user_id": user_id,
                "details": {"address": "456 Elm St"},
                "updated_at": "2023-01-02T12:00:00Z"  # Updated to ISO format
            },
            "comment": "test_update_user_details"
        }
        update_message["request_id"] = request_id  # Include request_id in the message
        update_message["signature"] = self.sign_message(update_message)
        response = self.send_and_receive_message(update_message)  # Removed request_id parameter
        response_data = response
        print("Update User Details Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], details_id)

    def test_delete_user_details(self):
        logging.debug("Running test_delete_user_details")
        # First, create a user to associate with user details
        create_user_response = self.__create_user("test_delete_user_details", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create user details
        create_details_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_details_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_user_details",
            "data": {
                "user_id": user_id,
                "details": {"address": "123 Main St"},
                "created_at": "2023-01-01T12:00:00Z",
                "updated_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_delete_user_details"
        }
        create_details_message["request_id"] = create_details_request_id  # Include request_id in the message
        create_details_message["signature"] = self.sign_message(create_details_message)
        create_details_response = self.send_and_receive_message(create_details_message)  # Removed request_id parameter
        create_details_response_data = create_details_response
        self.assertEqual(create_details_response_data["status"], "success")
        details_id = create_details_response_data["data"]["id"]

        # Now, delete the user details
        request_id = str(uuid.uuid4())  # Generate unique request_id
        delete_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "delete_user_details",
            "data": {
                "id": details_id
            },
            "comment": "test_delete_user_details"
        }
        delete_message["request_id"] = request_id  # Include request_id in the message
        delete_message["signature"] = self.sign_message(delete_message)
        response = self.send_and_receive_message(delete_message)  # Removed request_id parameter
        response_data = response
        print("Delete User Details Response:", response_data)
        self.assertEqual(response_data["status"], "success")

    def test_get_user_details(self):
        logging.debug("Running test_get_user_details")
        # First, create a user to associate with user details
        create_user_response = self.__create_user("test_get_user_details", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create user details
        create_details_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_details_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_user_details",
            "data": {
                "user_id": user_id,
                "details": {"address": "123 Main St"},
                "created_at": "2023-01-01T12:00:00Z",
                "updated_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_get_user_details"
        }
        create_details_message["request_id"] = create_details_request_id  # Include request_id in the message
        create_details_message["signature"] = self.sign_message(create_details_message)
        create_details_response = self.send_and_receive_message(create_details_message)  # Removed request_id parameter
        create_details_response_data = create_details_response
        self.assertEqual(create_details_response_data["status"], "success")
        details_id = create_details_response_data["data"]["id"]

        # Now, get the user details
        request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "get_user_details",
            "data": {
                "id": details_id
            },
            "comment": "test_get_user_details"
        }
        get_message["request_id"] = request_id  # Include request_id in the message
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)  # Removed request_id parameter
        response_data = response
        print("Get User Details Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], details_id)

    def test_create_webauthn_credentials(self):
        logging.debug("Running test_create_webauthn_credentials")
        # First, create a user using __create_user
        create_user_response = self.__create_user("test_create_webauthn_credentials", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create webauthn credentials remains unchanged
        request_id = str(uuid.uuid4())  # Generate unique request_id
        credential_id = str(uuid.uuid4())  # Generate a unique credential_id
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_webauthn_credentials",
            "data": {
                "user_id": user_id,
                "credential_id": credential_id,
                "public_key": "public_key_data",
                "sign_count": 0,
                "transports": "usb",
                "attestation_format": "packed",
                "credential_type": "public-key",
                "created_at": "2023-01-01T12:00:00Z",  # Updated to ISO format
                "last_used_at": "2023-01-01T12:00:00Z",  # Updated to ISO format
                "counter_last_updated": "2023-01-01T12:00:00Z"  # Updated to ISO format
            },
            "comment": "test_create_webauthn_credentials"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["signature"] = self.sign_message(message)
        response = self.send_and_receive_message(message)
        response_data = response
        print("Create WebAuthn Credentials Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertIn("id", response_data["data"])

    def test_update_webauthn_credentials(self):
        logging.debug("Running test_update_webauthn_credentials")
        # First, create a user to associate with webauthn credentials
        create_user_response = self.__create_user("test_update_webauthn_credentials", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create webauthn credentials
        create_credentials_request_id = str(uuid.uuid4())  # Generate unique request_id
        credential_id = str(uuid.uuid4())  # Generate a unique credential_id
        create_credentials_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_webauthn_credentials",
            "data": {
                "user_id": user_id,
                "credential_id": credential_id,
                "public_key": "public_key_data",
                "sign_count": 0,
                "transports": "usb",
                "attestation_format": "packed",
                "credential_type": "public-key",
                "created_at": "2023-01-01T12:00:00Z",
                "last_used_at": "2023-01-01T12:00:00Z",
                "counter_last_updated": "2023-01-01T12:00:00Z"
            },
            "comment": "test_update_webauthn_credentials"
        }
        create_credentials_message["request_id"] = create_credentials_request_id  # Include request_id in the message
        create_credentials_message["signature"] = self.sign_message(create_credentials_message)
        create_credentials_response = self.send_and_receive_message(create_credentials_message)  # Removed request_id parameter
        create_credentials_response_data = create_credentials_response
        self.assertEqual(create_credentials_response_data["status"], "success")
        credentials_id = create_credentials_response_data["data"]["id"]

        # Now, update the webauthn credentials
        request_id = str(uuid.uuid4())  # Generate unique request_id
        update_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "update_webauthn_credentials",
            "data": {
                "id": credentials_id,
                "user_id": user_id,
                "public_key": "updated_public_key_data",
                "sign_count": 1,
                "transports": "nfc",
                "attestation_format": "packed",
                "credential_type": "public-key",
                "last_used_at": "2023-01-02T12:00:00Z",  # Updated to ISO format
                "counter_last_updated": "2023-01-02T12:00:00Z"  # Updated to ISO format
            },
            "comment": "test_update_webauthn_credentials"
        }
        update_message["request_id"] = request_id  # Include request_id in the message
        update_message["signature"] = self.sign_message(update_message)
        response = self.send_and_receive_message(update_message)  # Removed request_id parameter
        response_data = response
        print("Update WebAuthn Credentials Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], credentials_id)

    def test_delete_webauthn_credentials(self):
        logging.debug("Running test_delete_webauthn_credentials")
        # First, create a user to associate with webauthn credentials
        create_user_response = self.__create_user("test_delete_webauthn_credentials", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create webauthn credentials
        create_credentials_request_id = str(uuid.uuid4())  # Generate unique request_id
        credential_id = str(uuid.uuid4())  # Generate a unique credential_id
        create_credentials_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_webauthn_credentials",
            "data": {
                "user_id": user_id,
                "credential_id": credential_id,
                "public_key": "public_key_data",
                "sign_count": 0,
                "transports": "usb",
                "attestation_format": "packed",
                "credential_type": "public-key",
                "created_at": "2023-01-01T12:00:00Z",
                "last_used_at": "2023-01-01T12:00:00Z",
                "counter_last_updated": "2023-01-01T12:00:00Z"
            },
            "comment": "test_delete_webauthn_credentials"
        }
        create_credentials_message["request_id"] = create_credentials_request_id  # Include request_id in the message
        create_credentials_message["signature"] = self.sign_message(create_credentials_message)
        create_credentials_response = self.send_and_receive_message(create_credentials_message)  # Removed request_id parameter
        create_credentials_response_data = create_credentials_response
        self.assertEqual(create_credentials_response_data["status"], "success")
        credentials_id = create_credentials_response_data["data"]["id"]

        # Now, delete the webauthn credentials
        request_id = str(uuid.uuid4())  # Generate unique request_id
        delete_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "delete_webauthn_credentials",
            "data": {
                "id": credentials_id
            },
            "comment": "test_delete_webauthn_credentials"
        }
        delete_message["request_id"] = request_id  # Include request_id in the message
        delete_message["signature"] = self.sign_message(delete_message)
        response = self.send_and_receive_message(delete_message)  # Removed request_id parameter
        response_data = response
        print("Delete WebAuthn Credentials Response:", response_data)
        self.assertEqual(response_data["status"], "success")

    def test_get_webauthn_credentials(self):
        logging.debug("Running test_get_webauthn_credentials")
        # First, create a user to associate with webauthn credentials
        create_user_response = self.__create_user("test_get_webauthn_credentials", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create webauthn credentials
        create_credentials_request_id = str(uuid.uuid4())  # Generate unique request_id
        credential_id = str(uuid.uuid4())  # Generate a unique credential_id
        create_credentials_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_webauthn_credentials",
            "data": {
                "user_id": user_id,
                "credential_id": credential_id,
                "public_key": "public_key_data",
                "sign_count": 0,
                "transports": "usb",
                "attestation_format": "packed",
                "credential_type": "public-key",
                "created_at": "2023-01-01T12:00:00Z",
                "last_used_at": "2023-01-01T12:00:00Z",
                "counter_last_updated": "2023-01-01T12:00:00Z"
            },
            "comment": "test_get_webauthn_credentials"
        }
        create_credentials_message["request_id"] = create_credentials_request_id  # Include request_id in the message
        create_credentials_message["signature"] = self.sign_message(create_credentials_message)
        create_credentials_response = self.send_and_receive_message(create_credentials_message)  # Removed request_id parameter
        create_credentials_response_data = create_credentials_response
        self.assertEqual(create_credentials_response_data["status"], "success")
        credentials_id = create_credentials_response_data["data"]["id"]

        # Now, get the webauthn credentials
        request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "get_webauthn_credentials",
            "data": {
                "id": credentials_id
            },
            "comment": "test_get_webauthn_credentials"
        }
        get_message["request_id"] = request_id  # Include request_id in the message
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)  # Removed request_id parameter
        response_data = response
        print("Get WebAuthn Credentials Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], credentials_id)

    def test_create_oauth2_signins(self):
        logging.debug("Running test_create_oauth2_signins")
        # First, create a user to associate with oauth2 signins
        create_user_response = self.__create_user("test_create_oauth2_signins", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create oauth2 signins
        request_id = str(uuid.uuid4())  # Generate unique request_id
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_oauth2_signins",
            "data": {
                "user_id": user_id,
                "name": "google",
                "provider": "Google",
                "openid_identifier": "openid_identifier_data",
                "access_token": "access_token_data",
                "refresh_token": "refresh_token_data",
                "token_expires_at": "2024-01-01T12:00:00Z",  # Updated to ISO format
                "scopes": "email profile",
                "id_token": "id_token_data",
                "last_refreshed": "2023-01-01T12:00:00Z"  # Updated to ISO format
            },
            "comment": "test_create_oauth2_signins"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["signature"] = self.sign_message(message)
        response = self.send_and_receive_message(message)  # Removed request_id parameter
        response_data = response
        print("Create OAuth2 Signins Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertIn("id", response_data["data"])

    def test_update_oauth2_signins(self):
        logging.debug("Running test_update_oauth2_signins")
        create_user_response = self.__create_user("test_update_oauth2_signins", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create oauth2 signins
        create_signins_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_signins_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_oauth2_signins",
            "data": {
                "user_id": user_id,
                "name": "google",
                "provider": "Google",
                "openid_identifier": "openid_identifier_data",
                "access_token": "access_token_data",
                "refresh_token": "refresh_token_data",
                "token_expires_at": "2024-01-01T12:00:00Z",  # Updated to ISO format
                "scopes": "email profile",
                "id_token": "id_token_data",
                "last_refreshed": "2023-01-01T12:00:00Z"  # Updated to ISO format
            },
            "comment": "test_update_oauth2_signins"
        }
        create_signins_message["request_id"] = create_signins_request_id  # Include request_id in the message
        create_signins_message["signature"] = self.sign_message(create_signins_message)
        create_signins_response = self.send_and_receive_message(create_signins_message)  # Removed request_id parameter
        create_signins_response_data = create_signins_response
        self.assertEqual(create_signins_response_data["status"], "success")
        signins_id = create_signins_response_data["data"]["id"]

        # Now, update the oauth2 signins
        request_id = str(uuid.uuid4())  # Generate unique request_id
        update_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "update_oauth2_signins",
            "data": {
                "id": signins_id,
                "user_id": user_id,
                "name": "google",
                "provider": "Google",
                "openid_identifier": "updated_openid_identifier_data",
                "access_token": "updated_access_token_data",
                "refresh_token": "updated_refresh_token_data",
                "token_expires_at": "2025-01-01T12:00:00Z",  # Updated to ISO format
                "scopes": "email profile",
                "id_token": "updated_id_token_data",
                "last_refreshed": "2023-01-02T12:00:00Z"  # Updated to ISO format
            },
            "comment": "test_update_oauth2_signins"
        }
        update_message["request_id"] = request_id  # Include request_id in the message
        update_message["signature"] = self.sign_message(update_message)
        response = self.send_and_receive_message(update_message)  # Removed request_id parameter
        response_data = response
        print("Update OAuth2 Signins Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], signins_id)

    def test_delete_oauth2_signins(self):
        logging.debug("Running test_delete_oauth2_signins")
        # First, create a user to associate with oauth2 signins
        create_user_response = self.__create_user("test_delete_oauth2_signins", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create oauth2 signins
        create_signins_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_signins_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_oauth2_signins",
            "data": {
                "user_id": user_id,
                "name": "google",
                "provider": "Google",
                "openid_identifier": "openid_identifier_data",
                "access_token": "access_token_data",
                "refresh_token": "refresh_token_data",
                "token_expires_at": "2024-01-01T12:00:00Z",  # Updated to ISO format
                "scopes": "email profile",
                "id_token": "id_token_data",
                "last_refreshed": "2023-01-01T12:00:00Z"  # Updated to ISO format
            },
            "comment": "test_delete_oauth2_signins"
        }
        create_signins_message["request_id"] = create_signins_request_id  # Include request_id in the message
        create_signins_message["signature"] = self.sign_message(create_signins_message)
        create_signins_response = self.send_and_receive_message(create_signins_message)  # Removed request_id parameter
        create_signins_response_data = create_signins_response
        self.assertEqual(create_signins_response_data["status"], "success")
        signins_id = create_signins_response_data["data"]["id"]

        # Now, delete the oauth2 signins
        request_id = str(uuid.uuid4())  # Generate unique request_id
        delete_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "delete_oauth2_signins",
            "data": {
                "id": signins_id
            },
            "comment": "test_delete_oauth2_signins"
        }
        delete_message["request_id"] = request_id  # Include request_id in the message
        delete_message["signature"] = self.sign_message(delete_message)
        response = self.send_and_receive_message(delete_message)  # Removed request_id parameter
        response_data = response
        print("Delete OAuth2 Signins Response:", response_data)
        self.assertEqual(response_data["status"], "success")

    def test_get_oauth2_signins(self):
        logging.debug("Running test_get_oauth2_signins")
        # First, create a user to associate with oauth2 signins
        create_user_response = self.__create_user("test_get_oauth2_signins", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create oauth2 signins
        create_signins_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_signins_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_oauth2_signins",
            "data": {
                "user_id": user_id,
                "name": "google",
                "provider": "Google",
                "openid_identifier": "openid_identifier_data",
                "access_token": "access_token_data",
                "refresh_token": "refresh_token_data",
                "token_expires_at": "2024-01-01T12:00:00Z",  # Updated to ISO format
                "scopes": "email profile",
                "id_token": "id_token_data",
                "last_refreshed": "2023-01-01T12:00:00Z"  # Updated to ISO format
            },
            "comment": "test_get_oauth2_signins"
        }
        create_signins_message["request_id"] = create_signins_request_id  # Include request_id in the message
        create_signins_message["signature"] = self.sign_message(create_signins_message)
        create_signins_response = self.send_and_receive_message(create_signins_message)  # Removed request_id parameter
        create_signins_response_data = create_signins_response
        self.assertEqual(create_signins_response_data["status"], "success")
        signins_id = create_signins_response_data["data"]["id"]

        # Now, get the oauth2 signins
        request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "get_oauth2_signins",
            "data": {
                "id": signins_id
            },
            "comment": "test_get_oauth2_signins"
        }
        get_message["request_id"] = request_id  # Include request_id in the message
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)  # Removed request_id parameter
        response_data = response
        print("Get OAuth2 Signins Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], signins_id)

    def test_create_public_ssh_keys(self):
        logging.debug("Running test_create_public_ssh_keys")
        # First, create a user to associate with public SSH keys
        create_user_response = self.__create_user("test_create_public_ssh_keys", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create public SSH keys
        request_id = str(uuid.uuid4())  # Generate unique request_id
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_public_ssh_keys",
            "data": {
                "user_id": user_id,
                "name": "my_ssh_key",
                "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAr...",
                "key_type": "rsa",
                "fingerprint": str(uuid.uuid4()),  # Ensure unique fingerprint
                "created_at": "2023-01-01T12:00:00Z",
                "last_used_at": "2023-01-01T12:00:00Z",
                "expiry_date": "2024-01-01T00:00:00Z"
            },
            "comment": "test_create_public_ssh_keys"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["signature"] = self.sign_message(message)
        response = self.send_and_receive_message(message)  # Removed request_id parameter
        response_data = response
        print("Create Public SSH Keys Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertIn("id", response_data["data"])

    def test_update_public_ssh_keys(self):
        logging.debug("Running test_update_public_ssh_keys")
        # First, create a user to associate with public SSH keys
        create_user_response = self.__create_user("test_update_public_ssh_keys", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create public SSH keys
        create_keys_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_keys_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_public_ssh_keys",
            "data": {
                "user_id": user_id,
                "name": "my_ssh_key",
                "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAr...",
                "key_type": "rsa",
                "fingerprint": str(uuid.uuid4()),  # Ensure unique fingerprint
                "created_at": "2023-01-01T12:00:00Z",
                "last_used_at": "2023-01-01T12:00:00Z",
                "expiry_date": "2024-01-01T00:00:00Z"
            },
            "comment": "test_update_public_ssh_keys"
        }
        create_keys_message["request_id"] = create_keys_request_id  # Include request_id in the message
        create_keys_message["signature"] = self.sign_message(create_keys_message)
        create_keys_response = self.send_and_receive_message(create_keys_message)  # Removed request_id parameter
        create_keys_response_data = create_keys_response
        self.assertEqual(create_keys_response_data["status"], "success")
        keys_id = create_keys_response_data["data"]["id"]

        # Now, update the public SSH keys
        request_id = str(uuid.uuid4())  # Generate unique request_id
        update_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "update_public_ssh_keys",
            "data": {
                "id": keys_id,
                "user_id": user_id,
                "name": "my_updated_ssh_key",
                "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAr...",
                "key_type": "rsa",
                "fingerprint": str(uuid.uuid4()),  # Ensure unique fingerprint
                "last_used_at": "2023-01-02T12:00:00Z",
                "expiry_date": "2025-01-01T00:00:00Z"
            },
            "comment": "test_update_public_ssh_keys"
        }
        update_message["request_id"] = request_id  # Include request_id in the message
        update_message["signature"] = self.sign_message(update_message)
        response = self.send_and_receive_message(update_message)  # Removed request_id parameter
        response_data = response
        print("Update Public SSH Keys Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], keys_id)

    def test_delete_public_ssh_keys(self):
        logging.debug("Running test_delete_public_ssh_keys")
        # First, create a user to associate with public SSH keys
        create_user_response = self.__create_user("test_delete_public_ssh_keys", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create public SSH keys
        create_keys_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_keys_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_public_ssh_keys",
            "data": {
                "user_id": user_id,
                "name": "my_ssh_key",
                "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAr...",
                "key_type": "rsa",
                "fingerprint": str(uuid.uuid4()),  # Ensure unique fingerprint
                "created_at": "2023-01-01T12:00:00Z",
                "last_used_at": "2023-01-01T12:00:00Z",
                "expiry_date": "2024-01-01T00:00:00Z"
            },
            "comment": "test_delete_public_ssh_keys"
        }
        create_keys_message["request_id"] = create_keys_request_id  # Include request_id in the message
        create_keys_message["signature"] = self.sign_message(create_keys_message)
        create_keys_response = self.send_and_receive_message(create_keys_message)  # Removed request_id parameter
        create_keys_response_data = create_keys_response
        self.assertEqual(create_keys_response_data["status"], "success")
        keys_id = create_keys_response_data["data"]["id"]

        # Now, delete the public SSH keys
        request_id = str(uuid.uuid4())  # Generate unique request_id
        delete_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "delete_public_ssh_keys",
            "data": {
                "id": keys_id
            },
            "comment": "test_delete_public_ssh_keys"
        }
        delete_message["request_id"] = request_id  # Include request_id in the message
        delete_message["signature"] = self.sign_message(delete_message)
        response = self.send_and_receive_message(delete_message)  # Removed request_id parameter
        response_data = response
        print("Delete Public SSH Keys Response:", response_data)
        self.assertEqual(response_data["status"], "success")

    def test_get_public_ssh_keys(self):
        logging.debug("Running test_get_public_ssh_keys")
        # First, create a user to associate with public SSH keys
        create_user_response = self.__create_user("test_get_public_ssh_keys", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create public SSH keys
        create_keys_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_keys_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_public_ssh_keys",
            "data": {
                "user_id": user_id,
                "name": "my_ssh_key",
                "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAr...",
                "key_type": "rsa",
                "fingerprint": str(uuid.uuid4()),  # Ensure unique fingerprint
                "created_at": "2023-01-01T12:00:00Z",
                "last_used_at": "2023-01-01T12:00:00Z",
                "expiry_date": "2024-01-01T00:00:00Z"
            },
            "comment": "test_get_public_ssh_keys"
        }
        create_keys_message["request_id"] = create_keys_request_id  # Include request_id in the message
        create_keys_message["signature"] = self.sign_message(create_keys_message)
        create_keys_response = self.send_and_receive_message(create_keys_message)  # Removed request_id parameter
        create_keys_response_data = create_keys_response
        self.assertEqual(create_keys_response_data["status"], "success")
        keys_id = create_keys_response_data["data"]["id"]

        # Now, get the public SSH keys
        request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "get_public_ssh_keys",
            "data": {
                "id": keys_id
            },
            "comment": "test_get_public_ssh_keys"
        }
        get_message["request_id"] = request_id  # Include request_id in the message
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)  # Removed request_id parameter
        response_data = response
        print("Get Public SSH Keys Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], keys_id)

    def test_create_login_tokens(self):
        logging.debug("Running test_create_login_tokens")
        # First, create a user to associate with login tokens
        create_user_response = self.__create_user("test_create_login_tokens", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create login tokens
        request_id = str(uuid.uuid4())  # Generate unique request_id
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_login_tokens",
            "data": {
                "user_id": user_id,
                "token": str(uuid.uuid4()),  # Ensure unique token
                "revoked": False,
                "expires_at": "2024-01-01T12:00:00Z"
            },
            "comment": "test_create_login_tokens"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["signature"] = self.sign_message(message)
        response = self.send_and_receive_message(message)  # Removed request_id parameter
        response_data = response
        print("Create Login Tokens Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertIn("id", response_data["data"])

    def test_update_login_tokens(self):
        logging.debug("Running test_update_login_tokens")
        # First, create a user to associate with login tokens
        create_user_response = self.__create_user("test_update_login_tokens", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create login tokens
        create_tokens_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_tokens_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_login_tokens",
            "data": {
                "user_id": user_id,
                "token": str(uuid.uuid4()),  # Ensure unique token
                "revoked": False,
                "expires_at": "2024-01-01T12:00:00Z"
            },
            "comment": "test_update_login_tokens"
        }
        create_tokens_message["request_id"] = create_tokens_request_id  # Include request_id in the message
        create_tokens_message["signature"] = self.sign_message(create_tokens_message)
        create_tokens_response = self.send_and_receive_message(create_tokens_message)  # Removed request_id parameter
        create_tokens_response_data = create_tokens_response
        self.assertEqual(create_tokens_response_data["status"], "success")
        tokens_id = create_tokens_response_data["data"]["id"]

        # Now, update the login tokens
        request_id = str(uuid.uuid4())  # Generate unique request_id
        update_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "update_login_tokens",
            "data": {
                "id": tokens_id,
                "user_id": user_id,
                "token": str(uuid.uuid4()),  # Ensure unique token
                "revoked": True,
                "expires_at": "2025-01-01T12:00:00Z"
            },
            "comment": "test_update_login_tokens"
        }
        update_message["request_id"] = request_id  # Include request_id in the message
        update_message["signature"] = self.sign_message(update_message)
        response = self.send_and_receive_message(update_message)  # Removed request_id parameter
        response_data = response
        print("Update Login Tokens Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], tokens_id)

    def test_delete_login_tokens(self):
        logging.debug("Running test_delete_login_tokens")
        # First, create a user to associate with login tokens
        create_user_response = self.__create_user("test_delete_login_tokens", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create login tokens
        create_tokens_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_tokens_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_login_tokens",
            "data": {
                "user_id": user_id,
                "token": str(uuid.uuid4()),  # Ensure unique token
                "revoked": False,
                "expires_at": "2024-01-01T12:00:00Z"
            },
            "comment": "test_delete_login_tokens"
        }
        create_tokens_message["request_id"] = create_tokens_request_id  # Include request_id in the message
        create_tokens_message["signature"] = self.sign_message(create_tokens_message)
        create_tokens_response = self.send_and_receive_message(create_tokens_message)  # Removed request_id parameter
        create_tokens_response_data = create_tokens_response
        self.assertEqual(create_tokens_response_data["status"], "success")
        tokens_id = create_tokens_response_data["data"]["id"]

        # Now, delete the login tokens
        request_id = str(uuid.uuid4())  # Generate unique request_id
        delete_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "delete_login_tokens",
            "data": {
                "id": tokens_id
            },
            "comment": "test_delete_login_tokens"
        }
        delete_message["request_id"] = request_id  # Include request_id in the message
        delete_message["signature"] = self.sign_message(delete_message)
        response = self.send_and_receive_message(delete_message)  # Removed request_id parameter
        response_data = response
        print("Delete Login Tokens Response:", response_data)
        self.assertEqual(response_data["status"], "success")

    def test_get_login_tokens(self):
        logging.debug("Running test_get_login_tokens")
        # First, create a user to associate with login tokens
        create_user_response = self.__create_user("test_get_login_tokens", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create login tokens
        create_tokens_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_tokens_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_login_tokens",
            "data": {
                "user_id": user_id,
                "token": str(uuid.uuid4()),  # Ensure unique token
                "revoked": False,
                "expires_at": "2024-01-01T12:00:00Z"
            },
            "comment": "test_get_login_tokens"
        }
        create_tokens_message["request_id"] = create_tokens_request_id  # Include request_id in the message
        create_tokens_message["signature"] = self.sign_message(create_tokens_message)
        create_tokens_response = self.send_and_receive_message(create_tokens_message)  # Removed request_id parameter
        create_tokens_response_data = create_tokens_response
        self.assertEqual(create_tokens_response_data["status"], "success")
        tokens_id = create_tokens_response_data["data"]["id"]

        # Now, get the login tokens
        request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "get_login_tokens",
            "data": {
                "id": tokens_id
            },
            "comment": "test_get_login_tokens"
        }
        get_message["request_id"] = request_id  # Include request_id in the message
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)  # Removed request_id parameter
        response_data = response
        print("Get Login Tokens Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], tokens_id)

    def test_create_passwords(self):
        logging.debug("Running test_create_passwords")
        # First, create a user to associate with passwords
        create_user_response = self.__create_user("test_create_passwords", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create passwords
        request_id = str(uuid.uuid4())  # Generate unique request_id
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_passwords",
            "data": {
                "user_id": user_id,
                "password_hash": "hashed_password",
                "expiry_date": "2024-01-01T00:00:00Z",
                "created_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_create_passwords"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["signature"] = self.sign_message(message)
        response = self.send_and_receive_message(message)  # Removed request_id parameter
        response_data = response
        print("Create Passwords Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertIn("id", response_data["data"])

    def test_update_passwords(self):
        logging.debug("Running test_update_passwords")
        # First, create a user to associate with passwords
        create_user_response = self.__create_user("test_update_passwords", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create passwords
        create_passwords_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_passwords_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_passwords",
            "data": {
                "user_id": user_id,
                "password_hash": "hashed_password",
                "expiry_date": "2024-01-01T00:00:00Z",
                "created_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_update_passwords"
        }
        create_passwords_message["request_id"] = create_passwords_request_id  # Include request_id in the message
        create_passwords_message["signature"] = self.sign_message(create_passwords_message)
        create_passwords_response = self.send_and_receive_message(create_passwords_message)  # Removed request_id parameter
        create_passwords_response_data = create_passwords_response
        self.assertEqual(create_passwords_response_data["status"], "success")
        passwords_id = create_passwords_response_data["data"]["id"]

        # Now, update the passwords
        request_id = str(uuid.uuid4())  # Generate unique request_id
        update_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "update_passwords",
            "data": {
                "id": passwords_id,
                "user_id": user_id,
                "password_hash": "updated_hashed_password",
                "expiry_date": "2025-01-01T00:00:00Z",
                "updated_at": "2023-01-02T12:00:00Z"
            },
            "comment": "test_update_passwords"
        }
        update_message["request_id"] = request_id  # Include request_id in the message
        update_message["signature"] = self.sign_message(update_message)
        response = self.send_and_receive_message(update_message)  # Removed request_id parameter
        response_data = response
        print("Update Passwords Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], passwords_id)

    def test_delete_passwords(self):
        logging.debug("Running test_delete_passwords")
        # First, create a user to associate with passwords
        create_user_response = self.__create_user("test_delete_passwords", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create passwords
        create_passwords_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_passwords_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_passwords",
            "data": {
                "user_id": user_id,
                "password_hash": "hashed_password",
                "expiry_date": "2024-01-01T00:00:00Z",
                "created_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_delete_passwords"
        }
        create_passwords_message["request_id"] = create_passwords_request_id  # Include request_id in the message
        create_passwords_message["signature"] = self.sign_message(create_passwords_message)
        create_passwords_response = self.send_and_receive_message(create_passwords_message)  # Removed request_id parameter
        create_passwords_response_data = create_passwords_response
        self.assertEqual(create_passwords_response_data["status"], "success")
        passwords_id = create_passwords_response_data["data"]["id"]

        # Now, delete the passwords
        request_id = str(uuid.uuid4())  # Generate unique request_id
        delete_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "delete_passwords",
            "data": {
                "id": passwords_id
            },
            "comment": "test_delete_passwords"
        }
        delete_message["request_id"] = request_id  # Include request_id in the message
        delete_message["signature"] = self.sign_message(delete_message)
        response = self.send_and_receive_message(delete_message)  # Removed request_id parameter
        response_data = response
        print("Delete Passwords Response:", response_data)
        self.assertEqual(response_data["status"], "success")

    def test_get_passwords(self):
        logging.debug("Running test_get_passwords")
        # First, create a user to associate with passwords
        create_user_response = self.__create_user("test_get_passwords", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        create_user_response_data = create_user_response
        user_id = create_user_response_data["data"]["id"]

        # Now, create passwords
        create_passwords_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_passwords_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "create_passwords",
            "data": {
                "user_id": user_id,
                "password_hash": "hashed_password",
                "expiry_date": "2024-01-01T00:00:00Z",
                "created_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_get_passwords"
        }
        create_passwords_message["request_id"] = create_passwords_request_id  # Include request_id in the message
        create_passwords_message["signature"] = self.sign_message(create_passwords_message)
        create_passwords_response = self.send_and_receive_message(create_passwords_message)  # Removed request_id parameter
        create_passwords_response_data = create_passwords_response
        self.assertEqual(create_passwords_response_data["status"], "success")
        passwords_id = create_passwords_response_data["data"]["id"]

        # Now, get the passwords
        request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,  # Ensure ISO format
            "operation": "get_passwords",
            "data": {
                "id": passwords_id
            },
            "comment": "test_get_passwords"
        }
        get_message["request_id"] = request_id  # Include request_id in the message
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)  # Removed request_id parameter
        response_data = response
        print("Get Passwords Response:", response_data)
        self.assertEqual(response_data["status"], "success")
        self.assertEqual(response_data["data"]["id"], passwords_id)

    def test_create_users_with_different_timezones(self):
        logging.debug("Running test_create_users_with_different_timezones")
        request_id = str(uuid.uuid4())  # Generate unique request_id
        message = {
            "client_id": self.client_id,
            "timestamp": "2023-01-01T12:00:00+05:00",  # Timestamp in UTC+5
            "operation": "create_users",
            "data": {
                "username": f"jane_doe_{uuid.uuid4()}",
                "email": "jane@example.com",
                "user_type": "human",
                "expiry_date": "2024-01-01T00:00:00-05:00"  # Timestamp in UTC-5
            },
            "comment": "test_create_users_with_different_timezones"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["signature"] = self.sign_message(message)
        response = self.send_and_receive_message(message)  # Removed request_id parameter
        response_data = response
        self.assertEqual(response_data["status"], "success")
        self.assertIn("id", response_data["data"])

    def test_update_users_with_different_timezones(self):
        logging.debug("Running test_update_users_with_different_timezones")
        
        # Create a user before updating
        create_request_id = str(uuid.uuid4())  # Generate unique request_id
        create_message = {
            "client_id": self.client_id,
            "request_id": "req_create_{}".format(uuid.uuid4()),
            "timestamp": "2023-01-02T12:00:00Z",
            "operation": "create_users",
            "data": {
                "username": f"timezone_user_{uuid.uuid4()}",
                "email": "timezone@example.com",
                "user_type": "human",
                "expiry_date": "2024-01-01T00:00:00-05:00"
            },
            "comment": "test_update_users_with_different_timezones"
        }
        create_message["request_id"] = create_request_id  # Include request_id in the message
        create_message["signature"] = self.sign_message(create_message)
        create_response = self.send_and_receive_message(create_message)  # Removed request_id parameter
        create_response_data = create_response
        self.assertEqual(create_response_data["status"], "success")
        user_id = create_response_data["data"]["id"]

        # Proceed to update the user with a different timezone
        update_request_id = str(uuid.uuid4())  # Generate unique request_id
        update_message = {
            "client_id": self.client_id,
            "request_id": "req_update_{}".format(uuid.uuid4()),
            "timestamp": "2023-01-03T12:00:00+05:00",
            "operation": "update_users",
            "data": {
                "id": user_id,
                "expiry_date": "2024-01-05T03:00:00+06:00"
            },
            "comment": "test_update_users_with_different_timezones"
        }
        update_message["request_id"] = update_request_id  # Include request_id in the message
        update_message["signature"] = self.sign_message(update_message)
        update_response = self.send_and_receive_message(update_message)  # Removed request_id parameter
        update_response_data = update_response
        self.assertEqual(update_response_data["status"], "success")
        self.assertEqual(update_response_data["data"]["id"], user_id)
        
        # Optionally, retrieve the user to verify the update
        get_request_id = str(uuid.uuid4())  # Generate unique request_id
        get_message = {
            "client_id": self.client_id,
            "request_id": "req_get_{}".format(uuid.uuid4()),
            "timestamp": "2023-01-04T12:00:00Z",
            "operation": "get_users",
            "data": {
                "id": user_id
            },
            "comment": "test_update_users_with_different_timezones"
        }
        get_message["request_id"] = get_request_id  # Include request_id in the message
        get_message["signature"] = self.sign_message(get_message)
        get_response = self.send_and_receive_message(get_message)  # Removed request_id parameter
        get_response_data = get_response
        self.assertEqual(get_response_data["status"], "success")
        self.assertEqual(get_response_data["data"]["expiry_date"], "2024-01-04 21:00:00")

    def test_create_1000_users_with_passwords(self):
        logging.debug("Running test_create_1000_users_with_passwords")
        actions = []
        for i in range(1000):
            user_id = str(uuid.uuid4())
            actions.append({
                "action": "create_users",
                "data": {
                    "id": user_id,
                    "username": f"user_{uuid.uuid4()}",
                    "email": f"user_{i}@example.com",
                    "user_type": "human",
                    "expiry_date": "2024-01-01T00:00:00Z"
                }
            })
            actions.append({
                "action": "create_passwords",
                "data": {
                    "user_id": user_id,
                    "password_hash": "hashed_password",
                    "expiry_date": "2024-01-01T00:00:00Z",
                    "created_at": "2023-01-01T12:00:00Z"
                }
            })
        reqid = str(uuid.uuid4())
        batch_message = {
            "client_id": self.client_id,
            "request_id": reqid,
            "timestamp": self.timestamp,
            "operation": "batch_operations",
            "data": {"actions": actions},
            "comment": "test_create_1000_users_with_passwords"
        }
        batch_message["signature"] = self.sign_message(batch_message)
        response = self.send_and_receive_message(batch_message)
        self.assertEqual(response["status"], "success")

    def test_create_users_with_all_records_in_blocks(self):
        logging.debug("Running test_create_users_with_all_records_in_blocks")
        total_users = 100
        block_size = 20
        for block_start in range(0, total_users, block_size):
            actions = []
            for i in range(block_start, min(block_start + block_size, total_users)):
                user_id = str(uuid.uuid4())
                # Create user record
                actions.append({
                    "action": "create_users",
                    "data": {
                        "id": user_id,
                        "username": f"user_{uuid.uuid4()}",
                        "email": f"user_{i}@example.com",
                        "user_type": "human",
                        "expiry_date": "2024-01-01T00:00:00Z"
                    }
                })
                # Associated user details record
                actions.append({
                    "action": "create_user_details",
                    "data": {
                        "user_id": user_id,
                        "details": {"address": f"{i} Main St"},
                        "created_at": "2023-01-01T12:00:00Z",
                        "updated_at": "2023-01-01T12:00:00Z"
                    }
                })
                # Associated passwords record
                actions.append({
                    "action": "create_passwords",
                    "data": {
                        "user_id": user_id,
                        "password_hash": "hashed_password",
                        "expiry_date": "2024-01-01T00:00:00Z",
                        "created_at": "2023-01-01T12:00:00Z"
                    }
                })
                # Associated webauthn credentials record
                actions.append({
                    "action": "create_webauthn_credentials",
                    "data": {
                        "user_id": user_id,
                        "credential_id": str(uuid.uuid4()),
                        "public_key": "public_key_data",
                        "sign_count": 0,
                        "transports": "usb",
                        "attestation_format": "packed",
                        "credential_type": "public-key",
                        "created_at": "2023-01-01T12:00:00Z",
                        "last_used_at": "2023-01-01T12:00:00Z",
                        "counter_last_updated": "2023-01-01T12:00:00Z"
                    }
                })
                # Associated OAuth2 signins record
                actions.append({
                    "action": "create_oauth2_signins",
                    "data": {
                        "user_id": user_id,
                        "name" : f"{user_id} name",
                        "openid_identifier" : f"{user_id} identifier",
                        "provider": "example_provider",
                        "created_at": "2023-01-01T12:00:00Z"
                    }
                })
                # Associated public SSH keys record
                actions.append({
                    "action": "create_public_ssh_keys",
                    "data": {
                        "user_id": user_id,
                        "name" : f"{user_id} name",
                        "key_type" : f"some key type",
                        "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...",
                        "created_at": "2023-01-01T12:00:00Z"
                    }
                })
                # Associated login tokens record
                actions.append({
                    "action": "create_login_tokens",
                    "data": {
                        "user_id": user_id,
                        "token": str(uuid.uuid4()),
                        "expires_at": "2024-01-01T00:00:00Z",
                        "created_at": "2023-01-01T12:00:00Z"
                    }
                })
            block_reqid = str(uuid.uuid4())
            batch_message = {
                "client_id": self.client_id,
                "request_id": block_reqid,
                "timestamp": self.timestamp,
                "operation": "batch_operations",
                "data": {"actions": actions},
                "comment": f"test_create_users_with_all_records_block_{block_start // block_size + 1}"
            }
            batch_message["signature"] = self.sign_message(batch_message)
            print("\n\n")
            print(batch_message)
            print("\n\n")
            response = self.send_and_receive_message(batch_message)
            self.assertEqual(response["status"], "success")
            logging.info(f"Block {block_start // block_size + 1} processed successfully")

    def test_get_user_details_by_user_id(self):
        logging.debug("Running test_get_user_details_by_user_id")
        # Create a user first
        create_user_response = self.__create_user("test_get_user_details_by_user_id", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        user_id = create_user_response["data"]["id"]

        # Create user details record for the user
        details_request_id = str(uuid.uuid4())
        create_details_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "create_user_details",
            "data": {
                "user_id": user_id,
                "details": {"address": "123 Test St"},
                "created_at": "2023-01-01T12:00:00Z",
                "updated_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_create_user_details_for_get_by_user_id"
        }
        create_details_message["request_id"] = details_request_id
        create_details_message["signature"] = self.sign_message(create_details_message)
        create_details_response = self.send_and_receive_message(create_details_message)
        self.assertEqual(create_details_response["status"], "success")

        # Get user details by user_id
        get_request_id = str(uuid.uuid4())
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "get_user_details_by_user_id",
            "data": {"user_id": user_id},
            "comment": "test_get_user_details_by_user_id"
        }
        get_message["request_id"] = get_request_id
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)
        self.assertEqual(response["status"], "success")
        # Expect a list of user details records
        self.assertIsInstance(response["data"], list)
        self.assertGreaterEqual(len(response["data"]), 1)
        for record in response["data"]:
            self.assertEqual(record["user_id"], user_id)

    def test_get_passwords_by_user_id(self):
        logging.debug("Running test_get_passwords_by_user_id")
        # Create a user
        create_user_response = self.__create_user("test_get_passwords_by_user_id", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        user_id = create_user_response["data"]["id"]

        # Create a password record for that user
        password_request_id = str(uuid.uuid4())
        create_password_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "create_passwords",
            "data": {
                "user_id": user_id,
                "password_hash": "test_hash",
                "expiry_date": "2024-01-01T00:00:00Z",
                "created_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_create_password_for_get_by_user_id"
        }
        create_password_message["request_id"] = password_request_id
        create_password_message["signature"] = self.sign_message(create_password_message)
        create_password_response = self.send_and_receive_message(create_password_message)
        self.assertEqual(create_password_response["status"], "success")

        # Get passwords by user_id
        get_request_id = str(uuid.uuid4())
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "get_passwords_by_user_id",
            "data": {"user_id": user_id},
            "comment": "test_get_passwords_by_user_id"
        }
        get_message["request_id"] = get_request_id
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)
        self.assertEqual(response["status"], "success")
        self.assertIsInstance(response["data"], list)
        self.assertGreaterEqual(len(response["data"]), 1)
        for record in response["data"]:
            self.assertEqual(record["user_id"], user_id)

    def test_get_webauthn_credentials_by_user_id(self):
        logging.debug("Running test_get_webauthn_credentials_by_user_id")
        # Create a user
        create_user_response = self.__create_user("test_get_webauthn_credentials_by_user_id", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        user_id = create_user_response["data"]["id"]

        # Create a webauthn credential for that user
        webauthn_request_id = str(uuid.uuid4())
        create_webauthn_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "create_webauthn_credentials",
            "data": {
                "user_id": user_id,
                "credential_id": str(uuid.uuid4()),
                "public_key": "public_key_data",
                "sign_count": 0,
                "transports": "usb",
                "attestation_format": "packed",
                "credential_type": "public-key",
                "created_at": "2023-01-01T12:00:00Z",
                "last_used_at": "2023-01-01T12:00:00Z",
                "counter_last_updated": "2023-01-01T12:00:00Z"
            },
            "comment": "test_create_webauthn_for_get_by_user_id"
        }
        create_webauthn_message["request_id"] = webauthn_request_id
        create_webauthn_message["signature"] = self.sign_message(create_webauthn_message)
        create_webauthn_response = self.send_and_receive_message(create_webauthn_message)
        self.assertEqual(create_webauthn_response["status"], "success")

        # Get webauthn credentials by user_id
        get_request_id = str(uuid.uuid4())
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "get_webauthn_credentials_by_user_id",
            "data": {"user_id": user_id},
            "comment": "test_get_webauthn_credentials_by_user_id"
        }
        get_message["request_id"] = get_request_id
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)
        self.assertEqual(response["status"], "success")
        self.assertIsInstance(response["data"], list)
        self.assertGreaterEqual(len(response["data"]), 1)
        for record in response["data"]:
            self.assertEqual(record["user_id"], user_id)

    def test_get_oauth2_signins_by_user_id(self):
        logging.debug("Running test_get_oauth2_signins_by_user_id")
        # Create a user
        create_user_response = self.__create_user("test_get_oauth2_signins_by_user_id", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        user_id = create_user_response["data"]["id"]

        # Create an OAuth2 signin record for that user
        oauth_request_id = str(uuid.uuid4())
        create_oauth_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "create_oauth2_signins",
            "data": {
                "user_id": user_id,
                "name": "google",
                "provider": "Google",
                "openid_identifier": "openid_identifier_data",
                "access_token": "access_token_data",
                "refresh_token": "refresh_token_data",
                "token_expires_at": "2024-01-01T12:00:00Z",
                "scopes": "email profile",
                "id_token": "id_token_data",
                "last_refreshed": "2023-01-01T12:00:00Z"
            },
            "comment": "test_create_oauth2_for_get_by_user_id"
        }
        create_oauth_message["request_id"] = oauth_request_id
        create_oauth_message["signature"] = self.sign_message(create_oauth_message)
        create_oauth_response = self.send_and_receive_message(create_oauth_message)
        self.assertEqual(create_oauth_response["status"], "success")

        # Get OAuth2 signins by user_id
        get_request_id = str(uuid.uuid4())
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "get_oauth2_signins_by_user_id",
            "data": {"user_id": user_id},
            "comment": "test_get_oauth2_signins_by_user_id"
        }
        get_message["request_id"] = get_request_id
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)
        self.assertEqual(response["status"], "success")
        self.assertIsInstance(response["data"], list)
        self.assertGreaterEqual(len(response["data"]), 1)
        for record in response["data"]:
            self.assertEqual(record["user_id"], user_id)

    def test_get_public_ssh_keys_by_user_id(self):
        logging.debug("Running test_get_public_ssh_keys_by_user_id")
        # Create a user
        create_user_response = self.__create_user("test_get_public_ssh_keys_by_user_id", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        user_id = create_user_response["data"]["id"]

        # Create a public SSH key record for that user
        ssh_request_id = str(uuid.uuid4())
        create_ssh_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "create_public_ssh_keys",
            "data": {
                "user_id": user_id,
                "name": "my_ssh_key",
                "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...",
                "key_type": "rsa",
                "fingerprint": str(uuid.uuid4()),
                "created_at": "2023-01-01T12:00:00Z"
            },
            "comment": "test_create_ssh_for_get_by_user_id"
        }
        create_ssh_message["request_id"] = ssh_request_id
        create_ssh_message["signature"] = self.sign_message(create_ssh_message)
        create_ssh_response = self.send_and_receive_message(create_ssh_message)
        self.assertEqual(create_ssh_response["status"], "success")

        # Get public SSH keys by user_id
        get_request_id = str(uuid.uuid4())
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "get_public_ssh_keys_by_user_id",
            "data": {"user_id": user_id},
            "comment": "test_get_public_ssh_keys_by_user_id"
        }
        get_message["request_id"] = get_request_id
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)
        self.assertEqual(response["status"], "success")
        self.assertIsInstance(response["data"], list)
        self.assertGreaterEqual(len(response["data"]), 1)
        for record in response["data"]:
            self.assertEqual(record["user_id"], user_id)

    def test_get_login_tokens_by_user_id(self):
        logging.debug("Running test_get_login_tokens_by_user_id")
        # Create a user
        create_user_response = self.__create_user("test_get_login_tokens_by_user_id", str(uuid.uuid4()), f"john_doe_{uuid.uuid4()}")
        user_id = create_user_response["data"]["id"]

        # Create a login token record for that user
        token_request_id = str(uuid.uuid4())
        create_token_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "create_login_tokens",
            "data": {
                "user_id": user_id,
                "token": str(uuid.uuid4()),
                "revoked": False,
                "expires_at": "2024-01-01T12:00:00Z"
            },
            "comment": "test_create_login_token_for_get_by_user_id"
        }
        create_token_message["request_id"] = token_request_id
        create_token_message["signature"] = self.sign_message(create_token_message)
        create_token_response = self.send_and_receive_message(create_token_message)
        self.assertEqual(create_token_response["status"], "success")

        # Get login tokens by user_id
        get_request_id = str(uuid.uuid4())
        get_message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "get_login_tokens_by_user_id",
            "data": {"user_id": user_id},
            "comment": "test_get_login_tokens_by_user_id"
        }
        get_message["request_id"] = get_request_id
        get_message["signature"] = self.sign_message(get_message)
        response = self.send_and_receive_message(get_message)
        self.assertEqual(response["status"], "success")
        self.assertIsInstance(response["data"], list)
        self.assertGreaterEqual(len(response["data"]), 1)
        for record in response["data"]:
            self.assertEqual(record["user_id"], user_id)

if __name__ == '__main__':
    unittest.main(failfast=True)
