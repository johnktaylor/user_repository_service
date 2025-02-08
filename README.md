# User Repository Service

## Overview
The User Repository Service manages user data and provides secure operations through cryptographic signing, verification, and AES encryption. It supports CRUD operations, batch processing, and integrates with RabbitMQ for asynchronous message handling. The service is capable of performing a Diffie-Hellman key exchange to derive a shared symmetric key for optional message encryption.

Please note this software is under active development.

## Features
- **CRUD Operations:** Create, read, update, and delete user records and associated details.
- **Batch Operations:** Execute grouped actions atomically, with support for both plain and encrypted messages.
- **Secure Communication:** 
  - **Message Signing and Verification:** Uses RSA with PKCS#1 v1.5 padding and SHA-256 hashing to sign messages. All messages include a `signature` field which the service validates against public keys stored in the configured `public_keys_dir`.
  - **Key Exchange:** Supports a key exchange process via the `key_exchange_request` operation, allowing clients and the service to derive a shared AES encryption key.
  - **Message Encryption:** Optionally encrypt message payloads using AES encryption. The service supports both **AES 256 CBC** and **AES 256 GCM** modes. The chosen algorithm is specified in the `algorithm` field of the message and is used for encrypting and decrypting the data, ensuring confidentiality and integrity.
- **Message Processing:** Accepts JSON-based messages with fields like `client_id`, `request_id`, `timestamp`, `operation`, and `data`. 
- **Testing:** Includes both unit and integration tests, including tests for encryption workflows. **Integration tests should not be run in a production environment.**

## Setup
1. **Clone the Repository:**
    ```bash
    git clone https://github.com/yourusername/user_repository.git
    cd user_repository
    ```
2. **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3. **Configure Settings:**
    - Create a `settings.yml` file by copying the provided `template_for_settings.yml` and updating it with your database, cryptographic (including `encryption_key_path` if applicable), and RabbitMQ configurations.
    - **Important:** Ensure that your cryptographic key paths (including the `public_keys_dir` and optionally `encryption_key_path`) and RabbitMQ settings are correctly configured.
4. **Generate Cryptographic Keys:**
    The repository uses RSA keys for signing messages and supports AES encryption derived from a Diffie-Hellman key exchange.
    - To regenerate all signing keys (and update the `encryption_key_path` if specified), run:
      ```bash
      python generate_keys.py --regenerate-all-signing-keys
      ```
    - To delete all signing keys without regenerating them, run:
      ```bash
      python generate_keys.py --delete-all-signing-keys
      ```
    - Running the script without any arguments will check for missing keys and report their status.
5. **Initialize the Database:**
    ```bash
    mysql -u your_db_user -p < init.sql
    ```

## Running the Service
- **Start the Service:**
    ```bash
    python user_repository.py
    ```
- The service listens on the RabbitMQ queue specified by `queue_name` in your `settings.yml` and sends responses to the queue defined by `response_queue_name`.

## Usage
- **Message Format:**
  The service expects JSON messages containing the following fields:
  - `client_id`: Unique identifier for the client.
  - `request_id`: Unique identifier for each request.
  - `timestamp`: ISO 8601 formatted timestamp.
  - `operation`: The operation to perform, such as `create_users`, `update_users`, `delete_users`, `get_users`, `batch_operations`, or `key_exchange_request`.
  - `data`: A dictionary containing the required details for the operation.
  - `signature`: Hexadecimal representation of the cryptographic signature (computed over all fields except the signature itself).
  - Optional `encrypt` flag (Boolean): Set to `true` if the `data` field is AES-encrypted.
  
  **Example Message (Unencrypted):**
  ```json
  {
    "client_id": "client123",
    "request_id": "req-456",
    "timestamp": "2023-10-10T12:00:00Z",
    "operation": "create_users",
    "data": {
      "username": "jdoe",
      "email": "jdoe@example.com",
      "user_type": "human"
    },
    "signature": "abcdef123456..."
  }
  ```
  
  **Example Encrypted Batch Operation:**
  ```json
  {
    "client_id": "client123",
    "request_id": "req-789",
    "timestamp": "2023-10-10T12:00:00Z",
    "operation": "batch_operations",
    "encrypt": true,
    "data": "<AES Encrypted JSON string containing batch actions>",
    "signature": "abcdef123456..."
  }
  ```
  - **Key Exchange:**  
    To secure subsequent communications, a client performs a `key_exchange_request` to send its Diffie-Hellman public key. The service responds with its public key so that both parties can derive a shared AES encryption key.

- **Supported Operations:**
  - **Create Operations:** e.g., `create_users`, `create_user_details`, etc.
  - **Update Operations:** e.g., `update_users`, `update_user_details`, **`update_webauthn_credentials`**, **`update_oauth2_signins`**, **`update_public_ssh_keys`**, etc.
  - **Delete Operations:** e.g., `delete_users`, etc.
  - **Get Operations:** e.g., `get_users`, etc.
  - **Batch Operations:** Execute multiple sub-actions atomically by sending a `batch_operations` message.
  - **Key Exchange:** Initiated using the `key_exchange_request` operation.

## Example Interactions
For practical examples on how to interact with the service programmatically, please refer to:
- [integration_tests.py](tests/integration_tests.py): Demonstrates various operations including create, update, delete, get, and batch operations.
- [integration_tests_encryption.py](tests/integration_tests_encryption.py): Provides examples on performing key exchange and handling encrypted messages.

These files serve as a valuable reference for understanding the message format, operation calls, and both unencrypted and encrypted interactions with the service.

## Advanced Message Security Details

### Message Signing
- Every message must include a valid `signature` generated using the client's RSA private key.
- The signature is computed over all message fields (excluding the `signature` field itself) using PKCS#1 v1.5 padding with SHA-256.
- The service verifies the signature by loading available public keys from the specified `public_keys_dir`.

### Message Encryption and Key Exchange
- **Encryption:**  
  When the `encrypt` flag is `true`, the `data` field must be encrypted using AES. You can choose between **CBC** mode for compatibility or **GCM** mode for authenticated encryption. The symmetric key used for encryption is derived from the Diffie-Hellman key exchange.
- **Key Exchange:**  
  Clients initiate a secure channel by sending a `key_exchange_request` message containing their Diffie-Hellman public key. The service replies with its own public key. Both parties then use the exchange to derive a shared symmetric AES key for encrypting subsequent messages.

## Testing
- **Running Unit and Integration Tests:**
    To run all tests, execute:
    ```bash
    python -m unittest discover tests
    ```
- **Important:**  
  Ensure your `settings.yml` is correctly configured. **Integration tests should not be run in a production environment.**

## Troubleshooting
- **Signature Verification Fails:**  
  Ensure that the message is correctly signed (excluding the `signature` field) using the proper RSA private key.
- **Decryption Errors:**  
  Verify that the `encrypt` flag is set appropriately and that the Diffie-Hellman key exchange has successfully provided a symmetric key. Also, confirm that the key length is valid.
- **Configuration and Connection Issues:**  
  Confirm that the database and RabbitMQ configurations in `settings.yml` are correct and that the corresponding services are running.
- **Timestamp Format:**  
  Timestamps must follow the ISO 8601 standard. Timestamps lacking timezone info default to UTC.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new feature branch.
3. Commit your changes with descriptive messages.
4. Open a pull request describing your changes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for details.