# User Repository Service

## Overview
The User Repository Service manages user data and supports secure operations through cryptographic signatures and encryption. It handles CRUD operations, batch processing, and integrates with messaging systems like RabbitMQ.

Please note this software is currently under heavy development.

## Features
- **CRUD Operations:** Create, read, update, and delete user data.
- **Batch Operations:** Execute grouped actions atomically.
- **Secure Communication:** Utilizes digital signatures and AES encryption.
- **Message Processing:** Supports JSON-based messaging with RabbitMQ integration.
- **Testing:** Includes unit and integration tests for continuous validation.

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
    - Create a `settings.yml` file by copying the provided `template_for_settings.yml` and updating it with your database, cryptographic, and RabbitMQ configurations.
4. **Generate Cryptographic Keys:**
    To generate all required cryptographic keys, run:
    ```bash
    python generate_keys.py --regenerate-all-keys
    ```
    You can also perform individual key operations:
    - **Regenerate only signing keys:**
      ```bash
      python generate_keys.py --regenerate-signing-keys-only
      ```
    - **Regenerate only the encryption key:**
      ```bash
      python generate_keys.py --regenerate-encryption-key-only
      ```
5. **Initialize the Database:**
    ```bash
    mysql -u your_db_user -p < init.sql
    ```

## Running the Service
- **Start the Service:**
    ```bash
    python user_repository.py
    ```
- The service listens for messages on the RabbitMQ queue `user_repository` and sends responses to the `user_repository_responses` queue.

## Usage
- **Message Format:**  
  The service expects JSON messages with fields like `client_id`, `request_id`, `timestamp`, `operation`, and optionally `data`, `signature`, and an `encrypt` flag.
  
- **Example Message:**  
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
  
- **Sending a Message:**  
  You can publish messages to the `user_repository` queue using any RabbitMQ client or command-line tool. For example, using `rabbitmqadmin`:
    ```bash
    rabbitmqadmin publish routing_key=user_repository payload='{"client_id":"client123", "request_id":"req-456", "timestamp":"2023-10-10T12:00:00Z", "operation":"create_users", "data":{"username":"jdoe", "email":"jdoe@example.com", "user_type":"human"}, "signature":"abcdef123456..."}'
    ```
  
- **Expected Response:**  
  The service processes the message and sends a response (which includes status, message, and a new signature) to the `user_repository_responses` queue.

### Additional Development Details

A good point of reference for how to use the service programmatically would be integration_tests.py, please
do not run the integration tests in a production environment.

## Testing
- **Running Unit and Integration Tests:**
    To run all tests, execute:
    ```bash
    python -m unittest discover tests
    ```
- **Important:**  
  Ensure your `settings.yml` is correctly configured. **Integration tests should not be run in a production environment.**

## Advanced Message Security Details

### Message Signing
- Every message must include a valid `signature` field.
- The signature is generated using the RSA private key with PKCS#1 v1.5 padding and SHA-256 hashing.
- The signature is computed over all message fields except the `signature` field.
- Upon receipt, the service verifies the signature against available RSA public keys. Failure in verification results in an error response.

### Message Encryption
- When the `encrypt` flag is set to true, the `data` field is encrypted using AES symmetric encryption in CBC mode.
- A securely generated symmetric key is used for encryption and stored separately.
- Encrypted messages are decrypted by the service before processing, ensuring data confidentiality.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new feature branch.
3. Commit your changes with clear messages.
4. Open a pull request describing your changes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for details.